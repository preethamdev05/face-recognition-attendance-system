package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/preethamdev05/face-recognition-attendance-system/internal/shared"
)

var (
	logger          = shared.NewLogger("capture-service")
	verificationURL = os.Getenv("VERIFICATION_SERVICE_URL")
	sessionPubKey   []byte
)

type captureRequest struct {
	SessionToken   string `json:"session_token"`
	CapturePayload string `json:"capture"`
}

type captureResponse struct {
	Status        string `json:"status"`
	CorrelationID string `json:"correlation_id"`
}

// correlationMiddleware extracts or generates correlation IDs
func correlationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cid := r.Header.Get("X-Correlation-ID")
		if cid == "" {
			cid = shared.GenerateCorrelationID()
		}
		ctx := shared.WithCorrelationID(r.Context(), cid)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func captureHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cid := shared.GetCorrelationID(ctx)

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req captureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.LogError(ctx, "invalid capture request", err, nil)
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Malformed JSON", cid, false)
		return
	}

	if req.SessionToken == "" || req.CapturePayload == "" {
		writeError(w, http.StatusBadRequest, "MISSING_FIELDS", "session_token and capture are required", cid, false)
		return
	}

	// Decode and verify session token
	sessBytes, err := base64.StdEncoding.DecodeString(req.SessionToken)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_SESSION_TOKEN", "Unable to decode session token", cid, false)
		return
	}

	var st shared.SessionToken
	if err := json.Unmarshal(sessBytes, &st); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_SESSION_TOKEN", "Malformed session token", cid, false)
		return
	}

	if !st.IsValid(time.Now().UTC()) {
		writeError(w, http.StatusUnauthorized, "SESSION_EXPIRED", "Session token is not valid in current time window", cid, false)
		return
	}

	if !st.Verify(sessionPubKey) {
		writeError(w, http.StatusUnauthorized, "SESSION_SIGNATURE_INVALID", "Session token signature invalid", cid, false)
		return
	}

	// Forward to verification service without exposing identity
	client := shared.NewHTTPClient(verificationURL, 3*time.Second)
	vr := map[string]string{
		"session_token":   req.SessionToken,
		"capture_payload": req.CapturePayload,
	}

	resp, err := client.Post(ctx, "/v1/verify", vr, nil)
	if err != nil {
		logger.LogError(ctx, "verification service error", err, nil)
		writeError(w, http.StatusBadGateway, "VERIFICATION_UNAVAILABLE", "Verification service unavailable", cid, true)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Do not leak verification details to client
		writeError(w, http.StatusForbidden, "VERIFICATION_FAILED", "Verification failed", cid, false)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Correlation-ID", cid)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(captureResponse{Status: "accepted", CorrelationID: cid})
}

func writeError(w http.ResponseWriter, status int, code, msg, cid string, retryable bool) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Correlation-ID", cid)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(shared.ErrorResponse{
		Code:          code,
		Message:       msg,
		CorrelationID: cid,
		Retryable:     retryable,
	})
}

func mustInitKeys() {
	pubB64 := os.Getenv("SESSION_PUBLIC_KEY_B64")
	if pubB64 == "" {
		panic("SESSION_PUBLIC_KEY_B64 not set")
	}
	pk, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		panic("invalid SESSION_PUBLIC_KEY_B64")
	}
	sessionPubKey = pk
}

func main() {
	mustInitKeys()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthHandler)
	mux.HandleFunc("/v1/capture", captureHandler)

	h := correlationMiddleware(mux)

	addr := ":8080"
	logger.LogInfo(context.Background(), "starting capture service", map[string]interface{}{"addr": addr})
	if err := http.ListenAndServe(addr, h); err != nil {
		logger.LogError(context.Background(), "server exited", err, nil)
	}
}
