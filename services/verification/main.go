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
	vLogger        = shared.NewLogger("verification-service")
	templateURL    = os.Getenv("TEMPLATE_SERVICE_URL")
	decisionURL    = os.Getenv("DECISION_SERVICE_URL")
	verifierSeed   []byte
	verificationSK *shared.Ed25519Signer
)

type verifyRequest struct {
	SessionToken   string `json:"session_token"`
	CapturePayload string `json:"capture_payload"`
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

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cid := shared.GetCorrelationID(ctx)

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req verifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		vLogger.LogError(ctx, "invalid verify request", err, nil)
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Malformed JSON", cid, false)
		return
	}

	// Decode and parse session token (signature & policy checks handled upstream)
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

	// Fetch cohort templates (no caching in compute layer)
	client := shared.NewHTTPClient(templateURL, 2*time.Second)
	resp, err := client.Get(ctx, "/v1/templates?cohort_id="+st.CohortID, nil)
	if err != nil {
		vLogger.LogError(ctx, "template service error", err, nil)
		writeError(w, http.StatusBadGateway, "TEMPLATE_UNAVAILABLE", "Template repository unavailable", cid, true)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		writeError(w, http.StatusBadGateway, "TEMPLATE_ERROR", "Failed to load templates", cid, true)
		return
	}

	var templates []shared.BiometricTemplate
	if err := json.NewDecoder(resp.Body).Decode(&templates); err != nil {
		writeError(w, http.StatusBadGateway, "TEMPLATE_DECODE_ERROR", "Malformed template response", cid, true)
		return
	}

	if len(templates) == 0 {
		writeError(w, http.StatusForbidden, "NO_TEMPLATES", "No templates available for cohort", cid, false)
		return
	}

	// Mock privacy-preserving matching: choose first template deterministically
	// Real implementation would transform both capture and templates in a non-reversible domain.
	matchedTemplate := templates[0]
	assertion := shared.IdentityAssertion{
		EnrollmentID:   matchedTemplate.EnrollmentID,
		Confidence:     0.9,
		MatchThreshold: 0.8,
		Timestamp:      time.Now().UTC(),
		SessionID:      st.SessionID,
		CorrelationID:  cid,
	}

	// Sign assertion
	unsigned := assertion
	unsigned.VerificationSig = nil
	data, err := json.Marshal(unsigned)
	if err != nil {
		vLogger.LogError(ctx, "failed to marshal assertion", err, nil)
		writeError(w, http.StatusInternalServerError, "ASSERTION_ERROR", "Unable to create assertion", cid, true)
		return
	}

	sig, err := verificationSK.Sign(data)
	if err != nil {
		vLogger.LogError(ctx, "failed to sign assertion", err, nil)
		writeError(w, http.StatusInternalServerError, "SIGNING_ERROR", "Unable to sign assertion", cid, true)
		return
	}
	assertion.VerificationSig = sig

	// Forward to decision service for business rules and ledger append
	dClient := shared.NewHTTPClient(decisionURL, 3*time.Second)
	body := map[string]interface{}{
		"assertion":     assertion,
		"session_token": req.SessionToken,
	}

	dResp, err := dClient.Post(ctx, "/v1/decide", body, nil)
	if err != nil {
		vLogger.LogError(ctx, "decision service error", err, nil)
		writeError(w, http.StatusBadGateway, "DECISION_UNAVAILABLE", "Decision service unavailable", cid, true)
		return
	}
	defer dResp.Body.Close()

	if dResp.StatusCode != http.StatusOK {
		// Fail-safe: do not leak decision details, treat as verification failure
		writeError(w, http.StatusForbidden, "DECISION_REJECTED", "Verification rejected", cid, false)
		return
	}

	// We do not expose identity to clients; just success/failure.
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Correlation-ID", cid)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":         "verified_and_recorded",
		"correlation_id": cid,
	})
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

func mustInitSigner() {
	seedB64 := os.Getenv("VERIFICATION_SEED_B64")
	if seedB64 == "" {
		panic("VERIFICATION_SEED_B64 not set")
	}
	seed, err := base64.StdEncoding.DecodeString(seedB64)
	if err != nil {
		panic("invalid VERIFICATION_SEED_B64")
	}
	verificationSK, err = shared.NewEd25519Signer(seed)
	if err != nil {
		panic("failed to create verification signer")
	}
	verifierSeed = seed
}

func main() {
	mustInitSigner()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthHandler)
	mux.HandleFunc("/v1/verify", verifyHandler)

	h := correlationMiddleware(mux)

	addr := ":8080"
	vLogger.LogInfo(context.Background(), "starting verification service", map[string]interface{}{"addr": addr})
	if err := http.ListenAndServe(addr, h); err != nil {
		vLogger.LogError(context.Background(), "server exited", err, nil)
	}
}
