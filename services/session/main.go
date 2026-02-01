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
	sLogger   = shared.NewLogger("session-service")
	issuerKID = os.Getenv("SESSION_ISSUER_KEY_ID")
	seed      []byte
	signer    *shared.Ed25519Signer
)

type sessionRequest struct {
	CohortID     string `json:"cohort_id"`
	DurationSecs int64  `json:"duration_secs"`
	GeofenceHash string `json:"geofence_hash"`
}

type sessionResponse struct {
	Token        string `json:"token"`
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

func createSessionHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cid := shared.GetCorrelationID(ctx)

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req sessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sLogger.LogError(ctx, "invalid session request", err, nil)
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Malformed JSON", cid, false)
		return
	}

	if req.CohortID == "" || req.DurationSecs <= 0 {
		writeError(w, http.StatusBadRequest, "MISSING_FIELDS", "cohort_id and positive duration_secs required", cid, false)
		return
	}

	now := time.Now().UTC()
	st := shared.SessionToken{
		SessionID:    shared.GenerateCorrelationID(),
		CohortID:     req.CohortID,
		ValidFrom:    now,
		ValidUntil:   now.Add(time.Duration(req.DurationSecs) * time.Second),
		GeofenceHash: req.GeofenceHash,
		IssuerKeyID:  issuerKID,
	}

	if err := st.Sign(signer); err != nil {
		sLogger.LogError(ctx, "failed to sign session token", err, nil)
		writeError(w, http.StatusInternalServerError, "SIGNING_ERROR", "Unable to sign token", cid, true)
		return
	}

	bytes, err := json.Marshal(st)
	if err != nil {
		sLogger.LogError(ctx, "failed to marshal session token", err, nil)
		writeError(w, http.StatusInternalServerError, "ENCODE_ERROR", "Unable to encode token", cid, true)
		return
	}

	token := base64.StdEncoding.EncodeToString(bytes)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Correlation-ID", cid)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(sessionResponse{Token: token, CorrelationID: cid})
}

// Expose public key for verification services and auditors
func publicKeyHandler(w http.ResponseWriter, r *http.Request) {
	cid := shared.GetCorrelationID(r.Context())
	pub := signer.PublicKey
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Correlation-ID", cid)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"public_key_b64": base64.StdEncoding.EncodeToString(pub),
		"key_id":         issuerKID,
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
	seedB64 := os.Getenv("SESSION_SEED_B64")
	if seedB64 == "" {
		panic("SESSION_SEED_B64 not set")
	}
	b, err := base64.StdEncoding.DecodeString(seedB64)
	if err != nil {
		panic("invalid SESSION_SEED_B64")
	}
	seed = b
	signer, err = shared.NewEd25519Signer(seed)
	if err != nil {
		panic("failed to create session signer")
	}
}

func main() {
	mustInitSigner()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthHandler)
	mux.HandleFunc("/v1/session", createSessionHandler)
	mux.HandleFunc("/v1/session/public-key", publicKeyHandler)

	h := correlationMiddleware(mux)

	addr := ":8080"
	sLogger.LogInfo(context.Background(), "starting session service", map[string]interface{}{"addr": addr})
	if err := http.ListenAndServe(addr, h); err != nil {
		sLogger.LogError(context.Background(), "server exited", err, nil)
	}
}
