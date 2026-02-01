package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/preethamdev05/face-recognition-attendance-system/internal/shared"
)

var (
	dLogger       = shared.NewLogger("decision-service")
	ledgerURL     = os.Getenv("LEDGER_SERVICE_URL")
	sessionPubKey []byte
	decisionSK    *shared.Ed25519Signer
)

type decisionRequest struct {
	Assertion    shared.IdentityAssertion `json:"assertion"`
	SessionToken string                  `json:"session_token"`
}

type decisionResponse struct {
	RecordID      string `json:"record_id"`
	CorrelationID string `json:"correlation_id"`
}

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

func decideHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cid := shared.GetCorrelationID(ctx)

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req decisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		dLogger.LogError(ctx, "invalid decision request", err, nil)
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Malformed JSON", cid, false)
		return
	}

	// Fail-safe: confidence must exceed threshold
	if req.Assertion.Confidence < req.Assertion.MatchThreshold {
		writeError(w, http.StatusForbidden, "LOW_CONFIDENCE", "Verification confidence below threshold", cid, false)
		return
	}

	// Decode and validate session token
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

	// Placeholder geofence validation – structure only, real implementation swaps here
	geofenceValid := st.GeofenceHash != ""
	timeValid := true

	record := shared.AttendanceRecord{
		EnrollmentID:  req.Assertion.EnrollmentID,
		SessionID:     st.SessionID,
		Confidence:    req.Assertion.Confidence,
		DecisionTime:  time.Now().UTC(),
		GeofenceValid: geofenceValid,
		TimeValid:     timeValid,
		CorrelationID: cid,
	}

	// Deterministic record ID
	h := sha256.New()
	h.Write([]byte(record.EnrollmentID))
	h.Write([]byte(record.SessionID))
	h.Write([]byte(record.DecisionTime.Format(time.RFC3339Nano)))
	record.RecordID = hex.EncodeToString(h.Sum(nil))

	// Sign attendance record
	if err := record.Sign(decisionSK); err != nil {
		dLogger.LogError(ctx, "failed to sign record", err, nil)
		writeError(w, http.StatusInternalServerError, "SIGNING_ERROR", "Unable to sign record", cid, true)
		return
	}

	// Append to ledger with idempotency key
	client := shared.NewHTTPClient(ledgerURL, 3*time.Second)
	appendReq := map[string]interface{}{
		"record":          record,
		"idempotency_key": record.RecordID,
	}

	lResp, err := client.Post(ctx, "/v1/ledger/append", appendReq, nil)
	if err != nil {
		dLogger.LogError(ctx, "ledger service error", err, nil)
		writeError(w, http.StatusBadGateway, "LEDGER_UNAVAILABLE", "Ledger service unavailable", cid, true)
		return
	}
	defer lResp.Body.Close()

	if lResp.StatusCode != http.StatusOK {
		writeError(w, http.StatusBadGateway, "LEDGER_ERROR", "Failed to append record", cid, true)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Correlation-ID", cid)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(decisionResponse{RecordID: record.RecordID, CorrelationID: cid})
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

	seedB64 := os.Getenv("DECISION_SEED_B64")
	if seedB64 == "" {
		panic("DECISION_SEED_B64 not set")
	}
	seed, err := base64.StdEncoding.DecodeString(seedB64)
	if err != nil {
		panic("invalid DECISION_SEED_B64")
	}
	decisionSK, err = shared.NewEd25519Signer(seed)
	if err != nil {
		panic("failed to create decision signer")
	}
}

func main() {
	mustInitKeys()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthHandler)
	mux.HandleFunc("/v1/decide", decideHandler)

	h := correlationMiddleware(mux)

	addr := ":8080"
	dLogger.LogInfo(context.Background(), "starting decision service", map[string]interface{}{"addr": addr})
	if err := http.ListenAndServe(addr, h); err != nil {
		dLogger.LogError(context.Background(), "server exited", err, nil)
	}
}
