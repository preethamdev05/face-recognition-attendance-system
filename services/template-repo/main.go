package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/preethamdev05/face-recognition-attendance-system/internal/shared"
)

var (
	tLogger   = shared.NewLogger("template-repo-service")
	secretKey []byte
)

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

// GET /v1/templates?cohort_id=COHORT
// Mock, stateless implementation: deterministically derives templates from cohort ID.
func templatesHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cid := shared.GetCorrelationID(ctx)

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	cohort := r.URL.Query().Get("cohort_id")
	if cohort == "" {
		writeError(w, http.StatusBadRequest, "MISSING_COHORT", "cohort_id is required", cid, false)
		return
	}

	// Deterministically derive a small set of templates without persisting state.
	const n = 3
	templates := make([]shared.BiometricTemplate, 0, n)

	for i := 0; i < n; i++ {
		id := shared.EnrollmentID(cohort + "-" + strconv.Itoa(i))
		bt := shared.BiometricTemplate{
			EnrollmentID: id,
			Embedding:    []float32{float32(i)},
			Version:      1,
			Revoked:      false,
			CreatedAt:    time.Now().UTC(),
		}
		hashBytes, err := bt.NonReversibleTransform(secretKey)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "TRANSFORM_ERROR", "Unable to transform template", cid, true)
			return
		}
		bt.TemplateHash = hex.EncodeToString(hashBytes)
		// Do not expose raw embeddings in logs or external systems.
		bt.Embedding = nil
		templates = append(templates, bt)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Correlation-ID", cid)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(templates)
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

func mustInitKey() {
	keyHex := os.Getenv("TEMPLATE_SECRET_KEY_HEX")
	if keyHex == "" {
		panic("TEMPLATE_SECRET_KEY_HEX not set")
	}
	b, err := hex.DecodeString(keyHex)
	if err != nil {
		panic("invalid TEMPLATE_SECRET_KEY_HEX")
	}
	secretKey = b
}

func main() {
	mustInitKey()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthHandler)
	mux.HandleFunc("/v1/templates", templatesHandler)

	h := correlationMiddleware(mux)

	addr := ":8080"
	tLogger.LogInfo(context.Background(), "starting template repo service", map[string]interface{}{"addr": addr})
	if err := http.ListenAndServe(addr, h); err != nil {
		tLogger.LogError(context.Background(), "server exited", err, nil)
	}
}
