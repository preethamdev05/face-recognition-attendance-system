package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/preethamdev05/face-recognition-attendance-system/internal/shared"
)

var (
	aLogger   = shared.NewLogger("audit-service")
	ledgerURL = os.Getenv("LEDGER_SERVICE_URL")
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

// Read-only boundary for attendance ledger
func recordsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cid := shared.GetCorrelationID(ctx)

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	client := shared.NewHTTPClient(ledgerURL, 3*time.Second)
	resp, err := client.Get(ctx, "/v1/ledger/records", nil)
	if err != nil {
		aLogger.LogError(ctx, "ledger query error", err, nil)
		writeError(w, http.StatusBadGateway, "LEDGER_UNAVAILABLE", "Ledger service unavailable", cid, true)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		writeError(w, http.StatusBadGateway, "LEDGER_ERROR", "Failed to query ledger", cid, true)
		return
	}

	var records []shared.AttendanceRecord
	if err := json.NewDecoder(resp.Body).Decode(&records); err != nil {
		writeError(w, http.StatusBadGateway, "DECODE_ERROR", "Malformed ledger response", cid, true)
		return
	}

	// In a real deployment this endpoint would also return signature chains and
	// public keys for independent verification. Structure is ready to be extended.
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Correlation-ID", cid)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(records)
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

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthHandler)
	mux.HandleFunc("/v1/audit/records", recordsHandler)

	h := correlationMiddleware(mux)

	addr := ":8080"
	aLogger.LogInfo(context.Background(), "starting audit service", map[string]interface{}{"addr": addr})
	if err := http.ListenAndServe(addr, h); err != nil {
		aLogger.LogError(context.Background(), "server exited", err, nil)
	}
}
