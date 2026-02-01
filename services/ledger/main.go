package main

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/preethamdev05/face-recognition-attendance-system/internal/shared"
)

var (
	lLogger = shared.NewLogger("ledger-service")

	// In production, this is an external append-only store. Here: in-memory mock with immutability.
	ledgerMu sync.Mutex
	ledger   = make(map[string]shared.AttendanceRecord) // key: record ID
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

type appendRequest struct {
	Record         shared.AttendanceRecord `json:"record"`
	IdempotencyKey string                 `json:"idempotency_key"`
}

type appendResponse struct {
	CommitID      string `json:"commit_id"`
	StoredAt      string `json:"stored_at"`
	CorrelationID string `json:"correlation_id"`
}

func appendHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cid := shared.GetCorrelationID(ctx)

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req appendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		lLogger.LogError(ctx, "invalid append request", err, nil)
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Malformed JSON", cid, false)
		return
	}

	if req.IdempotencyKey == "" || req.Record.RecordID == "" {
		writeError(w, http.StatusBadRequest, "MISSING_FIELDS", "record_id and idempotency_key required", cid, false)
		return
	}

	ledgerMu.Lock()
	defer ledgerMu.Unlock()

	if existing, ok := ledger[req.Record.RecordID]; ok {
		// Idempotent: return existing commit without mutation
		_ = existing
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Correlation-ID", cid)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(appendResponse{
			CommitID:      req.Record.RecordID,
			StoredAt:      existing.DecisionTime.Format(time.RFC3339Nano),
			CorrelationID: cid,
		})
		return
	}

	// Immutable append
	ledger[req.Record.RecordID] = req.Record

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Correlation-ID", cid)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(appendResponse{
		CommitID:      req.Record.RecordID,
		StoredAt:      req.Record.DecisionTime.Format(time.RFC3339Nano),
		CorrelationID: cid,
	})
}

// Read API for audit and internal consumers – read-only
func recordsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cid := shared.GetCorrelationID(ctx)

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	ledgerMu.Lock()
	defer ledgerMu.Unlock()

	records := make([]shared.AttendanceRecord, 0, len(ledger))
	for _, rec := range ledger {
		records = append(records, rec)
	}

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
	mux.HandleFunc("/v1/ledger/append", appendHandler)
	mux.HandleFunc("/v1/ledger/records", recordsHandler)

	h := correlationMiddleware(mux)

	addr := ":8080"
	lLogger.LogInfo(context.Background(), "starting ledger service", map[string]interface{}{"addr": addr})
	if err := http.ListenAndServe(addr, h); err != nil {
		lLogger.LogError(context.Background(), "server exited", err, nil)
	}
}
