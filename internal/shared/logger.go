package shared

import (
	"context"
	"log"
	"os"
	"time"
)

// Logger provides structured logging with correlation IDs
type Logger struct {
	serviceName string
	logger      *log.Logger
}

// NewLogger creates a new structured logger
func NewLogger(serviceName string) *Logger {
	return &Logger{
		serviceName: serviceName,
		logger:      log.New(os.Stdout, "", log.LstdFlags),
	}
}

// LogInfo logs an informational message
func (l *Logger) LogInfo(ctx context.Context, msg string, fields map[string]interface{}) {
	l.log(ctx, "INFO", msg, fields)
}

// LogError logs an error message
func (l *Logger) LogError(ctx context.Context, msg string, err error, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}
	if err != nil {
		fields["error"] = err.Error()
	}
	l.log(ctx, "ERROR", msg, fields)
}

// LogWarn logs a warning message
func (l *Logger) LogWarn(ctx context.Context, msg string, fields map[string]interface{}) {
	l.log(ctx, "WARN", msg, fields)
}

func (l *Logger) log(ctx context.Context, level, msg string, fields map[string]interface{}) {
	cid := GetCorrelationID(ctx)
	if fields == nil {
		fields = make(map[string]interface{})
	}
	fields["service"] = l.serviceName
	fields["level"] = level
	fields["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	if cid != "" {
		fields["correlation_id"] = cid
	}
	
	// Simple JSON-like output for production use structured logging library
	l.logger.Printf("[%s] [%s] [%s] %s fields=%+v", level, l.serviceName, cid, msg, fields)
}
