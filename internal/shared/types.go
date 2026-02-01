package shared

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// CorrelationIDKey is the context key for distributed tracing
type CorrelationIDKey struct{}

// GetCorrelationID extracts correlation ID from context
func GetCorrelationID(ctx context.Context) string {
	if cid, ok := ctx.Value(CorrelationIDKey{}).(string); ok {
		return cid
	}
	return ""
}

// WithCorrelationID injects correlation ID into context
func WithCorrelationID(ctx context.Context, cid string) context.Context {
	return context.WithValue(ctx, CorrelationIDKey{}, cid)
}

// GenerateCorrelationID creates a new correlation ID
func GenerateCorrelationID() string {
	timestamp := time.Now().UnixNano()
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%d", timestamp)))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// Ed25519Signer handles cryptographic signing operations
type Ed25519Signer struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

// NewEd25519Signer creates a signer from seed
func NewEd25519Signer(seed []byte) (*Ed25519Signer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid seed size: expected %d, got %d", ed25519.SeedSize, len(seed))
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	return &Ed25519Signer{
		PrivateKey: privateKey,
		PublicKey:  privateKey.Public().(ed25519.PublicKey),
	}, nil
}

// Sign creates a cryptographic signature over data
func (s *Ed25519Signer) Sign(data []byte) ([]byte, error) {
	return ed25519.Sign(s.PrivateKey, data), nil
}

// VerifySignature validates a signature
func VerifySignature(publicKey, data, signature []byte) bool {
	return ed25519.Verify(publicKey, data, signature)
}

// EnrollmentID is an opaque token representing a student enrollment
type EnrollmentID string

// String returns the string representation
func (e EnrollmentID) String() string {
	return string(e)
}

// SessionToken represents a signed, ephemeral verification session
type SessionToken struct {
	SessionID    string        `json:"sid"`
	CohortID     string        `json:"coh"`
	ValidFrom    time.Time     `json:"vf"`
	ValidUntil   time.Time     `json:"vu"`
	GeofenceHash string        `json:"geo"`
	IssuerKeyID  string        `json:"kid"`
	Signature    []byte        `json:"sig,omitempty"`
}

// Encode serializes the session token (without signature)
func (st *SessionToken) Encode() ([]byte, error) {
	return json.Marshal(st)
}

// EncodeForSigning returns the canonical bytes for signing
func (st *SessionToken) EncodeForSigning() ([]byte, error) {
	temp := *st
	temp.Signature = nil
	return json.Marshal(temp)
}

// Sign signs the session token
func (st *SessionToken) Sign(signer *Ed25519Signer) error {
	data, err := st.EncodeForSigning()
	if err != nil {
		return err
	}
	sig, err := signer.Sign(data)
	if err != nil {
		return err
	}
	st.Signature = sig
	return nil
}

// Verify verifies the session token signature
func (st *SessionToken) Verify(publicKey ed25519.PublicKey) bool {
	if len(st.Signature) == 0 {
		return false
	}
	data, _ := st.EncodeForSigning()
	return VerifySignature(publicKey, data, st.Signature)
}

// IsValid checks temporal validity
func (st *SessionToken) IsValid(now time.Time) bool {
	return now.After(st.ValidFrom) && now.Before(st.ValidUntil)
}

// IdentityAssertion is the result of biometric verification
type IdentityAssertion struct {
	EnrollmentID    EnrollmentID `json:"eid"`
	Confidence      float64      `json:"conf"`
	MatchThreshold  float64      `json:"thresh"`
	Timestamp       time.Time    `json:"ts"`
	SessionID       string       `json:"sid"`
	CorrelationID   string       `json:"cid"`
	VerificationSig []byte       `json:"vsig"`
}

// AttendanceRecord represents a signed attendance event
type AttendanceRecord struct {
	RecordID      string        `json:"rid"`
	EnrollmentID  EnrollmentID  `json:"eid"`
	SessionID     string        `json:"sid"`
	Confidence    float64       `json:"conf"`
	DecisionTime  time.Time     `json:"dts"`
	GeofenceValid bool          `json:"geo"`
	TimeValid     bool          `json:"tvalid"`
	CorrelationID string        `json:"cid"`
	Signature     []byte        `json:"sig"`
}

// EncodeForSigning returns canonical bytes for signing
func (ar *AttendanceRecord) EncodeForSigning() ([]byte, error) {
	temp := *ar
	temp.Signature = nil
	return json.Marshal(temp)
}

// Sign signs the attendance record
func (ar *AttendanceRecord) Sign(signer *Ed25519Signer) error {
	data, err := ar.EncodeForSigning()
	if err != nil {
		return err
	}
	sig, err := signer.Sign(data)
	if err != nil {
		return err
	}
	ar.Signature = sig
	return nil
}

// Verify verifies the attendance record signature
func (ar *AttendanceRecord) Verify(publicKey ed25519.PublicKey) bool {
	if len(ar.Signature) == 0 {
		return false
	}
	data, _ := ar.EncodeForSigning()
	return VerifySignature(publicKey, data, ar.Signature)
}

// BiometricTemplate is a non-reversible template representation
type BiometricTemplate struct {
	EnrollmentID EnrollmentID `json:"eid"`
	TemplateHash string       `json:"thash"`
	Embedding    []float32    `json:"emb"`
	Version      int          `json:"ver"`
	Revoked      bool         `json:"rev"`
	CreatedAt    time.Time    `json:"cat"`
}

// NonReversibleTransform applies a privacy-preserving transformation
// This is a mock implementation - replace with actual privacy-preserving algorithm
func (bt *BiometricTemplate) NonReversibleTransform(key []byte) ([]byte, error) {
	// In production: use homomorphic encryption, secure multi-party computation,
	// or cancelable biometric transforms
	h := sha256.New()
	h.Write(key)
	h.Write([]byte(bt.EnrollmentID))
	for _, v := range bt.Embedding {
		h.Write([]byte(fmt.Sprintf("%.6f", v)))
	}
	return h.Sum(nil), nil
}

// MatchResult represents the outcome of biometric comparison
type MatchResult struct {
	Matched        bool      `json:"matched"`
	Confidence     float64   `json:"confidence"`
	EnrollmentID   EnrollmentID `json:"enrollment_id"`
	MatchThreshold float64   `json:"threshold"`
}

// ErrorResponse is a standardized error structure
type ErrorResponse struct {
	Code          string `json:"code"`
	Message       string `json:"message"`
	CorrelationID string `json:"correlation_id,omitempty"`
	Retryable     bool   `json:"retryable"`
}

// Base64Encode helper
func Base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// Base64Decode helper
func Base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
