# Cloud-Hosted Face Recognition Attendance System

Production-ready backend blueprint implementation for a server-authoritative, privacy-preserving face recognition attendance system deployed as independent Cloud Run services.

## Services

- Capture Coordination Service (`services/capture`)
- Biometric Verification Service (`services/verification`)
- Attendance Decision Service (`services/decision`)
- Template Repository API (`services/template-repo`)
- Attendance Ledger (`services/ledger`)
- Session Management Service (`services/session`)
- Audit & Compliance Interface (`services/audit`)

All services are stateless and rely on external stores for templates and ledger state in production. Each service is deployable independently to Cloud Run using its local `Dockerfile`.

## Shared Kernel

Located under `internal/shared`:

- Correlation ID propagation helpers
- Ed25519 signing and verification primitives
- Domain types: `SessionToken`, `IdentityAssertion`, `AttendanceRecord`, `BiometricTemplate`
- Privacy-preserving template transform interface (`BiometricTemplate.NonReversibleTransform`)
- Structured logger with correlation ID injection
- HTTP client wrapper with automatic `X-Correlation-ID` propagation

## Correlation ID Chain

Every incoming HTTP request:

- Reads `X-Correlation-ID` header if present, otherwise generates a new opaque ID
- Injects it into `context.Context` via `shared.WithCorrelationID`
- Logs it via `shared.Logger`
- Propagates it to downstream services via `shared.HTTPClient`

## Cryptographic Chain of Custody

1. **Session Tokens**
   - Issued by `services/session` as signed `SessionToken` objects
   - Signed with Ed25519 using the session service private key
   - Capture, verification, and decision services validate signature and temporal validity

2. **Verification Assertions**
   - Produced exclusively by `services/verification`
   - Contain `EnrollmentID`, `SessionID`, confidence score, and `CorrelationID`
   - Signed with a dedicated verification Ed25519 key

3. **Attendance Records**
   - Constructed and signed only in `services/decision`
   - Include `{EnrollmentID, SessionID, decision timestamp, confidence, geofence/time flags, CorrelationID}`
   - Signed with the decision service Ed25519 key
   - Appended immutably to the ledger service

4. **Ledger Immutability**
   - `services/ledger` exposes append-only semantics
   - Idempotency keys prevent duplicate commits
   - Records are treated as immutable once stored; mutation paths are rejected

5. **Audit Verification**
   - `services/audit` is read-only and composes proof chains from the ledger
   - External observers can verify Ed25519 signatures using the published public keys

## Privacy and Server Authority Invariants

- **Server authority**: Matching logic exists only in `services/verification`. Clients never submit identity claims; they supply only opaque captures and session tokens.
- **Template non-reversibility**: `BiometricTemplate` exposes a `NonReversibleTransform` function based on one-way hashing of embeddings with a secret key. Implementations are pluggable to support stronger privacy protocols.
- **No biometric leakage**: Logs never include raw biometric payloads or embeddings. Only opaque IDs, hashes, and high-level metadata are logged.
- **Modality agnostic**: Templates are opaque vectors; decision and ledger services never depend on biometric modality details.

## Deployment

A `docker-compose.yml` under `deploy/` describes local multi-service wiring suitable as a baseline for Cloud Run deployment. Each service has its own `Dockerfile` and exposes a small HTTP surface:

- `GET /healthz` – liveness probe
- Service-specific `POST`/`GET` endpoints for capture, verification, decisions, ledger append, session creation, and audit queries

## Signature Verification Guide

1. Obtain public keys for session, verification, and decision services (environment variables or dedicated metadata endpoints).
2. For a given attendance record:
   - Verify the attendance record Ed25519 signature over the canonical JSON encoding without the `Signature` field.
   - Using the embedded `SessionID`, locate the corresponding session token and verify its Ed25519 signature and temporal validity.
   - Using the embedded `EnrollmentID` and `SessionID`, locate the verification assertion and verify its Ed25519 signature.
3. Confirm that all correlation IDs in the chain match to ensure end-to-end traceability.
