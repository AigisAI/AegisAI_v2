# Data Model: Production Scan Architecture

## Core Entities

### Tenant

Represents an isolated customer boundary. Every long-lived production architecture entity
is tenant-attributed.

### UserOAuthIdentity

Stores only user-to-provider identity metadata. OAuth access and refresh tokens are
transient during login and are not persisted in this model.

### ScmIntegration

Represents a GitHub App installation or GitLab Cloud integration. It records provider,
external installation identity, and separate principal identifiers for repo-read,
comment-write, and integration-admin authority.

### RepositoryBinding

Represents a repository made available through an SCM integration. It is not a user OAuth
token connection.

### ScanRequest

Represents a canonical scan request with tenant, repository binding, lane, target ref,
fixed commit SHA, policy version, scanner-set version, status, isolation class, and
canonical key.

### ScannerRun

Represents one deterministic scanner execution attempt such as Opengrep, Trivy, or Syft.
Raw artifacts are referenced by short-lived object keys, not stored as long-lived database
content.

The in-memory mock contract adds optional `planning` metadata for manifest-driven runs:
scan profile, detected languages/surfaces, and Java advisory eligibility. No-manifest
runs omit it. This increment does not add persistence columns or store repository paths.

### NormalizedFinding

Represents a customer-visible finding after scanner output normalization and correlation.
It records scanner provenance, severity, file path, line range, status, and optional policy
decision relationship.

Manifest-driven Java mock findings additionally carry `language: JAVA` and
`scanProfile: JAVA_DETAILED`. Common-only runs emit no mock Java finding. The narrowed
`JavaDetailedFinding` contract is the only finding type accepted by AI advisory types.

### EvidencePack

Represents reduced, redacted, short-lived evidence metadata. Object keys are tenant and
scan scoped and expire by TTL.

### PolicyDecision

Represents a structured policy-as-code result with enforcement action, comment visibility,
dashboard visibility, block/ticket requests, reason codes, coverage requirements, waiver
state, stale suppression, and AI advisory visibility.

### Waiver

Represents an auditable exception with owner, reason, scope, expiry, creation time, and
review state.

### Suppression

Represents stale-result, duplicate, or policy-based suppression of findings or comments.

### AuditEvent

Represents security and operational lineage for token issuance, webhook intake, scan
planning, evidence access, policy evaluation, comment publication, waiver lifecycle, and
model version use.

## State Transitions

- ScanRequest: `QUEUED -> PLANNING -> RUNNING -> COMPLETED | FAILED | CANCELED`
- ScannerRun: `QUEUED -> RUNNING -> COMPLETED | FAILED | TIMED_OUT | SKIPPED`
- NormalizedFinding: `OPEN -> ACCEPTED | REJECTED | WAIVED | SUPPRESSED | FIXED`
- EvidencePack: available until `expiresAt`, after which TTL enforcement must delete or
  deny access.

## Isolation Rules

- Every query over production architecture data must carry tenant attribution.
- Evidence object keys must include `tenantId` and `scanRequestId`.
- AI advisory requests must not include SCM credentials or full repository payloads.
- Token Broker requests must be scan-scoped and must not persist token values.
- User-facing tenant filters must be derived from the authenticated session rather than
  caller-provided tenant identifiers.
