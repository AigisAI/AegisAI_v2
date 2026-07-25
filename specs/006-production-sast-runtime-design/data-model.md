# Data Model: Production SAST Runtime

## Ownership

- Control Plane owns immutable scan intent, policy version, canonical identity, tenant
  quota, and external publication decisions.
- Scan Plane owns scan attempts, sandbox lifecycle, scanner runs, artifact ingestion,
  normalization, correlation, evidence construction, and coverage.
- Data/Security Plane owns durable tenant-attributed findings, short-lived artifacts and
  evidence, audit events, KMS context, and retention enforcement.
- AI Plane owns advisory request/response metadata only.

No entity in this model contains a repository credential value, full repository archive,
or user-supplied executable scanner configuration.

## Core Entities

### SastScanProfile

Versioned, immutable profile selected during planning.

- `id`: `JAVA_FAST_V1 | JAVA_DEEP_V1 | COMMON_DEEP_V1`
- `lane`: `FAST | DEEP`
- `language`: `JAVA | COMMON`
- `scope`: changed files with context or full repository
- `requiredScanners`
- `optionalScanners`
- `requiredCapabilities`
- `sourceExtensions`
- `manifestNames`
- `pathPolicy`
- `resourceLimits`
- `aiAdvisoryEligible`
- hard `false` values for build, package install, dynamic execution, and network enrichment

Profiles may be deprecated but are never mutated after use.

### ScannerSetDescriptor

Reproducible scanner and data set for one scan.

- `scannerSetVersion`, digest, signature, and provenance
- scanner image/binary version, digest, signature, provenance, and SBOM per scanner
- wrapper digest, signature, and provenance per scanner
- rule bundle descriptors
- vulnerability database version, published timestamp, digest, signature, and provenance
- Trivy checks bundle digest
- SBOM schema plus schema-bundle digest/signature/provenance
- normalizer-bundle digest/signature/provenance
- rollback reference

### RuleBundle

Immutable platform-managed rule collection.

- `bundleId`
- semantic `version`
- lifecycle `state`
- `scanner`
- content `digest`
- `signatureRef`
- `provenanceRef`
- `compatibilityRef`
- `rolloutPolicyRef`
- `killSwitchRef`
- creation, validation, promotion, suspension, rollback, and retirement timestamps

### RuleDefinitionMetadata

Non-executable searchable rule metadata stored independently from the signed bundle.

- `semanticRuleId`
- `scannerRuleId`
- `bundleId` and bundle digest
- `capability`
- `language`
- `category`
- default severity and confidence
- CWE and OWASP mappings
- source/sink taxonomy
- documentation reference
- first and last supported scanner versions
- deprecation and replacement metadata

### TenantRulePolicy

Selection metadata only; it cannot inject executable configuration.

- `tenantId`
- `policyVersion`
- enabled approved categories/rules
- disabled approved categories/rules
- severity floor for display or publication
- repository overrides
- approved waiver/suppression references
- effective and expiry timestamps
- actor and audit reference

### SastScanPlan

Immutable execution plan produced from `ScanRequest`.

- `tenantId`
- `scanRequestId`
- `canonicalScanKey`
- `repositoryBindingId`
- fixed commit SHA and contextual target ref
- trusted inventory digest and signed preflight attestation reference used for deterministic selection
- profile snapshot and digest
- scanner-set snapshot and digest
- tenant rule-policy version
- isolation class
- per-scan result ingress, evidence output, and audit references
- creation timestamp

### TrustedSastRepositoryMetadata

Attested, content-free inventory consumed by the planner. It is produced by an approved
internal metadata/preflight path, never supplied by a public scan request.

- repository binding and full fixed commit SHA
- inventory digest, attestation reference, and collection timestamp
- normalized source-language file/byte signals and manifest names
- repository/selected bytes, file count, largest file, and maximum path depth

The entity contains no source text, archive, credential, command, environment map, or
tenant-provided scanner configuration. Metadata and the immutable scan request must bind to
the same repository and fixed commit before profile selection.

### SastQueuePolicySet

Signed platform policy controlling lane admission without hard-coding environment capacity
inside a public API.

- policy version, digest, signature, and provenance
- distinct `scan.fast.v1` and `scan.deep.v1` lane policies
- tenant active/queued/daily limits
- repository concurrency and minimum-frequency limits
- lane queue capacity and bounded retry condition
- mandatory `TENANT_ROUND_ROBIN` fairness strategy

Usage snapshots are attributed to exactly one tenant, repository binding, lane, and UTC
daily window. Beyond those identifiers they contain counters and timestamps only; they
contain no repository content or credential material.
Every snapshot carries a monotonic authoritative lane-global `snapshotVersion`. Active/queued
lane, tenant, and repository counters remain in that lane-global ledger across UTC rollover;
only `admittedTodayForTenant` is keyed by the normalized UTC day. Admission compares the global
version, every live counter, and the current daily-admission row, then creates one
scan/canonical-key reservation and advances them atomically. Stale versions are retryable and
cannot be admitted. The production ledger is shared across replicas and cannot be implemented as
an independent per-pod cache. PostgreSQL persists this boundary as `SastQueueLedger`,
`SastQueueTenantUsage`, `SastQueueDailyTenantUsage`, `SastQueueRepositoryUsage`, and
`SastQueueReservation`. The immutable `ScanRequest` and reduced planning state are durable rather
than process-local. Serializable transactions make ledger initialization, global live-counter
comparison, daily-budget comparison, reservation creation, and version advancement one atomic
operation.

The reservation row is also the durable pending-dispatch record. It stores the admitted planning
state and complete immutable `SastScanPlan`, but no source or credential material, and has a
restrictive foreign key to the durable scan request. A shared lane-global `lastServedTenantId`
cursor selects the oldest eligible reservation by tenant round robin; bounded owner/expiry fields
make dispatch claims recoverable. Dispatch searches pending reservations across every admission
day, so a dispatcher restart cannot strand yesterday's backlog. An unacknowledged lease is attempted at most
twice; the next post-expiry claim atomically marks the reservation and scan request `FAILED` and
returns its queued capacity. `publishedAt`/`startedAt`, `completedAt`, and terminal status make
queued-to-active-to-terminal counter transitions transactional and idempotent without deleting the
admission identity.

Repository removal is durable revocation rather than row deletion. `RepositoryBinding.status` and
`revokedAt` hide the binding from new work while preserving historical `ScanRequest` and queue
reservation foreign keys. Integration and binding inventory reads are durable rather than
process-local, so replicas and restarts reuse the same identity. A later authorized re-add
reactivates the same binding identity.

### SastPlanningState

Safe status attached to the tenant-scoped scan request and returned by status reads.

- `ADMITTED | DEFERRED | REJECTED`
- selected profile and coverage claim when available
- lane queue and SHA-256 canonical scan key when available
- queue-policy version and digest when admission reached a valid policy
- bounded reason codes and retry-after condition
- decision timestamp

`COMMON_DEEP_V1` reports `COMMON_STATIC_COVERAGE_ONLY` and
`LANGUAGE_SPECIFIC_SAST_UNAVAILABLE`; it never claims language-complete SAST coverage.
The first recorded canonical planning identity is immutable. A deferred decision may become
admitted only for that same identity; an admitted decision is idempotent and cannot be downgraded
or replaced. Redelivery with a later request timestamp returns the original decision timestamp
and plan, and no planning write may change a running or terminal scan. Risk-escalated requests
retain `RESTRICTED` isolation in their immutable plan.

### SastScanAttempt

One execution attempt for a plan. A retry creates a new attempt.

- `attemptId`
- `scanRequestId`
- `attemptNumber`
- `sandboxId`
- `workloadIdentityRef`
- runtime stage
- started/completed timestamps
- failure class and reason
- retry eligibility
- cleanup/destruction evidence reference

Maximum automatic attempts are two and only retryable infrastructure failures qualify.

### SastRepositoryCredentialLease

Durable, tenant-and-attempt-unique metadata for the repository credential handoff. It contains no
credential value.

- tenant, repository binding, scan request, and attempt identifiers
- workload identity reference and full fixed commit SHA
- opaque credential ID and SHA-256 credential fingerprint
- `RESERVED | ISSUED | WIPED | REVOKED`
- issued, expiry, wiped, and revoked timestamps

The database enforces one lease per tenant/attempt, valid fixed-SHA/fingerprint forms, expiry after
issuance, and terminal timestamp consistency. Lifecycle mutations are tenant- and attempt-scoped
conditional updates so concurrent wipe/revoke handling cannot reopen or rewrite a terminal
lease. Composite foreign keys bind the lease to one tenant/repository/scan tuple even if
application checks fail, and reservation is allowed only while that durable scan request is
`RUNNING`. An attested HTTP completion records distributed wipe/revoke, while periodic expiry
reconciliation atomically revokes stale `RESERVED` or `ISSUED` leases.

### SandboxLifecycleEvent

- tenant, scan, attempt, and sandbox identifiers
- `PLANNED | PROVISIONING | READY | RUNNING | DRAINING | TERMINATED | FAILED`
- actor and workload identity reference
- resource profile
- event timestamp
- reason and bounded metadata

The final successful lifecycle requires a `TERMINATED` event and cleanup evidence.

### RepositoryPreflightResult

- attempt ID, fixed commit SHA, path-policy version, and canonical path/content inventory digest
- each entry's Git object ID, normalized metadata, and bytewise length-prefixed digest binding
- signed attestation reference bound to the accepted decision and inventory digest
- `ALL_SCANNABLE` or normalized changed/context path allowlist selection bound into that digest
- repository and selected byte totals
- file, directory, symlink, LFS pointer, submodule, and archive counts
- maximum depth
- generated/vendor/fixture classifications
- rejected paths and reason counts
- applied path policy version
- decision: `ACCEPT | REJECT | RESTRICTED_ESCALATION`

Repository contents are not stored in this entity.

### ScannerRun

Extends the production architecture scanner run with:

- `attemptId`
- scanner and wrapper versions
- scanner image/binary digest
- rule/database/check bundle digests
- required/optional marker
- capability set
- execution status and bounded exit metadata
- timing and resource measurements
- artifact envelope references

### ScannerArtifactEnvelope

Metadata that crosses out of the sandbox.

- tenant, repository binding, scan, attempt, scanner run, and workload-identity references
- scanner, wrapper, image, scanner-set, profile, rule, database, schema, and normalizer
  versions/digests
- fixed input commit SHA
- preflight attestation reference, attested inventory digest, and scanner-visible re-manifest
  digest
- content digest
- object reference
- byte and record counts
- truncated marker
- execution status and exit code
- produced timestamp

The envelope never embeds raw artifact bytes.

### SastArtifactIngestion

Operational write-only intake state before an `ArtifactIngestionDecision`.

- tenant, repository binding, scan, attempt, scanner run, and workload-identity references
- scanner-run-unique idempotency key, canonical envelope snapshot, and canonical envelope digest
- declared and independently observed content digests and byte counts
- opaque Data/Security Plane object key, never returned by the ingress or user-facing APIs
- workload-identity validation result
- `RECEIVING | PENDING_VALIDATION | ACCEPTED | REJECTED | QUARANTINED`
- rejection reason, bounded validation metadata, received timestamp, and audit references
- disposition lease owner, opaque fencing token, expiry, retry time/count, and bounded error code
- immutable disposition intent, intent digest, idempotent storage operation ID, retention expiry,
  and final-decision timestamp

Only a directly authenticated, attempt-bound workload can create the row. `RECEIVING` has no
object key or observed metadata. `PENDING_VALIDATION` has an immutable object key, matching
transport byte count, observed digest, and receipt timestamp; it is not yet eligible for
normalization. Its bounded `artifactValidation` metadata contains
`sast-artifact-validation-v1`, outcome, artifact schema, envelope and observed-content digests,
per-boundary boolean checks, globally ordered reason codes, aggregate parser/path/coordinate
statistics, and a deterministic result digest. It never contains raw artifact/source bytes,
secret values, or the object key. One scanner run can own at most one ingestion.

The canonical envelope JSON is stored separately from the digest so T031 can make an
independent disposition without trusting request reconstruction. The nullable database column
supports rolling deployment of legacy rows; every new application reservation writes it.
`PENDING_VALIDATION` remains a transport-complete state regardless of validation outcome until
T031 atomically chooses `ACCEPTED`, `REJECTED`, or `QUARANTINED`.
An ingress rejected before immutable object creation remains a metadata-only `REJECTED` row
with no T031 decision or disposition attempt. This distinct pre-object terminal path preserves
rolling compatibility and cannot become normalization-eligible.

### ArtifactIngestionDecision

- ingestion plus tenant, repository, scan, attempt, and scanner-run scope
- `sast-artifact-disposition-v1` intent and decision digests
- validation-result digest and ordered validation/disposition reason codes
- `ACCEPTED | REJECTED | QUARANTINED`
- `RETAIN_ACCEPTED | DELETE_REJECTED | MOVE_REENCRYPT_QUARANTINE` storage action
- failure class, normalization eligibility, acceptance-control reference, retention expiry,
  opaque storage receipt reference/digest, and quarantine encryption-context digest
- immutable audit reference and decision timestamp

The decision never stores a raw artifact, object key, KMS key identifier, encryption key, or
plaintext. The ingestion row alone owns the internal accepted/quarantine object key. A
scanner-run-unique background worker claims `PENDING_VALIDATION` with a bounded lease and
fencing token, revalidates the durable envelope, validation-result digest, transport metadata,
immutable plan, and terminal scanner state, then persists an immutable intent before invoking
the Data/Security Plane. The storage operation ID is deterministic per immutable
storage-mutating intent generation, and the final decision binds that exact operation plus a
bounded `storage-receipt://` opaque reference, so a crash after retain/delete/server-side
re-encryption replays without duplication. A later safety supersession receives a different
operation ID and cannot collide with an older storage receipt. A storage-confirmed
missing-source intent retains the operation
ID of that absence receipt because it performs no second object mutation. Only `ACCEPTED` is
normalization-eligible.

The maximum accepted or quarantine retention timestamp is derived from `receivedAt`, never
from retry or decision time, and is no later than seven days. Expired or storage-confirmed
missing objects become metadata-only `REJECTED` rows. Malformed validation metadata, digest or
plan rebinding failures, unsuccessful scanner state, failed validation, and explicit acceptance
denial become `QUARANTINED` with a restricted-prefix object and exact encryption-context digest.

### NormalizedSastFinding

- immutable `tenantId`, `repositoryBindingId`, `scanRequestId`, `attemptId`, and `commitSha`
  attribution
- lane and capability family
- stable fingerprint
- title, bounded description, severity, and confidence
- CWE/CVE identifiers
- normalized location and symbol anchor
- scanner/rule/artifact provenance
- evidence references
- current lifecycle status

Raw descriptions and snippets are never treated as trusted markup.

### FindingOccurrence

One observation of a stable finding in a scan.

- `findingId`
- `scanRequestId`
- `scannerRunId`
- commit and target context
- current line/column coordinates
- artifact digest
- observed timestamp

Occurrences provide history without changing stable identity.

### FindingCorrelation

- source and target finding/occurrence IDs
- `EXACT_FINGERPRINT | SAME_DEPENDENCY_CVE | SUPPORTING_EVIDENCE | POSSIBLE_OVERLAP`
- deterministic correlation version
- confidence
- preserved provenance references
- decision timestamp

`POSSIBLE_OVERLAP` never merges authoritative findings automatically.

### ScannerCoverageRecord

- scan and scanner identifiers
- required marker
- capability set
- scanner/rule/schema versions
- execution status
- `artifactAccepted`; `SUCCEEDED` without an accepted, digest-bound artifact is incomplete
- output digest
- reason code

### SastCoverageDecision

- `PENDING | COMPLETE | PARTIAL | FAILED`
- missing and failed required scanners
- achieved and missing capabilities
- `duplicateScanners`; any duplicate authoritative scanner record is a security failure
- stale/security-blocked markers
- external publication and AI advisory eligibility
- reason codes
- decision timestamp and policy version

### EvidenceFragment

- evidence pack and finding identifiers plus `normalizedPath`
- bounded `startLine`, `endLine`, `sourceFileLineCount`, and `byteSize`
- `redactedContent` and its SHA-256 `contentDigest`
- invariant `secretRedactionApplied = true` plus `redactionDecisionRef`
- invariant `isFullFile = false`; a fragment spanning the complete source file is invalid

### SastEvidencePack

- `evidencePackId`, tenant, repository, scan, and `findingFingerprint` attribution
- `policyVersion`, fragments, exact `totalBytes`, and per-fragment content digests
- `truncated` and non-negative `suppressedFragmentCount`
- invariant `reconstructionRiskChecked = true` plus `reconstructionRiskDecisionRef`
- `classificationDecisionRef`, `deletionScheduleRef`, `dashboardSafe`, and `aiSafe`
- `createdAt` and `expiresAt`; retention cannot exceed the evidence policy

The pack is unavailable to the dashboard when `dashboardSafe = false` and unavailable to the AI
Plane when `aiSafe = false`. These decisions cannot be inferred from a successful scan status.

### RuleBundlePromotionEvidence

- immutable bundle descriptor
- signature and provenance verification
- scanner compatibility matrix
- corpus identifiers and digests
- precision, recall, regression, malicious-input, parser, failure, and latency measurements
- security approval and rollback references
- measured timestamp

### SastQualityEvaluation

- scanner-set and rule-bundle versions
- corpus and environment identifiers
- all quantitative measurements from `quality-gates.md`
- `PASS | FAIL`
- failed gate names
- evaluator identity and timestamp

## State Machines

### Scan Runtime

```text
QUEUED
  -> PLANNING
  -> PROVISIONING
  -> FETCHING
  -> PREFLIGHT
  -> SCANNING
  -> INGESTING
  -> NORMALIZING
  -> CORRELATING
  -> EVIDENCE_BUILDING
  -> POLICY_PENDING
  -> CLEANUP_PENDING
  -> COMPLETED
```

`CLEANUP_PENDING` transitions to `COMPLETED` only after credential revocation/wipe, scanner and
child-process termination, writable-volume destruction, microVM termination, result-ingress
closure, and attempt-bound cleanup evidence plus the final audit event. Any missing, failed, or
overdue cleanup condition transitions to terminal `CLEANUP_FAILED`; it cannot transition to
`COMPLETED` and denies external publication and AI advisory. Every other non-terminal runtime
state may transition to `FAILED` or `CANCELED`. Security violations transition to `FAILED` with
quarantine and no automatic identical retry.

### Scanner Run

```text
PENDING -> RUNNING -> SUCCEEDED
                   -> FAILED
                   -> TIMED_OUT
                   -> QUARANTINED
                   -> KILLED
PENDING -> SKIPPED_BY_POLICY
```

### Rule Bundle

```text
DRAFT -> VALIDATED -> CANARY -> ACTIVE -> RETIRED
CANARY --suspend--> SUSPENDED <--suspend-- ACTIVE
SUSPENDED --rollback--> ROLLED_BACK
```

The two incoming edges are `CANARY -> SUSPENDED` and `ACTIVE -> SUSPENDED`; the single recovery
edge is `SUSPENDED -> ROLLED_BACK`.

### Finding

```text
OPEN -> WAIVED | SUPPRESSED | FIXED
FIXED -> OPEN only when a later complete scan observes the same stable fingerprint
```

## Retention

- Raw scanner artifacts and quarantine objects: maximum seven days.
- Evidence packs and attached model output: maximum seven days.
- AI request payloads: maximum 24 hours.
- Normalized findings, occurrences, coverage, policy decisions, and scan metadata: default
  365 days or tenant contract.
- Security and lifecycle audit events: minimum 365 days.
- Repository workspaces and credentials: destroyed at attempt termination; never retained as
  application data.

## Required Indexes and Constraints for Implementation

- Unique plan by canonical scan key.
- Unique attempt by `(scanRequestId, attemptNumber)`.
- Unique scanner run by `(attemptId, scanner, wrapperVersion)`.
- Unique artifact by `(scannerRunId, contentDigest)`.
- Unique durable finding by `(tenantId, repositoryBindingId, stableFingerprint)`.
- Unique occurrence by `(findingId, scanRequestId, scannerRunId, artifactDigest)`.
- Tenant-first indexes on every queryable entity.
- Expiry indexes on raw artifacts, evidence, quarantine, and AI payload metadata.
- Check constraints require non-negative counts, including zero findings, symlinks, archives,
  rejected paths, and suppressed fragments. Strict positivity is reserved for non-empty artifact
  or evidence byte sizes, declared resource limits, attempt numbers, and known file coordinates.
  Coordinate constraints also require safe-integer bounds and matching attested file metadata;
  retention constraints enforce the declared maximums.
- Foreign keys must prevent cross-tenant association even when application checks fail.
- Planning-state reason codes are constrained to the shared contract enum and never carry
  free-form repository, scanner output, or credential material.
