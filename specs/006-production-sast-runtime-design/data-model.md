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
- trusted inventory digest used for deterministic selection
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
Every snapshot carries a monotonic authoritative lane/day `snapshotVersion`. Admission compares
that version and all applicable lane, tenant, and repository counters, then creates one
scan/canonical-key reservation and advances the counters/version atomically. Stale versions are
retryable and cannot be admitted. The production ledger is shared across replicas and cannot be
implemented as an independent per-pod cache.

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
or replaced, and no planning write may change a running or terminal scan.

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

### SandboxLifecycleEvent

- tenant, scan, attempt, and sandbox identifiers
- `PLANNED | PROVISIONING | READY | RUNNING | DRAINING | TERMINATED | FAILED`
- actor and workload identity reference
- resource profile
- event timestamp
- reason and bounded metadata

The final successful lifecycle requires a `TERMINATED` event and cleanup evidence.

### RepositoryPreflightResult

- attempt ID, fixed commit SHA, path-policy version, and canonical path inventory digest
- signed attestation reference bound to the accepted decision and inventory digest
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

- tenant, scan, attempt, scanner run, and workload-identity references
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

### ArtifactIngestionDecision

- envelope reference and digest
- workload identity validation result
- scope, digest, schema, encoding, size, count, and timestamp validation results
- `ACCEPTED | REJECTED | QUARANTINED`
- reason codes
- quarantine object reference when applicable
- retention expiry
- audit reference

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
