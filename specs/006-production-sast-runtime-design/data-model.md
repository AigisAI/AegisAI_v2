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

### SyftCycloneDxInventoryBatch

An in-memory, non-durable T034 handoff from one accepted Syft artifact. It is separate from
`SastNormalizedFindingCandidate`.

- exact `syft-cyclonedx-inventory-ingestor-v1`, CycloneDX JSON `1.6`, pinned Syft version,
  image/wrapper, schema/normalizer bundle, immutable plan, canonical scan, preflight,
  validation, disposition, envelope, artifact, tenant/repository/scan/attempt/scanner, lane,
  and fixed-commit provenance
- validated producer metadata: exact schema URI, BOM version, `anchore/syft` tool identity,
  generated timestamp, and SHA-256 document serial-number digest
- deterministically ordered package/application/model/operating-system components with
  versioned SHA-256 `componentId`, SHA-256 producer-BOM-reference digest, bounded
  group/name/version, canonical PURL, NISTIR 7695 CPE 2.3 formatted strings, and sorted
  de-duplicated license identities whose SPDX IDs and exceptions resolve to Syft's pinned
  SPDX License List 3.28.0
- deterministically ordered dependency edges that reference only component IDs, never raw BOM
  references
- observed component/dependency counts plus counts for discarded properties, source-location
  properties, external references, license URLs, and prose fields
- `dataHandling={rawArtifactEmbedded:false,rawPropertiesStored:false,
  sourceLocationsStored:false,rawLicenseTextStored:false}`
- `authority={capability:"SBOM",mayCreateFindings:false,
  mayEvaluateVulnerabilities:false,policyAuthority:false,aiPayloadEligible:false}`
- `retentionExpiresAt` inherited from the accepted T031 decision,
  `durablePersistenceAllowed=false`, and a canonical batch digest

The batch never contains raw artifact bytes, object keys, raw properties, source paths, raw
BOM references, raw license text, license URLs, prose, external-reference payloads, findings,
severity, stable fingerprints, evidence references, policy state, or AI content. The raw SBOM
remains only in the short-lived Data/Security Plane object governed by the T031 receipt-based
retention deadline of at most seven days. A future durable inventory store requires its own
explicit data-handling and retention gate; T034 does not authorize one.

### SastNormalizedFindingCandidate

An in-memory, non-durable T032/T033 handoff from one accepted scanner artifact.

- immutable tenant, repository binding, scan request, attempt, scanner run, fixed commit, and
  lane attribution
- exact `opengrep-sarif-normalizer-v1` or `trivy-json-normalizer-v1` adapter version
- bounded title/description, severity/confidence, CWE/CVE identifiers, location, and complete
  scanner/rule/artifact provenance
- immutable `planDigest`, `canonicalScanKey`, `preflightAttestationRef`, and
  `preflightInventoryDigest` on both the batch and every candidate; a supplied attestation
  that does not match these bindings rejects instead of degrading to an unknown location
- scanner-local `ruleId` as provenance. OpenGrep, Trivy secret, and Trivy IaC
  `ruleRevision`/`ruleSemanticId` resolve only from the immutable signed rule-bundle manifest;
  Trivy dependency identity instead resolves from the pinned vulnerability ID and database
  version, with `ruleSource=VULNERABILITY_DATABASE`
- bounded scanner identity material for T036, including the OpenGrep `matchBasedId/v1` only
  as a non-authoritative hint and namespaced opaque Trivy structural hashes that never contain
  detected secret values. Trivy secret/IaC identity preimages exclude line/column coordinates;
  coordinates remain occurrence metadata, while a deterministic producer-order ordinal
  distinguishes multiple findings for the same semantic rule and canonical target. Dependency
  identity includes its canonical package/result target so separate monorepo manifests do not
  collide
- capability-discriminated Trivy details: package/advisory state for
  `DEPENDENCY_VULNERABILITY`, category plus explicit payload-discard booleans for
  `SECRET_DETECTION`, or check type/AVD ID/failing result for `IAC_MISCONFIGURATION`
- Trivy `scannerDisposition` with `DIRECT|MODIFIED`, the validated scanner status, and
  `platformPolicyAuthority=false`; it is provenance and never a platform waiver, suppression,
  lifecycle state, severity override, or policy decision
- exact Trivy vulnerability-database digest alongside scanner image, checks bundle, artifact,
  schema, and normalizer provenance
- deterministic plan/attestation/validation/disposition/envelope/schema/normalizer/artifact
  digest binding and canonical batch digest
- batch-level scanner version/image and rule-bundle provenance, retained even when the accepted
  artifact has zero findings, plus candidate-level `scannerRunId`
- `durablePersistenceAllowed=false`

The candidate intentionally has no stable fingerprint, evidence reference, platform finding
status, or policy authority. Raw snippets, fixes, code flows, help Markdown, Trivy
title/description/message, secret match/code/context, modified-finding statement/source,
misconfiguration traces/rendered causes, and scanner payload substructures are never fields.
Dependency locations remain explicitly unknown when the fixed Trivy wrapper omits package
coordinates; no fallback line is invented. Exact-coordinate secret/IaC duplicates that cannot
be distinguished without coordinate-derived identity are rejected as ambiguous. This is the
pre-redaction T035 input and cannot be logged, audited, persisted, exposed, or used as evidence.

### SastSecretRedactionBatch

A fresh, in-memory, non-durable T035 handoff produced only from one canonical T032/T033 batch:

- exact `sast-secret-redaction-v1`, source adapter/schema, ingestion and immutable
  tenant/repository/scan/attempt/scanner scope, scanner/rule/artifact, plan/canonical scan,
  preflight, validation, disposition, envelope, schema/normalizer, lane, and fixed-commit
  provenance
- the active T031 `retentionExpiresAt`, revalidated at or after disposition time before and
  after the pass
- a fresh ordered copy of each candidate with sanitized title, description, and optional
  location symbol; no object from the input candidate graph is returned as the non-durable
  handoff
- per-candidate `SastFindingSecretRedaction`: exact version, fixed `[REDACTED]` marker,
  inspected-field count, ordered redacted fields, merged replacement count, ordered detector
  categories, and a decision reference/digest computed only from sanitized content and safe
  metadata
- batch summary counts covering the eight scope/binding fields even when there are zero
  findings, plus all inspected candidate fields, redacted candidates/fields, replacements,
  and ordered detector categories
- invariants `secretRedactionApplied=true`, `secretValueStored=false`,
  `matchedValueDigestStored=false`, `rawCandidateStored=false`,
  `sourceCandidateDigestStored=false`, and `durablePersistenceAllowed=false`
- a canonical SHA-256 batch digest whose preimage contains only the fresh sanitized batch
- an 8,000,000 inspected UTF-16 code-unit work ceiling and cooperative async chunk boundaries
  of 64 candidates or 32,768 code units; overflow rejects the complete batch without payload

Registered platform values are transient caller-owned inputs and never output fields. Known
provider/private-key/authentication/URL/JWT/assignment/high-entropy matches may be replaced
only in display fields. A match in ingestion/scope/preflight bindings or in normalized path,
semantic rule identity, symbol anchor, sink kind, scanner version/match identity, rule
provenance identifier/revision, dependency vulnerability/package/type/installed/fixed-version
identity, secret category, or IaC check type/AVD identity rejects the complete batch. The
rejection contains only
ordered coarse reason codes, negative storage assertions, and a digest over those safe
values. It omits the ingestion/scope values, matched field/type/value/length, matched-value
hash, artifact digest, and pre-redaction batch digest.

Candidate, batch, and rejection validators require a trusted canonical SHA-256 digester and
recompute every T035 decision preimage. A digest that is merely well-formed but does not bind
the sanitized object is invalid and cannot enter T036.

The pre-redaction source batch may be used only inside this gate. OpenGrep and Trivy
normalizers are no longer exported from `ScanPlaneModule`; downstream code receives the
redaction service only through the internal T036 consumer. The successful output still has no
platform fingerprint, evidence, finding lifecycle, policy, dashboard, or AI authority.

### SastFingerprintedFindingBatch

The fresh canonical T036 handoff and first object eligible for durable normalized-finding
persistence:

- exact `sast-finding-identity-v1`, source `sast-secret-redaction-v1`, source adapter/schema,
  immutable tenant/repository/scan/attempt/scanner scope, fixed commit, plan/attestation,
  artifact/disposition/validation, scanner image, rule bundle, and optional Trivy database
  provenance
- the exact verified T035 batch digest and a fresh ordered copy of every sanitized candidate;
  no T035 object reference is reused
- one `SastFindingFingerprintDecision` per candidate containing the seven canonical identity
  components, `sast-fingerprint-v1`, stable SHA-256 fingerprint, source redaction-decision
  digest, safe decision digest/reference, and explicit false assertions for coordinate,
  scanner-match, and preimage authority/storage
- `UNKNOWN` locations project to `normalizedPath=""`; provider-availability reason and
  coordinates never become stable identity, while a valid `FILE` location retains its
  normalized path
- aggregate finding, distinct-fingerprint, and repeated-observation counts; repeated
  byte-identical preimages remain separate candidates for T037 occurrence construction
- a transient collision check that rejects the complete batch when one digest maps to
  different preimages
- the inherited active retention deadline checked before and after the pass, a 25,000-finding
  ceiling, and a cooperative event-loop yield every 64 findings
- canonical decision and batch SHA-256 digests recomputed by validators, with no source
  candidate, fingerprint preimage, raw payload, or secret in rejection/audit projections
- `durablePersistenceAllowed=true` and
  `normalizedFindingPersistenceEligible=true`

Persistence eligibility grants no downstream authority. `occurrenceAuthority`,
`lifecycleAuthority`, `correlationAuthority`, `coverageAuthority`, `evidenceAuthority`,
`policyAuthority`, `publicationAuthority`, and `aiPayloadEligible` remain false. T037 must
turn this batch into stable rows and occurrences before the final entity below gains
lifecycle state; later coverage, evidence, policy, publication, and AI gates remain mandatory.
At the T037 checkpoint `ScanPlaneModule` exported only the lineage service to T038. T038 then
exported correlation to T039. With T039 installed, identity, lineage, correlation, and raw
normalization remain internal and only the coverage service crosses the module boundary to
T040.

### SastFindingLineage

One durable platform identity scoped by tenant, repository binding, capability, and
fingerprint version:

- deterministic `finding-lineage://<sha256>` ID from the framed lineage-key preimage
- first stable fingerprint plus immutable `sast-fingerprint-v1`
- first and last observed timestamps
- one-to-many exact identity aliases, occurrences, target-context states, and events

The lineage is not a policy decision, correlation group, evidence record, or AI object.
Different capabilities never share a lineage.

### SastFindingIdentityAlias

- tenant/repository/capability/fingerprint-version/stable-fingerprint unique key
- canonical normalized path and owning lineage
- optional verified rename-attestation digest only for a newly added path alias
- old aliases remain immutable so historical exact observations retain continuity

An exact current alias remains authoritative for lineage ownership. When a verified rename
predecessor resolves to that same lineage, the observation is still classified `RENAMED` and
emits the next event even if the current alias was retained from older history, as in a
rename-back. Conflicting current/predecessor aliases, multiple current identities resolving
to one lineage, path chains/cycles, and unverified/future/non-durable rename claims reject
the complete observation.

### SastFindingObservationBatch

- deterministic ID and unique tenant/source T036 batch digest plus tenant/scanner-run fence
- immutable tenant/repository/scan/attempt/scanner scope, target ref, fixed commit, lane,
  profile, plan/canonical key, and accepted-artifact provenance
- canonical observed-finding capability set (empty for zero findings), optional verified
  rename-attestation digest, exact finding and
  distinct-identity counts, and created/exact/renamed classification counts
- observed timestamp

A replay returns the original ledger only when every binding and every ordered persisted
occurrence agree. A changed, missing, extra, or malformed row on the same scanner run is a
conflict.

### FindingOccurrence

Every ordered T036 finding becomes one occurrence, including byte-identical repeated
fingerprints:

- deterministic occurrence ID and unique `(observationBatchId, ordinal)`
- lineage and normalized-finding IDs
- immutable tenant/repository/scan/attempt/scanner attribution
- capability, fingerprint version/value/decision digest
- the sanitized T036 finding object, current location/coordinates, and observed timestamp

The companion legacy `NormalizedFinding` row receives nullable T037 identity metadata for a
rolling migration. Its `status` remains policy/triage state and is never used as the lifecycle
authority. Raw descriptions and snippets are never treated as trusted markup.

### SastFindingLifecycleState

- deterministic state ID unique by tenant, repository, lifecycle-context key, and lineage
- lifecycle context key derived from tenant, repository binding, and NFC target ref
- independent `OPEN | FIXED`, monotonic revision, last observation binding, and last applied
  reconciliation sequence
- fixed/reopened timestamps

Observing a lineage updates observation metadata but never reopens a fixed state.
The lifecycle-context reconciliation sequence is globally contiguous. A state that is newly
created or newly eligible after an earlier reconciliation may advance from any non-future
state sequence to the current global sequence; a state fence ahead of the previous global
sequence rejects.

### SastFindingLifecycleReconciliation

- deterministic ID and unique coverage-decision digest
- strict unique `(tenant, repository, lifecycleContextKey, sequence)`
- complete T039 decision, current scan/attempt/profile binding, exact eligible and observed
  counts, and transition counts
- reconciled timestamp

The expected observation-batch digest list must equal every durable T037 batch for the current
scan, including zero-finding batches. Every observed complete-capability lineage must be
eligible, and every eligible lineage must exist in the same target context.

### SastFindingLifecycleEvent

Append-only `CREATED | RENAMED | FIXED | REOPENED` with unique state revision, exact source
observation or reconciliation ID, previous/next lifecycle state, and occurred timestamp.
Only `FIXED` and `REOPENED` change lifecycle status.

### SastFindingCorrelationBatch

- deterministic `finding-correlation://<sha256>` ID from the complete durable source set and
  tenant/repository/scan/attempt/target/profile/plan binding
- one unique current-attempt lifecycle-context fence and replay-independent source-set digest
- exact source-batch, occurrence, total-edge, and per-kind counts
- correlation decision timestamp

Creating this batch closes the attempt's T037 observation set. An already-persisted T037
batch remains exactly replayable, but a new late batch conflicts rather than silently changing
the source set.

### SastFindingCorrelationSource

- one row for every T037 observation batch, including zero-finding batches
- scanner/run and canonical capability list, T036 source-batch digest, finding/occurrence
  counts, lifecycle context, and observed time
- deterministic source-binding digest that intentionally excludes the T037 result digest and
  its replay flag

### SastFindingCorrelationEdge

- canonical source and target occurrence IDs with one unique ordered pair per batch
- `EXACT_FINGERPRINT | SAME_DEPENDENCY_CVE | SUPPORTING_EVIDENCE | POSSIBLE_OVERLAP`
- sorted unique hashed match bases, fixed confidence, decision timestamp, and edge digest
- immutable safety object with finding merge and severity/lifecycle/coverage/policy
  inheritance disabled

Exact and dependency groups use deterministic star edges, while cross-capability identifier
groups connect each occurrence to a representative from another capability. This retains
reachability without quadratic all-pairs expansion. Stronger exact/dependency decisions win
when several bases identify the same pair, while every basis digest remains attached.
`POSSIBLE_OVERLAP` never merges authoritative findings automatically.

### SastFindingCorrelationProvenance

Exactly two rows per edge, one `SOURCE` and one `TARGET`, retain the occurrence, observation,
lineage, normalized-finding, scanner-run, scanner/capability authority level, severity,
fingerprint decision, sanitized source-finding digest, scanner/image, rule/revision/bundle,
artifact, and optional vulnerability-database binding. Composite occurrence foreign keys
prevent cross-tenant or cross-attempt edges. Correlation never copies raw artifacts or secret
values and never becomes lifecycle, coverage, evidence, policy, publication, or AI state.

### SastScannerCoverageRecord

- deterministic `sast-scanner-coverage://<sha256>` ID and one unique scanner row per coverage
  decision, including an explicit `NOT_STARTED` row for an absent optional scanner
- composite tenant/repository/scan/attempt binding to the coverage decision, scanner run,
  artifact ingestion/final disposition, and T038 correlation source when applicable
- restrictive artifact-ingestion deletion plus an abort-path dependency check; immutable
  coverage rows cannot be cascade-deleted independently of their decision ledger
- platform-derived required marker, scanner-owned capability set, profile-required capability
  subset, and achieved capability set; optional output cannot replace a required owner
- exact scanner/image/wrapper/rule/database/schema/normalizer provenance plus artifact envelope,
  content, disposition, and source-binding digests
- execution status, accepted/normalization-eligible booleans, explicit finding-observation
  requirement/closure, ordered reason codes, canonical record object, and record digest

### SastScanCoverageDecision

- deterministic `sast-coverage://<sha256>` ID and unique tenant/repository/scan/attempt plus
  one-to-one T038 correlation-batch binding
- fixed target, commit, lane, approved profile/digest, canonical scan key, plan/scanner-set,
  lifecycle context, and correlation source-set digest
- `PENDING | COMPLETE | PARTIAL | FAILED`, exact required/optional/missing/pending/failed/
  duplicate scanner lists, achieved/missing capability lists, and optional incomplete scanners
- digest of the canonical three-record set, ordered reason codes, decision timestamp and digest
- authority object with only `coverageCalculationAuthority=true`; scanner execution, artifact
  acceptance, correlation, lifecycle, evidence, policy, publication, and AI authority false

### SastExternalPublicationDecision

- deterministic `sast-publication://<sha256>` ID and one-to-one composite coverage binding
- T039 invariant false external comment, blocking status, AI advisory, and lifecycle mutation
- latest-target authority `UNAVAILABLE`, stale status `UNKNOWN`, and comparability `UNKNOWN`
  as the immutable T039 source projection consumed by T040
- ordered denial reasons, canonical decision object, timestamp, and unique digest

`PENDING` is returned as a canonical non-durable evaluation and is never inserted into these
tables, so later terminal scanner state can be reevaluated without mutating an immutable
attempt ledger. For a terminal evaluation, all three structures are created atomically in a
bounded serializable transaction. Exact
replay returns the existing ledger; changed, missing, extra, reordered, cross-scope, or late
durable state rejects without partial writes. T039 cannot synthesize a lifecycle-compatible
`stale=false`/`comparable=true` projection from complete coverage alone.

### SastLatestTargetObservation

- deterministic `sast-target-observation://<sha256>` ID and unique
  tenant/repository/provider/target/sequence binding
- provider-authoritative fixed head commit, strictly positive monotonic sequence, observer
  reference, observed time, canonical object, and digest
- composite repository scope foreign key and latest-target index; no credential, repository
  content, SCM write principal, comment, status, or AI payload

### SastScanFreshnessDecision

- deterministic `sast-freshness://<sha256>` ID and one-to-one T039 coverage binding
- exact tenant/repository/provider/target/fixed-commit/scan/attempt/profile/plan/canonical-key
  rebinding plus ordered required capabilities, `sast-fingerprint-v1`, and lifecycle scope
- optional composite target observation and previous completed coverage references whose
  identifier/digest/commit tuples are all-null or all-present
- `VERIFIED | UNAVAILABLE | INVALID`, `FRESH | STALE | UNKNOWN`, and
  `COMPARABLE | INCOMPARABLE | UNKNOWN` states with ordered fail-closed reasons
- comment/block eligibility and lifecycle mutation can be true only together for complete,
  verified, fresh, comparable state with zero reasons; AI and publication-attempt flags are
  database-enforced false

### SastScanRetryDecision

- deterministic `sast-retry://<sha256>` ID and unique requested attempt/sandbox/workload
  identities plus one decision per scan/attempt number
- exact original canonical scan key, plan and scanner-set digest, immediately preceding
  attempt scope, failure/completion/final-audit binding, and current safety snapshot digests
- allow only from attempt one to attempt two for `RETRYABLE_INFRASTRUCTURE`, with a new
  attempt/sandbox/workload identity and clear, available mutable runtime safety authority
- attempt two stores the decision foreign key; denied decisions remain durable audit evidence
  and permanently consume that scan/attempt slot, so they can never admit a sandbox
- an exact allowed replay carries forward the persisted decision timestamp into attempt
  creation rather than generating a conflicting second timestamp

T040 creates these ledgers in bounded serializable transactions with exact replay. It drops
the former permanent external-publication constraint name only after the online-schema step
validates the replacement invariant, builds populated-table indexes concurrently, and validates
their dependent foreign keys. Effective eligibility comes only from the independent freshness row.
T041 consumes that row internally. T042 keeps construction internal and exposes only
`SastEvidenceAccessService` as the sequential Scan Plane handoff to T043.

### SastEvidenceBuildDecision

- deterministic `sast-evidence-build://<sha256>` ID bound to the exact T040 freshness
  decision, T039 coverage decision, T037 occurrence/observation/lineage, normalized finding,
  policy version, and canonical candidate-set digest
- `ACCEPTED | REJECTED`, canonical reason codes, selected/suppressed counts, complete
  reconstruction decision and digest, optional pack ID/digest, bounded audit projection, and
  decision timestamp/digest
- only accepted decisions have `evidenceConstructionAuthority=true`; dashboard, AI, policy,
  publication, and lifecycle mutation authority are always false
- one exact replay key per tenant, occurrence, policy version, and candidate-set digest

### SastAcceptedEvidenceFragment

- evidence pack/build decision/candidate identifiers, deterministic ordinal and
  `PRIMARY | RELATED` role plus `normalizedPath`
- bounded `startLine`, `endLine`, attested anchor, `sourceFileLineCount`, and exact UTF-8
  `byteSize`
- `redactedContent`, raw-source and redacted-content SHA-256 digests, source attestation,
  scanner-redaction decision, platform-redaction decision, and canonical fragment digest
- invariants `secretRedactionApplied=true`, `rawSourceStored=false`, and
  `isFullFile=false`; the database stores no pre-redaction source or platform secret value

### SastAcceptedEvidencePack

- durable Prisma `id` stores the shared-contract `evidencePackId`; tenant, repository, scan,
  and `findingFingerprint` retain the complete attribution
- `policyVersion`, fragments, exact `totalBytes`, and per-fragment content digests
- `truncated` and non-negative `suppressedFragmentCount`
- invariant `reconstructionRiskChecked = true`; durable Prisma
  `reconstructionDecisionId` stores the shared-contract `reconstructionRiskDecisionRef`
- T041 invariants `classificationDecisionRef=null`, `deletionScheduleRef=null`,
  `dashboardSafe=false`, and `aiSafe=false`; T042 creates separate access and deletion
  authority rather than mutating this pack
- `createdAt` and `expiresAt`; retention cannot exceed the evidence policy

The reconstruction decision canonicalizes intervals per normalized path. More than two
fragments per file, overlap, adjacency, or combined coverage of at least 2,500 basis points is
`RISK` and rejects the whole build. Full-file or context-invalid input is rejected before that
calculation. The pack remains unavailable to the dashboard and AI Plane until T042; these
decisions cannot be inferred from a successful scan or accepted T041 pack.

### SastEvidenceAccessDecision

- deterministic purpose-bound `sast-evidence-access://<sha256>` identity for either
  `DASHBOARD` or `AI_ADVISORY`; one purpose cannot authorize the other
- exact tenant, repository, scan, attempt, occurrence, fingerprint, T041 build/pack digest,
  deletion schedule, access policy, and secret-registry version binding
- `ALLOWED | DENIED`, `DASHBOARD_SAFE | AI_REDUCED_REFERENCE_SAFE | UNSAFE`, canonical reason
  codes, counts, second-pass redaction reference, projection digest, and decision digest/time
- dashboard-safe content is returned transiently after the persisted decision and second clock
  check; it is never stored in the decision, logs, or audit
- AI decisions contain only a `sast-reduced-evidence://<sha256>` reference and an expiry no
  later than 24 hours or the pack expiry, whichever comes first; no AI payload is persisted
- all policy, publication, lifecycle, SCM, provider-call, retrieval, and tool authority remains
  false; T041 `dashboardSafe`, `aiSafe`, and null reference fields are never updated

### SastAiAdvisoryHandoff

- deterministic `sast-ai-handoff://<sha256>`, `sast-ai-request://<sha256>`, and
  `sast-ai-advisory://<sha256>` identities bind one model version to the exact T042 AI access
  decision, T037 occurrence, durable normalized finding, and reduced-evidence reference
- tenant, repository, scan, attempt, occurrence, normalized-finding, scanner-run, evidence-pack,
  fingerprint, access-decision, request, and handoff digests are enforced by composite foreign
  keys and exact-replay-only serializable persistence
- `payloadExpiresAt` is inherited from T042; the canonical creation timestamp is the immutable
  access-decision timestamp so later valid retries reproduce byte-identical identities
- the ledger stores no JSON handoff/request body, title, path, prompt, raw source, secret value,
  evidence fragment, or redacted content. It retains only relationship references, digests,
  model version, expiry, and explicit audit/authority booleans
- normalized-finding, reduced-reference, payload, and provider-call handoff authority are true;
  retrieval, tools, policy, publication, lifecycle mutation, and SCM write authority are false.
  Caller finding/evidence/prompt acceptance and every content-storage audit bit are false
- `AiAdvisoryMetadata.sastHandoffId` is nullable only for legacy rows and unique for T043 output;
  new results must rebind to the exact handoff and request digest. Parent deletion is restricted
  so the immutable audit chain cannot be silently cascaded away
- normal tenant/repository offboarding retains this digest-only chain beneath a soft-revoked
  tenant tombstone. Exceptional hard purge is an authorized, externally audited maintenance
  flow that deletes advisory metadata before temporarily bypassing the immutable handoff fence;
  ordinary application roles cannot perform that operation

### SastAiAdvisoryAuthorityProof

- one deterministic `sast-ai-authority-proof://<sha256>` row per T043 advisory/handoff, bound
  to tenant, repository, scan, attempt, occurrence, normalized finding, fingerprint, request
  digest, and handoff digest
- bounded component counts and SHA-256 digests cover the complete scan finding set, target
  status/severity row, exact T037 lifecycle context state/revision, finding policy decisions,
  `finding:<normalizedFindingId>` waivers, and finding suppressions. Both `before` and `after`
  fields project one database-fenced snapshot, so `beforeStateDigest` must equal
  `afterStateDigest`
- the transaction first locks advisory, scan, lifecycle-context, and finding fence rows;
  relevant authoritative writers advance the same rows, so a concurrent mutation conflicts
  and retries. The proof write is the only product/audit mutation in its transaction. Finding creation,
  finding status/severity, lifecycle, waiver, suppression, policy override, blocking,
  publication, and SCM authority are database-checked false; authoritative-write audit bits
  are false and `proofLedgerWritten` alone is true
- no JSON/content column exists. Advisory output, rationale, prompt, source, evidence fragment,
  secret value, policy payload, owner, or waiver reason is absent; only component row digests
  survive
- policy decisions, waivers, and suppressions returned by application services are persisted in
  the same Prisma tables included in the digest; no in-memory authority store exists
- occurrence and normalized-finding composite constraints are installed by the mandatory
  online-schema step after their populated referenced indexes are ready. Direct tenant,
  repository, scan, handoff, and advisory relations restrict deletion
- ordinary offboarding retains the proof with the advisory audit chain. Exceptional tenant or
  legal hard purge uses the reviewed
  [`docs/runbooks/sast-ai-authority-proof-hard-purge.md`](../../docs/runbooks/sast-ai-authority-proof-hard-purge.md)
  flow; application roles cannot update or delete it

### SastAiAdvisoryAuthorityFence

- internal coordination ledger containing only canonical JSON scope keys, monotonic versions,
  and creation time; it contains no finding, policy, advisory, source, evidence, or secret data
- advisory metadata writes touch the tenant/advisory key; normalized-finding and lifecycle bulk
  writes aggregate distinct affected scope keys once per SQL statement, while policy, waiver,
  and suppression writes touch their matching finding keys
- proof creation locks one advisory key before context reload and three authority keys before
  snapshot capture. Missing rows fail closed and concurrent changes surface as serializable
  conflicts; the fence never grants policy or lifecycle authority

### SastEvidenceDeletionSchedule

- deterministic `sast-evidence-deletion://<sha256>` schedule and
  `sast-evidence-delete://<sha256>` operation bound to the exact pack/build/scope digest
- created with the accepted T041 pack in the same serializable transaction; `deleteAfter` is
  positive and no more than seven days after `scheduledAt`
- immutable canonical schedule JSON and digest; due and tenant-expiry indexes support bounded
  backfill and deletion batches
- deliberately has no cascading relation to pack content, so schedule/access/proof audit state
  survives pack/fragment content deletion

### SastEvidenceDeletionClaim

- one mutable operational row per schedule with
  `PENDING | CLAIMED | COMPLETED | QUARANTINED`, bounded attempt count, next-attempt time,
  lease owner, unique lease token, lease expiry, bounded error code, and quarantine timestamp
- claim and finalize use serializable compare-and-set semantics; only the current unexpired
  owner/token may commit a receipt or release for retry
- a deterministic durable-context drift advances the retry cursor in a separate fencing write;
  after three failed validations the row is quarantined so it cannot block later due schedules
- a claim blocks dashboard and AI reads, including readers that began before expiry but finish
  after the claim

### SastEvidenceDeletionProof

- deterministic `sast-evidence-deletion-proof://<sha256>` proof bound to schedule, operation,
  tenant, pack, retained T041 build decision, provider receipt reference/digest, and completion
  time
- `contentDeleted`, `fragmentsDeleted`, `buildDecisionRetained`, and
  `accessAuthorityRevoked` are all true; a changed receipt cannot replay
- content deletion cascades from pack to fragments only after receipt validation. The T041
  build decision, schedule, access ledgers, proof, and bounded audit projections remain
  durable and contain no source or second-pass redacted content

Normal tenant and repository offboarding is a soft revocation and never hard-deletes these
audit ledgers. `SastEvidenceDeletionProof_schedule_scope_fkey` therefore uses `RESTRICT` so a
parent cascade cannot silently erase deletion evidence. An exceptional authorized hard purge
must first revoke all access, complete provider deletion for any live pack, retain/export the
required external audit record, delete the proof ledger explicitly, and only then delete the
tenant or another parent scope whose cascade removes schedule/access/build rows.

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

### Finding lifecycle

```text
OPEN --verified complete absence--> FIXED
FIXED --verified complete observation--> OPEN
```

Waived, suppressed, accepted, and rejected remain separate policy/triage states. A lifecycle
transition requires a later complete, non-stale, comparable T039 decision with exact durable
observation coverage; a finding observation alone cannot transition state.

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
- Unique identity alias by
  `(tenantId, repositoryBindingId, capability, fingerprintVersion, stableFingerprint)`.
- Unique occurrence by `(observationBatchId, ordinal)` and one normalized-finding extension
  per occurrence.
- Unique lifecycle state by
  `(tenantId, repositoryBindingId, lifecycleContextKey, lineageId)`.
- Unique reconciliation by coverage-decision digest and by lifecycle-context sequence.
- Unique append-only event by `(lifecycleStateId, revision)`.
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
