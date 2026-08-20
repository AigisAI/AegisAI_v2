# Quickstart: Production SAST Runtime Design

## Goal

Use this feature package as the canonical implementation entry point for the production
SAST runtime and rule-governance design. The source product and platform baseline remains
`Security Scan SaaS Final Specification.docx`.

This package follows the completed production deployment operations baseline in
[`specs/005-production-deployment-operations/`](../005-production-deployment-operations/).
It narrows the next implementation boundary to deterministic scanner execution, result
normalization, coverage, evidence, and rule lifecycle without weakening the completed
Control, Scan, AI, and Data/Security plane boundaries.

## Canonical Use

- Agents should arrive here from [`AGENTS.md`](../../AGENTS.md).
- This package is the active implementation target for production SAST runtime design.
- T040 through T052 are complete. The T053 repository-side 123-cell provider handoff, T054
  repository-side 3,462-cell end-to-end contract, T055 repository-side 169-cell supply-chain and
  rollback contract, and T056 repository-side 54-gate immutable go/no-go contract are package-ready
  with offline cryptographic verifiers. The 005 consumer now requires a fresh Qualification
  Authority-signed current-contract T056 `GO` binding and has no evidence-free preflight path. T054
  remains blocked until an externally authorized T053
  run supplies all destruction evidence, T055 remains `BLOCKED_T054_QUALIFICATION` until the exact
  T054 result passes on the same provider, and T056 remains `BLOCKED_T055_QUALIFICATION` until the
  exact signed upstream chain and external evidence exist.
- Production Kubernetes rollout remains deferred until T053-T056 pass. A standalone or staging
  qualification provider may execute T053 only with its external dependency set, trust bundle, and
  detached approvals; no repository or ordinary PR environment may substitute for that evidence.
- Issue #276 is explicitly reclassified by `spec.md` as a local-only Neo4j/MITRE CWE
  dev/demo bootstrap; it does not replace this package or advance T040.
- `005-production-deployment-operations` remains the completed deployment-operations
  baseline.
- `004-production-runtime-infrastructure` remains the completed runtime-infrastructure
  baseline.
- `003-production-ai-inference-runtime` remains the completed advisory-only AI baseline.
- `002-production-scan-architecture` remains the completed production scan architecture
  baseline.
- `001-aegisai-mvp-foundation` remains the legacy MVP baseline.

## Document Map

- `Security Scan SaaS Final Specification.docx`: highest-priority product, security, and
  operations specification
- `.specify/memory/constitution.md`: repository guardrails
- `spec.md`: SAST runtime scope, requirements, and acceptance
- `research.md`: scanner responsibility and design decisions
- `data-model.md`: runtime, artifact, finding, coverage, evidence, and rule entities
- `contracts/sast-runtime.md`: implementation-ready boundary and state contracts
- `threat-model.md`: hostile repository, scanner, artifact, and supply-chain threats
- `rule-governance.md`: rule bundle lifecycle, tenant policy, canary, rollback, and kill switch
- `quality-gates.md`: quantitative release and production readiness gates
- `language-profile-extension.md`: mandatory admission path for languages after Java v1
- `plan.md`: implementation sequencing and legacy-path retirement strategy
- `tasks.md`: execution-ordered design and future implementation slices
- `checklists/requirements.md`: design completeness checklist

## Required Read Order

1. `Security Scan SaaS Final Specification.docx`
2. `.specify/memory/constitution.md`
3. `specs/002-production-scan-architecture/quickstart.md`
4. `specs/002-production-scan-architecture/contracts/scan-architecture.md`
5. `specs/004-production-runtime-infrastructure/contracts/runtime-infrastructure.md`
6. `specs/005-production-deployment-operations/contracts/deployment-operations.md`
7. `specs/006-production-sast-runtime-design/spec.md`
8. `specs/006-production-sast-runtime-design/research.md`
9. `specs/006-production-sast-runtime-design/data-model.md`
10. `specs/006-production-sast-runtime-design/contracts/sast-runtime.md`
11. `specs/006-production-sast-runtime-design/threat-model.md`
12. `specs/006-production-sast-runtime-design/rule-governance.md`
13. `specs/006-production-sast-runtime-design/quality-gates.md`
14. `specs/006-production-sast-runtime-design/language-profile-extension.md`
15. `specs/006-production-sast-runtime-design/plan.md`
16. `specs/006-production-sast-runtime-design/tasks.md`
17. `specs/006-production-sast-runtime-design/checklists/requirements.md`

## Architecture Baseline

- OpenGrep is authoritative only for source-code SAST findings.
- Trivy is authoritative for dependency vulnerability, secret, and IaC
  misconfiguration findings.
- Syft is authoritative for source-workspace SBOM generation and does not create
  vulnerability findings.
- Every production scan runs in one non-reused ephemeral microVM with `HARDENED` or
  `RESTRICTED` isolation.
- Repository access is fixed-commit, repo-read only, short-lived, non-persisted, and
  issued through Token Broker.
- Scanner wrappers own tool-specific CLI details. Shared contracts own inputs, output
  schemas, provenance, limits, and failure behavior.
- Raw artifacts are hostile input. A result ingestor validates size, schema, digest,
  provenance, and tenant/scan attribution before normalization.
- Findings are deterministic and scanner-derived. AI receives only bounded, redacted,
  policy-classified evidence after coverage and normalization.
- Partial, stale, quarantined, or security-blocked scans cannot publish PR/MR comments or
  blocking results.

## SAST Profiles

- `JAVA_FAST_V1`: changed Java files plus bounded context, Java manifests, secrets, and
  dependency metadata; OpenGrep and Trivy required; 15-minute hard timeout.
- `JAVA_DEEP_V1`: full Java repository static analysis, dependency/secret/IaC coverage,
  and SBOM; OpenGrep, Trivy, and Syft required; 60-minute hard timeout.
- `COMMON_DEEP_V1`: dependency/secret/IaC and SBOM coverage for repositories without an
  approved language-specific SAST profile; Trivy and Syft required; AI advisory disabled.

Fast and Deep lanes use separate queues and budgets but the same microVM security boundary.

## Execution Flow

1. Validate the immutable scan request and canonical scan key.
2. Select a versioned SAST profile and signed scanner set.
3. Provision one ephemeral microVM and attest its workload identity.
4. Inject a short-lived fixed-commit repo-read credential without persistence or logging.
5. Fetch the repository, enforce path/resource policy, and reject unsafe input.
6. Remove the SCM remote and Git metadata, wipe and revoke the credential, and remove the
   signed repository-binding host egress rule.
7. Run signed, digest-pinned scanner wrappers without package install, build, dynamic
   execution, or runtime internet enrichment.
8. Upload non-empty bounded artifact envelopes to the result ingestor.
9. Validate, normalize, fingerprint, correlate, reduce evidence, and evaluate coverage.
10. Send normalized findings to policy and reduced evidence references to AI when eligible.
11. Wipe the workspace, destroy the microVM, and record destruction evidence.

## Implemented Runtime Checkpoint

T022 through T034 are implemented as the complete Phase 5 runtime boundary plus the
ingress, validation, final-disposition, OpenGrep normalization, Trivy normalization, and
Syft CycloneDX inventory-ingestion
portion of Phase 6:

- OpenGrep, Trivy, and Syft adapters share one fail-closed scalar-streaming implementation
  for fixed parser slicing, fatal UTF-8, raw token/depth/duplicate-key bounds, content
  hashing, byte/record recount, and canonical rejection behavior. Finding adapters also
  share retention clocks, coordinate attestations, safe text/identifier bounds, and digest
  primitives; Syft shares the applicable retention and digest gates without inventing file
  coordinates.
- Token Broker verifies a signed, bounded-lifetime workload attestation against tenant,
  repository binding, scan request, attempt, workload identity, and fixed commit. A durable
  tenant/attempt-unique lease prevents replay while persisting only a SHA-256 credential fingerprint
  and lifecycle metadata, never the credential value. Reservation requires a `RUNNING` durable
  scan, composite foreign keys preserve the complete tenant/repository/scan binding, and the
  workload/preflight signing keys cannot reuse the token encryption key. Attested HTTP cleanup
  records distributed wipe/revoke and periodic reconciliation revokes expired nonterminal leases.
- The fetch runtime derives the GitHub Cloud or GitLab Cloud remote from the active durable
  repository binding, requires a verified tmpfs credential mount, and uses an opaque
  in-memory credential through `GIT_ASKPASS`. It performs only a full-SHA, `--depth=1`,
  no-tag, no-submodule fetch with LFS smudge disabled, enforces profile file/expanded-byte/
  single-file/depth limits from Git tree/object metadata before checkout, then removes the remote
  and `.git` metadata before wiping the credential file and memory buffer.
- Preflight normalizes separators and Unicode NFC, rejects unsafe roots/traversal/control
  paths and duplicate/case/Unicode collisions, resolves symlinks lexically without following outside
  the root, enforces profile limits, binds `ALL_SCANNABLE` or normalized Fast changed/context
  path selection into selected-byte accounting and the inventory digest, classifies
  generated/vendor/fixture/hidden/LFS/
  submodule/archive entries, binds Git object IDs against same-size content replacement,
  and produces a deterministic inventory digest plus signed
  `ACCEPT`, `REJECT`, or `RESTRICTED_ESCALATION` attestation.
- The scanner wrapper accepts only an immutable `SastScanPlan`, attempt binding, preflight
  binding, and a short-lived sandbox attestation that signs the complete plan digest, attempt
  identifier, attempt number, and cumulative deadline. It
  generates fixed shell-less OpenGrep SARIF, Trivy JSON offline, and Syft
  `cyclonedx-json@1.6` commands
  against `/workspace/repository` for Deep or the platform-owned,
  inventory-digest-bound `/workspace/selected/<digest>` projection for Fast, with output
  under `/workspace/output`; caller paths, commands, flags, environment maps, plugins, and
  executable configuration are not request fields. Processes
  start in the private output directory. OpenGrep repository ignore/`nosem`, Trivy repository
  config/ignore files, and Syft repository config/archive expansion, remote enrichment,
  file metadata, raw license content, and external package-tool execution are disabled;
  only wrapper/rule-digest-bound platform configuration is loaded.
- Immediately before each scanner launch, the installed provider must read the exact
  read-only repository mount, attest the exact scanner input, and return a content-bound
  manifest. Fast requires `PATH_ALLOWLIST` plus a read-only selected projection containing no
  unselected entry; Deep requires `ALL_SCANNABLE` plus the repository root. The runtime applies the same
  preflight algorithm and refuses to call the scanner when the attestation, attempt, selection,
  decision, or inventory digest differs.
- Sandbox policy requires non-root execution, read-only root and repository mounts, private
  writable output, bounded CPU/memory/disk/process/FD/log/artifact/time, no build/install/
  dynamic execution/runtime asset update, and no unrestricted public internet or cloud
  metadata access. Repository fetch temporarily permits HTTPS only to the signed
  repository-binding SCM host; scanner execution starts only after credential wipe/revocation
  and removal of that egress rule, then permits Result Ingress and telemetry only.
  The signed profile timeout is one cumulative attempt deadline shared by manifest and scanner
  calls, not a fresh allowance per scanner; provider calls receive an abort signal and cleanup
  has a separate 60-second deadline.
  The default provider remains unavailable and fails closed until the 005 provider rollout
  installs the live microVM adapter.
- Scanner terminal records persist exit/status/timing, bounded stdout/stderr metadata,
  resource observations, artifact metadata, and every relevant image/wrapper/rule/database/
  profile/preflight digest. Trivy's immutable cache path binds both its database and checks
  bundle digests, and a zero-byte JSON/SARIF/CycloneDX artifact is rejected before persistence.
  Serializable attempt admission plus a database partial unique index prevents concurrent active
  sandboxes for one scan. Attempt 2 is admitted only when durable attempt 1 ended `FAILED` with
  `RETRYABLE_INFRASTRUCTURE`, `retryEligible=true`, completion metadata, and a final audit event.
  The signed deadline is persisted, and reconciliation
  marks process-orphaned overdue attempts `CLEANUP_FAILED` with a final audit signal. Attempt
  completion additionally requires signed credential,
  process, volume, result-ingress, and microVM destruction evidence plus a final audit event;
  a missing, stale, or late condition becomes `CLEANUP_FAILED`. Database constraints reject
  null-bypassed runtime metadata and bind audit events to the same tenant and attempt. Existing
  `ScannerRun` and `AuditEvent` tables are handled by the mandatory, idempotent
  `prisma:online-schema` step immediately after transactional Prisma migration: it builds
  indexes concurrently, adds constraints `NOT VALID`, then validates them in separate
  autocommit statements to avoid holding write-blocking locks during existing-row scans.
- `ANALYSIS_CLIENT_MODE=mock`, the mock scan controller, legacy source collection, and
  `MockAnalysisApiClient` are test-only. Non-test configuration and runtime paths fail closed
  before repository credential decryption or source collection.
- Scanner runs are registered durably as `RUNNING` before sandbox execution so a scanner can
  upload only while its attempt remains `SCANNING` and before the signed deadline. The
  per-scan `application/octet-stream` ingress accepts canonical envelope metadata plus a
  bounded stream only from a directly authenticated mTLS SPIFFE identity that exactly matches
  the durable attempt. One immutable artifact is reserved per scanner run; exact replay is
  idempotent, changed replay is rejected, and the response exposes only a
  `PENDING_VALIDATION` receipt.
- The Scan Plane has no artifact read route and its object-store port exposes only immutable
  write and cleanup delete. The default provider fails closed until the production
  Data/Security Plane adapter is installed; raw object keys never enter user-facing responses.
- The T030 validator tees each newly reserved artifact through a strict UTF-8 and bounded
  streaming JSON parser while the immutable object write proceeds. Parser slices are aligned to
  global byte offsets, so valid and invalid results are invariant to transport chunking. It
  independently binds the semantic OpenGrep SARIF 2.1.0, Trivy JSON v2, or CycloneDX 1.6 schema
  plus scanner-set,
  schema-bundle, normalizer-bundle, rule, and Trivy database digests together with the exact
  scanner and canonical artifact reference. The transport and validator independently recompute
  content digest and byte count, and the validator recomputes schema-specific record count;
  CycloneDX counting includes root/nested inventory components but excludes
  `metadata.tools.components`. It
  rejects duplicate keys, excessive depth/tokens/key size/object-key count/string/number size, unknown boundary fields
  or enums, missing required tool/message structures, unsafe paths, path collisions,
  and invalid coordinates. SARIF URI paths are decoded only from canonical uppercase
  percent-encoding before exact attested-path comparison.
- Validation emits only a versioned, bounded, deterministically ordered result containing
  boolean checks, reason codes, aggregate statistics, and a result digest. The canonical
  envelope snapshot and result are durable on `SastArtifactIngestion`; neither raw bytes nor
  object keys enter logs, audit metadata, user APIs, or the AI Plane. File coordinates require
  exact provisioner-attested metadata for the attempt and inventory digest; the production
  default provider returns no attestation and therefore never relaxes a location check.
- T030 deliberately leaves both valid and invalid completed transports in
  `PENDING_VALIDATION`. The T031 disposition worker claims only terminal scanner runs with a
  database lease and opaque fencing token, revalidates the durable envelope, deterministic
  validation digest, transport values, immutable plan binding, scanner image/wrapper/rule/
  database/schema/normalizer/profile/preflight/workspace digests, and exit/timeout/output
  outcome, then persists an immutable `sast-artifact-disposition-v1` intent before calling
  storage.
  The deterministic intent-bound operation ID makes retain/delete/server-side re-encryption
  safe to replay across process crashes while giving a later safety supersession a distinct
  operation. The final decision binds that operation and a bounded `storage-receipt://`
  opaque receipt reference. Finalization rechecks the live fence and atomically
  persists the ingestion state, scanner state, immutable decision, and bounded audit event.
- The disposition storage port is Data/Security-owned and no-read. `ACCEPTED` retains the
  short-lived opaque object only after an explicit acceptance-gate `ALLOW`;
  `QUARANTINED` requires a restricted-prefix object re-encrypted with the exact
  `sast-artifact-quarantine-context-v1` digest; expired or storage-confirmed missing objects
  become metadata-only `REJECTED`. Retention is derived from the original receipt, capped at
  seven days, and cannot finalize acceptance or quarantine at or after expiry. Only accepted
  artifacts are normalization-eligible, and durable decisions/audits contain no raw payload,
  object key, secret, or key material.
- The T049 kill-switch engine supplies the authoritative acceptance-gate adapter. An affected
  artifact is quarantined and unavailable authority remains retryable/fail-closed; until the
  production Data/Security disposition adapter is installed, its independent default still
  fails closed and valid rows remain pending rather than being implicitly accepted.
  The online `ScannerRun_runtime_metadata_v3_check` accepts legacy digest-version rows during
  rolling deployment while enforcing semantic schema versions and separate schema/normalizer
  digests for new rows, and removes v1/v2 only after v3 validation succeeds.
- `opengrep-sarif-normalizer-v1` independently rebinds an unexpired T031 accepted decision,
  validation/envelope/content digests, immutable plan digest, canonical scan key, coordinated
  attestation binding, and exact OpenGrep supply-chain metadata before reading a bounded
  stream. It resolves semantic rule identity and revision only from the signed bundle manifest,
  never from scanner-local SARIF fields. It accepts only the OASIS 2.1.0 schema, one
  `Opengrep OSS` run, the exact pinned driver version, one successful notification-free
  invocation, unique rule/result resolution, and at most one primary location. The official
  `%SRCROOT%` OpenGrep URI base is allowed while every other indirect base remains rejected.
- The adapter reuses the strict T030 token/UTF-8/depth/duplicate-key limits, fixed parser
  slicing, content hashing, byte count, and record count without materializing the raw SARIF
  or complete result objects. Raw JSON surrogate pairs are validated before token decoding.
  Snippets, code flows, fixes, help Markdown, and raw properties are discarded. Golden fixtures
  prove chunk-invariant ordering, literal markup handling, severity/confidence/CWE/CVE mapping,
  attested location rebinding, retention-clock enforcement, and bounded rejection.
- T032 produces only canonical, digest-bound `SastNormalizedFindingCandidate` batches with
  `durablePersistenceAllowed=false`. OpenGrep `matchBasedId/v1` remains a non-authoritative
  T036 identity hint; the candidate has no stable fingerprint, evidence reference, status,
  policy authority, user route, or AI path. The implemented T035 redaction and T036
  fingerprinting gates remain mandatory before normalized-finding persistence eligibility.
- `trivy-json-normalizer-v1` independently rebinds the unexpired T031 accepted decision,
  immutable plan, coordinated attestation, validation/envelope/content/disposition digests,
  exact Trivy 0.66.0 scanner/image/wrapper/schema/normalizer/checks-bundle metadata, and pinned
  vulnerability-database digest/version before reading a bounded stream. The adapter has no
  route or general object-store capability. T035 is the implemented in-memory redaction
  boundary consumed by T036, but artifact reading and the durable database flow remain
  unwired until the later Data/Security-owned orchestration and persistence worker exist.
- The Trivy adapter accepts only JSON v2 dependency, secret, and failed IaC result classes.
  It streams bounded scalars through globally aligned parser slices, independently rehashes
  bytes and recounts direct plus `ExperimentalModifiedFindings`, and never materializes the
  artifact or a complete raw finding. Supported modified records remain findings; scanner
  status is retained only with `platformPolicyAuthority=false`, while unknown/unsupported
  status or capability rejects the complete batch.
- Dependency semantic identity/revision comes from the pinned vulnerability ID/database;
  secret and IaC identity/revision comes only from the signed checks manifest. Scanner
  title/description/message, secret match/code/context, modified statement/source, and
  misconfiguration trace/rendered cause are discarded in favor of deterministic safe text.
  Dependency identity includes the canonical package/result target so identical advisories
  in separate monorepo manifests remain distinct.
  Dependency locations are explicitly unknown because the fixed wrapper omits package-file
  coordinates; secret/IaC ranges require exact attested bounds and never receive invented
  fallback coordinates. Those coordinates remain occurrence metadata and are excluded from
  secret/IaC structural identity; deterministic producer-order ordinals distinguish repeated
  same-rule/target records, while exact-coordinate ambiguity fails closed.
- T033 golden and malicious fixtures prove chunk-invariant direct/modified normalization,
  exact record counts, capability-specific authority, zero-finding provenance, non-authoritative
  scanner disposition, secret/context non-copy, bounded identifiers/packages, duplicate
  identity rejection, line-shift identity invariance, occurrence distinction,
  attestation/retention rebinding, and fail-closed malformed streams.
  Its canonical Trivy candidate batches remain transient with
  `durablePersistenceAllowed=false`; the implemented T035 redaction and T036 fingerprinting
  gates are still mandatory consumers.
- `syft-cyclonedx-inventory-ingestor-v1` independently rebinds the unexpired T031 accepted
  decision, validation/envelope/content/disposition digests, immutable plan and exact Syft
  image/wrapper/schema/normalizer metadata before reading. It accepts only the pinned Syft
  v1.44.0 CycloneDX JSON 1.6 directory producer: one exact tool component, the
  wrapper-owned source path, package/application/model and operating-system components,
  Syft provenance properties, canonical PURL/BOM-reference relations, complete NIST CPE 2.3
  formatted-string validation, SPDX 2.3 expressions resolved against Syft's pinned License
  List 3.28.0, bounded declared licenses, and sorted dependency nodes/edges.
- T034 uses the shared fixed-slice streaming core and never materializes the raw BOM. It
  independently rehashes/recounts, handles legitimate URL-empty Java `build-meta` digest
  references, de-duplicates repeated license identities after discarding their URLs, and
  rejects foreign producer/schema fields, file/nested/vulnerability extensions, malformed
  identities, invented SPDX IDs/exceptions, malformed CPE quoting/language fields, invalid
  licenses/hashes, dangling/duplicate/self/non-canonical dependencies, resource bombs, and
  retention drift.
- The canonical CycloneDX inventory is transient with
  `durablePersistenceAllowed=false`. Raw BOM references and the serial number are retained
  only as SHA-256 digests; raw properties, source locations, license text/URLs, prose,
  external references, and raw artifact bytes are absent. Authority is explicitly SBOM-only:
  no finding creation, vulnerability decision, policy authority, durable persistence, or AI
  payload eligibility.
- `sast-secret-redaction-v1` now verifies the exact OpenGrep/Trivy canonical batch digest,
  T031 accepted disposition/validation binding, and active retention window before and after
  processing. It inspects the eight ingestion/scope/preflight binding fields even for an
  empty batch and rejects binding drift without copying the rejected values.
- The T035 detector combines transient registered platform values with bounded private-key,
  authorization/URL credential, documented provider-token, JWT, contextual assignment, and
  high-entropy detection. Overlapping spans become the one fixed `[REDACTED]` marker only in
  title, description, and optional symbol display fields. A forged marker or any match in a
  normalized path, semantic rule identity, symbol anchor, sink kind, scanner version/match
  identity, rule provenance identifier/revision, dependency
  vulnerability/package/type/installed/fixed-version identity, secret category, or IaC check
  type/AVD identity rejects the whole batch rather than creating a secret-derived fingerprint
  input.
- The async gate rejects more than 8,000,000 inspected UTF-16 code units and yields before the
  next candidate whenever the 64-candidate or 32,768-code-unit chunk boundary is reached.
  Receiving code must supply the trusted SHA-256 canonical digester so candidate, batch, and
  rejection validators recompute their preimages instead of format-checking digests only.
- Successful T035 output is a fresh canonical `SastSecretRedactionBatch` with per-finding
  sanitized-only decisions, safe aggregate counts, no raw or matched value, no matched-value
  hash, and no pre-redaction candidate digest. Its audit helper exposes metadata only.
  `secretRedactionApplied=true` does not grant persistence:
  `durablePersistenceAllowed=false` remains fixed until T036.
- `sast-finding-identity-v1` now accepts only that complete T035 handoff, recomputes its batch
  and every sanitized decision digest, checks retention before and after construction, rejects
  more than 25,000 findings, and cooperatively yields at each 64-finding boundary.
- T036 projects repository binding, capability, semantic rule identity, normalized path,
  symbol anchor, sink kind, and structural hash in the published order. Every string is NFC
  normalized and framed by its decimal UTF-8 byte length under `sast-fingerprint-v1`.
  `UNKNOWN` contributes the explicit empty path; reason, coordinates, commit, scanner
  `matchBasedId`, display text, and severity remain outside stable identity.
- A repeated byte-identical preimage remains a separate observation for T037. One digest
  associated with different preimages rejects the complete batch. Rejection and audit output
  carry no source candidate, fingerprint preimage, rejected T035 batch/artifact digest, or
  secret value.
- Successful T036 output is a fresh canonical `SastFingerprintedFindingBatch`. It preserves
  sanitized OpenGrep/Trivy provenance, binds the source redaction batch and decisions, records
  exact distinct/repeated counts, and sets normalized-finding persistence eligibility with
  `durablePersistenceAllowed=true`. Occurrence, lifecycle, correlation, coverage, evidence,
  policy, publication, and AI authority all remain false until T037 and later gates.
- `sast-finding-lineage-v1` now revalidates that complete T036 handoff and the active
  accepted-artifact, scanner-run, immutable-plan, fixed-commit, profile, digest, and retention
  scope before a serializable write. One repository/capability/fingerprint-version lineage is
  created or reused, while every producer-ordered finding becomes its own immutable
  occurrence and legacy normalized-finding row. Batch/scanner-run replay is idempotent only
  when the full ledger agrees; changed or incomplete replay fails closed.
- Lifecycle context is the SHA-256 of tenant, repository binding, and NFC target ref. Its
  `OPEN|FIXED` state and monotonic revision are separate from
  `NormalizedFinding.status`, which remains policy/triage state. `CREATED`, `RENAMED`,
  `FIXED`, and `REOPENED` are append-only events; observing a fixed lineage alone never
  reopens it.
- Rename continuity accepts only a canonical, signed/provenance-backed, fixed-commit,
  one-to-one attestation verified by an injected authority. T037 reconstructs the predecessor
  fingerprint by changing the normalized path component only, retains old and new aliases,
  and rejects alias collisions, chains/cycles, ambiguous lineages, future attestations, and
  missing durable predecessor scans. The production default verifier is unavailable and
  therefore fail-closed.
- Fixed/reopened reconciliation accepts only an injected T039 coverage decision with exact
  `COMPLETE`, `stale=false`, and `comparable=true`. It rechecks the current/previous durable
  scan contexts, strict sequence, eligible lineage scope, capabilities, and the exact sorted
  observation-batch digest set before transitions. Partial, stale, incomparable, omitted,
  out-of-order, or unavailable coverage cannot mutate lifecycle state. T037 consumes this
  authority but has `coverageCalculationAuthority=false`.
- The Prisma rollout adds nullable T037 metadata to legacy `NormalizedFinding`, creates
  tenant-scoped lineage, alias, batch, occurrence, target-state, reconciliation, and event
  tables, and installs existing-table indexes/checks plus composite foreign keys through the
  mandatory online-schema step. All writes run at serializable isolation with a five-second
  acquisition wait, 120-second transaction deadline, and at most three bounded retries.
- T038 accepts every canonical T037 observation result for one attempt, including explicit
  zero-finding batches. It verifies each result digest, then reloads and requires exact
  equality with the complete durable observation-batch and occurrence set. Its replay key is
  derived from durable source bindings rather than T037's result digest, because the valid
  T037 `replayed` flag intentionally changes that digest.
- `sast-finding-correlation-v1` derives only deterministic `EXACT_FINGERPRINT`,
  `SAME_DEPENDENCY_CVE`, `SUPPORTING_EVIDENCE`, and `POSSIBLE_OVERLAP` edges. Dependency
  equality requires the NFC ecosystem/package/installed-version/CVE tuple. Cross-capability
  CVE and same-file CWE overlap uses the scanner responsibility matrix and active profile:
  required capabilities are authoritative, while optional capability output is
  `SUPPORTING_ONLY`. No path-only, fuzzy, title, severity, scanner-local, or AI match is
  accepted.
- Every edge keeps both immutable occurrence references and two complete provenance rows.
  `findingMergeAllowed`, severity/lifecycle/policy/coverage inheritance, evidence, publication,
  and AI authority remain false. A Critical authoritative result therefore cannot be hidden
  by a lower-severity correlated result, and `POSSIBLE_OVERLAP` remains display-only.
- The Prisma rollout creates correlation batch, source, edge, and provenance tables. One
  serializable write revalidates the closed T037 source set, stores at most 100,000
  deterministic star edges, and retries serialization/unique races at most three times.
  The mandatory online-schema step installs composite occurrence-scope foreign keys, and a
  completed correlation batch fences late T037 additions while preserving exact T037 replay.
- T039 accepts only the canonical T038 result reference, then reloads immutable plan,
  current attempt, every scanner run, artifact envelope/final disposition, and the complete
  correlation source set. `sast-scan-coverage-v1` derives required/optional scanners and
  capabilities exclusively from the platform profile and scanner-responsibility matrix.
- A required scanner contributes coverage only after terminal success, exact pinned
  scanner/image/wrapper/rule/database/schema/normalizer provenance, an accepted and
  normalization-eligible artifact, and (for finding scanners) a valid T038 zero/nonzero
  observation source. Missing, pending, failed, quarantined, killed, foreign, or tampered
  state remains explicit and cannot be replaced by optional output.
- `PENDING` is returned as a canonical non-persisted result with zero ledger writes, allowing
  required scanners to advance before reevaluation. Terminal coverage, all three scanner
  records, and `sast-external-publication-v1` are written in one bounded serializable
  transaction. Exact replay returns the existing decision; changed, reordered, cross-scope,
  or late durable state conflicts without partial rows.
- The mandatory online-schema step creates the two new existing-table composite indexes
  concurrently, then installs and validates scanner-run, ingestion, disposition, and source
  scope foreign keys without putting an online-index dependency in the transactional Prisma
  migration.
- The immutable T039 source row still stores external comment, blocking status, AI advisory,
  and lifecycle mutation as false. T040 adds its replacement constraint `NOT VALID`; the
  mandatory online-schema step validates it before dropping the old permanent constraint,
  builds the populated coverage-comparison and attempt retry-decision indexes concurrently,
  and then installs or validates their dependent foreign keys. Independent
  `sast-scan-freshness-v1` rows never rewrite or weaken exact T039 replay.
- T040 rebinds tenant, repository, provider, target, fixed commit, scan, attempt, approved
  profile/plan, canonical scan key, required capability set, `sast-fingerprint-v1`, and a
  canonical lifecycle-eligibility scope. A provider-authoritative, monotonic target-head
  observation must match the fixed commit exactly. The default observer is unavailable, so
  deployments without a read-only provider adapter remain fail closed.
- Comparability selects the newest completed `COMPLETE` coverage source from a different scan
  request in the same tenant/repository/target with a compatible profile family and exact
  required capability set; a current-scan attempt or incompatible profile cannot mask an older
  valid predecessor. Fingerprint version and lifecycle-eligibility scope also match. Only
  `VERIFIED` + `FRESH` +
  `COMPARABLE` marks comment/block eligibility and lets the T037 gate verify lifecycle input.
  The T037 consumer performs another provider-head read and rejects if the target advanced
  after the stored decision. This is eligibility only: T040 creates no SCM write, publisher
  route, or AI payload.
- T040 stores every attempt-two retry decision before admission. It permits only the
  immediately preceding durable attempt-one `FAILED` row with
  `RETRYABLE_INFRASTRUCTURE`, `retryEligible=true`, completion time, and exact terminal audit
  binding. It rechecks scanner-set availability and kill-switch authority, preserves the
  canonical scan identity and plan digest, and requires a new attempt, sandbox, and workload
  identity. Attempt three, cleanup failure, capacity/input/scanner/security failure, missing
  audit, unavailable safety authority, or changed scanner set is denied.
  Attempt two refreshes its signed, at-most-60-second-old attempt-scoped preflight and sandbox
  attestations while retaining the original fixed commit, inventory digest, canonical key,
  and immutable plan. Exact allowed replay reuses the persisted decision time for attempt
  creation; denied evidence permanently consumes that scan/attempt slot and recovery starts a
  new scan request.
- T041 accepts only a durable T037 occurrence that belongs to the exact T038 source set behind
  the T039 `COMPLETE` decision and T040 verified, fresh, comparable decision. It reloads the
  fingerprinted source finding and normalized row rather than accepting finding authority,
  path, coordinates, or freshness from the caller.
- The T041 source authority defaults to unavailable. A verified provider returns only a
  bounded scanner-redacted fragment in memory. The service applies known-format and
  platform-secret redaction again, stores no raw source or secret value, and checks exact UTF-8
  bytes and line counts before building a canonical fragment.
- The canonical pack permits at most 32 KiB, five fragments, 8 KiB per fragment, and five
  context lines on either side of each attested anchor. Selection is deterministic and records
  truncation plus suppressed count. A full file, more than two fragments from one file,
  overlapping or adjacent intervals, or combined coverage of at least 25% of a source file
  rejects the whole pack and persists only the immutable rejection/audit decision.
- `SastEvidenceBuildDecision`, `SastAcceptedEvidencePack`, and
  `SastAcceptedEvidenceFragment` are tenant/scan/attempt scoped with exact T040 and occurrence
  composite foreign keys. Serializable re-read permits only exact replay.
- Alongside the four established runtime exports (`RepositoryFetchService`,
  `RepositoryPreflightService`, `SandboxRuntimeAttestationService`, and
  `SastScannerRuntimeService`), `ScanPlaneModule` exports
  `SastEvidenceAccessService` as the sole sequential T042 handoff to T043. T041 construction,
  T040 freshness, and all earlier coverage/correlation/lineage/identity/redaction providers
  remain internal.
  T041 adds no controller, evidence access route, AI payload, policy decision, publisher, or
  SCM writer; `dashboardSafe` and `aiSafe` remain false and classification/deletion
  references remain null.
- T042 creates the immutable `sast-evidence-deletion-schedule-v1` row in the same serializable
  transaction as each accepted T041 pack, with a maximum seven-day `deleteAfter`. Every read
  reloads and revalidates that durable pack, fragments, scope, T041 build decision, T040
  freshness, T039 coverage, and T038/T037 source bindings.
- Dashboard and AI classification are separate immutable `sast-evidence-access-decision-v1`
  decisions. Each purpose reruns known-format, registered-platform-value, and entropy
  redaction, rejects unsafe path/identifier material, verifies canonical content and digests,
  and checks time both before and immediately after the read. A missing registry, tampered
  binding, deletion claim, expiry, or clock rollback denies without returning content.
- The authenticated dashboard route requires the session tenant and repository binding and
  returns only the dashboard-safe projection. AI classification returns only a reduced
  evidence reference with an at-most-24-hour eligibility window; T042 creates no provider
  request, AI payload, retrieval/tool grant, policy mutation, publisher, or SCM action.
- Expiry processing uses a deterministic operation ID, lease owner/token fencing, a deletion
  authority that defaults unavailable, and a bounded provider receipt. Only a valid receipt
  permits pack/fragment deletion and canonical `sast-evidence-deletion-proof-v1` completion.
  The worker starts immediately, schedules against the earliest durable due timestamp, and
  immediately continues a saturated bounded batch. The T041 build decision and bounded
  audit/proof ledgers remain durable. An original receipt from an exact deterministic retry
  succeeds when it remains deadline/observation/lease bounded; a changed receipt cannot mutate
  the result.
- T043 accepts only exact advisory intent (`tenantId`, `repositoryBindingId`, `evidencePackId`,
  and `modelVersion`). It classifies T042 AI access twice around a durable T037 occurrence,
  source-finding, and normalized-finding rebind; any scope, digest, access, clock, or expiry drift
  returns the same generic unavailable result.
- `sast-ai-advisory-handoff-v1` derives deterministic request, handoff, and advisory identities
  from the immutable T042 decision timestamp. Its ledger stores only scope references, digests,
  expiry, model version, and fixed audit/authority bits. It stores no request/handoff JSON,
  title/path, source, secret, fragment, prompt, or provider payload.
- The internal AI runtime receives one normalized metadata projection and one opaque reduced
  reference with `snippets=[]`. Retrieval, tools, policy, publication, lifecycle mutation, and
  SCM write authority remain false; the legacy caller-supplied finding/evidence route is denied.
- T044 accepts only tenant and advisory identity under a tenant-bound internal credential, then
  locks the advisory context and rebinds the T043 metadata/handoff to the
  exact T037 occurrence, normalized finding, lineage, and lifecycle context. In one bounded
  serializable transaction it locks the scan, lifecycle-context, and finding authority fences,
  hashes the complete scan finding set, target status/severity, lifecycle state/revision, durable
  finding policy decisions, finding-scoped waivers, and suppressions once, and projects that
  locked snapshot into identical before/after proof fields. Covered writers use the same fence;
  bulk normalized-finding and lifecycle statements advance each distinct affected scope once.
  Any missing, over-limit, cross-scope, concurrent, or changed replay state fails closed.
- `sast-ai-advisory-authority-proof-v1` stores no JSON or model/content payload. It retains only
  scope references, counts, component/state/proof digests, verification time, and database-
  checked booleans: proof-ledger written is true while every finding creation/status/severity,
  lifecycle, policy, waiver, suppression, block, publication, SCM, and authoritative-write bit
  is false. Immutable triggers and restricted parent relations preserve exact replay and audit.
- Policy accepts only a tenant/finding-bound `sast-ai-advisory-policy-reference-v1` to set
  display visibility. Deterministic finding severity and coverage alone derive enforcement,
  reasons, tickets, and blocks. The legacy `suggestedAction` shape and advisory/proof fields in
  exact waiver or suppression payloads fail closed before mutation.
- T047 records one exact, content-free `sast-rule-bundle-promotion-evidence-v1` object for a
  candidate and its distinct T045 baseline. The evidence must bind the verified manifest,
  profile supported by both candidate and baseline, rollback target, immutable corpus/environment
  references, denominator-bound sufficient sample counts, relative and absolute p95 gates, all
  other quantitative gates, and zero security events. Automated evidence never grants approval.
- Human approvals use `sast-rule-bundle-promotion-approval-v1`, bind the exact evidence and
  candidate, reject the candidate author, and remain unique by role and approver. Every lifecycle
  transition requires Security Engineering; `ACTIVE` and `RETIRED` also require an independent
  Scan Platform or Security Operations approval.
- `sast-rule-bundle-lifecycle-transition-v1` is an append-only, previous-digest-linked state
  ledger. Only `DRAFT -> VALIDATED -> CANARY -> ACTIVE -> RETIRED`, `CANARY|ACTIVE -> SUSPENDED`,
  and `SUSPENDED -> ROLLED_BACK` are legal. T048 installs the exact canary-observation authority,
  T049 installs exact active-switch emergency suspension, and T050 installs the independent
  last-known-good rollback authority.
- Before tenant policy, planning revalidates the latest lifecycle snapshot and persists a
  `sast-rule-bundle-lifecycle-selection-v1` receipt. Only latest `CANARY` or `ACTIVE` bundles are
  selectable. All selected bundle receipts are committed atomically under ordered manifest-row
  locks, so one invalid or concurrently changed bundle leaves no partial scanner-set receipt.
  The immutable plan retains the lifecycle descriptor and receipt for audit. The stable state,
  sequence, transition, evidence, and approval-set projection enters
  `sast-canonical-scan-key-v3`, while the evaluation-time-derived receipt ID/digest is excluded so
  exact retries remain idempotent. Queue reservation locks and revalidates a trigger-maintained
  latest-transition head plus the receipt before insertion; the T047 schema cutover refuses to
  proceed while prior v2 SAST work is non-terminal.
- T048 binds one immutable rollout per candidate manifest and profile to the exact `CANARY`
  lifecycle head, distinct `ACTIVE` baseline, T047 evidence and transition, signed profile,
  HMAC-key reference/version, eligibility policy, and observation-source digest. It persists no
  key material, repository content, finding content, or generic JSON. A paused candidate/profile
  cannot be resumed or re-enrolled; recovery requires a new candidate manifest, fresh evidence,
  fresh approvals, and a new rollout.
- Platform-managed eligibility permits only internal corpus, internal repository, or eligible
  production scopes and records explicit contractual/residency exclusions. Stable cohort
  membership is HMAC-SHA-256 over length-framed tenant, repository binding, profile, and rollout
  identity. The first eight digest bytes map to one of 10,000 basis-point buckets and are
  recomputed by PostgreSQL; customer attributes, repository content, findings, and severity do
  not participate. The required key is supplied through
  `SAST_CANARY_COHORT_HMAC_KEY_BASE64`, `SAST_CANARY_COHORT_HMAC_KEY_REF`, and
  `SAST_CANARY_COHORT_HMAC_KEY_VERSION`; decoded key material must be at least 32 bytes and is
  zeroed after use. The digest suffix of `KEY_REF` must equal SHA-256 of the decoded key, so a key
  cannot silently change under an existing reference/version; only that non-secret fingerprint
  is persisted.
- Assignment progresses without skipping through `INTERNAL_CORPUS`,
  `INTERNAL_REPOSITORIES`, `PERCENT_1`, `PERCENT_5`, `PERCENT_25`, and `PERCENT_100`. Only an
  exact candidate assignment receives a canary descriptor. If a supplied `CANARY` descriptor
  resolves to `BASELINE` or `EXCLUDED`, the gate rejects it instead of rewriting an already
  compatibility/lifecycle-verified descriptor. Trusted orchestration must submit the separately
  verified exact `ACTIVE` baseline scanner set for non-cohort production; excluded scopes are
  never silently assigned to the candidate. The
  planner order is compatibility -> lifecycle -> canary -> kill switch -> tenant policy. Queue admission locks
  and revalidates both lifecycle and canary heads so a pause or step change cannot enqueue a
  stale candidate plan.
- `sast-canonical-scan-key-v4` adds only the stable rollout, membership, bucket, and
  candidate-assigned projection. The immutable plan retains the assignment receipt, rollout
  step, and step-head binding for admission/audit, but those evaluation-time values are excluded
  from the key. The T048 migration drains or cancels non-terminal v3 work before cutover and
  leaves terminal v3 history immutable.
- T048 observations are append-only, content-free, and accepted only from the rollout's exact
  observation-source digest after the immutable candidate/baseline plan, assignment, terminal
  attempt interval, coverage decision, publication decision, and telemetry source are rebound.
  The caller identifies only rollout/scope/scan/attempt; the trusted adapter derives candidate or
  baseline role and repository-size bucket from durable plan/telemetry authority.
  Coverage and publication denial counts are derived from their authoritative rows; missing
  telemetry and incomplete coverage remain explicit rather than being omitted. Evaluation
  automatically uses the trusted service clock as the window cutoff and binds every committed
  observation in that exact closed step window; callers cannot supply a cutoff, observation IDs,
  or omit an unfavorable scan.
- Each step compares candidate and baseline by profile and all `SMALL|MEDIUM|LARGE` repository
  size buckets. The first four steps require at least 200 completed scans per arm and 24 hours;
  25% and 100% require at least 1,000 per arm and 48 hours. Gates enforce at most a two-point
  false-positive increase, at most 2% candidate scanner failures, at most 20% p95 latency and
  completed-scan-normalized Critical/High rate increase over baseline, absolute 10-minute Fast
  or 45-minute Deep p95, complete telemetry/coverage/size comparison, and zero cross-tenant,
  secret-leak, sandbox-escape,
  stale-publication, unauthorized-egress, missing-destruction-evidence, evidence-policy, or
  unsigned-artifact-execution events. Insufficient time/sample is `PENDING`; every hard failure
  is terminal `PAUSED`.
- Only six ordered `PASSED` decisions issue an immutable
  `sast-rule-bundle-canary-observation-receipt-v1`, which the lifecycle authority router accepts
  solely for the exact `CANARY -> ACTIVE` transition. The default production observation source
  remains unavailable until a production-qualified adapter supplies the exact durable metrics;
  it never fabricates evidence. T049 emergency suspension and T050 rollback are installed as
  separate, non-interchangeable authorities.
- T049 accepts only platform-managed, signed, append-only `ACTIVATE | DEACTIVATE` decisions for
  canonical global SAST, scanner/version, bundle digest, semantic rule, signed profile,
  tenant, repository-binding, capability, and scoped external-publication selectors. Decisions
  bind sequence/predecessor, actor role, incident/reason, effective/review/expiry times,
  rollback-target, signature/provenance, and audit references. An exact immutable verification
  must commit with each decision; invalid/future/forked/expired-active/unavailable authority fails
  closed. Every boundary time must also remain within the bounded skew of the service-owned
  trusted clock; a caller-selected stale or future time cannot replay a prior clear evaluation.
  The production signature port deliberately defaults unavailable until qualified.
- Trigger-owned selector heads and durable inactive placeholders close the absent-head first-
  activation race. Planning runs after canary and before tenant policy and retains only a
  `CLEAR` evaluation descriptor in the immutable plan. It does not change
  `sast-canonical-scan-key-v4`. Queue admission reconstructs the plan context and canonical keys,
  then locks/revalidates the exact complete head set; the database independently compares every
  selector identity and the closed-set count before accepting a direct insert. The context is
  limited to two rule bundles and 50,020 selectors; both evaluation and queue admission use one
  canonically ordered set-based lock and an anti-join instead of per-selector SQL loops.
- Fresh gates cover scanner start, artifact acceptance, retry, effective coverage, external
  publication, and AI advisory. Scanner cancellation happens after its durable run is created
  but before any provider repository read or scanner execution, records `KILLED`, and preserves
  cleanup. Affected artifacts quarantine before downstream acceptance; a clear switch still
  delegates to the independently unavailable-by-default Data/Security acceptance port. Retry
  admission also requires an independent current scanner-set availability authority; a clear
  switch cannot imply that withdrawn images, wrappers, rules, or databases remain available.
  Publisher calls and model calls are denied when affected.
  A recovered accepted artifact intent is checked again before storage and is replaced by a
  quarantine intent when authority changed. AI is checked before inference and again immediately
  before advisory persistence. Effective lifecycle coverage first
  requires a fresh T049 `COVERAGE` evaluation and delegates only a clear result to the independent
  T040 coverage authority; active scope never reaches that authority. External comment planning
  and every worker claim independently re-evaluate `EXTERNAL_PUBLICATION`, so activation between
  those boundaries yields zero claims and publisher calls. Current `PARTIAL | FAILED` effective
  coverage is separate from immutable T039 history.
- An active applicable global/bundle/scanner-version/semantic-rule/exact-profile decision set can
  issue the sole digest-bound `EMERGENCY_SUSPENSION` receipt for an exact latest
  `CANARY | ACTIVE -> SUSPENDED` edge. Its reference ends in its exact receipt digest, matching
  the lifecycle authority contract. The lifecycle transition locks and recomputes the complete
  applicable active decision set and digest, so deactivation or replacement of any non-trigger
  selector invalidates the receipt. It cannot authorize rollback.
- Automatic canary input contains only the exact T048 step-decision ID/digest. A serializable
  lifecycle-then-canary lock derives the current `PAUSED`/zero-tolerance signal and all manifest,
  bundle, signed-profile, transition, reason, and time bindings from durable rows; caller targets
  and stale/non-paused decisions fail closed. The signal itself has zero mutation authority.
- T050 accepts a candidate suspension reference and bounded incident/actor/reason/audit/signing
  metadata only; the caller cannot supply a baseline or rollback target. The signed command
  derives the distinct last-known-good manifest/bundle from the original T047 promotion evidence,
  revalidates both T045 attestations, the exact T049 suspension receipt, common scanner/profile
  compatibility, and current candidate `SUSPENDED` plus baseline `ACTIVE` heads. Within 15
  minutes it requires fresh Security Engineering and independent Scan Platform or Security
  Operations human approvals, excluding the command actor. Command, verification, approvals,
  receipt, and receipt bindings are normalized append-only exact-replay ledgers.
- Receipt issuance and lifecycle commit lock candidate and baseline heads in canonical manifest
  order and recheck all bindings. The receipt authorizes only one candidate
  `SUSPENDED -> ROLLED_BACK` append; every baseline/history/scanner-set/finding/policy/publication/
  SCM authority bit is false. New work can use the handoff identity only after trusted scanner-set
  ownership selects the still-current `ACTIVE` baseline and the normal planning gates pass.

This checkpoint proves the provider-facing execution contract but does not claim that the
provider microVM platform is live. The non-production opaque credential issuer and test
runtime provider exist only to verify the handoff contract. Default production credential
issuance and scanner execution both fail closed until live rollout installs provider-backed
GitHub App/GitLab scoped minting, microVM, artifact object-store/disposition,
file-coordinate-attestation, and acceptance-gate adapters. T035 secret redaction, T036
`sast-fingerprint-v1` identity construction, T037 occurrence/exact-lineage lifecycle, and
T038 authority-aware cross-tool correlation, T039 fail-closed scanner/capability coverage,
T040 stale-scan denial and bounded infrastructure-only retry, T041 bounded accepted-finding
evidence with reconstruction-risk checks, and T042 purpose-bound dashboard/AI classification,
second-pass secret redaction, seven-day expiry enforcement, and deletion proof are complete;
T043 normalized-finding plus reduced-reference advisory handoff is complete. T044 zero-authority
output proof is also complete. T045 signed immutable, content-free rule-bundle manifests,
trusted signature/provenance attestations, exact runtime compatibility receipts, and the
pre-queue fail-closed planning gate are complete. T046 reusable semantic rule metadata,
byte-exact signed-manifest bindings, monotonic non-executable tenant policy, immutable
resolution receipts, and canonical-plan/queue gating are also complete. T047 quantitative
promotion evidence, independent approvals, append-only lifecycle transitions, latest-state
selection receipts, and canonical v3 planning gates are complete. T048 deterministic
tenant-safe cohorts, candidate/baseline observations, terminal pause, six-step promotion
  authority, queue-head fencing, and canonical v4 planning gates are complete. T049 signed
  scanner, bundle, rule, profile, tenant, repository, capability, publication, and global kill
  switches, full runtime propagation, and emergency-suspension authority are complete. T050
  evidence-derived last-known-good rollback, signed dual control, two-head fencing, append-only
  receipt/lifecycle persistence, and PostgreSQL direct-write/race enforcement are complete. T051
  versioned golden qualification corpus is complete: one immutable snapshot binds 400 positive,
  400 paired negative, and 400 prior Critical/High must-detect cases across 40 platform-owned
  source bundles. A separate overwrite-protected manifest authenticates the exact historical case
  identities and its reviewed digest is pinned in code.
  T052 multi-class qualification corpus is complete: 84 immutable declarative cases bind every
  required schema/parser, malicious-repository, fingerprint/correlation, evidence/privacy, and
  profile/size performance scenario without materializing or executing hostile content. T053's
  repository provider-handoff implementation is complete, but T053 itself remains pending until
  real production-equivalent provider receipts prove all 123 isolated executions and destruction.
Live deployment eligibility
still requires the 005 rollout and the remaining 006 gates.

### T049-T056 Package Validation Checkpoint

- Shared kill-switch contract tests cover canonical selectors/context, decision and verification
  shape, complete evaluation/head/match sets, coverage effects, planning descriptors, active
  expiry, and emergency-suspension receipts.
- API boundary tests cover planning active/unavailable denial, plan-context and complete-selector
  queue revalidation,
  scanner cancellation before provider/scanner calls, artifact quarantine, retry denial, AI
  denial, lifecycle routing, persistence structure, and database-trigger invariants.
- A clean PostgreSQL 16.4 database applies every migration through
  `20260819180000_sast_kill_switch_authority`; online-schema validation passes. Direct SQL proves
  signed activation, sequential signed deactivation, immutable-ledger rejection, and deferred
  rejection/rollback of an unsigned decision.
- A clean PostgreSQL 16.15 database applies every migration through
  `20260819220000_sast_rule_bundle_rollback`. The post-migration application probe creates exact
  T045/T047 state, proves that a forged direct lifecycle insert is rejected, rechecks candidate
  and baseline head drift, converges concurrent exact rollback attempts to one transition, keeps
  the baseline and history unchanged, and rejects rollback-ledger mutation. CI runs this probe
  immediately after migration deployment.
- T051's shared exact-shape contracts, deterministic generator, and root-confined loader bind all
  800 cases to owner, license, digest-bound provenance, revision, source bytes/digest, exact line
  range/anchor, and unique future materialization path. Every profile has at least 200 positive and
  200 negative cases; every Critical/High rule has 20 of each. The prior-release manifest binds the
  exact 400 historical positives and rejects deletion, mutation, forged references, or automatic
  inclusion of later positives. Five negative classes are non-empty and use applicable, distinct
  source behavior (95 patched, 35 sanitizer, 95 safe-API, 80 comment/string, 95 generated/vendor).
  CI rejects manifest/snapshot/source drift, non-allowlisted root entries, path escape,
  symlink/junction traversal, identity changes across guarded reads/writes, extra files, invalid
  UTF-8/NFC/LF, oversized input, range drift, authority widening, and mutable or executable corpus
  metadata.
- T051 fixes golden and prior-release qualification inputs only. T052 adds 84 exact recipe-bound
  cases: 16 schema/parser, 25 malicious-repository, 17 fingerprint/correlation, 17
  evidence/privacy, and 9 performance buckets. The recipes use allowlisted declarative actions,
  inline bounded base64 segments, exact profile limits, one digest-bound hardware class, and 30
  required measured runs per performance bucket. No fixture contains a live special file,
  executable command, customer content, package install, build, dynamic test, scanner run, or
  network requirement.
- T052 validation regenerates the complete expected fixture set in memory, requires exact root and
  class directory allowlists, byte-exact UTF-8/NFC/LF assets, no-follow reads where supported, and
  stable before/open/after file and directory identity. It grants no finding, policy, publication,
  or readiness authority. T053 is the first stage allowed to materialize the T053-designated
  recipes and perform production-equivalent isolated scanner execution.
- T052 revision `1.0.2` binds profile-relative cases—including artifact bytes and record count—to
  each selected profile's exact limit plus one through generic segment formulas. Shared JSON depth
  and string cases bind the validator's exact 64+1 and 4,096+1 boundaries. It also declares both
  symlink-cycle edges, preserves binary/malformed UTF-8 as raw bytes, and gives identity/correlation
  cases complete vectors and relations. Future runners consume those bound declarations directly
  and never branch on scenario names to manufacture a pass.
- T053 derives the exact 41 applicable cases across all three profiles into 123 canonical cells.
  The checked-in manifest binds the T052 snapshot, fixtures, profiles, scanners, exact
  materialization projections, provisioning contract, and a closed guest-only action policy.
- A live dependency set must bind every scanner, wrapper, rule/database/schema/normalizer,
  materializer/runner/harness, microVM kernel/rootfs, provider, and trust artifact. The generated
  plan requires Security Engineering and Scan Platform approval. Each cell then requires one new
  microVM plus provider and qualification-runtime Ed25519 signatures over its receipt.
- The offline verifier rejects duplicate/reused attempt, sandbox, workload, attestation, cell, or
  receipt identity; wrong outcome/materialization; any phase egress or prohibited effect; stale or
  changed signatures; approval at or after the earliest execution start; caller-selected evaluation
  time; incomplete cleanup; and cleanup over 60 seconds. It uses only its service-owned trusted UTC
  clock. Its exit codes are 0 only
  for all 123 valid receipts, 1 for failure, and 2 for `PENDING_PROVIDER_EXECUTION`.
- Repository CI validates package determinism, exact filesystem bytes, real Ed25519 verification,
  tamper rejection, and the mandatory pending state. It never launches a scanner/microVM, creates
  provider attestations, or checks T053 complete. T054 remains blocked until a real T053 pass.
- T055 derives exactly 169 immutable cells: 144 mount/digest/signature/provenance drills across all
  36 T054 artifacts, one unlisted-component rejection, six internal vulnerability-database drills,
  three result-schema drills, and 15 ordered rollback phases across all three profiles. Exactly 115
  cells reject before execution and only 39 allow one artifact invocation.
- A T055 plan requires the exact T054 manifest, `PASSED` result, dependency set, complete artifact-
  verification set, and execution plan, plus a Qualification Authority entry signature and the
  same provider/adapter. `SAST_T055_TRUST_POLICY_DIGEST` independently pins the trust bundle, and
  every artifact signature and provenance envelope is reloaded, digest-recomputed, and Ed25519-
  verified before any drill evidence is accepted.
- Qualification Authority and Supply Chain Authority independently sign each profile's exact
  durable prior rollback-ledger head, sequence, reference, provider, and release sets before the
  attestations enter the plan. Security Engineering and Scan Platform approvals bind that plan and
  strictly predate the earliest submitted receipt or attempt. Each receipt is
  independently signed by Supply Chain Authority, MicroVM Provider, and Qualification Runtime and
  uses globally unique cell, attempt, sandbox, workload, attestation, audit, and receipt identities.
  Mounts are read-only; customer code, package installation, repository build, dynamic testing,
  public egress, and production mutation remain prohibited.
- Rollback receipts bind exact candidate/baseline release-set digests, fence new candidate work,
  prove in-flight abort and cleanup, derive and reverify the last-known-good baseline, require zero
  post-fence invocations, and append `STANDBY -> ACTIVE` only by referencing the exact plan-bound
  head attestation and using exactly `head.sequence + 1`.
  A complete pass grants only T056 entry. Repository validation remains
  `BLOCKED_T054_QUALIFICATION` and never grants Kubernetes, deployment, or production-readiness
  authority.
- T056 fixes exactly 54 mandatory gates across six ordered evidence kinds: 34 upstream
  qualification observations, six repository assurances, five canary replay checks, four
  kill-switch checks, three rollback-readiness checks, and two reference-only deployment boundary
  checks. Every v1 gate prohibits `NOT_APPLICABLE`.
- A T056 plan requires the exact same-provider T054/T055 chain, a Qualification Authority entry
  signature, and trust bytes independently pinned by `SAST_T056_TRUST_POLICY_DIGEST`. Every
  category binds candidate/baseline/profile/corpus and T054/T055 measurement digests, repository
  commit, digest-bound evidence, validity window, and its independent signer roles. The verifier
  owns its UTC clock and recomputes upstream values instead of accepting caller aggregates.
- Missing valid categories or Security Engineering/Scan Platform approvals remain
  `PENDING_FINAL_EVIDENCE`; malformed, unsigned, stale, drifted, threshold-breaching, or
  `NOT_APPLICABLE` evidence is `NO_GO`. Only all 54 passing gates and both fresh approvals produce
  `GO`. That record authorizes only entry to the 005 operations workflow; it cannot execute
  Kubernetes, mutate production, or establish readiness. Repository validation remains
  `BLOCKED_T055_QUALIFICATION` and synthetic fixtures are verifier tests only.
- 005 preflight independently verifies a short-lived Qualification Authority Ed25519 entry
  attestation over the exact T056 record/manifest/plan, repository commit, provider/adapter,
  rollback, kill-switch evidence, and current 005 contract digest. It reconstructs the binding
  under trusted UTC, requires all credential scopes and approvals, and allows only a bounded
  handoff that begins before qualification expiry and keeps the exact rollback target. No step
  grants deployment, Kubernetes, provider mutation, production mutation, or readiness authority.
- Repository completion still requires the standard commands below on the final branch. Live
  signing, publisher, object-store, provider repository, microVM, and Kubernetes qualification
  remain fail-closed rollout dependencies rather than fabricated local evidence.

## Deployment Position

Oracle VPS and Docker Compose remain dev/demo paths. Production SAST execution requires the
separated Scan Plane and stronger-than-pod isolation defined by 004 and 005. This design does
not authorize live provider execution or introduce provider credentials as local defaults.

## Spec Kit Compatibility

When working on GitHub-style branches, use:

```powershell
$env:SPECIFY_FEATURE = "006-production-sast-runtime-design"
```

## Completion Gate

Before claiming the 006 design milestone complete:

1. Re-run the validation commands below.
2. Confirm `AGENTS.md`, `README.md`, and `docs/github-conventions.md` point to 006.
3. Confirm 002 through 005 remain linked as completed baselines.
4. Confirm scanner responsibilities do not overlap without an explicit correlation rule.
5. Confirm no contract accepts customer code execution, package install, build, dynamic
   tests, direct source upload, SCM write authority, or AI full-repository access.
6. Confirm every rule bundle and scanner image requires digest, signature, provenance,
   staged rollout, rollback, and kill-switch references.
7. Confirm partial, stale, failed, quarantined, and security-blocked scans fail closed.
8. Confirm evidence cannot contain full files or exceed the seven-day retention boundary.
9. Confirm all quantitative quality and security gates are explicit and testable.
10. Confirm any language after Java follows `language-profile-extension.md` before the product
    claims SAST-complete coverage.
11. Against a disposable PostgreSQL 16 database, apply every migration and run the opt-in T050
    rollback probe; never aim the probe at a shared or production database.
12. Validate the checked-in T051 golden corpus from its deterministic generator before using it as
    a qualification denominator.
13. Validate the checked-in T052 corpus and T053 provider handoff, confirm the repository-only T053
    verdict is `PENDING_PROVIDER_EXECUTION`, and never mark T053 complete without 123 external
    provider/runtime-signed receipts and complete destruction evidence.
14. Validate the T054 repository-side 3,462-cell qualification contract, confirm it remains
    `BLOCKED_T053_QUALIFICATION`, and never issue its provider plan without a signed T053 pass or
    its exact dependency/provider binding and an independently pinned trust-policy digest. Confirm
    each artifact's complete signature envelope and provenance statement is digest-recomputed and
    individually Ed25519-verified before the closed verification-set signature is accepted. Never
    treat CI/local receipt fixtures as end-to-end, latency, reliability, or capacity evidence.
15. Validate the T055 repository-side 169-cell supply-chain and rollback contract, confirm it
    remains `BLOCKED_T054_QUALIFICATION`, and never issue its drill plan without the exact signed
    T054 pass, same-provider dependency/verification/plan bindings, and independently pinned trust
    policy. Confirm every profile has a dual-signed durable prior-ledger-head attestation in the
    approved plan and that final activation accepts only its exact sequence + 1. Never treat
    synthetic signatures, local receipts, or repository validation as external supply-chain,
    rollback, T056, Kubernetes, deployment, or production-readiness evidence.
16. Validate the T056 repository-side 54-gate immutable go/no-go contract, confirm it remains
    `BLOCKED_T055_QUALIFICATION`, and never issue its plan without the exact signed same-provider
    T054/T055 chain and independently pinned trust root. Confirm all six evidence categories,
    verifier-owned time, upstream recomputation, mandatory-gate and dual-approval rules, and that
    `GO` grants only 005 deployment-operations entry. Never treat synthetic signatures, local
    evidence, or repository validation as canary, kill-switch, rollback, Kubernetes, deployment,
    or production-readiness evidence.
17. Validate that 005 preflight has no evidence-free path: it must require the exact current-
    contract T056 `GO` record and a fresh Qualification Authority Ed25519 entry attestation, bind
    repository commit/provider/adapter/rollback/kill-switch evidence, use trusted UTC, require all
    credential scopes and approvals, and reject expiry or drift. Confirm handoff begins before
    qualification expiry, preserves the exact rollback target, and grants no live authority.

## Validation Commands

```powershell
corepack pnpm lint
corepack pnpm test
corepack pnpm typecheck
corepack pnpm build
corepack pnpm qualification:validate
corepack pnpm --filter @aegisai/api prisma:validate
corepack pnpm --filter @aegisai/api prisma:migrate:deploy
$env:RUN_SAST_ROLLBACK_POSTGRES_PROBE = "1"
try {
  corepack pnpm --filter @aegisai/api test --runInBand test/rule-governance/sast-rule-bundle-rollback.postgres.e2e-spec.ts
  if ($LASTEXITCODE -ne 0) {
    throw "T050 PostgreSQL rollback probe failed with exit code $LASTEXITCODE"
  }
} finally {
  Remove-Item Env:RUN_SAST_ROLLBACK_POSTGRES_PROBE -ErrorAction SilentlyContinue
}
node --test test/runtime/*.test.mjs
git diff --check
```
