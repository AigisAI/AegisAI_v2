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
- The T049 kill-switch engine will supply the authoritative acceptance-gate adapter. Until
  that adapter and the production Data/Security disposition adapter are installed, both
  defaults fail closed and valid rows remain pending rather than being implicitly accepted.
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
  and lifecycle mutation as false. T040 drops the old permanent constraint name and replaces
  it with a T039-source constraint plus independent `sast-scan-freshness-v1` authority rows;
  it never rewrites or weakens exact T039 replay.
- T040 rebinds tenant, repository, provider, target, fixed commit, scan, attempt, approved
  profile/plan, canonical scan key, required capability set, `sast-fingerprint-v1`, and a
  canonical lifecycle-eligibility scope. A provider-authoritative, monotonic target-head
  observation must match the fixed commit exactly. The default observer is unavailable, so
  deployments without a read-only provider adapter remain fail closed.
- Comparability requires the immediately preceding completed `COMPLETE` coverage source in
  the same tenant/repository/target, a supported profile family, the exact required capability
  set, fingerprint version, and lifecycle-eligibility scope. Only `VERIFIED` + `FRESH` +
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
  Attempt two refreshes its signed attempt-scoped preflight and sandbox attestations while
  retaining the original fixed commit, inventory digest, canonical key, and immutable plan.
- `ScanPlaneModule` now exports only `SastScanFreshnessService` as the sequential T040 handoff
  to T041. T039 coverage, T038 correlation, T037 lineage, T036 identity construction, T035
  redaction, and raw OpenGrep/Trivy/Syft normalization remain internal providers. There is
  still no user route, artifact reader, SCM writer, evidence, policy, publication, or AI path.

This checkpoint proves the provider-facing execution contract but does not claim that the
provider microVM platform is live. The non-production opaque credential issuer and test
runtime provider exist only to verify the handoff contract. Default production credential
issuance and scanner execution both fail closed until live rollout installs provider-backed
GitHub App/GitLab scoped minting, microVM, artifact object-store/disposition,
file-coordinate-attestation, and acceptance-gate adapters. T035 secret redaction, T036
`sast-fingerprint-v1` identity construction, T037 occurrence/exact-lineage lifecycle, and
T038 authority-aware cross-tool correlation, T039 fail-closed scanner/capability coverage,
and T040 stale-scan denial and bounded infrastructure-only retry are complete; T041 bounded
accepted-finding evidence with reconstruction-risk checks is therefore the next implementation task.
Live deployment eligibility
still requires the 005 rollout and the remaining 006 gates.

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

## Validation Commands

```powershell
corepack pnpm lint
corepack pnpm test
corepack pnpm typecheck
corepack pnpm build
corepack pnpm --filter @aegisai/api prisma:validate
node --test test/runtime/*.test.mjs
git diff --check
```
