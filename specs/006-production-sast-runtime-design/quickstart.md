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

T022 through T031 are implemented as the complete Phase 5 runtime boundary plus the
ingress, validation, and final-disposition portion of Phase 6:

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
  generates fixed shell-less OpenGrep SARIF, Trivy JSON offline, and Syft CycloneDX commands
  against `/workspace/repository` for Deep or the platform-owned,
  inventory-digest-bound `/workspace/selected/<digest>` projection for Fast, with output
  under `/workspace/output`; caller paths, commands, flags, environment maps, plugins, and
  executable configuration are not request fields. Processes
  start in the private output directory. OpenGrep repository ignore/`nosem`, Trivy repository
  config/ignore files, and Syft repository config/archive expansion, remote enrichment, and
  external package-tool execution are disabled; only wrapper/rule-digest-bound platform
  configuration is loaded.
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
  global byte offsets, so valid and invalid results are invariant to transport chunking. It independently binds the
  semantic OpenGrep SARIF 2.1.0, Trivy JSON v2, or CycloneDX 1.6 schema plus scanner-set,
  schema-bundle, normalizer-bundle, rule, and Trivy database digests together with the exact
  scanner and canonical artifact reference. The transport and validator independently recompute
  content digest and byte count, and the validator recomputes schema-specific record count; it
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

This checkpoint proves the provider-facing execution contract but does not claim that the
provider microVM platform is live. The non-production opaque credential issuer and test
runtime provider exist only to verify the handoff contract. Default production credential
issuance and scanner execution both fail closed until live rollout installs provider-backed
GitHub App/GitLab scoped minting, microVM, artifact object-store/disposition,
file-coordinate-attestation, and acceptance-gate adapters. T032 is therefore the next
implementation task; live deployment eligibility still requires the 005 rollout and the
remaining 006 gates.

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
