# Specification: Production SAST Runtime and Rule Governance

**Feature ID**: `006-production-sast-runtime-design`

**Status**: Active design baseline

**Primary Reference**: `Security Scan SaaS Final Specification.docx`

## Purpose

Define a production implementation contract for deterministic security scanning. This
milestone closes the design gaps between the completed Scan Plane architecture and a real
scanner runtime: tool responsibility, lane/profile selection, rule governance, hostile
input handling, artifact ingestion, normalization, fingerprinting, correlation, evidence,
coverage, failure semantics, quality gates, and legacy-path retirement.

## Scope

### In Scope

- OpenGrep, Trivy, and Syft responsibility boundaries
- Java Fast (`JAVA_FAST_V1`) and Deep (`JAVA_DEEP_V1`) SAST profiles plus the common
  non-language-specific `COMMON_DEEP_V1` profile
- Versioned and signed scanner-set and rule-bundle contracts
- Per-scan microVM inputs, limits, lifecycle, and result-ingress boundary
- Fixed-commit repository fetch and hostile path/resource preflight
- Raw artifact envelopes, validation, quarantine, and retention
- Deterministic finding normalization, provenance, stable identity, and correlation
- Coverage completeness and fail-closed external publication rules
- Evidence reduction, redaction, classification, and retention
- Rule promotion, tenant policy, canary, rollback, and kill switch
- Quantitative correctness, performance, security, and reliability gates
- Migration from the legacy `/api/scans` mock-analysis path to the canonical Scan Plane

### Out of Scope

- Customer code execution, package install, repository build, or dynamic testing
- Direct source upload
- Runtime or interactive application security testing
- Auto-fix PR/MR creation or merge
- Tenant-supplied executable scanner configuration
- AI-created authoritative findings or AI policy authority
- Full repository, source archive, raw scanner payload, or SCM credential input to AI
- Provider credential storage or live production infrastructure execution in this slice
- Language-specific SAST profiles beyond Java v1

## Terminology

- **SAST**: source-code vulnerability detection. OpenGrep is the v1 authoritative engine.
- **SCA**: dependency vulnerability analysis. Trivy is authoritative in v1.
- **Secret detection**: credential-pattern detection. Trivy is authoritative in v1.
- **IaC misconfiguration**: Dockerfile, Kubernetes, Terraform, CloudFormation, and similar
  static configuration checks. Trivy is authoritative in v1.
- **SBOM**: source-workspace component inventory. Syft is authoritative in v1.
- **Scanner wrapper**: platform-owned adapter that pins the binary/image, rules, input,
  output schema, resources, and exit semantics. Product contracts never accept arbitrary
  CLI strings.
- **Coverage**: evidence that all scanners and capabilities required by the selected
  profile completed with valid output.
- **Stable fingerprint**: line- and commit-independent identity used to track one finding
  across rescans.

## User Scenarios

### Story 1 - Deterministic Scan Planning

As the Control Plane, I can turn an immutable scan request into exactly one versioned scan
profile and scanner set without supplying source content or SCM credential values.

### Story 2 - Isolated Scanner Execution

As the Scan Plane, I can execute one fixed repository state inside one disposable microVM,
produce bounded artifacts, and prove that the workspace and credential were destroyed.

### Story 3 - Trustworthy Findings

As the policy engine, I receive normalized findings with stable identity, full scanner/rule
provenance, coverage state, and evidence references, not unvalidated raw tool output.

### Story 4 - Safe Rule Evolution

As a security operator, I can validate, canary, promote, suspend, roll back, or kill a
signed rule bundle using measurable correctness and performance gates.

### Story 5 - Conservative Publication

As a repository owner, I never receive a blocking or PR/MR comment result from an
incomplete, stale, quarantined, or security-blocked scan.

## Functional Requirements

### Scanner Responsibility

- **FR-001**: OpenGrep MUST be authoritative only for `SAST` findings.
- **FR-002**: Trivy MUST be authoritative for dependency vulnerability, secret, and IaC
  misconfiguration findings.
- **FR-003**: Syft MUST be authoritative for SBOM generation and MUST NOT create
  vulnerability findings.
- **FR-004**: An overlapping rule from a non-authoritative scanner MUST be disabled or
  explicitly marked non-authoritative before production use.
- **FR-005**: Scanner wrappers MUST use machine-readable, schema-versioned output.

### Planning and Repository State

- **FR-006**: Every plan MUST bind tenant, repository binding, scan request, fixed commit
  SHA, lane, profile, policy version, scanner-set version, and rule-bundle digest.
- **FR-007**: Branch names and PR/MR refs are context only; execution MUST use the resolved
  fixed commit SHA.
- **FR-008**: Fast and Deep lanes MUST use separate queue and resource policies.
- **FR-009**: A scan profile MUST define required scanners, optional scanners, required
  capabilities, source/manifests, path policy, limits, AI eligibility, and timeout.
- **FR-010**: Profile selection MUST be deterministic from repository metadata and policy.
- **FR-011**: Profile or scanner-set changes MUST produce a different canonical scan key.

### Isolation and Fetch

- **FR-012**: One scan MUST create one non-reused `HARDENED` or `RESTRICTED` microVM.
- **FR-013**: Repository credentials MUST be repo-read, fixed-scan scoped, short-lived,
  non-persisted, non-logged, and delivered only after workload identity validation.
- **FR-014**: Scanner sandboxes MUST NOT receive comment-write or integration-admin
  authority.
- **FR-015**: Repository fetch MUST prefer shallow fixed-commit fetch.
- **FR-016**: Submodules MUST be disabled by default and require an approved future policy.
- **FR-017**: LFS payload retrieval MUST be disabled by default; pointer metadata may be
  inspected.
- **FR-018**: Archive expansion MUST be disabled in v1.
- **FR-019**: Paths MUST be Unicode-normalized and checked for absolute paths, parent
  traversal, root-escaping symlinks, case-fold collisions, maximum depth, and duplicate
  canonical names.
- **FR-020**: CPU, memory, disk, inode/file count, process count, finding count, output size,
  and wall-clock limits MUST be enforced outside scanner control.

### Scanner and Supply Chain

- **FR-021**: Scanner images/binaries MUST be immutable, digest-pinned, signed, provenance
  verified, allowlisted, and associated with an SBOM.
- **FR-022**: Rule bundles, Trivy databases/check bundles, and schema bundles MUST be pinned
  by digest for each scan.
- **FR-023**: Sandboxes MUST use pre-mirrored scanner assets and MUST NOT perform runtime
  internet enrichment.
- **FR-024**: Customers MAY select approved rules/categories through tenant policy but MUST
  NOT supply executable rules, CLI flags, plugins, or arbitrary configuration.
- **FR-025**: Scanner stdout/stderr, exit code, duration, version, digest, and resource use
  MUST be captured as bounded metadata.

### Artifact Ingestion and Normalization

- **FR-026**: The sandbox MUST upload artifacts only through a per-scan write-only result
  ingress reference.
- **FR-027**: Result ingress MUST verify tenant/scan attribution, workload identity,
  scanner and rule digests, content digest, schema version, size, count, encoding, and
  timestamp before acceptance.
- **FR-028**: Invalid, oversized, mismatched, or malformed output MUST be rejected or
  quarantined and MUST NOT enter normalization.
- **FR-029**: Raw scanner output MUST never be returned directly by user-facing APIs.
- **FR-030**: Normalized findings MUST include capability, severity, confidence, location,
  scanner/rule/artifact provenance, stable fingerprint, and evidence references.
- **FR-031**: Normalization MUST use explicit per-schema adapters with golden fixtures.
  Adapter output before T035 redaction and T036 fingerprinting MUST be an in-memory,
  non-durable candidate with no evidence, lifecycle, policy, or AI authority. It MUST retain
  immutable plan/attestation bindings. OpenGrep, Trivy secret, and Trivy IaC semantic identity
  MUST resolve from signed bundle metadata; Trivy dependency identity MUST resolve from the
  pinned vulnerability ID/database rather than scanner-local prose or checks metadata.
- **FR-031a**: Trivy direct and supported modified dependency/secret/IaC records MUST be
  normalized without granting scanner disposition platform suppression, waiver, lifecycle,
  severity, or policy authority. Raw secret match/code/context, scanner prose, and
  misconfiguration trace/rendered-cause values MUST be discarded before candidate
  construction.
- **FR-032**: Unknown enum values, invalid coordinates, overlong strings, unsafe encodings,
  and excessive nesting MUST fail closed.

### Identity, Correlation, and Lifecycle

- **FR-033**: Stable finding identity MUST exclude branch, commit SHA, and line numbers.
- **FR-034**: Identity MUST include repository binding, capability family, semantic rule
  identity, normalized path, symbol anchor, sink kind, and structural hash.
- **FR-035**: Exact fingerprint matches MUST update one finding lineage rather than create
  duplicate findings.
- **FR-036**: Cross-tool correlation MUST preserve every provenance record and MUST NOT
  collapse distinct capability families into one authoritative finding.
- **FR-037**: A finding MAY transition to fixed only after a complete later scan of the
  relevant profile no longer reports it.
- **FR-038**: Stale scans MUST NOT resolve findings or publish external results.

### Coverage, Failure, and Publication

- **FR-039**: Coverage MUST be `COMPLETE`, `PARTIAL`, `PENDING`, or `FAILED` with explicit
  missing/failed scanner and reason codes.
- **FR-040**: Required scanner failure, timeout, absence, invalid output, or quarantine MUST
  prevent complete coverage.
- **FR-041**: Partial, stale, failed, quarantined, or security-blocked scans MUST NOT publish
  PR/MR comments or blocking results.
- **FR-042**: Only retryable infrastructure failures MAY retry automatically, with a
  maximum of two total attempts.
- **FR-043**: Input-policy, capacity, scanner-defect, and security failures MUST NOT retry
  automatically under identical conditions.
- **FR-044**: Retry MUST reuse the canonical scan identity but create a new attempt and
  sandbox identity.
- **FR-045**: Every partial or failed scan MUST remain visible in the dashboard with reason,
  achieved coverage, and retry eligibility.

### Evidence and AI

- **FR-046**: Evidence MUST be built only from accepted normalized findings and bounded
  source fragments.
- **FR-047**: The default evidence maximum is 32 KiB total, five fragments, 8 KiB per
  fragment, and five context lines on either side.
- **FR-048**: Evidence MUST redact detected and platform-format secrets before persistence
  and again before AI inference.
- **FR-049**: Evidence MUST NOT contain a full file, repository archive, or fragments that
  can reconstruct a substantial repository portion.
- **FR-050**: Evidence retention MUST NOT exceed seven days; AI request payload retention
  MUST NOT exceed 24 hours.
- **FR-051**: AI eligibility requires complete non-stale coverage, an approved profile,
  reduced evidence, and tenant/repository opt-in.
- **FR-052**: AI output MUST remain advisory and MUST NOT create, suppress, waive, resolve,
  re-severity, or block a deterministic finding.

### Rule Governance

- **FR-053**: Rule bundles MUST move through `DRAFT -> VALIDATED -> CANARY -> ACTIVE` before
  general production use.
- **FR-054**: `SUSPENDED`, `ROLLED_BACK`, and `RETIRED` bundles MUST be unavailable for new
  scans.
- **FR-055**: Promotion MUST require signature/provenance verification, corpus results,
  compatibility evidence, security approval, and rollback reference.
- **FR-056**: Canary assignment MUST be deterministic and tenant-safe; one tenant MUST NOT
  receive mixed bundle versions for the same canonical scan.
- **FR-057**: Emergency kill switches MUST exist for scanner version, rule bundle, rule ID,
  tenant, repository, capability, and external publication.
- **FR-058**: Rule suppressions MUST use policy/waiver metadata and MUST NOT mutate the
  signed bundle.

### Audit and Observability

- **FR-059**: Planning, profile selection, token issuance, sandbox lifecycle, scanner start
  and completion, artifact acceptance/rejection, normalization, correlation, evidence
  access, rule promotion, policy decision, and cleanup MUST be auditable.
- **FR-060**: Audit metadata MUST exclude credential values, repository content, raw
  scanner payloads, and unredacted evidence.
- **FR-061**: Metrics MUST include queue depth, lane latency, scanner failure/timeout,
  normalization rejection, quarantine, coverage state, evidence generation/deletion,
  rule version, false-positive feedback, quota rejection, and sandbox destruction lag.
- **FR-062**: Every log, metric, trace, artifact, and audit event MUST carry tenant and scan
  attribution where applicable.

## Quantitative Defaults

- Fast lane: p95 <= 10 minutes; hard timeout 15 minutes.
- Deep lane: p95 <= 45 minutes; hard timeout 60 minutes.
- Fast selected input: <= 256 MiB, 25,000 files, 2 MiB per file, 5,000 findings.
- Deep input: <= 2 GiB, 250,000 files, 5 MiB per file, 25,000 findings.
- Fast artifact: <= 64 MiB and 25,000 records; Deep artifact: <= 256 MiB and
  250,000 records; bounded stdout/stderr: <= 1 MiB per scanner run.
- File descriptors: <= 1,024 Fast and <= 2,048 Deep.
- Maximum canonical path depth: 64.
- Evidence: <= 32 KiB, five fragments, 8 KiB per fragment, five context lines each side.
- Evidence/raw artifact retention: <= 7 days.
- Automatic retry: only infrastructure class; <= two total attempts.

These are maximum v1 platform defaults. Tenant policy may lower them. Raising them requires
security and capacity approval and may force `RESTRICTED` isolation.

## Success Criteria

- Scanner responsibility is unambiguous and test-enforced.
- Every implementation input and output is represented by a shared contract without source
  content or credential-value fields.
- Rule promotion and production readiness have measurable fail-closed gates.
- Stable identity behavior is independent of line, branch, and commit changes.
- Coverage and failure matrices cannot authorize external publication when incomplete.
- The legacy mock-analysis path has an explicit retirement plan and cannot be considered the
  production SAST runtime.
- A language after Java cannot claim SAST completeness until the immutable profile,
  normalizer/identity semantics, corpus, supply chain, canary, and rollback contract in
  `language-profile-extension.md` passes.
