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

### Explicitly Reclassified Adjacent Bootstrap: Issue #276

Issue #276 is approved as a narrower, local development bootstrap alongside this active
milestone. The reclassification permits only a self-hosted Neo4j dev/demo stack, bounded
ingestion of the public MITRE CWE catalog, deterministic CWE hierarchy and mitigation
records, and the tests and CI checks required to validate that bootstrap. It does not
replace `006-production-sast-runtime-design`, advance or satisfy T040, or make Neo4j part of
the production runtime.

The bootstrap MUST NOT receive Scan Plane, AI Plane, policy, finding, evidence,
publication, SCM, or tenant authority. It MUST NOT expose a production route or GraphRAG
consumer, process repository content or scanner artifacts, store provider credentials, or
become a live deployment dependency. Any OWASP mapping, scanner-rule mapping, vector
index, GraphRAG retrieval, or production integration requires a later explicit feature
specification and threat review.

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
- **FR-031b**: Syft CycloneDX ingestion MUST accept only the pinned directory-producer subset,
  rebind the exact accepted artifact and immutable plan before and after scalar streaming,
  and emit a deterministic transient inventory. Raw BOM references MUST be retained only as
  digests; raw properties, source locations, license text, prose, external references, and
  artifact bytes MUST NOT enter the inventory. SBOM inventory MUST NOT create findings,
  evaluate vulnerabilities, influence policy, enter AI payloads, or become durably
  persisted before a later explicit data-handling gate.
- **FR-031c**: `sast-secret-redaction-v1` MUST revalidate the exact canonical T032/T033
  batch digest, accepted T031 disposition digest, validation binding, and active retention
  window before and after redaction. Display-only title, description, and optional symbol
  values MUST replace detected platform values, private keys, credentials, supported
  provider tokens, secret assignments, JWTs, and high-entropy tokens with one fixed marker.
  A detected value in a batch binding or normalized path, semantic rule identity, symbol
  anchor, sink kind, scanner version/match identity, rule provenance identifier/revision,
  dependency vulnerability/package/type/installed/fixed-version identity, secret category,
  or IaC check type/AVD identity MUST reject the complete batch rather than create a
  secret-derived fingerprint input. The gate MUST reject more than 8,000,000 inspected
  UTF-16 code units and yield between bounded chunks of at most 64 candidates or 32,768
  inspected code units. Successful output MUST be a fresh, deterministic, still non-durable
  candidate batch with explicit redaction decisions whose canonical digests are recomputed
  at every receiving trust boundary.
  Matched values, value lengths, matched-value digests, raw candidates, and the
  pre-redaction candidate-batch digest MUST NOT enter output, rejection, log, audit,
  dashboard, evidence, policy, or AI payloads.
- **FR-032**: Unknown enum values, invalid coordinates, overlong strings, unsafe encodings,
  and excessive nesting MUST fail closed.

### Identity, Correlation, and Lifecycle

- **FR-033**: Stable finding identity MUST exclude branch, commit SHA, and line numbers.
- **FR-034**: Identity MUST include repository binding, capability family, semantic rule
  identity, normalized path, symbol anchor, sink kind, and structural hash.
- **FR-034a**: `sast-finding-identity-v1` MUST recompute the complete canonical T035 handoff,
  normalize every fingerprint component to NFC, encode the seven ordered fields with UTF-8
  byte-length prefixes, and produce the lowercase SHA-256 `sast-fingerprint-v1` digest.
  `UNKNOWN` locations MUST contribute the explicit empty path component; location reason,
  coordinates, scanner match identity, commit, display text, and severity MUST NOT enter the
  fingerprint. Repeated byte-identical preimages MAY remain separate observations, while one
  digest associated with different preimages MUST reject the complete batch. The gate MUST
  reject more than 25,000 findings, clock rollback, and expiry reached before or during the
  pass, and MUST yield between 64-finding chunks. Success MUST be a fresh canonical,
  persistence-eligible handoff that preserves sanitized provenance but grants no occurrence,
  lifecycle, correlation, coverage, evidence, policy, publication, or AI authority.
  Rejection and audit projections MUST NOT expose a source candidate, fingerprint preimage,
  rejected T035 batch digest, artifact digest, or secret value.
- **FR-035**: Exact fingerprint matches MUST update one finding lineage rather than create
  duplicate findings.
- **FR-035a**: `sast-finding-lineage-v1` MUST independently revalidate the complete T036
  handoff and every durable tenant, repository, scan, scanner-run, fixed-commit, target,
  profile, artifact, schema, normalizer, rule, database, and preflight binding before one
  serializable write. One repository/capability/fingerprint-version/fingerprint tuple MUST
  identify one lineage, while every ordered producer observation, including byte-identical
  repeated fingerprints, MUST create its own immutable occurrence and provenance row.
  Replaying one source batch is idempotent only when the complete observation-batch record
  and its entire ordered occurrence ledger are byte-for-byte canonical matches; missing,
  extra, changed, malformed, or cross-scope rows MUST reject.
- **FR-035b**: Path continuity MUST be granted only by a verified, canonical, fixed-commit,
  fixed-target, one-to-one `sast-finding-rename-attestation-v1`. The predecessor alias MUST
  already resolve to exactly one lineage and both old and new aliases MUST remain durable.
  Missing, ambiguous, chained, cyclic, fuzzy, coordinate-, title-, severity-, scanner-ID-,
  or AI-derived rename claims MUST reject or create no continuity authority.
- **FR-036**: Cross-tool correlation MUST preserve every provenance record and MUST NOT
  collapse distinct capability families into one authoritative finding.
- **FR-036a**: `sast-finding-correlation-v1` MUST revalidate every supplied T037 result and
  require exact equality with all durable current-attempt observation batches and ordered
  occurrences, including zero-finding batches, before one serializable write. Replay identity
  MUST use canonical durable source bindings and MUST NOT depend on T037's mutable replay flag.
- **FR-036b**: Correlation MUST use only exact fingerprint, canonical dependency
  ecosystem/package/installed-version/CVE, cross-capability CVE, or same-file CWE rules.
  Scanner responsibility plus required-versus-optional profile capability MUST distinguish
  authoritative from supporting evidence. Fuzzy, path-only, title, severity, scanner-local,
  and AI similarity MUST grant no correlation authority.
- **FR-036c**: Every correlation edge MUST keep both immutable occurrence and provenance
  references. No edge may merge findings or inherit severity, lifecycle, coverage, evidence,
  policy, publication, or AI authority; `POSSIBLE_OVERLAP` MUST remain display-only.
- **FR-037**: A finding MAY transition to fixed only after a complete later scan of the
  relevant profile no longer reports it.
- **FR-037a**: Lifecycle state MUST be unique per lineage and canonical tenant/repository/
  target context, separate from policy and triage status, and backed by append-only
  `CREATED`, `RENAMED`, `FIXED`, and `REOPENED` events. T037 MUST NOT calculate coverage.
  It MAY apply `FIXED` or `REOPENED` only after an injected T039-compatible gate verifies a
  strictly newer `sast-finding-lifecycle-coverage-v1` decision with `COMPLETE`,
  `stale=false`, `comparable=true`, and exact equality to every durable T037 observation
  batch for the current scan, including zero-finding batches. Missing, partial, pending,
  failed, stale, incomparable, out-of-order, or scope-mismatched decisions MUST leave
  lifecycle state unchanged.
- **FR-038**: Stale scans MUST NOT resolve findings or publish external results.

### Coverage, Failure, and Publication

- **FR-039**: Coverage MUST be `COMPLETE`, `PARTIAL`, `PENDING`, or `FAILED` with explicit
  missing/failed scanner and reason codes.
- **FR-039a**: `sast-scan-coverage-v1` MUST reload the immutable plan, current attempt,
  complete T038 source set, every selected scanner run, artifact envelope, and final
  disposition. Required/optional scanners and capabilities MUST be derived from the approved
  platform profile and scanner responsibility matrix; the caller MUST NOT supply coverage,
  stale, publication, lifecycle, or AI authority.
- **FR-039b**: One bounded serializable transaction MUST persist exactly one attempt-scoped
  terminal coverage decision, one canonical record for each platform scanner (including
  absent optional scanners), and one `sast-external-publication-v1` decision. A `PENDING`
  evaluation MUST remain explicitly non-durable and be reevaluated after scanner state
  advances. Byte-identical terminal replay,
  including a serialization race, MAY return the existing ledger without duplicate rows;
  changed, missing, extra, reordered, cross-scope, or late durable state MUST reject
  atomically.
- **FR-039c**: Until T040 proves the latest target, freshness, and comparability, every T039
  publication decision MUST set external comment, blocking status, AI advisory, and lifecycle
  mutation authority to false even when scanner/capability coverage is `COMPLETE`.
- **FR-039d**: T040 MUST independently reload the exact terminal T039 decision and bind a
  provider-authoritative, target-scoped, monotonic head observation. Freshness MUST be true
  only when that head equals the fixed scanned commit. Comparability MUST require the same
  tenant/repository/target, supported profile family, exact required capability set,
  `sast-fingerprint-v1`, and lifecycle-eligibility scope as the previous completed complete
  scan. Missing or invalid authority MUST fail closed.
- **FR-039e**: T040 MAY expose comment/block eligibility and lifecycle verification only for
  complete, verified, fresh, comparable state. It MUST keep AI advisory and publication
  execution false and MUST NOT expose an SCM-write route.
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
- **FR-044a**: Attempt two MUST have a durable canonical retry decision that re-verifies the
  immediately preceding attempt-one infrastructure failure, retry-eligible flag, completion
  time, final audit event, current scanner-set availability, and kill-switch state. Attempt
  three, cleanup/input/capacity/scanner/security failure, unavailable safety authority, or
  reused attempt/sandbox/workload identity MUST deny.
- **FR-045**: Every partial or failed scan MUST remain visible in the dashboard with reason,
  achieved coverage, and retry eligibility.

### Evidence and AI

- **FR-046**: Evidence MUST be built only from accepted normalized findings and bounded
  source fragments.
- **FR-046a**: T041 MUST reload the exact T040 complete, verified, fresh, comparable decision
  and the T037 occurrence, observation, normalized-finding, lineage, and fingerprint rows.
  Caller-provided finding, path, coordinate, coverage, freshness, or evidence authority MUST
  NOT substitute for durable rebinding.
- **FR-046b**: A source fragment MUST come from an internal authority that defaults to
  unavailable, remain memory-only before redaction, preserve its attested line count, and be
  redacted for known-format and platform secret values before a pack or audit projection is
  persisted. Raw source and secret values MUST NOT be stored.
- **FR-046c**: Reconstruction evaluation MUST reject a full file, more than two fragments per
  file, overlapping or adjacent intervals, or combined fragment coverage of at least 25% of a
  source file. Rejection MUST create no pack and MUST preserve only a canonical immutable
  decision/audit projection.
- **FR-046d**: T041 accepted packs MUST keep dashboard, AI, policy, publication, and lifecycle
  authority false. Classification/deletion references MUST remain absent until T042, and T041
  MUST expose no user route, AI payload, or SCM writer.
- **FR-047**: The default evidence maximum is 32 KiB total, five fragments, 8 KiB per
  fragment, and five context lines on either side.
- **FR-048**: Evidence MUST redact detected and platform-format secrets before persistence
  and again before AI inference.
- **FR-048a**: T042 MUST classify dashboard and AI access independently from a complete
  durable rebind of the T041 build decision, pack, fragments, scope, T040 freshness, T039
  coverage, and T038/T037 source. It MUST rerun known-format, registered platform-value, and
  entropy redaction at access time and MUST fail closed on an unavailable registry, unsafe
  path/identifier, digest mismatch, clock rollback, expiry, or deletion claim.
- **FR-048b**: T042 MUST NOT mutate T041 `dashboardSafe`, `aiSafe`, classification reference,
  or deletion reference fields. Each purpose MUST have a separate immutable canonical
  `sast-evidence-access-decision-v1` ledger with explicit zero policy, publication, lifecycle,
  SCM, provider-call, retrieval, and tool authority.
- **FR-048c**: Dashboard reads MUST require authenticated tenant and repository binding scope
  and return only a second-pass-redacted dashboard projection. AI classification MUST return
  only a reduced evidence reference with an eligibility window no longer than 24 hours; T042
  MUST create no AI provider request or request payload.
- **FR-048d**: Every accepted T041 pack MUST receive an immutable deterministic deletion
  schedule in the same serializable transaction. A due deletion MUST use a leased, token-fenced
  claim and a deletion provider that defaults unavailable. Pack/fragment content MUST be
  deleted only after a bounded provider receipt is validated and an immutable canonical proof
  is committed; the T041 build decision and bounded proof/audit state MUST remain retained.
  The deletion task MUST run at startup, target the earliest durable due timestamp, and
  immediately continue saturated bounded batches so polling delay or a per-tick cap cannot
  extend retention.
- **FR-048e**: Concurrent access, schedule, claim, receipt, and proof operations MUST permit
  exact replay only. Late readers, changed receipts, stale lease owners, deletion races, and
  reference-time rollback MUST fail closed without returning or restoring content. An exact
  deterministic deletion retry MAY reuse its original receipt when completion is at or after
  `deleteAfter` and no later than the current observation and lease. A context-drifted due row
  MUST be durably moved behind other work and quarantined after three failed validations so it
  cannot starve the deletion queue.
- **FR-049**: Evidence MUST NOT contain a full file, repository archive, or fragments that
  can reconstruct a substantial repository portion.
- **FR-050**: Evidence retention MUST NOT exceed seven days; AI request payload retention
  MUST NOT exceed 24 hours.
- **FR-051**: AI eligibility requires complete non-stale coverage, an approved profile,
  reduced evidence, and tenant/repository opt-in.
- **FR-051a**: T043 MUST accept only tenant, repository binding, evidence-pack, and model-version
  intent. It MUST independently obtain T042 `AI_ADVISORY` access before and after reloading the
  exact T037 occurrence, source finding, and normalized-finding row. Caller-provided findings,
  evidence, prompts, paths, digests, expiry, or authority MUST be rejected before access.
- **FR-051b**: The canonical `sast-ai-advisory-handoff-v1` MUST contain only the rebound
  normalized finding and the T042 opaque reduced-evidence reference. Its immutable database
  ledger MUST store only scope references, digests, expiry, model version, and fixed audit/
  authority booleans; it MUST NOT persist the handoff/request body, raw source, secret values,
  access-time fragments, or prompt text.
- **FR-051c**: The AI runtime request MUST carry no snippets or retrievable content and MUST set
  retrieval, tools, policy, publication, lifecycle mutation, and SCM write authority false.
  Tenant/scan/finding/request correlation and payload expiry MUST be validated, and an exact
  retry MUST derive the same request, handoff, and advisory identities. Drift, expiry, clock
  rollback, unknown fields, or authority widening MUST fail closed.
- **FR-052**: AI output MUST remain advisory and MUST NOT create, suppress, waive, resolve,
  re-severity, or block a deterministic finding.
- **FR-052a**: T044 authority-proof intent MUST accept exactly `tenantId` and `advisoryId`, and
  the body tenant MUST match a tenant-bound authenticated internal credential. A serializable
  transaction MUST first lock the advisory context, then rebind the T043 advisory/handoff to its tenant, repository,
  scan, attempt, occurrence, normalized finding, fingerprint, request digest, and handoff
  digest. It MUST lock shared scan, lifecycle-context, and finding authority fences before
  capturing one bounded canonical authoritative snapshot and projecting that snapshot into the
  proof's before/after fields. All covered authoritative writers MUST advance the same fences;
  bulk normalized-finding and lifecycle writes MUST deduplicate affected scope keys per statement.
  The scan finding set, target status/severity, T037 lifecycle state/revision, finding policy
  decisions, finding-scoped waivers, and suppressions MUST come from the same durable tables and
  have identical state digests. Missing fences and concurrent or replay drift MUST fail closed.
- **FR-052b**: `sast-ai-advisory-authority-proof-v1` MUST be immutable and MUST store only
  scope references, bounded counts, SHA-256 digests, proof time, and fixed zero-authority/audit
  bits. Advisory output, rationale, prompt, source, evidence, secrets, policy payloads, and
  caller-provided authority state MUST NOT be stored. Exact retry MUST reuse one proof; changed,
  cross-tenant, over-limit, or incomplete state MUST fail closed.
- **FR-052c**: Policy evaluation MAY make AI advisory metadata visible only from an exact,
  durable advisory/proof reference with `advisoryOnly=true`. AI fields MUST NOT contribute to
  enforcement action, reason codes, ticketing, blocking, severity, finding status, waiver,
  suppression, or lifecycle decisions. Waiver and suppression APIs MUST reject unknown,
  advisory, proof, and authority fields through exact request-shape validation.

### Rule Governance

- **FR-053**: Rule bundles MUST move through `DRAFT -> VALIDATED -> CANARY -> ACTIVE` before
  general production use.
- **FR-054**: `SUSPENDED`, `ROLLED_BACK`, and `RETIRED` bundles MUST be unavailable for new
  scans.
- **FR-055**: Promotion MUST require signature/provenance verification, corpus results,
  compatibility evidence, security approval, and rollback reference.
- **FR-055a**: Promotion evidence MUST bind one exact T045 candidate and distinct baseline,
  profile supported by both manifests, candidate author, tested rollback target, digest-bound
  environment/corpora, trusted measurement time, denominator-bound sufficient sample counts,
  relative and absolute p95 limits, every other quantitative threshold, and zero security events.
  Automated evidence MUST NOT grant approval, and invalid evidence MUST create no row.
- **FR-055b**: Lifecycle approvals MUST be immutable human decisions bound to the exact evidence
  and candidate. Candidate self-approval, duplicate roles/approvers, and approvals outside the
  evidence-to-transition interval MUST fail closed. Every edge MUST have Security Engineering;
  `ACTIVE` and `RETIRED` MUST also have Scan Platform or Security Operations approval.
- **FR-055c**: Lifecycle transitions MUST be append-only, strictly sequenced, and bound to the
  immediately previous digest. Only the documented state graph is legal. `CANARY -> ACTIVE`,
  suspension, and rollback MUST require matching digest-bound external-authority receipts; their
  default providers MUST be unavailable. Planning MUST admit only the latest `CANARY` or `ACTIVE`
  transition through one immutable selection receipt before tenant policy and queue reservation.
  Queue reservation MUST lock and revalidate a database-maintained latest-transition projection
  and the exact receipt, making a concurrent lifecycle change serializable and fail closed. The
  immutable plan MUST retain the receipt. T047 canonical scan-key v3 MUST commit only the stable
  lifecycle transition/evidence/approval projection and MUST exclude its evaluation-time-derived
  receipt identity; T048 MUST preserve that projection in v4.
- **FR-056**: Canary assignment MUST be deterministic and tenant-safe; one tenant MUST NOT
  receive mixed bundle versions for the same canonical scan.
- **FR-056a**: One immutable rollout MUST bind one candidate manifest/profile pair to the exact
  latest `CANARY` candidate, distinct latest `ACTIVE` baseline, T045 manifests/bundles, T047
  evidence/transition, profile, HMAC-key reference/version, eligibility policy, observation
  source, and six non-skippable steps. A paused or completed candidate/profile MUST NOT be
  re-enrolled; recovery MUST use a new signed candidate, evidence, approvals, and rollout.
- **FR-056b**: Eligibility MUST be platform-managed with explicit contractual/residency
  exclusions. Membership MUST use HMAC-SHA-256 over length-framed tenant, repository binding,
  profile, and rollout identity, persist no key material/content/finding/customer attribute, and
  require the key reference digest to equal the decoded key's SHA-256 fingerprint, and derive the
  same 0-9,999 bucket in application and PostgreSQL. Planning MUST run compatibility,
  lifecycle, canary, then tenant-policy gates. A supplied candidate that resolves outside the
  cohort MUST be rejected, not rewritten after verification. Trusted orchestration MUST submit a
  separately compatibility/lifecycle-verified exact `ACTIVE` baseline set for non-cohort
  production; exclusion MUST NOT select the candidate.
- **FR-056c**: Canonical scan-key v4 MUST preserve v3 and add only stable rollout,
  membership, bucket, and candidate-assigned identity. Assignment receipt, rollout step, and
  step-head identity MUST remain in the immutable plan but MUST NOT enter the key. Queue
  reservation MUST lock/revalidate lifecycle heads, canary head, and exact assignment receipt.
  Deployment MUST drain or cancel non-terminal v3 plans/reservations before v4 cutover.
- **FR-056d**: Canary observations MUST be append-only and content-free and MUST rebind the exact
  candidate/baseline plan, assignment where applicable, terminal attempt interval, profile/lane/
  size bucket, durable coverage/publication authorities, rollout-fixed observation source, and
  telemetry source. Collection callers MUST NOT provide cohort role or repository-size bucket;
  the trusted source MUST derive both from durable authority. A decision MUST use trusted service
  time as its cutoff, automatically bind
  every committed observation in its exact closed window, and reject caller-selected cutoff or
  observation IDs, omissions, and extra bindings.
  Decisions MUST recompute all aggregates, including the completed-scan-normalized candidate/
  baseline Critical/High rate. The first four steps MUST require
  200 scans per arm and 24 hours; 25% and 100% MUST require 1,000 per arm and 48 hours. Missing
  samples/time MUST be `PENDING`; telemetry, coverage, or size incompleteness, any quantitative
  breach, or any zero-tolerance event MUST be terminal `PAUSED`. Only six ordered passes MAY issue
  the exact
  `CANARY_OBSERVATION` receipt for `CANARY -> ACTIVE`; the default production observation source
  MUST remain unavailable until a qualified adapter is installed.
- **FR-057**: Emergency kill switches MUST exist for global SAST runtime, scanner version, rule
  bundle digest, semantic rule ID, exact signed profile, tenant, repository binding, capability,
  and global/tenant/repository external publication.
- **FR-057a**: Every activation and deactivation MUST be a platform-managed, signed, immutable,
  digest-bound decision in one monotonic predecessor chain per canonical selector. It MUST bind
  actor role, reason, incident, effective/review/expiry times, rollback-target reference,
  signature/provenance references, and audit reference. Exact trusted signature/provenance
  verification MUST commit with the decision. A missing/invalid verification, fork, future
  activation, expired active decision, invalid trusted clock, or unavailable authority MUST fail
  closed and MUST NOT be interpreted as clear.
- **FR-057b**: Planning MUST evaluate every applicable selector after lifecycle/canary and before
  tenant policy and retain an immutable successful receipt in the plan without changing
  `sast-canonical-scan-key-v4`. Queue admission MUST lock the complete selector-head set and
  reconstruct and revalidate the plan-bound context digest and exact selector identity set in
  both application and database paths. A missing, substituted, extra, or drifted selector MUST
  reject. Durable inactive placeholders and trigger-owned heads MUST prevent a first-activation/
  absent-row race. The normalized selector snapshot MUST reject more than 50,020 bindings and
  MUST use set-based canonical locking and comparison rather than a selector-sized SQL loop.
- **FR-057c**: Fresh purpose-bound evaluation MUST occur before scanner execution, artifact
  acceptance, retry admission, effective-coverage use, external publication, and AI advisory. A
  scanner MUST create its durable run before evaluation but MUST perform no provider repository
  read or scanner execution after an active/unavailable result. Active affected runs MUST become
  `KILLED`, artifacts MUST be quarantined, retries and AI/publication MUST be denied, and cleanup
  MUST remain mandatory. A recovered accepted artifact intent MUST be re-evaluated before storage apply;
  denial MUST persist a replacement quarantine intent. AI MUST re-evaluate after inference and
  immediately before advisory persistence. A clear artifact kill-switch evaluation MUST delegate to, and MUST NOT
  replace, the independent fail-closed Data/Security Plane acceptance authority.
- **FR-057d**: Kill-switch evaluation MUST NOT rewrite historical plans, findings, or T039 factual
  coverage. It MUST expose a separate current effective-coverage result: semantic-rule or
  capability-only activation is `PARTIAL`, other affected runtime scopes are `FAILED`, and an
  external-publication-only activation is `UNCHANGED` while publication and AI remain denied.
- **FR-057e**: An active applicable global, bundle, scanner-version, semantic-rule, or exact
  signed-profile decision MAY authorize only the exact latest
  `CANARY | ACTIVE -> SUSPENDED` lifecycle edge through one immutable digest-bound
  `EMERGENCY_SUSPENSION` receipt. It MUST NOT authorize rollback, select a replacement bundle, or
  mutate historical state.
- **FR-057f**: Automatic canary-suspension input MUST accept only an exact T048 step-decision
  ID/digest and MUST derive the current `PAUSED` rollout, lifecycle target, signed profile, hard-
  failure reason set, and zero-tolerance status from locked durable authority. Callers MUST NOT
  supply or override those fields. The derived content-free signal MUST grant no decision,
  lifecycle, publication, AI, or rollback authority by itself.
- **FR-057g**: A rollback request MUST identify only the exact latest suspended candidate and
  bounded incident/actor/reason/audit/signature/provenance metadata; it MUST NOT accept a
  baseline, target, or scanner set. The service MUST derive the distinct last-known-good baseline
  solely from the candidate's original T047 promotion evidence, require the exact T049 suspension
  provenance, reverify both T045 supply-chain attestations and common scanner/profile
  compatibility, and require the candidate latest head to be `SUSPENDED` and the derived baseline
  latest head to be `ACTIVE`. Caller, customer, AI, and scanner output MUST have zero target or
  approval authority.
- **FR-057h**: Rollback MUST require an exact signed command whose production signature provider
  defaults unavailable and exactly two fresh independent human approvals within 15 minutes:
  Security Engineering plus Scan Platform or Security Operations, excluding the command actor.
  Command, verification, approval, receipt, and receipt-approval rows MUST be normalized,
  content-free, append-only, and exact-replay only. Candidate and baseline heads MUST be locked in
  canonical order and revalidated at receipt issuance and lifecycle commit. The receipt MUST
  authorize only one candidate `SUSPENDED -> ROLLED_BACK` append and MUST grant no baseline,
  historical, scanner-set, finding, policy, publication, AI, or SCM mutation authority. The
  baseline and every historical manifest, transition, plan, finding, coverage, evidence, and
  audit row MUST remain unchanged; new plans MAY use the baseline only after trusted scanner-set
  selection and every existing planning/queue gate passes.
- **FR-057i**: Golden qualification inputs MUST use exact versioned case and snapshot contracts and
  MUST be platform-owned, immutable, license/provenance/revision bound, and reproducible from a
  reviewed deterministic generator. Every supported profile MUST contain at least 200 positive and
  200 paired negative cases; every rule MUST meet the `quality-gates.md` case floor, every
  Critical/High rule MUST contain at least 20 positive and 20 negative cases, and every released
  Critical/High positive MUST be authenticated by a separately checked-in immutable prior-release
  manifest that binds its exact case ID/digest/key, case/rule revision, semantic rule ID, and
  severity. The reviewed manifest digest MUST be pinned outside the manifest, overwrite MUST be
  refused, a missing/changed historical case MUST fail closed, and a new current positive MUST NOT
  enter the prior denominator automatically. Patched, sanitizer, safe-API, comment/string, and
  generated/vendor negative classes MUST all be non-empty and MUST be assigned only where their
  source behavior is semantically applicable; generated/vendor cases MUST retain the unsafe
  construct under the excluded path rather than masquerade as comment cases. Each case MUST bind
  exact source bytes/digest, line range, anchor, and a unique root-confined materialization path.
  Unknown fields, count/digest/range drift, duplicate paths, path escape, symlink/junction traversal,
  invalid UTF-8/NFC/LF, oversized or extra source files, mutable metadata, customer content,
  executable configuration, dependency installation, builds, dynamic execution, and network
  requirements MUST fail closed. T051 corpus validity MUST grant no finding, policy, promotion, or
  production-readiness authority and MUST NOT substitute for T052-T056 execution evidence.
- **FR-057j**: Multi-class qualification inputs MUST use exact versioned fixture, case, and
  snapshot contracts for schema/parser, malicious-repository, fingerprint/correlation,
  evidence/privacy, and performance classes. Every required `quality-gates.md` scenario MUST occur
  exactly once in the reviewed v1 denominator. Hostile paths/bytes, special files, resource
  pressure, identity sequences, privacy sentinels, and performance shapes MUST be encoded only as
  bounded platform-owned declarative recipes with allowlisted actions and typed parameters/byte
  segments; command, argv, environment, executable configuration, customer content, package
  installation, build, dynamic execution, scanner execution, host mutation, and network authority
  MUST be structurally absent or false. The corpus MUST contain no live symlink, FIFO, device, or
  expanded bomb. All cases MUST bind their exact fixture ID/digest/bytes, expected control outcome,
  responsible T053/T054 evidence stage, owner/license/provenance/revision, and zero prohibited
  effects. Performance MUST provide small/medium/exact-large-limit buckets for all three v1
  profiles, bind one immutable hardware-class reference/digest, and require at least 30 measured
  runs per bucket after warm-up. Every profile-relative boundary MUST bind the selected profile's
  exact limit plus one through data-driven materialization metadata; parser-wide depth and string
  boundaries MUST bind the shared validator's exact limit plus one. Generation and loading MUST
  reject missing/extra scenarios,
  unknown keys/actions, outcome/stage/profile/hardware drift, path or case-fold collision,
  invalid/noncanonical base64/UTF-8/NFC/LF, BOM, NUL, oversize, extra/empty directories, links,
  filesystem identity changes, and snapshot/fixture/count/digest tampering. T052 validation MUST
  materialize or execute nothing and MUST grant no finding, correlation, lifecycle, evidence,
  policy, publication, promotion, or production-readiness authority; T053 is the first isolated
  materialization stage.
  Profile-relative limit-plus-one recipes MUST bind the exact value for every supported immutable
  profile and select it only from the case profile. Cycles MUST declare every directed link.
  Binary and malformed-encoding cases MUST carry the intended raw octets, and fingerprint
  invariance cases MUST contain complete identity vectors that differ only in the excluded field
  under test; a runner MUST NOT infer any behavior from the scenario label.
- **FR-057k**: T053 MUST derive exactly 123 canonical cells from the 41 T052 schema/parser and
  malicious-repository cases across the three signed profiles. Every cell MUST bind the exact
  source, fixture, profile, scanner, materialization, expected outcome, provisioning contract, and
  closed materialization policy and MUST require one new non-reused production-equivalent microVM.
  A live dependency set MUST bind every scanner/image/wrapper/rule/database/schema/normalizer,
  kernel/rootfs, materializer/runner/harness, provider-policy, and trust-policy artifact by digest,
  signature, and provenance within an at-most-24-hour window. Execution MUST require detached
  Security Engineering and Scan Platform approvals, and both signatures MUST strictly predate the
  earliest receipt execution start. Each receipt MUST have unique attempt,
  sandbox, workload, provider-attestation, runtime-attestation, and receipt identity; exact
  materialization and outcome; five phase-bound egress observations; zero prohibited effects; and
  digest-bound proof of credential wipe, process-tree termination, writable-volume destruction,
  result-ingress closure, microVM termination, and final audit within 60 seconds. The provider and
  qualification runtime MUST sign the receipt digest using trust keys whose canonical Ed25519 SPKI
  identities and raw trust-bundle digest rebind the dependency set. Missing valid receipts MUST be
  `PENDING_PROVIDER_EXECUTION`; any invalid, reused, drifted, stale, violating, or incomplete
  receipt MUST be `FAILED`; only all 123 valid receipts and both approvals MAY be `PASSED` and grant
  T054 entry. The verifier MUST derive evaluation time from its service-owned trusted UTC clock and
  MUST reject caller-selected evaluation time. No T053 state MAY grant finding, policy, publication, deployment, or production-
  readiness authority. Repository CI MUST validate the handoff and verifier but MUST NOT execute a
  scanner/microVM or fabricate live evidence.
- **FR-057l**: T054 MUST refuse plan creation unless a structurally valid T053 `PASSED` result,
  `t054EntryAuthorized=true`, and a Qualification Authority Ed25519 entry attestation bind the
  exact T053 and T054 manifests. The exact T053 dependency set MUST be supplied, its digest MUST
  equal the passing result, and its provider ID and provider-adapter ref MUST equal T054. Every
  T054 dependency artifact MUST have its complete digest-bound signature envelope and provenance
  statement represented exactly once in a `SUPPLY_CHAIN_AUTHORITY`-signed verification set. Before
  plan construction, the verifier MUST recompute both envelope digests, verify both per-artifact
  Ed25519 signatures, and bind the provenance subject, source, builder, and materials to the exact
  artifact. The trust bundle MUST match an independently configured
  `SAST_T054_TRUST_POLICY_DIGEST`; submitted evidence MUST NOT choose its own trust root. The
  repository manifest MUST derive exactly 3,462 immutable cells:
  1,880 candidate T051 case-profile cells, 940 baseline T051 negative case-profile cells, 102
  candidate T052 fingerprint/evidence-privacy cells, and 540 candidate/baseline performance cells
  covering nine fixed profile-size buckets with 30 post-warm-up runs per arm. The dependency set
  MUST bind distinct candidate/baseline scanner sets, all scanner and pipeline artifacts, one exact
  hardware class, provider/telemetry/trust policies, signatures, and provenance. Each cell MUST
  bind every queue-to-cleanup phase, a fresh microVM per attempt, at most one infrastructure retry,
  unique attempt/sandbox/workload and provider/runtime/telemetry attestations, resource observations,
  all cleanup controls within 60 seconds, and provider/runtime/telemetry Ed25519 signatures.
  Retries MUST remain in the reliability denominator. The verifier MUST accept no caller aggregate
  or evaluation time and MUST recompute exact conformance, >=95% recall, >=90% Critical/High
  precision, 100% prior recall, <=2-point false-positive increase, <=2% scanner failure, <=20% p95
  regression, 10/45-minute absolute p95, fingerprint/privacy/capacity pass rates, resource limits,
  and all eight zero-tolerance counters from the complete signed receipt set. Missing T053 evidence
  MUST be `BLOCKED_T053_QUALIFICATION`; a valid strict T054 subset MUST be
  `PENDING_PROVIDER_EXECUTION`; any drift or breached gate MUST be `FAILED`; only all 3,462 valid
  cells MAY be `PASSED` and set `t055EntryAuthorized=true`. No T054 state grants finding, policy,
  publication, deployment, Kubernetes, or production-readiness authority, and repository CI MUST
  never fabricate external execution evidence.
- **FR-057m**: T055 MUST refuse plan creation unless a structurally valid T054 `PASSED` result with
  `t055EntryAuthorized=true`, the exact T054 manifest, dependency set, complete artifact-
  verification set and execution plan, and a Qualification Authority Ed25519 entry attestation are
  mutually bound. T054 and T055 MUST use the same provider ID and provider-adapter ref. The T055
  trust bundle MUST match independently configured `SAST_T055_TRUST_POLICY_DIGEST`; submitted
  evidence MUST NOT select its own trust root. Before accepting drill evidence, the verifier MUST
  reload every one of the 36 T054 artifacts and its complete signature and provenance envelopes,
  recompute both envelope digests, rebind provenance subject/source/builder/materials, and verify
  every `SUPPLY_CHAIN_AUTHORITY` Ed25519 signature. The immutable denominator MUST be exactly 169
  cells: 144 read-only mount/digest/signature/provenance drills, one unlisted-component rejection,
  six internal-mirror/stale/network-enrichment vulnerability-database drills, three canonical/
  incompatible/malformed-or-oversized result-schema drills, and 15 ordered rollback phase drills
  across three profiles. Exactly 115 cells MUST reject before artifact invocation, exactly 39 MAY
  invoke one allowlisted artifact, and no cell MAY accept customer content, execute customer code,
  install packages, build a repository, run a dynamic test, use public egress, or mutate production.
  For every profile, Qualification Authority and Supply Chain Authority signatures MUST authenticate
  the exact durable rollback-ledger head digest, sequence, reference, provider, and candidate/
  baseline release sets before plan approval. Detached Security Engineering and Scan Platform
  approvals MUST bind those head attestations and strictly predate the earliest submitted receipt
  or attempt. Every receipt MUST use globally unique identities and carry Supply Chain Authority,
  MicroVM Provider, and Qualification Runtime Ed25519 signatures. Rollback MUST bind exact candidate
  and baseline release-set digests, suspend and fence the candidate, prove in-flight abort and
  cleanup, derive and reverify the last-known-good baseline, record zero candidate invocations after
  the fence, and activate `STANDBY -> ACTIVE` only through an append-only audit ledger entry that
  references the exact authenticated head and uses exactly `head.sequence + 1`.
  Missing T054 evidence MUST be `BLOCKED_T054_QUALIFICATION`; a valid strict subset MUST be
  `PENDING_DRILL_EXECUTION`; malformed evidence or any zero-tolerance breach MUST be `FAILED`; only
  all 169 valid cells MAY be `PASSED` and set `t056EntryAuthorized=true`. No T055 state grants
  finding, policy, publication, deployment, Kubernetes, or production-readiness authority, and
  repository CI MUST never fabricate external execution or rollback evidence.
- **FR-058**: Rule suppressions MUST use policy/waiver metadata and MUST NOT mutate the
  signed bundle.
- **FR-058a**: Semantic rule identity MUST be an immutable digest-bound core. Changing the
  vulnerability predicate, capability/category, language/format scope, source/sink model,
  default severity/confidence, finding identity, or tenant-control class MUST NOT reuse the
  same semantic rule ID.
- **FR-058b**: Reusable non-executable rule metadata MUST be separate from its exact signed-
  manifest binding. Tenant policy MUST accept only approved canonical selectors, literal
  normalized path prefixes, non-weakening severity floors, bounded existing waiver/
  suppression references, and repository overrides that only narrow the tenant policy.
- **FR-058c**: Planning MUST resolve the exact selected manifest metadata and tenant policy
  into one immutable content-free receipt before canonical-key construction and queue
  reservation. Missing, extra, mismatched, expired, unknown, cross-scope, mandatory-disable,
  persistence-unavailable, or trusted-clock-invalid state MUST fail closed and MUST create no
  successful receipt. The evaluation instant MUST come from a service-owned UTC clock, never
  a caller request timestamp. T047 introduced the lifecycle-bearing
  `sast-canonical-scan-key-v3`; the receipt and verified lifecycle selection MUST remain in the
  current `sast-canonical-scan-key-v4` preimage together with T048's stable canary projection.
  Deployment MUST drain or explicitly cancel every non-terminal prior-version SAST plan and
  reservation before each cutover while retaining terminal history as immutable audit records.

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
- Every pre-fingerprint finding candidate passes the versioned redaction gate, while a
  secret-bearing identity field fails closed without a matched-value or pre-redaction digest.
- Rule promotion and production readiness have measurable fail-closed gates.
- Stable identity behavior is independent of line, branch, and commit changes.
- Coverage and failure matrices cannot authorize external publication when incomplete.
- The legacy mock-analysis path has an explicit retirement plan and cannot be considered the
  production SAST runtime.
- A language after Java cannot claim SAST completeness until the immutable profile,
  normalizer/identity semantics, corpus, supply chain, canary, and rollback contract in
  `language-profile-extension.md` passes.
