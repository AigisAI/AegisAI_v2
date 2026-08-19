# Quality Gates: Production SAST Runtime

## Gate Policy

All gates are release blocking and fail closed. A missing metric, empty denominator,
expired evidence window, schema mismatch, or unverified artifact is a failure. Averages
cannot hide a language, profile, severity, tenant-isolation, or scanner regression.

Measurements are computed from immutable corpus/run references bound to scanner image,
wrapper, profile, database, rule bundle, schema, and normalizer digests. Production samples
contain metadata and aggregate outcomes only; repository content and evidence are not copied
into quality datasets without a separately approved, tenant-authorized path.

## Corpus Classes

| Corpus | Purpose | Required contents |
|---|---|---|
| Golden positive | Detection correctness | vulnerable examples with expected semantic rule, location anchor, severity, and capability |
| Golden negative | Precision and near misses | patched examples, sanitizers, safe APIs, comments/strings, generated/vendor fixtures |
| Prior must-detect | Regression prevention | every previously released Critical/High must-detect case |
| Schema/parser | Ingress hardening | valid fixtures for every supported schema plus malformed, oversized, recursive, Unicode, and enum attacks |
| Malicious repository | Sandbox/input safety | traversal, symlink escape, case collision, file bomb, archive, submodule, LFS, FIFO/device, output bomb, timeout, and secret fixtures |
| Fingerprint/correlation | Stable identity | line shifts, renames, branch/commit changes, multi-tool overlap, rule migration, fixed/reopen sequences |
| Performance | Capacity and SLO | representative small/medium/large repositories at profile limits with fixed hardware class |
| Evidence/privacy | Data minimization | secret-like values, reconstruction combinations, prompt injection, binary/encoding, retention expiry |

Corpus changes are reviewed like code. Each case has an owner, expected outcome, applicable
profile, source license/provenance, and immutable revision. A production incident that
exposes a missed detection or control failure must add a regression fixture before closure.

## Metric Definitions

- `mustDetectRecall = truePositiveMustDetect / expectedMustDetect`.
- `criticalHighPrecision = truePositiveCriticalHigh / reportedCriticalHigh`.
- `priorMustDetectRegressionRecall` uses only previously released must-detect cases.
- `goldenCorpusPassRate` is exact-case conformance across positive and negative fixtures.
- `maliciousCorpusPassRate` is the proportion of malicious cases producing the expected
  reject, quarantine, resource-kill, or safe-success outcome with no prohibited effect.
- `parserRejectRate` is malformed/unsupported artifacts rejected before normalization,
  divided by all fixtures expected to reject.
- `falsePositiveIncrease` is the candidate minus baseline false-positive rate in percentage
  points over the same negative corpus and canary observation set.
- `scannerFailureRate` is scanner-defect plus unexpected infrastructure failure attempts,
  divided by eligible attempts; input-policy and capacity rejections are reported separately.
- `p95LatencyIncrease = candidateP95 / baselineP95 - 1` on the same profile, corpus, and
  hardware class.

Retries do not erase the first attempt from reliability metrics. Duplicates produced by one
scanner run count once after exact scanner-local deduplication, before cross-tool correlation.

## Sample Sufficiency

- Every rule changed or added has at least 10 positive and 10 negative/near-miss fixtures;
  Critical/High rules have at least 20 of each unless Security Engineering documents why
  the reachable domain is smaller.
- Aggregate rule promotion uses at least 200 positive and 200 negative cases per affected
  language/profile, including all prior must-detect fixtures.
- Parser and malicious corpora contain every required attack class from `threat-model.md`;
  no class may have an empty denominator.
- Performance has at least 30 completed runs per candidate profile/size bucket after warm-up.
- Each canary step requires at least 200 eligible completed scans and 24 hours of observation;
  25% to 100% requires at least 1,000 completed scans and 48 hours. If traffic is lower,
  Security and Platform owners must explicitly approve a longer evidence plan; thresholds
  are never waived.

Sample minima prevent perfect rates from a trivial corpus. They do not replace representative
coverage or manual review.

## Rule and Scanner-Set Promotion Gates

| Gate | Threshold | Failure action |
|---|---:|---|
| Signature and provenance | 100% verified | reject artifact |
| Compatibility matrix | 100% supported | reject candidate |
| Golden corpus exact pass | 100% | return to `DRAFT` |
| Must-detect recall | >= 95% | return to `DRAFT` |
| Critical/High precision | >= 90% | return to `DRAFT` |
| Prior must-detect recall | 100% | block regression |
| Malicious corpus controls | 100% | security block |
| Expected malformed artifact rejection | 100% | security block |
| Stable fingerprint fixtures | 100% | block promotion |
| Coverage/publication decision fixtures | 100% | block promotion |
| False-positive increase | <= 2 percentage points | block or reduce candidate |
| Unexpected scanner failure rate | <= 2% | block promotion |
| Candidate p95 latency increase | <= 20% | block promotion |
| Cross-tenant/secret/sandbox/stale-publication events | exactly 0 | incident and block |

The candidate must satisfy both relative performance gates and the absolute SLOs below.
Security zero-tolerance gates cannot be overridden by a release approver.

## Absolute Runtime Gates

| Profile/lane | p95 target | Hard timeout | Maximum input selected for scan |
|---|---:|---:|---:|
| `JAVA_FAST_V1` | <= 10 minutes | 15 minutes | 256 MiB / 25,000 files |
| `JAVA_DEEP_V1` | <= 45 minutes | 60 minutes | 2 GiB / 250,000 files |
| `COMMON_DEEP_V1` | <= 45 minutes | 60 minutes | 2 GiB / 250,000 files |

The platform also verifies per-file, path-depth, findings, artifact bytes, process, memory,
disk, and CPU limits from the immutable profile. Hitting a declared input limit is an
explicit input/capacity outcome, not a successful complete scan.

## Security and Privacy Gates

All counts below must equal zero across corpus, canary, and the current production release
window:

- cross-tenant access or attribution mismatch
- SCM credential value, detected secret value, or platform secret in logs/findings/evidence
- full file or reconstructable repository content in evidence
- customer code execution, package install, build, or dynamic test execution
- sandbox escape, workspace reuse, residual workspace, or missing destruction evidence
  beyond the cleanup SLO
- unauthorized egress, SCM write/admin capability, or AI direct repository access
- external publication or finding resolution from stale/incomplete coverage
- unsigned/unpinned scanner, rules, database, schema, or normalizer execution

Raw artifact/evidence expiry is tested at seven days maximum and AI request payload expiry at
24 hours maximum. Expiry test failure blocks production readiness.

## Normalization and Data Integrity Gates

- 100% deterministic normalized output for repeated identical plan/artifact inputs.
- 100% OpenGrep/Trivy/Syft parity for fixed-slice scalar streaming, fatal UTF-8, raw
  token/depth/duplicate-key bounds, byte/content-digest recount, retention rebinding, and
  ordered rejection through one common implementation; finding-only coordinate/text helpers
  remain shared by OpenGrep and Trivy.
- 100% OpenGrep golden-fixture equality across transport chunk boundaries, with zero raw
  snippet/fix/code-flow/help payload fields in transient candidates.
- 100% Trivy golden-fixture equality across transport chunk boundaries for direct and
  `ExperimentalModifiedFindings` dependency/secret/IaC records, including exact record recount,
  deterministic ordering, zero-finding provenance, and canonical batch digest.
- 100% supported Trivy modified records remain normalized with
  `platformPolicyAuthority=false`; unknown status/type and unsupported license capabilities
  reject the complete batch, and scanner disposition never changes severity or policy state.
- 100% Trivy dependency semantic identity/revision resolves from the pinned vulnerability
  database while secret/IaC identity/revision resolves from the signed checks manifest;
  identical package advisories in different canonical result targets remain distinct.
- Exactly zero scanner `Title`, `Description`, `Message`, secret `Match`/`Code`,
  modified-finding `Statement`/`Source`, trace, or rendered-cause values may occur in transient
  candidates, identity/batch/rejection digests, logs, audit, evidence, or AI payloads.
- 100% Trivy dependency findings without package-file coordinates use
  `UNKNOWN/SCANNER_LOCATION_OMITTED`; no adapter may invent a fallback line.
- 100% Trivy secret/IaC `scannerMatchBasedId` and `structuralHash` stability under line-only
  shifts, while deterministic producer-order ordinals keep multiple same-rule/target
  occurrences distinct and exact-coordinate ambiguity rejects the complete batch.
- 100% Syft v1.44.0 CycloneDX JSON 1.6 golden-inventory equality across transport chunk
  boundaries, including zero components, package-ID fallback, library/application/model/OS
  components, URL-empty Java `build-meta` hashes, repeated-license de-duplication, sorted
  dependency edges, complete producer/supply-chain provenance, and canonical batch digest.
- Exactly zero raw CycloneDX properties, source paths, BOM references, license text/URLs,
  prose, external-reference payloads, artifact bytes, findings, severity, evidence, policy,
  or AI content may occur in the transient inventory or bounded rejection. Producer BOM
  references and the serial number may appear only as SHA-256 digests where contracted.
- 100% complete-batch rejection for CycloneDX schema/tool/version/source drift,
  metadata-tool count smuggling, vulnerability/VEX/nested/file extensions, malformed or
  duplicate BOM references, malformed PURL/SWID/hash identities, incomplete or illegally
  quoted CPE 2.3 fields, invented SPDX 3.28.0 license IDs/exceptions, invalid SPDX 2.3
  expressions, dangling/duplicate/self/non-canonical dependencies, resource bombs, and
  pre/post-stream retention drift.
- 100% CycloneDX authority assertions:
  `mayCreateFindings=false`, `mayEvaluateVulnerabilities=false`,
  `policyAuthority=false`, `aiPayloadEligible=false`, and
  `durablePersistenceAllowed=false`.
- 100% rejection equality for oversized/chunk-varied streams, unpaired Unicode escapes,
  pre-decision clocks, and retention expiry crossed during streaming.
- 100% rejection before artifact reads for supplied coordinate-attestation drift, and 100%
  semantic-rule/revision resolution from immutable bundle metadata rather than scanner IDs.
- 100% artifact tenant, scan, scanner, commit, schema, digest, size, and count binding.
- 100% unknown/unsafe enum, coordinate, path, encoding, and over-limit rejection.
- 100% `sast-secret-redaction-v1` determinism for repeated inputs, platform-value ordering,
  detector overlap/adjacency, empty batches, and OpenGrep/Trivy source adapters.
- 100% known-format, registered platform-value, private-key, authorization/URL credential,
  JWT, prefixed/quoted low-entropy assignment, and admitted high-entropy corpus removal from
  display fields using the one fixed marker, with zero matched value or length disclosure.
- 100% complete-batch rejection when any detected value occurs in ingestion/scope/preflight
  bindings or in normalized path, semantic rule identity, symbol anchor, sink kind, scanner
  version/match identity, rule provenance identifier/revision, dependency
  vulnerability/package/type/installed/fixed-version identity, secret category, or IaC check
  type/AVD identity; no secret-derived replacement identity or digest may be constructed.
- 100% rejection above 8,000,000 inspected UTF-16 code units, event-loop yielding before the
  next candidate at the 64-candidate or 32,768-code-unit chunk boundary, and canonical digest
  recomputation for every candidate, batch, rejection, and audit projection.
- Exactly zero matched values, matched-value digests, raw candidates, pre-redaction
  candidate-batch digests, or rejected bindings in redaction result, log, audit, dashboard,
  evidence, policy, or AI surfaces. A rejection also contains no accepted-artifact digest;
  success may retain only the pre-existing accepted-artifact provenance digest.
- 100% canonical source-batch and accepted-disposition digest verification plus pre/post-pass
  active-retention checks; malformed, forged-marker, invalid platform-set, clock rollback,
  and expiry-crossing cases fail closed.
- 100% secret-value redaction before persistence outside the scanner artifact quarantine;
  T035 success remains `durablePersistenceAllowed=false` until T036 fingerprinting.
- 100% `sast-finding-identity-v1` source-batch and source-decision digest recomputation,
  deterministic fresh output, OpenGrep/Trivy provenance preservation, and byte-exact
  interoperability with the published NFC/UTF-8 test vector.
- 100% fingerprint stability for line/column, branch/target, commit, scanner-match identity,
  display text, severity, and confidence-only changes; 100% fingerprint change when any of
  the seven canonical identity components changes.
- 100% `UNKNOWN` location projection to the empty length-prefixed path component with no
  reason code, coordinate, or invented path in stable identity.
- 100% complete-batch rejection for malformed/forged T035 handoffs, more than 25,000
  findings, non-monotonic clocks, retention expiry reached before or during construction,
  and one stable digest observed with different preimages. Byte-identical repeated preimages
  remain separate observations with exact distinct/repeated counts.
- Event-loop yielding before finding 65 and each subsequent 64-finding chunk. Exactly zero
  fingerprint preimages, rejected source candidates, rejected T035 batch digests, artifact
  digests, or secrets in identity rejection/audit output.
- T036 success alone sets normalized-finding persistence eligibility; occurrence, lifecycle,
  correlation, coverage, evidence, policy, publication, and AI authority remain false.
- 100% `sast-finding-lineage-v1` revalidation of the complete T036 handoff and durable
  tenant/repository/scan/scanner-run/fixed-commit/target/profile/artifact/schema/normalizer/
  rule/database/preflight bindings before persistence.
- 100% one-to-one preservation of producer ordinals as immutable occurrences, including
  byte-identical repeated fingerprints; no repeated observation may be silently collapsed.
- 100% source-batch replay equality across the canonical observation batch and complete
  ordered occurrence ledger. Missing, extra, changed, reordered, malformed, or cross-scope
  rows reject without partial writes.
- 100% rename continuity only for verified canonical fixed-commit/fixed-target one-to-one
  attestations with an existing unambiguous predecessor alias. Rename-back retains lineage;
  fuzzy, chained, cyclic, ambiguous, missing-predecessor, unavailable, or AI claims grant no
  continuity.
- 100% target-context isolation and append-only lifecycle revision order for `CREATED`,
  `RENAMED`, `FIXED`, and `REOPENED`; legacy policy/triage status remains unchanged.
- Exactly zero `FIXED` or `REOPENED` mutations unless an injected T039-compatible gate
  verifies a strictly newer `COMPLETE`, `stale=false`, `comparable=true` decision and exact
  expected-digest equality to every durable current-scan T037 observation batch, including
  zero-finding batches.
- 100% fail-closed behavior for partial, pending, failed, stale, incomparable, missing,
  extra, out-of-order, tampered, or unavailable coverage decisions, plus serializable
  lineage/lifecycle writes with no cross-tenant leakage under concurrency.
- T037 authority assertions remain exact:
  `coverageCalculationAuthority=false`, `correlationAuthority=false`,
  `policyAuthority=false`, `publicationAuthority=false`, and
  `aiPayloadEligible=false`; only `SastFindingLineageService` crosses the Scan Plane module
  boundary for T038.
- 100% provenance preservation during correlation; no lower-severity result may hide a
  higher-severity authoritative result.
- 100% exact equality between supplied canonical T037 results and every durable current-attempt
  observation batch and ordered occurrence, including zero-finding batches. T037 replay-flag
  changes produce the same correlation batch/source-set identity.
- 100% scanner-owner and active-profile authority classification: required capability output
  is `AUTHORITATIVE`, optional capability output is `SUPPORTING_ONLY`, and foreign capability
  claims reject the complete transaction.
- Exact correlation only for repeated lineage fingerprints; dependency correlation only for
  exact NFC ecosystem/package/installed-version/canonical-CVE tuples; cross-capability overlap
  only for canonical CVE or same-file canonical CWE. Path/title/coordinate/severity/
  scanner-ID/fuzzy/AI-only matches produce zero edges.
- Exactly two durable provenance rows per edge and invariant false finding-merge,
  severity/lifecycle/coverage/policy inheritance. Mixed Critical/Low fixtures retain both
  immutable occurrences and both severities.
- No quadratic correlation pass: at most 25,000 occurrences and 100,000 canonical star edges,
  event-loop yield before occurrence 65 and each subsequent 64-occurrence chunk, plus bounded
  chunked persistence and whole-operation edge-limit rejection.
- Serializable complete-ledger replay equality across source bindings, edges, match-basis
  digests, safety flags, and both provenance rows; missing, extra, changed, late, or cross-scope
  rows reject with no partial writes.
- T038 authority assertions remain exact: `correlationAuthority=true` and provenance
  preservation true, while severity, lifecycle, coverage calculation, evidence, policy,
  publication, and AI authority remain false. T038 is internal after T039 installation.
- 100% exact durable rebinding for `sast-scan-coverage-v1`: immutable plan/profile/scanner
  set, every scanner run, accepted artifact/final disposition, and the complete zero/nonzero
  T038 source set must match before a capability is achieved.
- Fast/Deep/Common, optional absence/failure, pending/partial/failed/quarantined/killed,
  provenance/artifact/source tamper, exact replay, changed/reordered/cross-scope replay, and
  serialization-race fixtures pass with no duplicate or partial coverage rows.
- 100% pending non-freeze invariant: a `PENDING` evaluation is marked non-persisted, performs
  zero coverage-ledger writes, and can be reevaluated after a required scanner becomes terminal.
- 100% T039 zero-publication invariant: even complete coverage has false comment/block/AI/
  lifecycle flags while latest-target authority is unavailable and stale/comparability are
  unknown. The T039 row remains immutable after T040 installation.
- The T039 caller records a structured rejection counter keyed by the coarse reason code;
  `SCAN_COVERAGE_PERSISTENCE_FAILED` is alerted separately from expected durable-scope,
  scanner-set, source-set, input, and replay rejections without logging sensitive context.
- 100% T040 stale-publication invariant: comment/block eligibility and T037 lifecycle
  verification require exact durable T039 `COMPLETE`, a provider-authoritative monotonic head
  equal to the fixed commit, and an exact prior-scan tenant/repository/target/profile-family/
  capability/fingerprint/lifecycle-scope comparison. Every unavailable, invalid, stale, or
  incomparable fixture produces zero authority and zero publication attempts. Current-scan
  attempt rows and incompatible profiles cannot mask the newest older compatible source.
- 100% T040 retry-fence invariant: only attempt one `FAILED` with
  `RETRYABLE_INFRASTRUCTURE`, retry eligibility, completion, exact final audit, unchanged and
  available scanner set, clear kill-switch authority, and fresh attempt/sandbox/workload
  identities plus a signed, attempt-bound preflight no more than 60 seconds old may admit
  attempt two. Exact allowed replay reuses the persisted authorization timestamp after an
  interrupted attempt insert; denied decisions remain permanent audit evidence. Attempt three
  and every other failure class produce zero sandbox admissions. Populated-table indexes are
  built concurrently before dependent foreign-key validation.
- 100% T041 accepted-source invariant: every pack rebinds one exact T037 occurrence and
  fingerprinted source finding through its T038 source, T039 `COMPLETE` coverage, and T040
  verified/fresh/comparable decision. Missing, rejected, UNKNOWN-location, foreign,
  cross-tenant, changed, or late durable state creates zero packs.
- 100% T041 evidence-bound invariant: exact UTF-8 content bytes are at most 8 KiB per
  fragment, five fragments and 32 KiB per pack, with no more than five context lines around
  each attested anchor. Raw source and platform secret values stored across pack, decision,
  audit, logs, dashboard, and AI surfaces equal zero.
- 100% T041 reconstruction invariant: full-file spans, more than two fragments per file,
  overlap, adjacency, or combined coverage at or above 2,500 basis points reject the complete
  build. Exact replay creates no duplicate decision, pack, or fragment row.
- T041 accepted and rejected decisions have zero dashboard/AI/policy/publication/lifecycle
  authority. The default source authority remains unavailable and no controller or SCM writer
  is added by T041.
- 100% T042 access invariant: dashboard and AI classifications are separate immutable
  decisions over a complete durable T041/T040/T039/T038/T037 rebind. Known-format,
  registered-platform, and entropy redaction run again at access time; unsafe path/identifier,
  unavailable registry, binding/digest drift, cross-tenant/repository scope, clock rollback,
  expiry, or deletion claim returns zero content and zero reduced references.
- 100% T042 authority invariant: dashboard responses contain only the authenticated
  second-pass-redacted projection; AI classification contains only an at-most-24-hour reduced
  reference. Provider requests, AI payload persistence, retrieval/tools, policy, publication,
  lifecycle mutation, and SCM actions equal zero. T041 safe/reference fields remain unchanged,
  and `SastEvidenceAccessService` is the only sequential Scan Plane handoff to T043.
- 100% T042 deletion-proof invariant: every accepted pack has one deterministic at-most-seven-
  day schedule and one fenced claim. Pack/fragment content is removed only after a valid
  operation-bound provider receipt; one immutable proof remains with the T041 build decision.
  Startup processing, earliest-due wakeup, and zero-delay continuation for saturated bounded
  batches prevent poll/cap backlog. Unavailable providers, stale tokens, changed receipts,
  concurrent workers, late readers, clock rollback, exact replay, and an original receipt
  recovered after finalization failure create zero false proofs, duplicate rows, overdue
  content, or restored content. A context-drifted claim is fenced and quarantined after three
  validations and cannot starve a later due schedule.
- 100% T043 source-binding invariant: every advisory handoff is derived from two matching T042
  AI classifications around one exact durable T037 occurrence/source/normalized-finding rebind.
  Caller finding, evidence, prompt, path, digest, expiry, unknown field, cross-scope identifier,
  changed decision, clock rollback, or late access creates zero handoffs and provider calls.
- 100% T043 reference-only invariant: the immutable ledger stores only scope relationships,
  digests, model version, expiry, and fixed authority/audit bits. Stored request/handoff JSON,
  source, secret, evidence fragment, prompt, retrieval payload, and redacted content equal zero.
  Exact valid retries reproduce one request, handoff, advisory, and result row.
- 100% T043 AI-boundary invariant: runtime requests contain one normalized metadata projection,
  one opaque reduced-evidence reference, and zero snippets. Retrieval, tools, policy,
  publication, lifecycle mutation, and SCM write authority are false in every request; legacy
  direct finding/evidence requests, correlation drift, expiry, and authority widening are denied.
- 100% T044 zero-authority invariant: one serializable operation locks one advisory-context and
  three authority fence rows, then writes only an immutable proof row. Every covered writer
  advances the same fence; bulk finding and lifecycle writes deduplicate affected keys once per
  SQL statement. The bounded scan finding set, target status/severity, exact lifecycle
  state/revision, durable finding policy decisions, waivers, and suppressions produce one locked
  snapshot projected into identical before/after state digests; authoritative writes and all
  authority bits equal zero.
- 100% T044 policy isolation invariant: only a tenant/finding-bound exact advisory/proof
  reference can set advisory visibility. AI contributes zero enforcement actions, reason codes,
  ticket/block requests, severity/status changes, waivers, suppressions, or lifecycle events.
  `suggestedAction`, authority, advisory, proof, unknown, cross-tenant, or drifted fields are
  rejected, not ignored.
- 100% T044 content-free/replay invariant: the proof ledger contains only scope references,
  counts, SHA-256 digests, time, and fixed booleans. Advisory/rationale/prompt/source/evidence/
  secret/policy payload retention and duplicate proofs equal zero; exact retry returns one row.
- 100% T046 semantic-identity invariant: one semantic ID maps to exactly one complete core.
  Predicate, capability/category, language/format, source/sink, default severity/confidence,
  finding identity, or tenant-control drift creates zero metadata bindings. Deprecated rules
  may omit a replacement; retired rules may not, and replacement cycles are rejected.
- 100% T046 manifest-binding invariant: reusable metadata can bind to later signed manifests
  without changing its content digest, while any manifest/bundle/scanner/rule/revision/
  metadata/semantic-identity drift rejects. The normalized ledgers contain zero rule body,
  source, secret, executable configuration, mutable URL, or generic JSON fields.
- 100% T046 policy/planning invariant: executable fields, unknown selectors, regex/glob or
  traversal paths, weakened severity floors, repository re-enable attempts, mandatory-rule
  disables, expired/cross-tenant references, missing metadata, and store outages create zero
  successful receipts and queue reservations. A valid retry returns one immutable receipt whose
  identity/digest and enabled/disabled binding sets are committed to the canonical scan plan.
  Caller request time has zero authority over policy windows or receipt time; old/future request
  times still use the trusted service clock, while throwing or invalid clocks fail closed. The
  tenant-policy receipt remains committed to the current canonical preimage.
- 100% T047 evidence invariant: candidate and distinct baseline rebind to exact T045 manifest,
  supply-chain verification, bundle, profile, and rollback identities. All seven immutable corpus
  references, minimum 200 positive/negative samples bound exactly to the golden denominator,
  minimum 30 performance runs, exact corpus pass requirements, recall/precision,
  false-positive/failure/relative-and-absolute-latency thresholds, and four zero-
  tolerance event counts are enforced in both shared contracts and normalized database checks.
  Failed, incomplete, future-dated, or drifted evidence creates no row.
- 100% T047 approval/lifecycle invariant: automated evidence grants no approval; every approval
  is human, candidate-author-separated, exact-evidence-bound, time-bounded, and unique by role and
  approver. Every legal edge has Security Engineering approval; `ACTIVE` and `RETIRED` have an
  additional Scan Platform or Security Operations approval. Sequence, previous digest, approval
  set, and exact external-authority receipt are append-only and cannot fork or mutate.
- 100% T047 planning invariant: after T045 compatibility and before T046 tenant policy, only the
  latest `CANARY` or `ACTIVE` transition can create one immutable lifecycle selection receipt.
  Suspended, rolled-back, retired, draft, validated, stale, cross-bundle, unavailable-store, or
  invalid-clock state creates zero successful receipts and queue reservations. Exact replay must
  recheck latest state; all bundle receipts use ordered manifest-row locks and one serializable
  scanner-set transaction, so later-bundle failure and concurrent transition produce no partial
  selection set. Queue reservation then locks the trigger-maintained latest head for every
  manifest and revalidates the exact receipt, so a selection-to-admission suspension race cannot
  enqueue stale work. T047's canonical preimage is exactly `sast-canonical-scan-key-v3`: it commits
  stable lifecycle transition/evidence/approval fields and the compatibility receipt, but excludes
  the evaluation-time-derived lifecycle selection receipt ID/digest. The immutable plan still
  retains that receipt for audit and admission validation. Migration
  rejects the cutover until every prior non-terminal v2 SAST plan and reservation has finished or
  been canceled.
- 100% T048 rollout/lifecycle invariant: one candidate manifest/profile has exactly one immutable
  rollout, bound to its exact latest `CANARY` head, distinct exact latest `ACTIVE` baseline, T045
  manifests/bundles, T047 evidence/transition, profile, cohort key reference/version, eligibility
  policy, observation source, and six fixed ordered steps. A paused or completed candidate/profile
  cannot be re-enrolled; lifecycle drift, duplicate rollout, or missing authority creates no
  assignment, observation, receipt, or promotion.
- 100% T048 cohort invariant: eligibility is platform-managed and contractual/residency exclusion
  is explicit. Membership uses HMAC-SHA-256 over length-framed tenant, repository binding,
  profile, and rollout identity with at least 32 bytes of canonical-base64 key material. Only its
  digest and the first-eight-byte modulo-10,000 bucket persist, and PostgreSQL independently
  recomputes the bucket. Content, findings, severity, customer attributes, or key material in the
  ledger equal zero. Membership remains stable and selection expands monotonically at 1%, 5%,
  25%, and 100%.
- 100% T048 planning/admission invariant: the order is compatibility -> lifecycle -> canary ->
  tenant policy. Only an exact candidate assignment adds a canary descriptor. A supplied canary
  resolving outside the cohort is rejected rather than rewritten; trusted orchestration submits
  the separately verified exact `ACTIVE` baseline set for non-cohort production, and excluded
  scopes use no candidate. The
  current preimage is exactly `sast-canonical-scan-key-v4`: it adds stable rollout/membership/
  bucket identity while excluding assignment receipt, step, and step-head identity retained by
  the plan. Queue reservation locks lifecycle heads then the canary head and revalidates the exact
  receipt. The v4 migration rejects non-terminal v3 work.
- 100% T048 observation invariant: every observation rebinds the immutable candidate or baseline
  plan, exact assignment where applicable, terminal attempt interval, profile/lane/size bucket,
  durable coverage and publication decisions, rollout-fixed observation source, and telemetry
  source. Coverage and publication counts are derived from those durable authorities. Source or
  finding content, secrets, arbitrary JSON, foreign scope, partial binding, reordered binding,
  or forged scalar authority creates zero observations.
- 100% T048 step-gate invariant: every decision automatically binds the canonically sorted set of
  every committed observation through the evaluator's trusted-time cutoff and recomputes all
  candidate/baseline aggregates; a caller cannot choose the cutoff or select/omit observation
  IDs. Internal through 5% requires 200
  completed scans per arm and 24 hours; 25% and 100% requires 1,000 per arm and 48 hours.
  Every repository-size bucket must be compared. Maximum candidate deltas are two percentage
  points for false positives and 20% for p95 latency and completed-scan-normalized Critical/High
  rate; candidate scanner failure is at most 2%, and p95 also satisfies the 10-minute Fast or
  45-minute Deep absolute SLO.
  All eight security counters are exactly zero.
- 100% T048 terminal-state invariant: insufficient time/sample is `PENDING`; missing telemetry,
  incomplete coverage or size comparison, threshold breach, or any zero-tolerance event is terminal
  `PAUSED`; only zero reasons is `PASSED`. Threshold waivers and step skipping equal zero. Six
  contiguous ordered passes issue one immutable observation receipt, and only that exact receipt
  authorizes the matching `CANARY -> ACTIVE` transition. The default production observation
  source remains unavailable and therefore cannot manufacture promotion evidence.

## T049 Kill-Switch Authority and Propagation Gates

T049 is release-blocking unless all of the following are proven against the shared contract,
application services, and PostgreSQL constraints:

- each global, scanner-version, bundle, semantic-rule, exact-profile, tenant, repository-binding,
  capability, and global/tenant/repository publication selector has canonical, deterministic
  matching and a content-free decision/evaluation representation;
- valid signed activation and deactivation append in sequence, exact replay is idempotent, and
  missing/mismatched signature, predecessor fork, future activation, mutation, or active expiry
  yields zero successful authority;
- a stale or future caller-selected boundary time outside the bounded service-owned trusted-clock
  skew yields zero evaluation authority;
- an inactive placeholder and ordered selector-head locks make first activation serialize with
  planning/queue evaluation; a plan admitted from a stale/missing head set equals zero;
- no context exceeds two rule bundles or 50,020 selector bindings, and both evaluation and direct
  queue admission prove one set-based ordered lock plus anti-join with zero per-head SQL loops;
- planning persists only `CLEAR`, leaves canonical key v4 unchanged, and queue admission
  reconstructs the plan-bound context/selector set and rejects a missing, substituted, extra, or
  later-drifted head in both the application transaction and direct database insert path;
- a switch activated after queue admission creates the durable scanner-run record but reaches
  zero provider repository reads and zero scanner executions, finishes `KILLED`, and still enters
  mandatory cleanup;
- affected artifact acceptance is `QUARANTINE` with zero downstream acceptance calls; a clear
  switch still requires the independent fail-closed Data/Security acceptance authority; affected
  retry admission is denied, and affected external-publication and AI paths make zero publisher/
  model calls;
- a crash-recovered accepted artifact intent receives a fresh gate before storage, denial writes a
  replacement quarantine intent, and activation during AI inference yields zero advisory writes;
- retry admission requires both a fresh switch evaluation and an independent exact-digest current
  scanner-set availability result; unavailable or withdrawn assets admit zero sandboxes even when
  the switch is clear;
- T037 lifecycle coverage first obtains a fresh `COVERAGE` evaluation and invokes the independent
  T040 authority only for `CLEAR`/`UNCHANGED`; active or unavailable T049 authority invokes T040
  zero times;
- external comment planning and every dispatch-worker claim each obtain a fresh
  `EXTERNAL_PUBLICATION` evaluation; activation between them creates zero claims and publisher
  calls;
- current coverage maps semantic-rule/capability-only matches to `PARTIAL`, other runtime matches
  to `FAILED`, and publication-only matches to `UNCHANGED`, while the original T039 decision is
  byte-for-byte unchanged; and
- an exact active global/bundle/scanner-version/semantic-rule/profile decision set can authorize
  only the matching latest `CANARY | ACTIVE -> SUSPENDED` edge. Cross-bundle, stale, deactivated,
  expired, replay-substituted, non-trigger decision-set drift, or rollback use yields zero
  lifecycle transitions; and
- the automatic canary input accepts only a T048 decision ID/digest, derives current `PAUSED` or
  zero-tolerance status plus every target field under lifecycle/canary locks, and rejects an extra
  caller target, stale head, non-pause outcome, incomplete reason set, or cross-rollout binding.

The propagation drill activates one selector between every adjacent gate—planning/queue,
queue/scanner, scanner/artifact, artifact/retry, and normalization/publication/AI—and records the
trusted decision time, rejection time, affected scope, zero forbidden side effects, and immutable
evaluation receipt. Authority-unavailable and active-expired drills have the same fail-closed
expectation as an active switch; only an exact signed deactivation restores later eligibility.

## T050 Last-Known-Good Rollback Gates

T050 is release-blocking unless all of the following are proven against the shared contract,
application services, Prisma persistence, and PostgreSQL 16 constraints:

- the exact request rejects every unknown field and contains no baseline, target, scanner-set,
  customer, AI, or scanner-selected authority;
- command construction derives the distinct baseline only from the candidate's original T047
  evidence and revalidates both T045 attestations, same bundle/scanner identity, common profile,
  exact T049 suspension provenance, candidate latest `SUSPENDED`, and baseline latest `ACTIVE`;
- the production signature authority defaults unavailable; only an exact signature/provenance
  verification bound to the command can commit;
- exactly two fresh approvals—Security Engineering plus independent Scan Platform or Security
  Operations—arrive within 15 minutes, with no command-actor self-approval, duplicate approver,
  duplicate role, two platform-side roles, automated approval, or post-receipt approval;
- command, verification, approvals, receipt, and receipt bindings are normalized, content-free,
  append-only, and exact-replay only, with restrictive composite keys and canonical digests;
- candidate and baseline heads are locked in canonical manifest-ID order and revalidated at
  command, receipt, and direct lifecycle insert boundaries; candidate or baseline drift produces
  zero `ROLLED_BACK` transitions;
- forged direct lifecycle insertion, cross-manifest/bundle/profile/evidence receipt, wrong edge,
  stale time, changed replay, update/delete, and unavailable persistence all fail closed;
- concurrent exact rollback attempts converge on one receipt and one candidate transition; the
  baseline head and all prior manifests, transitions, plans, findings, coverage, evidence, and
  audit records remain byte-for-byte authoritative history; and
- every receipt authority bit for baseline/history/scanner-set/finding/policy/publication/SCM
  mutation is false. Routing new work requires the trusted scanner-set owner to select the exact
  still-`ACTIVE` baseline and pass all existing planning and queue gates.

CI must apply every migration through `20260819220000_sast_rule_bundle_rollback` to a clean
PostgreSQL 16 database, run the opt-in application/Prisma rollback probe after migration, and
prove direct-write denial, both head-drift denials, concurrent exact replay, one append-only
success, immutable-ledger rejection, and unchanged baseline/history state.

## T051 Golden Qualification Corpus Gates

T051 is release-blocking unless the checked-in contract, prior-release manifest, generator, snapshot, source bundles,
loader, tests, and documentation prove all of the following without provider or Kubernetes access:

- one deterministic generation produces the byte-exact reviewed snapshot and source set; the
  snapshot has an exact semantic revision, UTC publish time, owner, license, digest-bound
  provenance and prior-release reference, derived corpus ID/digest, and no mutable reference;
- the separately checked-in prior-release manifest binds each historical case ID/digest/key,
  case/rule revision, semantic rule ID, and severity; its reviewed digest is pinned in code,
  overwrite is refused, every binding is still exact, and new positives are not added implicitly;
- exactly 800 cases form 400 compatible positive/negative pairs over 20 Critical/High semantic
  rule families and 40 bounded platform-owned source bundles; IDs, digests, case keys, pair
  polarities, and future materialization paths are complete and non-colliding;
- every rule has exactly 20 positive and 20 negative cases, the initial manifest authenticates all
  400 historical positives, and each of `JAVA_FAST_V1`, `JAVA_DEEP_V1`, and
  `COMMON_DEEP_V1` has at least 200 positive and 200 negative cases;
- `PATCHED`, `SANITIZER`, `SAFE_API`, `COMMENT_OR_STRING`, and `GENERATED_OR_VENDOR` each have a
  non-empty, semantically applicable denominator and matching expected zero-finding behavior;
  generated/vendor cases contain the actual unsafe construct under an excluded path, while
  comment/string cases keep it inert;
- every case binds the exact scanner/capability/profile, semantic rule/revision/severity, expected
  outcome/count, source byte count/digest, bounded line range/anchor, and unique root-confined
  materialization path;
- exact-shape validators reject unknown or malformed nested fields, count/digest/pair/profile/rule
  floor drift, duplicate scan paths, unsafe traversal/absolute/backslash paths, mutable ownership/
  provenance/license facts, and any widened execution or content authority without throwing;
- the filesystem loader rejects a missing, changed, noncanonical, or unpinned prior manifest,
  any extra or missing root entry, changed snapshot/source bytes, extra or missing files, symlinks or
  junctions, real-path escape, invalid UTF-8, BOM, CRLF, NUL, non-NFC text, missing final LF,
  oversized input, digest/byte/range/anchor drift, duplicate materialization paths, and file or
  directory identity changes across validation/read; and
- corpus and case facts fix platform ownership/immutability true and customer content/config,
  dependency installation, build, dynamic execution, and network requirements false.

`corepack pnpm qualification:validate` is a mandatory CI and completion command. Passing T051
authenticates only the input denominator; golden-case scanner conformance, precision/recall,
isolation/destruction, latency/capacity, drills, and production go/no-go remain T052-T056 gates.

## T052 Multi-Class Qualification Corpus Gates

T052 is release-blocking unless the checked-in exact-shape contracts, generator, snapshot,
fixtures, filesystem loader, tests, and documentation prove all of the following without
provider, microVM, scanner, or Kubernetes execution:

- exactly 84 cases and 84 immutable platform-owned fixtures exist: 16 schema/parser, 25
  malicious-repository, 17 fingerprint/correlation, 17 evidence/privacy, and 9 performance
  cases; every required scenario appears exactly once and no unknown class, scenario, fixture,
  file, or directory is accepted;
- schema/parser inputs cover all three accepted result schemas plus malformed JSON, total-size,
  nesting-depth, record-count, string-size, Unicode, enum, version, foreign-attribution,
  multi-run, unknown-field, and duplicate-key boundaries. Artifact-byte and record-count cases
  bind each selected profile's exact limit plus one, while nesting and string cases bind the
  shared validator's exact limit plus one;
- malicious-repository recipes cover traversal, absolute, backslash, case-fold and Unicode path
  collisions, depth/count/size limits, symlink cycles and outside-root links, submodule/LFS/archive
  non-expansion, FIFO/device declarations, output/findings/time limits, secret-bearing input, and
  executable-file no-run behavior without creating a live hostile object;
- fingerprint/correlation inputs cover line, branch, and commit invariance; attested rename and
  rename-back; unknown locations; multi-tool related-only and cross-capability no-merge behavior;
  distinct rule migration; fixed/reopen sequences; digest-collision and tampered-replay rejection;
  duplicate replay, edge limits, complete zero-finding batches, and severity preservation. Every
  invariance case supplies two complete seven-field identity vectors and changes only the excluded
  coordinate/context field under test;
- evidence/privacy inputs cover known-format, registered, high-entropy, private-key, authorization,
  and URL credentials; secret-bearing identity fields and reserved markers; full-file and overlap
  reconstruction; prompt injection as inert data; raw binary and malformed UTF-8 octets decoded
  from the declared base64 segment; retention expiry and exact boundary; zero audit/raw-artifact
  leakage; and cross-tenant reference rejection;
- the 9 performance cases bind small, medium, and large synthetic-repository recipes to each exact
  resource limit, one immutable hardware-class reference and digest, and at least 30 measured runs
  per bucket; T052 records the denominator only and does not manufacture latency or capacity
  measurements;
- recipes contain only allowlisted declarative actions and bounded typed parameters or canonical
  byte segments; command, executable, argv, environment, shell, script, URL, dynamic execution,
  package installation, build, network, customer-content, finding, policy, publication, SCM
  mutation, and readiness authority are all absent or false;
- each profile-relative schema/parser or malicious limit-plus-one case names the selected immutable
  profile-limit field and binds its exact value for every supported profile, while a symlink cycle
  declares both directed edges;
- exclusive initialization refuses overwrite, normal regeneration requires the exact reviewed
  root and fixture set, and the loader regenerates every expected byte in memory before accepting
  the corpus; and
- the loader rejects missing, extra, empty, changed, noncanonical, malformed, oversized, or
  duplicate inputs; invalid UTF-8, BOM, CRLF, NUL, non-NFC text; traversal, absolute, backslash,
  symlink, junction, real-path escape, and file/directory identity drift; recipe, class, scenario,
  outcome, stage, profile, hardware, run-count, limit, digest, and authority widening.

Passing T052 authenticates only deterministic qualification inputs. T053 must materialize the
parser and malicious-repository recipes inside production-equivalent isolated microVMs and prove
destruction evidence. T054 must execute fingerprint/correlation, evidence/privacy, Fast/Deep,
latency, reliability, and capacity gates. Neither task may infer a passing result from this corpus.

## T053 Production-Equivalent Isolated Integration Gates

The repository-side T053 package is release-blocking unless all of the following are true without
running a local scanner, microVM, or Kubernetes workload:

- exactly 41 T052-designated cases expand in canonical order to 123 unique case-profile cells, with
  every source snapshot, case, fixture, profile, scanner, selected boundary, provisioning contract,
  and closed materialization-policy digest rebound;
- one immutable dependency set contains every required scanner-set/image/wrapper/rule/database/
  schema/normalizer, microVM kernel/rootfs, materializer/runner/harness, provider-policy, and
  trust-policy artifact with digest, signature, and provenance references and a maximum 24-hour
  validity window;
- plan identity is stable under input reordering and requires independent Security Engineering and
  Scan Platform signatures whose timestamps are both strictly earlier than the earliest receipt
  execution start;
- every accepted cell has one unique attempt, sandbox, workload, provider attestation, runtime
  attestation, and receipt, with no reuse across the 123-cell set;
- actual materialization counts and outcome equal the cell's exact projection and expected control
  outcome; scenario-name branching, customer content, SCM credentials, arbitrary command/argv/env/
  script/URL, package install, repository build, and dynamic test remain absent;
- all five phase observations report zero public-internet connection, byte, DNS, and destination
  activity, and all eight prohibited-effect counters equal zero;
- credential wipe, process-tree termination, writable-volume destruction, result-ingress closure,
  microVM termination, and final audit are all `VERIFIED`, digest-bound, provider/runtime signed,
  and completed no later than 60 seconds after cleanup starts;
- trust keys are canonical Ed25519 SPKI identities, the external trust-bundle bytes match the
  dependency-set `TRUST_POLICY` digest, and stale/future, wrong-role, changed-key, changed-payload,
  or invalid signatures fail closed; and
- the verifier derives its evaluation instant only from a service-owned trusted UTC clock, rejects
  any caller-selected time argument, and evaluates dependency and receipt freshness against that
  instant; and
- filesystem tests reject missing/extra/changed assets, noncanonical UTF-8/NFC/LF, BOM, NUL, CRLF,
  symlink/junction, real-path escape, and before/open/after identity drift.

The aggregate contract has exactly three outcomes. Zero or a valid strict subset of 123 receipts is
`PENDING_PROVIDER_EXECUTION`; any invalid observation is `FAILED`; only both plan approvals and all
123 unique dual-signed valid receipts are `PASSED`. A pass sets only `t054EntryAuthorized=true`.
Finding, policy, publication, deployment, and production-readiness authority remain false.

`corepack pnpm qualification:validate` validates only the immutable handoff and must report live
evidence as pending. `verify-isolated-integration-evidence.mjs` uses exit code 2 for pending, 1 for
failed, and 0 only for a complete cryptographically valid external bundle. T053 itself stays open
until a production-equivalent provider supplies the real 123-cell and destruction evidence; CI or
repository fixtures must never manufacture it.

## T054 End-to-End Qualification Gates

Repository validation first proves an exact 3,462-cell manifest and must return
`BLOCKED_T053_QUALIFICATION`; it cannot issue a plan or count any run until an independently signed
T053 `PASSED` result grants T054 entry. The immutable denominator is 1,880 candidate golden cells,
940 same-negative-corpus baseline cells, 102 candidate fingerprint/privacy end-to-end cells, and
540 performance cells: 30 candidate plus 30 baseline measurements for each of nine fixed
profile-size-hardware buckets.

Before any T054 plan exists, the verifier must load the exact T053 dependency set bound by the
passing result and require the same provider ID and provider-adapter ref in T054. It must also
load every T054 artifact's full signature envelope and provenance statement, recompute their
digests, verify both Ed25519 signatures as `SUPPLY_CHAIN_AUTHORITY`, and bind provenance subject,
source, builder, and materials to that artifact. It then verifies the signed closed set covering
all records. The trust bundle digest comes only from independent process configuration
(`SAST_T054_TRUST_POLICY_DIGEST`), never from the submitted dependency/evidence set alone.

External execution is release-blocking unless every receipt:

- binds the exact manifest, dependency set, plan, candidate and baseline scanner-set digests,
  provider, hardware class, case, profile, and cell;
- contains one fresh microVM attempt or one infrastructure-failed attempt followed by exactly one
  fresh retry, with no identity or attestation reuse across the complete evidence set;
- preserves every attempt in the eligible reliability denominator and reports bounded latency,
  CPU, memory, disk, zero egress, all eight zero-tolerance counters, and six cleanup controls within
  60 seconds;
- proves all nine queue-to-cleanup phases and the exact normalized/fingerprint/correlation/
  coverage/policy/evidence digests for a completed cell; and
- carries independent valid Ed25519 signatures from the microVM provider, qualification runtime,
  and telemetry authority after execution, while both plan approvals strictly predate execution.

The offline verifier recomputes rather than accepts the following aggregates:

| Gate | Threshold |
|---|---:|
| Golden exact-case conformance | 100% |
| Must-detect recall | >= 95% |
| Critical/High precision | >= 90% |
| Prior must-detect recall | 100% |
| Candidate minus baseline false-positive rate | <= 2 percentage points |
| Scanner-defect plus infrastructure-failure attempts / eligible attempts | <= 2% |
| Candidate/baseline p95 per profile-size bucket | <= 20% increase |
| Fast / Deep candidate p95 | <= 10 / 45 minutes |
| Fingerprint/correlation, evidence/privacy, and capacity fixtures | 100% each |
| Cross-tenant, secret, escape, stale publication, egress, missing destruction, evidence-policy, unsigned execution | exactly 0 |

Resource maxima must also remain within the immutable profile CPU, memory, disk, and cumulative
timeout limits. A valid strict receipt subset is `PENDING_PROVIDER_EXECUTION`; malformed, missing-
sample-at-completion, stale, reused, unsigned, drifted, incomplete, over-limit, or threshold-
breaching evidence is `FAILED`. Only the complete passing set authorizes T055 entry. It never grants
finding, policy, publication, deployment, Kubernetes, or production-readiness authority.

## T055 Supply-Chain and Rollback Qualification Gates

Repository validation first proves an exact 169-cell manifest and must return
`BLOCKED_T054_QUALIFICATION`. No plan or receipt can count until a Qualification Authority signature
binds the exact T054 manifest, `PASSED` result, dependency set, complete artifact-verification set,
execution plan, and T055 manifest. The T054 and T055 provider ID and provider-adapter ref must
match. Trust-bundle bytes are accepted only when their digest equals independently configured
`SAST_T055_TRUST_POLICY_DIGEST`.

Before execution, all 36 T054 dependency artifacts must have their complete signature and
provenance envelopes reloaded, both envelope digests recomputed, provenance subject/source/
builder/materials rebound, and both `SUPPLY_CHAIN_AUTHORITY` Ed25519 signatures verified. For every
profile, Qualification Authority and Supply Chain Authority must sign the exact durable prior
rollback-ledger head digest, sequence, digest-bound reference, provider, and candidate/baseline
release sets before the attestations enter the plan. Security Engineering and Scan Platform
approvals must bind that exact plan strictly before the earliest submitted receipt or attempt.

The immutable denominator and thresholds are:

| Gate | Threshold |
|---|---:|
| Artifact mount/rehash, digest-reject, signature-reject, provenance-reject drills | 36 each |
| Unlisted component rejected before execution | 1 of 1 |
| Candidate/baseline internal vulnerability DB mirror accepted | 2 of 2 |
| Candidate/baseline stale vulnerability DB rejected before execution | 2 of 2 |
| Candidate/baseline network enrichment rejected before egress | 2 of 2 |
| Canonical result schema accepted | 1 of 1 |
| Incompatible and malformed/oversized result schemas rejected before execution | 2 of 2 |
| Ordered rollback phases | 5 per profile, 15 total |
| Pre-execution rejections | exactly 115 |
| Allowlisted artifact invocations | exactly 39 |
| Network egress and production mutation | exactly 0 |
| Customer content/code, package install, repository build, dynamic test | exactly 0 |
| Cleanup within 60 seconds | 169 of 169 |

Every receipt must bind the exact cell and upstream chain; use globally unique cell, receipt,
attempt, sandbox, workload, provider/runtime attestation, and audit identities; and carry valid
Supply Chain Authority, MicroVM Provider, and Qualification Runtime Ed25519 signatures. Read-only
positive mounts must rehash to the expected artifact and exact signature/provenance envelope
digests. Negative cells must reject before invocation or egress and retain the observed failure.

For every profile, rollback must bind exact candidate/baseline release-set digests and prove in
order: candidate suspension, queue-admission fence, in-flight abort and cleanup, derived and
reverified last-known-good target, and baseline `STANDBY -> ACTIVE` activation through an append-
only ledger entry. Candidate invocation after the fence is exactly zero. The final receipt must
reference its exact approved head attestation, repeat the attested previous digest, increment the
attested sequence by exactly one, and bind the new entry digest to both the head attestation and the
receipt audit ref.

A valid strict subset is `PENDING_DRILL_EXECUTION`; missing T054 evidence remains
`BLOCKED_T054_QUALIFICATION`; malformed, stale, reused, unsigned, cross-provider, over-SLO,
out-of-order, ledger-invalid, or zero-tolerance-breaching evidence is `FAILED`. Only all 169 passing
cells authorize T056 entry. They never grant finding, policy, publication, deployment, Kubernetes,
production mutation, or production-readiness authority.

## Canary and Continuous Production Gates

At every canary step compare candidate and last-known-good by profile and repository size:

- finding volume and Critical/High volume delta
- false-positive feedback, waiver, and suppression delta
- scanner failure/timeout and artifact rejection delta
- p50/p95 latency and CPU/memory/disk delta
- incomplete coverage and external-publication denial counts
- cleanup lag, egress denial, quarantine, and kill-switch signals

Automatic canary pause occurs on any zero-tolerance event, threshold breach, missing telemetry,
incomplete coverage, or unexplained completed-scan-normalized Critical/High rate change above
20%. `PAUSED` is terminal for that
candidate-manifest/profile pair. Recovery requires a new signed candidate manifest, new T047
evidence and human approvals, and a new rollout whose observation clock and sample counts begin
at zero; the old rollout and decisions remain immutable.

Production remains eligible only while rolling 24-hour and 7-day windows meet all security
gates, scanner failure <= 2%, absolute lane p95 SLOs, and no more than a two-percentage-point
false-positive increase against the approved baseline. A breach activates the relevant kill
switch or rollback path from `rule-governance.md`.

## Go/No-Go Record

Every promotion and production-readiness decision stores:

- candidate and baseline digests for scanner, wrapper, profile, rules, databases, schema,
  and normalizer
- corpus revisions, denominators, numerators, rates, latency distributions, and resource data
- canary cohort definition and observation interval
- every passed/failed/not-applicable gate with rationale
- security and platform approval references
- rollback target, kill-switch reference, decision time, and decision actor

`NOT_APPLICABLE` is allowed only for a capability the selected profile explicitly does not
claim. It cannot be used for missing evidence. The decision is machine-readable and immutable.

## Required Verification Layers

1. Unit/contract tests for profiles, wrappers, failure, coverage, evidence, and rule state.
2. Golden normalizer/parser and fingerprint/correlation fixtures.
3. Scanner integration tests with pinned real binaries/images and no network enrichment.
4. Malicious-repository microVM tests with egress denial and destruction evidence.
5. End-to-end Fast/Deep scans through queue, result ingress, policy, evidence, and cleanup.
6. Supply-chain verification for image/bundle/database/schema provenance and rollback.
7. Canary telemetry replay and kill-switch propagation drills.

Passing repository unit tests alone is not production readiness. Provider-specific live
microVM and Kubernetes evidence remains part of deployment execution governed by the 005
operations package.
