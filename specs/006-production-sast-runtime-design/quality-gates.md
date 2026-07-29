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
  JWT, assignment, and admitted high-entropy corpus removal from display fields using the
  one fixed marker, with zero matched value or length disclosure.
- 100% complete-batch rejection when any detected value occurs in ingestion/scope/preflight
  bindings, path, semantic rule, scanner hint, rule/package/version, anchor, sink, category,
  or check identity; no secret-derived replacement identity or digest may be constructed.
- Exactly zero matched values, matched-value digests, raw candidates, pre-redaction
  candidate-batch digests, or rejected bindings in redaction result, log, audit, dashboard,
  evidence, policy, or AI surfaces. A rejection also contains no accepted-artifact digest;
  success may retain only the pre-existing accepted-artifact provenance digest.
- 100% canonical source-batch and accepted-disposition digest verification plus pre/post-pass
  active-retention checks; malformed, forged-marker, invalid platform-set, clock rollback,
  and expiry-crossing cases fail closed.
- 100% secret-value redaction before persistence outside the scanner artifact quarantine;
  T035 success remains `durablePersistenceAllowed=false` until T036 fingerprinting.
- 100% fingerprint stability for line/branch/commit-only changes.
- 100% provenance preservation during correlation; no lower-severity result may hide a
  higher-severity authoritative result.
- 100% complete-coverage requirement before external comment/block, AI advisory, or fixed
  transition.

## Canary and Continuous Production Gates

At every canary step compare candidate and last-known-good by profile and repository size:

- finding volume and Critical/High volume delta
- false-positive feedback, waiver, and suppression delta
- scanner failure/timeout and artifact rejection delta
- p50/p95 latency and CPU/memory/disk delta
- incomplete coverage and external-publication denial counts
- cleanup lag, egress denial, quarantine, and kill-switch signals

Automatic canary pause occurs on any zero-tolerance event, threshold breach, missing telemetry,
or unexplained Critical/High volume change above 20%. Resume requires a new evidence record and
human approvals; the clock and minimum scan count restart for the affected step.

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
