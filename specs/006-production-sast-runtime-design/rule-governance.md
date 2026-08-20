# Rule Governance: Production SAST Runtime

## Objective

Make every production rule decision reproducible, reviewable, tenant-safe, and reversible.
Rules are platform supply-chain artifacts, not customer-provided executable configuration.
The immutable bundle used by a scan is fixed in its canonical scan plan and remains
discoverable after the bundle is retired.

## Governed Artifacts

| Artifact | Owner | Mutability | Required identity |
|---|---|---|---|
| OpenGrep rule bundle | Security Engineering | Immutable after build | bundle ID, semantic version, SHA-256 digest |
| Trivy checks bundle | Security Engineering | Immutable after build | bundle ID, semantic version, SHA-256 digest |
| Trivy vulnerability database snapshot | Security Operations | Immutable snapshot | database version, published time, SHA-256 digest |
| Scanner image/binary | Platform Engineering | Immutable | image digest and upstream version |
| Normalizer/schema bundle | Scan Platform | Immutable | schema version and SHA-256 digest |
| Tenant rule policy | Tenant administrator | Versioned metadata | policy ID, version, tenant ID |
| Waiver/suppression | Authorized tenant reviewer | Append-only decision | finding/rule scope, reason, actor, expiry |

Every executable or parser-affecting artifact requires a signature, provenance reference,
compatibility record, and rollback reference. Artifact references use digests; mutable tags
and unpinned URLs are invalid production inputs.

## Rule Identity

Each rule has two identities:

- `ruleId`: scanner-specific ID used to locate the concrete implementation.
- `ruleSemanticId`: platform-stable behavior family used for finding identity and migration.

Changing documentation, tags, or remediation text increments the rule revision without
changing `ruleSemanticId`. Changing the vulnerability predicate, source/sink model, default
severity, or finding identity semantics requires a new semantic ID or an explicit migration
record. Reusing a semantic ID for unrelated behavior is prohibited.

Rule metadata must include owner, capability, languages/formats, default severity,
confidence, CWE mapping, source and sink kinds where applicable, introduction version,
test fixture references, deprecation state, and replacement semantic ID when retired.

## Bundle Manifest

A signed bundle manifest contains only platform-controlled values:

- bundle ID, version, state, scanner kind, build timestamp, and source revision
- bundle digest and each member digest
- rule IDs, revisions, semantic IDs, and metadata digests
- compatible scanner versions and normalizer/schema versions
- golden, regression, malicious, and performance corpus result references
- signer identity, signature reference, and SLSA-compatible provenance reference
- rollout policy, kill-switch namespace, and rollback target

The immutable plan-visible bundle descriptor carries a bounded, code-unit-sorted,
unique-by-`ruleId` projection of those per-rule manifest fields. Normalizers must resolve
`ruleRevision` and `ruleSemanticId` from that signed projection; scanner output may select a
rule but cannot author or override its platform semantic identity.

The scanner wrapper verifies the manifest and member digests before execution. The result
ingress verifies that the reported bundle digest equals the plan. A customer cannot add
command-line flags, rule code, templates, post-processors, or executable configuration.

### T045 Planning and Ledger Boundary

- `sast-rule-bundle-manifest-v1` canonicalizes bounded member identities/digests, rule
  identity metadata, quality references, lifecycle state, rollback identity, and exact
  compatibility sets. It contains no executable rule body or customer content.
- A platform supply-chain authority must return a digest-bound
  `sast-rule-bundle-supply-chain-attestation-v1`. The installed default is unavailable and
  cannot self-attest a manifest.
- The database stores normalized immutable manifest/member/rule/compatibility rows,
  verification facts, and successful compatibility receipts. Denied evaluations write no
  receipt, and signature bytes or provenance payloads are never persisted.
- Planning compares the caller-visible descriptor with the verified manifest projection and
  checks the exact scanner version/image, wrapper, schema bundle, normalizer bundle, and
  profile before queue reservation. The receipt digest is part of the canonical scan key and
  immutable plan.
- T045 does not install a live registry signer verifier or microVM asset-mount verifier. The
  production sandbox provider must still rehash every mounted member before invocation; that
  provider rollout and its verification drill remain gated by T055 and the 005 deployment
  operations flow.

### T046 Semantic Metadata and Tenant Policy Boundary

- `sast-rule-semantic-identity-v1` makes capability, category, language/format coverage,
  predicate, source/sink taxonomy, default severity/confidence, finding identity, and
  mandatory/optional tenant control one immutable semantic core. A semantic ID cannot be
  reused with a different core.
- `sast-rule-definition-metadata-v1` is reusable content metadata. Its digest intentionally
  excludes bundle and manifest identity, avoiding a circular digest with the T045 rule
  projection. `sast-rule-definition-metadata-binding-v1` separately binds that digest,
  scanner rule/revision, semantic identity, bundle, and exact verified manifest projection.
- Metadata stores owner, taxonomy, documentation, fixture, scanner-support, introduction,
  and deprecation/replacement references only. Every reference is bounded and digest-bound;
  rule bodies, source, secrets, mutable URLs, customer flags, plugins, and arbitrary
  configuration are absent.
- `sast-tenant-rule-policy-v1` accepts canonical approved rule/category decisions, literal
  normalized path prefixes, non-weakening severity floors, repository-scoped narrowing,
  existing waiver/suppression references, one effective window, actor, and audit reference.
  A repository override cannot re-enable a tenant-disabled selection or weaken its floors.
  Mandatory rules cannot be disabled without a future explicitly scoped authority contract.
  Policy-window and evaluation instants use exact UTC millisecond strings so digest identity
  cannot drift through the database `TIMESTAMP(3)` representation.
- The planner obtains the policy evaluation instant only from its injected service-owned UTC
  clock. Caller-controlled request timestamps never establish the policy window or receipt
  `evaluatedAt`; an unavailable, throwing, or invalid trusted clock fails closed before any
  successful receipt or queue reservation.
- Planning resolves the selected signed manifests and all metadata bindings into one
  content-free `sast-tenant-rule-policy-resolution-v1` receipt. Missing, extra, conflicting,
  expired, cross-tenant, unknown-selector, or mandatory-disable state writes no receipt and
  fails closed before canonical-key construction or queue reservation.
- The receipt identity, receipt digest, semantic metadata set, enabled/disabled binding sets,
  path exclusions, and severity floors are frozen into `SastScanPlan`. Normalized immutable
  PostgreSQL ledgers, restrictive exact-projection foreign keys, mutation-rejection triggers,
  and serializable exact replay preserve the decision after process restart.
- The verified tenant-policy receipt remains committed to the current canonical plan. T047
  introduced `sast-canonical-scan-key-v3` with the stable lifecycle transition/evidence/approval
  projection; T048 advances the current preimage to v4 with stable canary rollout/membership/
  bucket identity. Both evaluation receipts remain in the immutable plan.
- T046 grants no lifecycle transition, scanner execution, waiver creation, finding mutation,
  publication, AI, or SCM authority. Those require their independently scoped runtime gates.

### T047 Promotion and Lifecycle Boundary

- `sast-rule-bundle-promotion-evidence-v1` binds a candidate and distinct last-known-good
  baseline to the exact T045 manifest/verification records, profile, rollback digest, immutable
  corpus/environment references, sufficient samples, all quantitative gates, and a trusted
  measurement time. It is automated evidence only and cannot approve a transition.
- `sast-rule-bundle-promotion-approval-v1` records one human approval from Security Engineering,
  Scan Platform, or Security Operations. Candidate self-approval, duplicate roles, duplicate
  approvers, pre-evidence approval, and post-transition approval fail closed.
- Every append-only `sast-rule-bundle-lifecycle-transition-v1` edge requires Security Engineering.
  `ACTIVE` and `RETIRED` additionally require an independent Scan Platform or Security Operations
  approval. The sequence and previous digest form one immutable history per manifest/bundle.
- `CANARY -> ACTIVE`, suspension, and rollback require exact digest-bound receipts from
  `CANARY_OBSERVATION`, `EMERGENCY_SUSPENSION`, and `ROLLBACK` authorities respectively. The
  T048 canary authority, T049 emergency-suspension authority, and T050 rollback authority are
  installed at separate router seams. Each production evidence/signature adapter retains its
  explicit unavailable default until qualified.
- Planning first verifies T045 compatibility, then revalidates the latest lifecycle state and
  persists `sast-rule-bundle-lifecycle-selection-v1`, then resolves T046 tenant policy. Only the
  latest `CANARY` or `ACTIVE` state is selectable; every other state, stale transition, digest
  drift, unavailable store, or invalid clock produces no successful receipt or queue reservation.
  Exact replay rechecks latest state, and ordered manifest-row locks commit all scanner-set
  selection receipts atomically so a concurrent or later-bundle failure leaves no partial set.
- Queue reservation locks a trigger-maintained latest-transition head per manifest in canonical
  order and revalidates the selected transition/evidence/approval projection and persisted
  selection receipt. The database insert trigger enforces the same fence for direct writes.
- T047's `sast-canonical-scan-key-v3` commits the stable lifecycle authorization projection, existing
  compatibility receipt digest, and tenant-policy receipt. The immutable plan retains the
  lifecycle selection receipt, but the key excludes its evaluation-time-derived ID/digest. The
  migration rejects deployment while any v2 plan or reservation is non-terminal; terminal v2
  history is retained and never rewritten or replayed as v3 work.
- T047 itself did not assign tenant-safe canary cohorts or observe production canaries. T048 owns
  those boundaries, T049 owns kill-switch actuation and emergency suspension, and T050 owns only
  evidence-derived last-known-good rollback. Scanner execution, scanner-set mutation,
  waiver/finding mutation, external publication, AI authority, and SCM writes remain independently
  gated elsewhere.

### T048 Deterministic Canary and Observation Boundary

- `sast-rule-bundle-canary-rollout-v1` is unique per candidate manifest/profile and binds the
  exact latest `CANARY` candidate, distinct latest `ACTIVE` baseline, T045 manifest/bundle,
  T047 evidence/transition, signed profile, cohort-key reference/version, eligibility policy,
  observation source, and six-step order. It contains no key material or repository/finding
  content. `PAUSED` and completed rollouts cannot be resumed or recreated for that pair.
- Platform-managed eligibility records internal corpus, internal repository, or eligible
  production classification and explicit contractual/residency exclusions. Stable membership is
  HMAC-SHA-256 over length-framed tenant, repository binding, profile, and rollout identity. The
  first eight digest bytes modulo 10,000 define the bucket. Application and database recompute
  it; only digest and bucket persist.
- Planning applies compatibility -> lifecycle -> canary -> kill switch -> tenant policy. Candidate selection
  requires the exact current rollout step/head and membership. A supplied candidate resolving to
  baseline or exclusion is rejected rather than rewritten after compatibility/lifecycle
  verification. Trusted orchestration supplies a separately verified exact `ACTIVE` baseline set
  for non-cohort production; exclusion never silently falls back to experimental code. Active
  bundle descriptors carry no canary assignment.
- `sast-canonical-scan-key-v4` adds stable rollout, membership, bucket, and candidate-assigned
  identity. Assignment receipt, current step, and mutable step-head binding stay in the immutable
  plan but out of the key. Queue admission locks lifecycle heads and then the canary head and
  revalidates the persisted candidate receipt; the v4 cutover drains non-terminal v3 work.
- Content-free terminal observations rebind the exact immutable candidate/baseline plan,
  assignment, attempt interval, T039 coverage, T040 publication authority, rollout observation
  source, and telemetry source. The store derives coverage/publication facts from durable rows and
  records scalar volume, feedback, failure, timeout, latency/resource, coverage/publication,
  egress, cleanup, quarantine, kill-switch, and eight zero-tolerance counters only.
- Collection requests identify only rollout, scope, scan, and attempt. Candidate/baseline role and
  repository-size bucket come from the trusted source and cannot be caller-selected.
- A step decision accepts no caller-provided cutoff or observation list. It uses trusted service
  time, locks the head, binds every committed observation in that exact closed window, and
  database constraints reject either an omitted observation or an extra/foreign binding before
  recomputing the scalar aggregates.
- The first four steps require 200 completed scans per arm and 24 hours; 25% and 100% require
  1,000 per arm and 48 hours. All size buckets must compare both arms. Candidate false-positive
  increase is at most two percentage points, failure rate at most 2%, p95 latency and
  completed-scan-normalized Critical/High rate increase at most 20%, and Fast/Deep absolute p95
  remains at most 10/45 minutes. Every zero-tolerance security counter is zero.
- Insufficient time or samples is `PENDING`; missing telemetry, incomplete coverage/size
  comparison, a threshold breach, or a zero-tolerance event is terminal `PAUSED`; only no reasons
  is `PASSED`. Six ordered
  passes create the sole immutable receipt accepted for that candidate's `CANARY -> ACTIVE` edge.
  The production observation-source port defaults unavailable until production qualification
  installs an exact durable adapter; T048 never fabricates evidence.

### T049 Signed Kill-Switch and Emergency-Suspension Boundary

- Every control is one signed, platform-managed, append-only `ACTIVATE | DEACTIVATE` decision
  chain. Its selector, sequence/predecessor, incident, actor/role, reason, effective/review/expiry
  times, rollback-target reference, signature/provenance references, and audit reference are
  digest-bound. Security On-Call and Platform On-Call are the only accepted actor roles.
- Selector scope is exact: global SAST, scanner/version, rule-bundle digest, semantic rule ID,
  signed profile ID/digest, tenant, repository binding, capability, or global/tenant/repository
  external publication. Customer input, mutable tags, repository/finding content, signature
  bytes, provenance payloads, secrets, and arbitrary JSON are absent.
- A decision cannot commit without an exact immutable trusted-signature/provenance verification.
  The default production signature authority is deliberately unavailable until a qualified
  adapter is installed. Every gate compares its boundary time with a service-owned trusted clock
  under a bounded skew; caller-selected stale or future time is rejected. An invalid clock,
  missing verification, broken/forked chain, future activation, active expired head, or
  unavailable store is authority failure and fails closed.
- The only mutable state is a database-trigger-owned selector head. Durable inactive
  placeholders are created before ordered locks, closing the first-activation/absent-head race.
  Direct head mutation and update/delete of any decision, verification, evaluation, or
  suspension receipt are rejected by PostgreSQL.
- Planning evaluates the complete content-free runtime context after canary and before tenant
  policy. Only `CLEAR` produces a `sast-kill-switch-planning-v1` descriptor. The descriptor is
  retained in the immutable plan but excluded from `sast-canonical-scan-key-v4`, because switch
  state is mutable operational authority rather than fixed source identity.
- Queue admission locks every applicable selector head in canonical order after lifecycle and
  canary fences, reconstructs the content-free context and selector keys from the immutable plan,
  and revalidates the context digest plus exact planning evaluation/head set. The database
  insertion trigger independently compares the normalized global, tenant, repository, profile,
  scanner-version, bundle, semantic-rule, and capability identities and their exact total against
  that plan. A direct writer cannot omit an active selector, and a concurrent activation therefore
  wins before admission or serializes after an already-authorized reservation.
  The context permits two rule bundles and at most 50,020 selector bindings. Evaluation and queue
  admission acquire the bounded set in one ordered set-based lock and detect drift with an
  anti-join, avoiding one query per semantic rule.
- Fresh purpose-bound evaluations occur at `SCANNER_START`, `ARTIFACT_ACCEPTANCE`,
  `RETRY_ADMISSION`, `COVERAGE`, `EXTERNAL_PUBLICATION`, and `AI_ADVISORY`. Scanner evaluation
  occurs only after creating the durable run and before any provider repository read or scanner
  process; an active switch records `KILLED` and cleanup remains mandatory. Artifact acceptance
  quarantines affected output, retry denies another attempt, and AI/publication calls receive no
  downstream authority. Authority unavailability is retryable only where the surrounding
  operational contract explicitly permits a safe retry; it never becomes `CLEAR`.
  Retry admission additionally invokes an independent current scanner-set availability authority;
  that port defaults unavailable and its exact current digest must match the kill-switch context.
  A clear switch therefore cannot authorize withdrawn images, wrappers, rules, or databases.
  At artifact acceptance, T049 is an outer short-circuit only: `ACTIVE` quarantines before any
  downstream authority call, while `CLEAR` must still pass the independent Data/Security Plane
  acceptance authority. Its production default remains unavailable, so enabling kill-switch
  reads cannot accidentally authorize artifact retention.
  A recovered `ACCEPTED` disposition intent is evaluated again immediately before storage apply;
  a new denial persists a replacement quarantine intent and operation before any storage call.
  AI evaluates before inference and again after completion immediately before persistence.
- T037 lifecycle coverage consumes a composite authority: a fresh T049 `COVERAGE` evaluation is
  the outer gate, and only `CLEAR` with `UNCHANGED` delegates to the independent T040 freshness/
  comparability authority. `ACTIVE` returns rejected coverage and unavailable T049 authority
  remains unavailable; neither condition invokes T040.
- External comment planning and every comment-dispatch worker claim each perform a fresh
  `EXTERNAL_PUBLICATION` evaluation over the persisted scan. Activation after planning therefore
  prevents claim mutation and produces zero publisher calls; an unavailable authority returns no
  publication authority.
- Current effective coverage is projected independently from immutable T039 factual coverage.
  Semantic-rule/capability-only matches yield `PARTIAL`, publication-only matches yield
  `UNCHANGED`, and any affected scanner, bundle, profile, tenant, repository, or global runtime
  scope yields `FAILED`. Historical findings and coverage decisions are never rewritten.
- An active applicable global, bundle, scanner-version, semantic-rule, or exact signed-profile
  decision can issue one immutable `sast-kill-switch-emergency-suspension-v1` receipt for the
  exact latest `CANARY | ACTIVE -> SUSPENDED` edge. The lifecycle trigger rebinds its manifest,
  bundle, transition, promotion evidence, active decision set, and time. At transition commit,
  PostgreSQL locks and recomputes the full applicable active selector set, count, and canonical
  digest; deactivation or replacement of any captured selector, including a non-trigger selector,
  rejects the receipt. It cannot authorize `SUSPENDED -> ROLLED_BACK`; the installed T050 path is
  a separate signed and independently approved authority.
- Canary automation accepts only a T048 step-decision ID/digest. Under lifecycle-then-canary head
  locks it reloads the current immutable `PAUSED` decision, rollout, and normalized hard-failure
  reasons and derives `CANARY_PAUSED` or `ZERO_TOLERANCE`. The manifest, bundle, signed profile,
  lifecycle target, reason set, and time are never caller fields, and the signal itself grants no
  activation, suspension, or rollback authority.

### T050 Last-Known-Good Rollback Boundary

- `sast-rule-bundle-rollback-request-v1` contains only the exact suspended candidate transition
  plus bounded incident, actor, reason, audit, signature, provenance, and command-time metadata.
  Baseline manifest/bundle/transition fields are forbidden caller input.
- The service derives the distinct baseline solely from the candidate's original T047 promotion
  evidence and rebinds `rollbackTargetDigest === baselineBundleDigest`. It then revalidates both
  T045 manifests and attestations, common bundle/scanner identity, shared signed profile support,
  the exact T049 emergency-suspension receipt, candidate latest `SUSPENDED` head, and baseline
  latest `ACTIVE` head.
- One signed `sast-rule-bundle-rollback-command-v1` has a 15-minute lifetime. Its signature and
  provenance port defaults unavailable. Receipt issuance requires exactly one fresh Security
  Engineering approval plus exactly one fresh independent Scan Platform or Security Operations
  approval; the command actor, duplicate approver, duplicate role, and two platform-side roles are
  rejected.
- Command, verification, approval, receipt, and receipt-approval ledgers are normalized,
  content-free, append-only, and exact-replay only. Candidate and baseline lifecycle heads are
  locked in canonical manifest-ID order during command, receipt, and lifecycle checks. PostgreSQL
  revalidates the suspension provenance, evidence-derived target, approvals, signature facts, and
  both current heads at the direct lifecycle insert boundary.
- The digest-bound receipt authorizes only the candidate's next
  `SUSPENDED -> ROLLED_BACK` append. It cannot mutate the baseline, choose or write a scanner set,
  alter historical manifests/plans/findings/coverage/evidence, change policy/waivers/suppressions,
  publish externally, call AI, or write to SCM. The receipt's baseline identity is a handoff only;
  trusted scanner-set ownership must separately select that still-`ACTIVE` baseline and pass the
  normal planning and queue gates.

### T051 Golden Qualification Corpus Boundary

- T051 freezes only the versioned golden positive/negative and prior must-detect inputs. Its
  `sast-qualification-corpus-case-v1`, `sast-qualification-prior-release-manifest-v1`, and
  `sast-qualification-corpus-snapshot-v1` contracts are exact-key, canonical, digest-derived, and
  platform-owned; corpus validity cannot transition a
  rule bundle or create finding, policy, AI, publication, SCM, or deployment authority.
- The v1 snapshot contains 400 one-to-one positive/negative pairs across 20 Critical/High semantic
  rule families. Every rule has 20 of each polarity, every positive belongs to the prior
  must-detect set in the initial imported release manifest, every supported profile meets the
  200/200 floor, and patched, sanitizer, safe-API, comment/string, and generated/vendor negatives
  each have a non-zero, semantically applicable denominator. Later positives do not become prior
  cases until a separately reviewed release manifest authenticates them.
- Every case binds owner, license, digest-bound provenance, corpus/rule revision, exact scanner and
  profile scope, expected result, source bytes/digest/range/anchor, and a unique root-confined
  future materialization path. Customer content/configuration, package installation, builds,
  dynamic execution, network use, and mutability are structurally forbidden.
- The deterministic generator is reviewed code. The prior manifest binds each historical case
  ID/digest/key/revision/rule/severity, its digest is pinned in code, and bootstrap refuses
  overwrite. The loader validates that authority before regenerating expected assets in memory
  and rejects any manifest/snapshot/source-set/byte/digest/range drift, unsafe or duplicate path, link,
  non-canonical text, oversize, extra field/file, or authority widening. CI runs the validator and
  hostile contract/filesystem tests on every change.
- A T051 pass means only that the golden and historical denominator is authentic and sufficient.
  T052 supplies the remaining corpus inputs below; T053-T056 must still produce isolated
  execution, performance, supply-chain/drill, and immutable go/no-go evidence before rollout.

### T052 Multi-Class Qualification Corpus Boundary

- T052 freezes exactly 84 platform-owned declarative cases: 16 schema/parser, 25
  malicious-repository, 17 fingerprint/correlation, 17 evidence/privacy, and 9 performance. Every
  required scenario occurs exactly once and is bound to an exact expected control outcome and the
  T053/T054 stage that must later provide evidence.
- Fixtures contain only typed bounded parameters, canonical base64 byte segments, and allowlisted
  declaration actions. General commands, argv, environment, executable configuration, customer
  content, package installation, build, dynamic execution, scanner execution, host mutation,
  network access, and all finding/policy/publication/promotion/readiness authority are rejected.
  Live symlinks, FIFOs, devices, archive bombs, and expanded performance trees are not checked in.
- Revision `1.0.2` binds profile-relative boundaries—including artifact bytes and record count—to
  the exact selected-profile limit plus one and gives their materializer a generic segment formula.
  JSON depth and string size bind the shared validator's exact limit plus one. It also declares both
  edges of a symlink cycle, preserves binary and malformed UTF-8 as raw octets, and records complete
  fingerprint vectors and concrete correlation relationships. A later runner must consume those
  values directly and cannot infer a test from the scenario name.
- The performance denominator has small, medium, and exact-large-limit buckets for each v1 profile,
  binds one immutable hardware-class reference/digest, and requires 30 post-warm-up measurements
  per bucket. T052 cannot claim a latency, reliability, or capacity result.
- The deterministic generator and root-confined loader bind every fixture path/ID/digest/byte count,
  case, class/scenario/profile index, hardware reference, and derived set digest. Exact root/class/
  file allowlists, no-follow access where supported, before/open/after identity, canonical
  UTF-8/NFC/LF, and hostile-shape tests fail closed on substitution or widening.
- A T052 pass authenticates only inputs. It cannot qualify or transition a rule bundle, establish
  detection/precision/privacy/isolation/performance success, or authorize production. T053 is the
  first materialization and production-equivalent isolated execution stage.

### T053 Isolated Integration Qualification Boundary

- The repository handoff contains exactly 123 canonical cells: 41 T052 schema/parser and
  malicious-repository cases across three signed profiles. It binds every fixture, scanner/profile,
  materialization projection, provisioning contract, and closed guest-only action policy.
- A live dependency set binds all scanner/rule/database/schema/normalizer, microVM,
  materializer/runner/harness, provider, and trust artifacts. The plan is unusable without detached
  Security Engineering and Scan Platform approvals.
- One fresh production-equivalent microVM and one unique receipt are required per cell. Provider
  and qualification-runtime Ed25519 signatures bind exact materialization/outcome, phase egress,
  zero prohibited effects, and six destruction proofs completed within 60 seconds.
- A valid partial run remains `PENDING_PROVIDER_EXECUTION`; any violation is `FAILED`; exactly 123
  valid receipts may authorize T054 entry only. T053 evidence cannot qualify, promote, activate,
  suspend, roll back, or select a rule bundle and never grants production-readiness authority.
- CI validates the manifest, loader, plan and cryptographic verifier with synthetic signing keys,
  but synthetic receipts are verifier tests only and never count as T053 execution evidence.

### T054 End-to-End Qualification Boundary

- T054 planning is impossible until an exact T053 `PASSED` result and Qualification Authority
  Ed25519 attestation authorize entry; repository validation remains
  `BLOCKED_T053_QUALIFICATION` and has no execution authority.
- The immutable denominator is exactly 3,462 cells: every T051 candidate case/profile, the same
  negative cases against the baseline, all T052 fingerprint/privacy case/profiles, and 30
  candidate plus 30 baseline measurements in every fixed performance bucket.
- The dependency set binds distinct candidate/baseline scanner assets and every shared pipeline,
  provider, hardware, telemetry, and trust artifact. Detached Security Engineering and Scan
  Platform approvals strictly predate all attempts.
- The exact T053 dependency set is mandatory. Its provider and adapter must equal T054, so isolated
  qualification cannot be transferred to another provider. Each complete artifact-signature
  envelope and provenance statement is loaded, digest-recomputed, and individually verified with
  the `SUPPLY_CHAIN_AUTHORITY` Ed25519 key; provenance subject/source/builder/materials are rebound
  to the artifact before the closed verification-set signature is checked. The trust bundle digest
  is pinned independently through `SAST_T054_TRUST_POLICY_DIGEST`.
- One infrastructure retry is permitted, but both fresh microVM attempts remain signed and counted.
  Global receipt/cell/attempt/sandbox/workload/provider/runtime/telemetry identities cannot be
  reused. All queue-to-cleanup phases, resource observations, zero-tolerance counters, and cleanup
  controls are independently signed by provider, runtime, and telemetry roles.
- The verifier accepts no aggregate input and recomputes every sample count, correctness,
  precision/recall, false-positive delta, failure rate, per-bucket p50/p95, absolute SLO, capacity,
  resource maximum, and security count from receipts. A partial valid run is pending; a breach is
  failed; only the complete passing set grants T055 entry.
- T054 evidence cannot qualify itself, select or mutate a lifecycle state, publish a result,
  deploy Kubernetes, or establish production readiness. Synthetic tests prove only verifier
  behavior and never satisfy the external run.

### T055 Supply-Chain and Rollback Qualification Boundary

- T055 planning is impossible until the exact T054 manifest, `PASSED` result, dependency set,
  complete artifact-verification set, and execution plan are rebound by a Qualification Authority
  Ed25519 signature. T054 and T055 must use the same provider and adapter; repository validation
  remains `BLOCKED_T054_QUALIFICATION`.
- The immutable denominator is exactly 169 cells: four drills for each of all 36 T054 artifacts,
  one unlisted-component rejection, six vulnerability-database drills, three result-schema drills,
  and five ordered rollback phases for each of three profiles. Exactly 115 reject before execution
  and exactly 39 allow one read-only artifact invocation.
- The T055 trust root is independently pinned through `SAST_T055_TRUST_POLICY_DIGEST`. Each artifact
  signature and provenance envelope is reloaded, digest-recomputed, provenance-rebound, and
  Ed25519-verified before any drill evidence is admitted.
- Qualification Authority and Supply Chain Authority independently sign each profile's durable
  prior rollback-ledger head digest, sequence, digest-bound reference, provider, and exact release
  sets before plan approval. Security Engineering and Scan Platform approvals bind those exact
  attestations and strictly predate the earliest submitted receipt or attempt. Supply Chain
  Authority, MicroVM Provider, and Qualification Runtime sign every receipt; all execution,
  attestation, audit, receipt, and cell identities are globally single-use. Customer code, package
  installation, repository builds, dynamic tests, public egress, and production mutation remain
  prohibited.
- Rollback binds exact candidate/baseline release sets and proves suspension, queue fencing,
  in-flight abort and cleanup, last-known-good derivation and reverification, zero post-fence
  candidate invocation, and baseline `STANDBY -> ACTIVE` through an append-only audit entry that
  references the exact plan-bound head attestation, repeats the attested previous digest, and uses
  exactly `head.sequence + 1`. Failed evidence remains visible and cannot be erased by a favorable
  aggregate.
- A valid subset is `PENDING_DRILL_EXECUTION`; any invalid or zero-tolerance evidence is `FAILED`;
  all 169 passing cells grant T056 entry only. T055 cannot create findings, alter policy, select or
  mutate production lifecycle state, publish, deploy Kubernetes, or establish production readiness.
  Synthetic signing tests prove verifier behavior only and never satisfy the external drill.

### T056 Immutable Production Go/No-Go Boundary

- T056 planning requires the exact T054/T055 manifest, entry, dependency, verification, plan, and
  passing-result chain on one provider/adapter, rebound by a Qualification Authority Ed25519 entry
  signature. The trust bundle is separately pinned through `SAST_T056_TRUST_POLICY_DIGEST`;
  submitted evidence cannot select its own root.
- The closed denominator is exactly 54 mandatory gates across six ordered evidence kinds:
  upstream qualification, repository assurance, canary telemetry replay, kill-switch propagation,
  rollback readiness, and the 005 reference-only handoff. Every v1 gate rejects
  `NOT_APPLICABLE`; no caller aggregate or caller-selected verification time exists.
- Each signed category binds candidate/baseline scanner sets, profiles, T051 current/prior and T052
  corpus authority, T054/T055 measurement digests, repository commit, digest-bound evidence,
  validity interval, and the category's signer roles. Upstream observations are recomputed from
  the signed results instead of trusted from the submission.
- A valid missing category or Security Engineering/Scan Platform approval remains
  `PENDING_FINAL_EVIDENCE`. Malformed, unsigned, stale, drifted, breached, or `NOT_APPLICABLE`
  evidence is `NO_GO`. Only all 54 passing gate results and both fresh plan signatures are `GO`.
- T056 never changes rule lifecycle, finding, policy, publication, SCM, AI, or production state.
  `GO` authorizes only entry to 005 deployment operations; deployment, Kubernetes execution,
  production mutation, and production-readiness authority remain false. Repository fixtures and
  CI remain `BLOCKED_T055_QUALIFICATION` and cannot replace external qualification evidence.

## Lifecycle

```text
DRAFT -> VALIDATED -> CANARY -> ACTIVE -> RETIRED
CANARY --suspend--> SUSPENDED <--suspend-- ACTIVE
SUSPENDED --rollback--> ROLLED_BACK
```

- `DRAFT`: isolated authoring only; never selectable by a production plan.
- `VALIDATED`: signature, provenance, compatibility, corpus, parser, security, and
  performance gates passed. Eligible for a controlled canary.
- `CANARY`: deterministically assigned production cohort; no cross-tenant comparison of
  source or evidence.
- `ACTIVE`: default bundle for a compatible profile after canary approval.
- `SUSPENDED`: immediately unavailable to new plans while investigation proceeds.
- `ROLLED_BACK`: replaced by the recorded last-known-good bundle; retained for audit.
- `RETIRED`: unavailable to new plans and outside normal rollback selection.

State changes are monotonic except an explicit suspension/rollback flow. Editing a bundle
in place, promoting by mutable tag, or returning a retired digest to active is forbidden;
the replacement is a newly versioned bundle.

## Promotion Evidence

Promotion from `DRAFT` to `VALIDATED` is fail-closed and requires:

1. artifact signature and provenance verification;
2. compatible scanner, wrapper, schema, and normalizer versions;
3. 100% golden-corpus execution and 100% prior must-detect regression recall;
4. at least 95% must-detect recall and at least 90% Critical/High precision;
5. 100% malicious-corpus control pass and malformed-artifact rejection;
6. no more than a two-percentage-point false-positive increase;
7. no more than 2% scanner failure rate, no more than 20% p95 latency regression, and the
   profile's absolute 10-minute Fast or 45-minute Deep p95 SLO;
8. zero cross-tenant, secret, sandbox-escape, or stale-publication events;
9. Security Engineering approval and a tested rollback reference.

The exact metric definitions, sample sufficiency requirements, observation windows, and
production gates are defined in `quality-gates.md`. Missing measurements fail the gate.

## Review and Separation of Duties

- The author cannot be the sole approver.
- Security Engineering approves rule behavior and vulnerability mappings.
- Scan Platform approves compatibility, normalizer behavior, and resource effects.
- Security Operations approves malicious-input and supply-chain evidence.
- Emergency suspension may be performed by the on-call security or platform role, but the
  action and reason must be audited and reviewed within one business day.
- Production signing identity is isolated from developer credentials and CI job logs.

At least two approvals are required for `ACTIVE`: one Security Engineering approval and
one Scan Platform or Security Operations approval. Automated evidence is necessary but is
not itself an approval.

## Canary Assignment

Canary assignment is deterministic from HMAC-SHA-256 over a version tag and UTF-8
byte-length-framed tenant ID, repository binding ID, profile ID, and rollout ID. Key material is
canonical-base64, at least 32 bytes, in-memory only, and zeroed after use. Its SHA-256 fingerprint
must match the digest-bound key reference so a reference/version cannot silently change material.
It must not use
repository content, finding counts, severity, or customer identity attributes.

- Default cohort progression: internal corpus -> internal repositories -> 1% -> 5% -> 25%
  -> 100% of eligible repository bindings.
- Internal corpus through 5% observes at least 24 hours and 200 completed scans per arm. The 25%
  and 100% steps observe at least 48 hours and 1,000 completed scans per arm; the slower
  requirement wins.
- A canonical scan uses exactly one bundle version. Retries retain that version.
- A repository binding remains in one cohort for the rollout duration.
- Tenants may be excluded for contractual or residency reasons, never silently forced into
  an experimental cohort.
- A non-cohort eligible production binding uses a separately compatibility/lifecycle-verified
  exact active baseline plan. Passing a candidate for that binding is rejected rather than
  rewritten; an excluded binding receives no candidate selection.
- Canary findings are authoritative only when the bundle is `CANARY`, its gates remain
  healthy, and selected profile coverage is complete.
- Every security zero-tolerance counter in `quality-gates.md`, including unauthorized egress,
  missing destruction evidence, evidence-policy violations, and unsigned artifact execution,
  must remain exactly zero at every step or the canary pauses immediately.
- A pause is terminal for that candidate/profile. Resume means a newly signed candidate,
  newly measured evidence, new approvals, and a new rollout; the old clock and samples cannot be
  reused.

## Tenant Policy, Suppression, and Waiver

The signed bundle defines what can run. Tenant policy can only narrow approved behavior:

- enable/disable an approved category or rule where platform policy permits;
- raise severity or block thresholds; lowering a mandatory platform rule requires waiver;
- exclude normalized paths using declarative non-executable patterns;
- attach a time-bounded finding waiver with reason and reviewer;
- mark accepted risk or false-positive feedback without changing scanner output.

Precedence is: platform emergency kill switch -> legal/security mandatory policy -> active
scanner/profile compatibility -> tenant policy -> time-bounded waiver -> presentation
preference. A policy conflict fails closed and emits a reason code.

Suppressions and waivers must contain tenant, scope, actor, reason, creation time, expiry,
and approval reference. They never delete the normalized finding or provenance. Expired
waivers are not automatically renewed. Broad repository/category waivers require stronger
authorization than a single-finding waiver.

## Kill Switches

Kill switches exist at scanner version, bundle digest, semantic rule ID, tenant, repository
binding, capability, signed profile identity, external publication, and global SAST runtime
scope. A switch is a versioned, signed, immutable control-plane decision chain with actor, reason,
incident reference, effective time, expiry/review time, rollback target, exact signature/
provenance verification, and a trigger-owned current head.

- A disabled required scanner or required rule capability makes coverage partial/failed;
  it never silently reports complete coverage.
- A repository-binding switch stops new attempts for that binding and denies reuse, publication,
  and AI advisory for its existing affected scans without affecting unrelated repositories.
- A capability switch removes that capability from authoritative coverage; a profile that
  requires it becomes partial/failed even when its scanner process succeeds.
- An external-publication switch denies comments and blocking decisions at the selected target
  scope while allowing safe internal normalization and dashboard processing to continue.
- A global or scanner kill switch stops new plans and cancels only attempts that have not
  crossed the safe cancellation boundary: the durable run exists, but no provider repository
  read or scanner execution has started.
- Accepted artifacts from a killed version are quarantined until reviewed.
- External comments, blocking decisions, and AI requests are denied for affected scans.
- Kill-switch evaluation occurs at planning, queue admission, immediately before scanner start,
  artifact acceptance, retry admission, effective-coverage use, external publication, and AI
  advisory. Each later gate uses a fresh trusted-time snapshot; it never trusts the planning
  receipt as current authority.

## Rollback

Every canary/active bundle records a tested last-known-good digest. Rollback creates a new
rollout decision; it does not mutate old scan plans or rewrite historical findings.

1. Activate the affected kill switch and stop new affected plans.
2. Submit only the exact suspended candidate plus incident metadata. Derive the compatible
   last-known-good target from its original promotion evidence and verify both supply chains.
3. Verify the signed rollback command and collect fresh independent dual approval within the
   15-minute window.
4. Append only the faulty candidate's `ROLLED_BACK` transition through the exact T050 receipt.
5. Have the trusted scanner-set owner route new plans to the still-current `ACTIVE` baseline and
   re-run all compatibility, lifecycle, canary, kill-switch, policy, and queue gates. Invalidate
   reusable scan results whose canonical key
   included the faulty digest.
6. Preserve artifacts and decisions under retention
   policy, and identify affected scans/findings.
7. Re-evaluate external policy decisions where the faulty bundle changed authority; never
   erase history.
8. Close rollback only after production gates remain healthy for the required window.

## Audit and Observability

Audit events cover authoring, build, signing, validation, approvals, state transitions,
canary cohort changes, tenant policy changes, waivers, kill switches, rollback, bundle
selection, and artifact verification. Events carry IDs and digests, never rule secrets,
repository content, credential values, raw findings, or unredacted evidence.

Minimum metrics:

- bundle selection and verification failures by digest and profile
- per-rule finding rate, precision feedback, suppression, waiver, and churn
- canary/control false-positive delta, scanner failure delta, and p50/p95 latency delta
- kill-switch activation/propagation lag and rollback completion lag
- unknown rule ID, schema mismatch, digest mismatch, and artifact quarantine count

## Production-Prohibited States

Production planning must reject unsigned bundles, mutable tags, missing provenance,
unsupported compatibility, `DRAFT`/`SUSPENDED`/`ROLLED_BACK`/`RETIRED` states, absent
rollback targets, customer executable rules, expired canary decisions, and any bundle whose
quality evidence is incomplete or no longer valid.
