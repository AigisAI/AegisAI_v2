# Threat Model: Production SAST Runtime

## Security Objective

Process malicious, multi-tenant repositories without allowing one scan to compromise
another tenant, retain credentials or source, escape its sandbox, poison durable findings,
exfiltrate data, or gain Control/AI/Data-Security authority.

## Protected Assets

- tenant and repository attribution
- fixed scan intent and canonical identity
- SCM repo-read credentials
- scanner/rule/database supply chain
- customer source and derived raw artifacts
- normalized finding integrity and provenance
- evidence confidentiality and retention
- policy and external publication integrity
- workload identities, KMS context, audit lineage, and kill switches

## Trust Zones

1. **Control Plane**: trusted planning and policy; no repository content.
2. **Scan Orchestrator**: trusted metadata controller; no source mount or credential value.
3. **Scanner Sandbox**: hostile-data processing zone; assumed compromisable.
4. **Result Ingress**: narrow validation gateway from sandbox to Scan/Data planes.
5. **Normalizer/Correlator**: hardened hostile-artifact processors without SCM authority.
6. **Data/Security Plane**: tenant-aware persistence, object storage, KMS, secrets, audit.
7. **AI Plane**: reduced-evidence advisory zone; no direct scanner or SCM access.

## Threat and Control Matrix

| Threat | Attack | Preventive controls | Detection/response |
| --- | --- | --- | --- |
| Mutable-ref race | Branch changes between plan and fetch | Control resolves fixed SHA; sandbox fetches SHA only | Commit mismatch kills attempt |
| Credential theft | Repository content exploits scanner and reads credential | Attested short-lived repo-read credential; memory/tmpfs; no argv/log; rapid wipe | Token-use anomaly and replay audit; revoke integration scope |
| Credential overreach | Scan receives comment/admin access | Separate principals; Token Broker validates scan/repo/commit and `REPO_READ` | Scope mismatch is security violation |
| Path traversal | `../`, absolute, UNC, drive roots, Unicode tricks | NFC normalization, root-bound resolution, collision checks | Reject before scanner; malicious corpus gate |
| Symlink escape | Link resolves outside scratch root | Do not follow outside root; mount repository read-only | Kill and `RESTRICTED` escalation |
| Archive bomb | Nested/compressed content exhausts disk/CPU | v1 archive expansion disabled; file/disk/time limits | Capacity/security event |
| Repository exhaustion | Huge files/count/depth/findings | Lane limits enforced by provisioner and preflight | Reject/defer/partial reason; tenant quota metrics |
| Scanner/parser exploit | Crafted source/output compromises tool | Per-attempt microVM, non-root, seccomp, no host mounts, default-deny egress | Kill VM; quarantine; scanner/rule kill switch |
| Scanner exfiltration | Compromised scanner calls external endpoint | No public egress; pre-mirrored assets; DNS/HTTP deny | Egress-deny telemetry; security alert |
| Result forgery | Sandbox submits another tenant/scan result | mTLS identity bound to attempt; per-scan ingress; scope and digest validation | Reject/quarantine and kill sandbox |
| Artifact parser bomb | Deep nesting, oversized strings/counts | Streaming byte cap, depth/record/string limits, strict schema | Quarantine; parser-reject metric |
| Normalizer semantic confusion | Foreign/multi-run SARIF, duplicate rules, ambiguous locations, partial invocation | Exact versioned OpenGrep subset, accepted-decision rebinding, whole-batch fail closed | Ordered bounded rejection; normalizer kill switch |
| Rule identity forgery | Scanner-local rule ID is presented as a platform semantic identity | Resolve semantic ID/revision only from unique signed bundle-manifest metadata; bind plan digest in every candidate | Golden mismatched-ID corpus; whole-batch rejection |
| Semantic identity reuse | A changed predicate, category, source/sink model, default severity, or finding identity reuses a trusted semantic ID | Digest the complete immutable semantic core; unique semantic-ID ledger; replacement chain/cycle checks | Conflicting-core and replacement-cycle corpus; registration rejection |
| Tenant rule-policy injection | Tenant metadata supplies executable rules, flags, plugins, regex/glob programs, foreign selectors, weakened floors, or a repository override that re-enables a disabled rule | Exact non-executable contract; approved-target and tenant-reference checks; monotonic narrowing; immutable pre-queue receipt | Unknown-field/path/selector/floor/mandatory-rule corpus; bounded fail-closed planning reason and zero queue reservations |
| Caller-controlled policy time | A stale or future request timestamp selects an otherwise inactive tenant policy or forges receipt evaluation time | Planner-owned injected UTC clock is the sole policy-time authority; throwing or invalid clock fails closed before persistence or admission | Old/future request-time corpus plus throwing/invalid clock tests; zero successful receipts and queue reservations |
| Promotion evidence forgery | A candidate uses insufficient, failing, future-dated, cross-bundle, or rollback-mismatched evidence | Exact T045 candidate/baseline rebinding; trusted lifecycle clock; quantitative shared and database checks; no row on failure | Threshold-boundary, drift, baseline, rollback, and future-time corpus; zero persisted evidence |
| Approval capture or self-approval | Automated output, the candidate author, one duplicated role, or a late approval promotes a bundle | Human-only exact-evidence approvals; candidate-author separation; unique role/approver set; approval interval checks; two-role requirement for active/retired | Self/duplicate/stale/late/cross-evidence approval rejection and deferred database constraint tests |
| Lifecycle fork, stale replay, or partial scanner-set selection | Concurrent transitions fork history, an exact receipt replay bypasses a later suspension, or an earlier bundle receipt survives when a later bundle fails | Ordered manifest-row locks plus per-bundle advisory locks; monotonic sequence/previous digest; immutable ledger; latest-before-replay validation; atomic serializable scanner-set receipt transaction | Illegal-edge, concurrent-sequence, mutation, suspension, stale-replay, later-bundle failure, and latest-transition drift tests; zero partial receipts or queue reservations |
| External lifecycle authority spoofing | Canary promotion, emergency suspension, or rollback occurs without the corresponding production decision | Exact per-edge authority type and digest-bound receipt; T048 accepts only its six-pass canary receipt; T049 accepts only an active applicable switch set for exact emergency suspension; T050 accepts only its evidence-derived, signed, independently approved rollback receipt | Missing/mismatched/cross-candidate/cross-bundle receipt tests, deactivated/expired switch denial, default-unavailable signature paths, and direct lifecycle insert rejection |
| Canary cohort steering or key disclosure | A caller chooses candidate membership, uses findings/content/customer traits, changes key material under one reference/version, tampers with a stored bucket, or extracts the HMAC key | Platform-only eligibility; length-framed HMAC-SHA-256 tenant/repository/profile/rollout input; canonical >=32-byte in-memory key whose SHA-256 fingerprint matches its reference; digest-only ledger; database bucket recomputation | Input-invariance, short/mismatched-key and config failure, bucket-tamper, no-key-material persistence, and stable/monotonic cohort tests |
| Canary plan/admission race | A candidate assignment is queued after pause, step advance, lifecycle drift, or assignment substitution | Immutable receipt in plan; stable v4 identity; ordered lifecycle-head then canary-head row locks; application and database admission fences | Pause/step/lifecycle race, stale receipt, baseline substitution, and direct-write rejection tests; zero stale reservations |
| Canary telemetry poisoning or omission | Forged, partial, cross-scope, reordered, content-bearing, source-drifted, role/bucket-steered, or caller-cherry-picked metrics promote a candidate | Fixed observation-source digest; trusted-source role/bucket derivation; exact immutable plan/assignment/attempt/coverage/publication/telemetry rebind; trusted-time cutoff and complete committed window; normalized scalar ledger; database closed-set, aggregate, and reason recomputation; incomplete coverage is a hard pause | Missing telemetry/coverage, caller-selected role/bucket/cutoff/IDs, omitted-window row, source drift, plan mismatch, scope/time drift, unequal-arm rate boundary, aggregate/reason/order tamper, and content sentinel tests |
| Canary pause bypass or evidence reuse | A failed candidate resumes the same rollout, reuses old samples, skips a step, or re-enrolls the same candidate/profile | `PAUSED` terminal head; candidate/profile unique rollout; contiguous sequence/step triggers; one six-pass receipt; new manifest/evidence/approvals required | Post-pause write denial, duplicate rollout, skipped-step, incomplete-receipt, and cross-rollout replay tests |
| Canonical scan-key version collision | Earlier work is replayed after lifecycle or stable canary identity is added to the key preimage | T047 explicit v3 lifecycle cutover followed by T048 explicit `sast-canonical-scan-key-v4`; each migration blocks while prior-version SAST work is non-terminal; terminal history stays immutable | v2->v3 and v3->v4 dirty-cutover rejection plus drained/canceled cutover checks |
| Kill-switch signature, chain, or expiry bypass | An unsigned/forked/future decision activates, an active expired decision is treated as clear, or a deactivation is overwritten | Exact digest-bound verification in the decision transaction; monotonic predecessor chain; trusted time; append-only ledgers; expired-active authority fails closed | Valid activation/deactivation/exact-replay plus unsigned, signature-drift, fork, future-time, expired-active, update, and delete rejection tests |
| First-activation, selector omission, and plan/admission race | Evaluation observes no selector row while a first activation commits, a forged internally consistent receipt omits an applicable active head, or a clear plan queues after any head changes | Durable inactive placeholders; 50,020-binding hard cap; one canonical set-based row lock and anti-join; complete normalized head snapshot; application reconstruction of plan context/key set; independent database identity/count comparison and current-head fence | Concurrent missing-head activation, omitted/substituted/extra selector, context mismatch, every selector-head drift fixture, and over-cap fan-out produce zero stale reservations |
| Post-queue scanner/artifact bypass | A switch activates after admission but customer source is read, the scanner runs, or its result is accepted; alternatively a clear switch is mistaken for artifact-retention authority | Durable run first; fresh scanner-start evaluation before provider read/execution; killed status and mandatory cleanup; fresh artifact short-circuit with quarantine; clear delegates to the independent fail-closed Data/Security acceptance authority | Active/unavailable scanner-start tests assert zero provider/scanner calls; affected artifact tests assert quarantine and zero downstream acceptance calls; clear plus unavailable production authority yields zero accepted rows |
| Kill-switch downstream authority bypass | Affected work retries, reports complete effective coverage, calls AI, or publishes externally by trusting its old plan | Fresh retry/coverage/AI/publication evaluations; explicit effective-coverage projection; plan receipt is never current authority; external-publication selectors are independently scoped | Between-gate activation corpus asserts retry denial, partial/failed coverage, zero model/publisher calls, and unchanged T039 history |
| Emergency-suspension receipt replay | A valid active switch suspends a different/stale bundle, is reused after deactivation/expiry, or authorizes rollback | Exact latest lifecycle/bundle/evidence and active-decision-set binding under locks and restrictive keys; authority limited to `CANARY\|ACTIVE -> SUSPENDED` | Cross-bundle/profile, stale transition, changed decision set, deactivated/expired, replay-conflict, and rollback denial tests |
| Rollback target substitution or race | A caller, customer, AI output, scanner result, stale receipt, or concurrent head change selects another baseline, rolls back an unsuspended candidate, mutates history, or widens authority | No target in request; derive only from original T047 evidence; reverify both T045 attestations and T049 suspension provenance; fresh signed dual control; canonical two-head locks; append-only narrow receipt and commit-time trigger | Unknown target field, cross-evidence/bundle/profile, self/duplicate/stale approval, unavailable signature, forged direct insert, candidate/baseline drift, concurrent exact replay, mutation/delete, and unchanged baseline/history probes |
| Qualification corpus substitution or path escape | A changed denominator, forged expected result, mutable source, duplicate materialization path, symlink/junction, encoding ambiguity, or oversized/extra file is accepted as reviewed golden input | Exact versioned case/snapshot contracts; deterministic in-memory regeneration; digest-derived identity; owner/license/digest-bound provenance; paired counts and floors; unique root-confined paths; byte-exact source set; canonical UTF-8/LF/NFC; no-link and bounded-input loader | Snapshot/count/digest/pair/path/authority tamper, source drift, CRLF/oversize/extra-file, symlink/junction, malformed nested shape, and deterministic reorder tests; zero scanner or promotion authority from validation |
| Multi-class qualification recipe substitution | A required parser, malicious-repository, identity, privacy, or performance scenario is missing, relabeled, represented only by its label, widened into an executable command, replaced by a live hostile filesystem object, bound to a Deep limit while claiming Fast coverage, uses a far-above-boundary parser value while claiming exact +1 coverage, or is bound to a different hardware/run denominator | Exact five-class/84-case snapshot; one case per required scenario; allowlisted declarative actions and typed bounded parameters/raw-byte segments; complete identity vectors; exact per-profile boundaries and generic segment formulas; exact shared parser depth/string constants; explicit directed link edges; no command/argv/environment fields; exact root/class/file allowlists; byte regeneration; one digest-bound performance hardware class and 30 runs per bucket | Missing/duplicate scenario, incomplete invariance vector, one-edge cycle, mislabeled binary bytes, selected-profile or shared-parser boundary drift, outcome/stage/profile/hardware drift, executable/authority widening, invalid base64/UTF-8/BOM/CRLF/NUL/oversize, extra/empty directory, symlink/junction, fixture byte drift, cycle/depth, and deterministic reorder tests; zero execution or readiness authority from T052 validation |
| Isolated qualification evidence forgery or reuse | A local fixture is presented as provider evidence; a plan omits an artifact; one microVM, sandbox, workload, attempt, attestation, receipt, or signature is reused; actual materialization/outcome differs; egress or a prohibited effect is hidden; cleanup is incomplete or late; a stale/future receipt, substituted trust key, or partial bundle claims T053 success | Exact 41-case/three-profile/123-cell manifest; digest-bound production-equivalent dependency set; detached Security Engineering and Scan Platform approvals; one new microVM per cell; unique identity sets; exact projection/outcome rebind; five phase egress and eight prohibited-effect observations; six cleanup proofs within 60 seconds; provider plus runtime Ed25519 signatures; trust-bundle digest bound to `TRUST_POLICY`; tri-state aggregate with no readiness authority | Contract, real-Ed25519, duplicate/reuse, outcome/egress/cleanup/SLO, signature tamper, partial/pending, authority widening, package byte drift, path/link/encoding, and deterministic-plan tests; repository CI can never create a passing provider receipt |
| Canary suspension-signal forgery | A caller labels a rollout paused/zero-tolerance or supplies a different manifest, bundle, profile, reason, or lifecycle target | Exact two-reference request; immutable T048 decision/rollout/reason reload; lifecycle-then-canary head locks; every target derived; signal has zero mutation authority | Extra-target, changed digest, non-current/non-paused head, reason omission/order, cross-rollout/lifecycle, and zero-authority tests |
| Rule metadata/manifest digest cycle or drift | Metadata embeds a manifest digest while the signed manifest embeds the metadata digest, or a later bundle silently changes the binding | Separate reusable metadata content from an immutable exact manifest binding; composite manifest/rule/metadata foreign keys | Cross-manifest reuse and projection-tamper tests; insert rejection |
| Coordinate-attestation downgrade | Supplied unverified or drifted attestation is treated as unavailable metadata | Distinguish provider absence from supplied drift; reject drift before artifact reads | Negative binding corpus; zero body-read assertion |
| Raw SARIF retention | Snippets, fixes, code flows, or help content are copied into findings | Scalar-only streaming projection; transient candidates; T035 persistence gate | Golden privacy corpus; zero raw-payload audit/API assertions |
| Candidate display secret smuggling | OpenGrep message, title, or symbol interpolates a repository/platform secret after raw snippets were discarded | Versioned provider/generic/exact-value redaction; one fixed marker; fresh output only | Known-format, entropy, registered-value, Unicode, overlap, and zero-leak serialization corpus |
| Identity redaction collision | Secret in path/rule/package/anchor is replaced and distinct findings collapse to one fingerprint | Reject the complete batch; never hash or replace an identity-bearing match | Identity-field corpus; zero secret-derived decision/fingerprint preimages |
| Redaction oracle | Rejection, match length/type, source-candidate digest, or matched-value hash allows correlation or guessing | Coarse ordered reasons and negative-storage assertions only; no rejected binding/artifact/source digest | Byte-level rejection/audit allowlist and sentinel non-occurrence tests |
| Redaction marker forgery | Scanner text includes `[REDACTED]` and falsely claims platform processing | Reserved input marker rejects before decision construction | Forged-marker corpus and exact decision-shape validation |
| Trivy disposition smuggling | `ExperimentalModifiedFindings` status is treated as a platform waiver, suppression, or lifecycle decision | Normalize supported modified records; preserve status only with `platformPolicyAuthority=false`; reject unknown type/status | Direct/modified golden parity and unsupported-license/status corpus |
| Trivy capability forgery | Scanner-local metadata changes dependency, secret, or IaC semantic authority | DB-derived dependency identity; signed checks-manifest identity for secret/IaC; exact capability/result class allowlist | Cross-capability/rule/database mismatch corpus; whole-batch rejection |
| Trivy secret-context leakage | Masked `Match` is accepted while nearby `Code`, `Statement`, or `Source` contains the secret | Never collect raw secret/context scalar values; emit deterministic platform text and explicit discard flags | Sentinel secret corpus; zero occurrence in candidates/digests/rejections |
| Trivy coordinate identity split | A line-only edit changes secret/IaC structural identity and breaks later finding lineage | Exclude coordinates from identity preimages; use deterministic producer-order occurrence ordinals; reject exact-coordinate ambiguity | Line-shift invariance and repeated-occurrence golden corpus |
| Canonical Unicode collapse | An escaped unpaired surrogate is decoded to a replacement character before hashing | Validate raw JSON escape pairs before token decoding; NFC plus scalar-value checks | One-byte-chunk paired/unpaired surrogate corpus |
| Stable fingerprint binding forgery | A digest-shaped T035 handoff, fingerprint decision, or T036 batch is accepted without binding the sanitized object | Trusted canonical SHA-256 recomputation at every receiving boundary; exact source-decision and source-batch binding | Tampered source/decision/batch corpus; syntax-only digest rejection |
| Stable fingerprint collision | Distinct canonical identities are collapsed under one digest and one finding silently wins | Transient digest-to-preimage map; allow only byte-identical repetition; reject the complete batch on mismatch | Forced-digester collision corpus; zero candidate/preimage rejection leakage |
| Unknown-location identity smuggling | Provider reason, coordinates, or an invented fallback path makes unavailable locations drift across runtimes | Fixed empty normalized-path component under length-prefixed framing; reason and coordinates excluded | Both UNKNOWN reasons produce one identity; forged path binding rejected |
| Finding-ledger replay forgery | A retry changes, omits, adds, reorders, or cross-scopes an occurrence while reusing a valid source-batch identity | Revalidate every durable T036/plan/artifact binding; unique source identity; exact canonical batch and complete ordered occurrence-ledger equality | Replay/tamper/cross-tenant corpus; reject the whole transaction with zero source data in output |
| Rename alias poisoning | An untrusted diff, fuzzy match, chain, cycle, missing predecessor, or AI claim joins unrelated findings | Canonical signed fixed-commit/fixed-target one-to-one attestation; exact predecessor alias; immutable old and new aliases; unavailable verifier fails closed | Rename, rename-back, ambiguous, missing-predecessor, chain/cycle, and unverified-attestation fixtures |
| Incomplete-batch false fix | A scanner failure or omitted zero-finding batch is presented as complete absence and resolves an open lineage | T037 never calculates coverage; T039-compatible gate must verify `COMPLETE`, non-stale, comparable, and exact equality to every durable T037 batch including zero-finding batches | Partial/stale/missing/extra/zero-batch tests; lifecycle mutation count remains zero |
| Lifecycle context bleed or race | One target resolves another target, or concurrent/out-of-order reconciliations overwrite a newer state | Canonical tenant/repository/target context key; monotonic reconciliation sequence; append-only events; serializable transaction and bounded retry | Cross-context, reopen, stale-sequence, and serialization-race corpus |
| Correlation source-set truncation | A caller omits a zero/nonzero T037 batch or races a late scanner result and presents an incomplete graph as final | Revalidate canonical T037 results against the exact durable attempt/context batch and occurrence set in the serializable write; completed batch fences late additions | Missing/extra/late/zero-batch and serialization-race fixtures; no partial rows |
| Cross-tool authority confusion | Optional or foreign scanner output replaces the configured owner or merges distinct capability families | Scanner responsibility plus required/optional profile authority matrix; `SUPPORTING_ONLY` cannot replace `AUTHORITATIVE`; no capability-lineage merge | Cross-capability/optional-profile fixtures and exact authority assertions |
| Severity laundering through correlation | A lower-severity related result hides or downgrades a Critical authoritative occurrence | Persist both severities/provenance rows; invariant merge/severity/lifecycle/coverage/policy inheritance false; overlap is display-only | Mixed Critical/Low fixtures; both occurrences and provenance remain queryable |
| Correlation fan-out exhaustion | Shared identifiers cause quadratic all-pairs memory/DB growth | 25,000-occurrence and 100,000-edge ceilings, canonical star edges, pair deduplication, 64-occurrence event-loop yield, chunked writes | High-cardinality shared-CVE/CWE corpus and edge-limit rejection |
| Correlation replay forgery | T037 replay flag or one changed edge/provenance row changes retry identity or silently mutates the ledger | Replay-independent durable source binding plus exact source/edge/two-sided-provenance equality and deterministic digests | T037 replay-flag parity and tampered edge/provenance fixtures |
| Coverage authority injection | A caller supplies a required-scanner/capability list or successful status that differs from the immutable profile and durable scanner run | Derive requirements from the approved profile/responsibility matrix; rebind scanner image, wrapper, rule/DB, schema, normalizer, artifact and disposition | Fast/Deep/Common, foreign/duplicate scanner, and provenance-tamper fixtures; zero caller-owned authority |
| Coverage replay drift | A late scanner/artifact/source change reuses an earlier attempt decision or concurrent writers create divergent coverage | Attempt-unique decision, composite foreign keys, serializable re-read, canonical three-record digest, exact replay only, bounded P2034/P2002 retry | Changed/missing/extra/reordered/cross-scope/concurrent replay corpus; no partial or duplicate rows |
| Premature complete publication | Complete scanner coverage is treated as proof that the result still matches the latest PR target | Preserve the T039 `UNAVAILABLE`/`UNKNOWN` zero-authority source; T040 independently requires a monotonic provider head equal to the fixed commit plus exact prior-scan comparability | Complete-only, unavailable, stale, non-monotonic, and incomparable fixtures have zero publication and lifecycle mutations |
| Retry escalation or sandbox reuse | A non-infrastructure failure, missing audit, attempt three, reused sandbox, or withdrawn scanner asset is admitted as a retry | Durable T040 decision rechecks immediate attempt-one failure/audit, independent current scanner-set availability, kill switches, immutable intent, and new attempt/sandbox/workload identity before attempt-two insertion | Every disallowed failure/safety state, unavailable asset, and identity-reuse fixture has zero sandbox admissions |
| Retention clock rollback | A caller supplies a past payload timestamp to normalize an expired accepted object | Adapter-owned default clock checked before and after streaming; trusted test/task clock seam only; require monotonic time at or after disposition | Expiry, stream-crossing, and pre-decision clock tests |
| Stored XSS | Rule message/path/package contains markup | Treat all strings as text; output encoding; sanitized Markdown only | Stored-XSS corpus; presentation CSP |
| Secret leakage | Finding, zero-finding binding, or source fragment includes a detected/platform secret | Scanner discard plus T035 display redaction, T041 bounded memory-only known/platform redaction, and T042 access-time re-redaction/classification | Secret-leak gate must remain zero |
| Cross-tenant object access | Object key or query omits tenant | Tenant/scan prefix, encryption context, tenant predicate, purpose-bound reads | Negative tests and access audit |
| Cache poisoning | Customer content enters shared cache | Shared cache only for signed public tool/rule/database assets | Cache inventory and digest monitoring |
| Rule supply-chain attack | Malicious rule or database promoted | Signed digest, provenance, two-person security approval, corpus gates, canary | Automatic rollback/kill switch |
| Prior-release denominator erasure | A new corpus revision drops or changes a historical must-detect case and derives an apparently perfect denominator from remaining positives | Separate exact-binding prior-release manifest, canonical manifest/release digests, reviewed digest pin outside the file, overwrite refusal, and snapshot completeness rebind | Missing/changed case, forged manifest/reference, and later-positive fixtures fail closed |
| Negative-class label forgery | A fixture claims sanitizer, safe-API, comment, or generated exclusion while reusing unrelated source behavior | Per-family applicable-kind policy, distinct source rendering, unsafe generated/vendor construct under excluded path, and source-range behavior assertions | All 400 negatives match declared behavior; inapplicable classes are absent |
| Dependency database drift | Sandbox downloads latest data | Mirror and pin digest outside runtime | Audit version per finding/scan |
| Retry replay | Same attempt/result is processed twice | Canonical scan identity, unique attempt, artifact digest idempotency | Duplicate events ignored and audited |
| Stale publication | Old commit result comments on newer PR, or a worker claims an outbox item after a kill switch activates | Latest-context comparison plus fresh `EXTERNAL_PUBLICATION` evaluation at both comment planning and every worker claim | Target stale publication count = zero; between-plan-and-claim activation yields zero claims and publisher calls |
| Kill-switch clock replay | A caller supplies a stale or future boundary time to preserve an earlier clear selector view | Compare every boundary time with the service-owned trusted clock under bounded skew before durable evaluation | Stale/future time corpus yields zero evaluation, coverage, publication, or AI authority |
| Incomplete coverage | Successful tool hides required tool failure | Explicit required coverage state | Comment/block/AI denied |
| Evidence source forgery | A caller supplies a path/range, finding authority, or fragment that is not the durable accepted occurrence | Rebind exact T040/T039/T038/T037 rows and require an internal source attestation that defaults unavailable | Cross-scope, missing occurrence, changed fingerprint, path/range, and unavailable-source fixtures reject |
| Evidence reconstruction | Multiple snippets rebuild source | 32 KiB/five-fragment/8 KiB/five-context caps; per-file maximum two; reject full-file, overlap, adjacency, or at least 25% combined line coverage | Evidence build reject and immutable audit with zero pack |
| Evidence-purpose confusion | Dashboard consent or one stale decision is reused to construct an AI payload | Separate immutable dashboard/AI decisions, complete T041 chain rebind, access-time redaction/classification, and explicit zero provider/tool authority | Purpose swap, opt-in, registry drift, unsafe identifier, cross-tenant, and replay fixtures deny |
| Evidence expiry race | A reader returns content while expiry/deletion is claimed or after the final clock check | Check retention before read and after the final awaited confirmation, confirm unchanged schedule/claim/proof, and deny from claim onward | Expiry-before/during/final-confirmation read, late-reader, deletion-race, and clock-rollback fixtures return no content |
| False deletion proof or overdue content | A worker marks evidence deleted without provider removal, rejects the original receipt after a finalization retry, or lets polling/batch caps or one corrupt claim create a retention backlog | Deterministic operation, leased owner/token fence, default-unavailable provider, deadline-aware startup/earliest-due scheduling, saturated zero-delay continuation, context-drift quarantine, exact receipt replay, delete-then immutable proof | Unavailable provider, changed/original receipt, stale token, concurrent claim/finalize, drifted-head queue, deadline wakeup, and exact replay corpus |
| AI handoff forgery or payload smuggling | A caller supplies a finding, prompt, fragment, stale access reference, or authority bit and causes it to reach the model | Exact four-field intent, double T042 classification, durable T037 source rebind, canonical expiring handoff, empty snippets, exact runtime keys, and fixed zero downstream authority | Legacy/extra-field, cross-scope, drift, expiry, correlation, snippet, secret-key, and authority-widening fixtures deny before provider use |
| AI output authority escalation or proof forgery | An advisory, caller snapshot, suggested action, forged proof, tenant spoof, concurrent writer, or lifecycle payload creates/resolves/re-severities a finding, waives/suppresses it, or overrides policy | Tenant-bound internal credential; exact two-field proof intent; shared advisory/scan/lifecycle/finding database fences; one durable policy/lifecycle source; single locked snapshot projected to before/after digests; proof-only write; fixed-false checks; immutable triggers; tenant/finding-bound display-only proof reference; exact lifecycle key allowlists | State-drift, tenant mismatch, cross-tenant, concurrent writer, replay-conflict, over-limit, suggested-action, proof-injection, and zero-authoritative-write fixtures deny |
| AI prompt injection | Evidence text instructs model | Evidence is untrusted data, bounded/redacted, no retrieval/tools/SCM | Advisory label and output schema validation |
| Sandbox persistence | Compromise survives next scan | No worker/workspace reuse; new microVM per attempt | Destruction evidence and lag alert |
| Operator credential leak | Deployment secrets enter repo/config | 005 reference-only credential handoff | Secret scanning and deployment audit |

## Network Allowlist

The default is deny. A sandbox may reach only workflow-specific private endpoints:

- Token Broker for attested issuance
- approved GitHub/GitLab repository endpoints for the bound repository fetch
- write-only Result Ingress
- bounded audit/telemetry collector

Scanner rule, vulnerability database, and image assets are attached from trusted mirrors
before scanning; scanners do not fetch updates. The sandbox cannot access Control Plane
databases, comment APIs, AI endpoints, general DNS, cloud metadata, package registries, or
the public internet.

## Isolation Escalation

Use `RESTRICTED` isolation when any of the following is present:

- new or untrusted tenant risk tier
- repository above the standard Fast limits or near Deep maximums
- abnormal symlink/path/collision inventory
- scanner/parser crash history
- repeated timeout, malformed artifact, or quarantine event
- token replay or unexpected egress signal
- security-operator override

Security violations do not downgrade or partial-scan automatically. They terminate the
attempt and require a new plan or approved response.

## Security Invariants

The following must always remain true:

1. A sandbox can read at most one fixed repository state.
2. A sandbox cannot publish comments, change policy, or access AI directly.
3. A compromised sandbox cannot write a durable finding without result-ingress validation.
4. A scanner or rule update cannot become active without a signed immutable digest and
   promotion evidence.
5. Incomplete or stale scans cannot publish externally.
6. Raw artifacts and evidence expire within seven days.
7. No customer-derived content enters a cross-tenant reusable cache.
8. Every attempt ends with auditable credential, workspace, and microVM destruction.
9. Scanner-side modified/ignored status never gains platform policy or lifecycle authority.
10. Detected secret values and neighboring scanner context never enter a normalized candidate,
    identity digest, rejection, log, audit, evidence, or AI payload.
11. A normalizer accepts only the authoritative capability families and exact producer schema
    pinned by its immutable plan.
12. CycloneDX inventory cannot smuggle finding, vulnerability, policy, durable-persistence,
    or AI authority; producer BOM references, properties, source paths, license text, prose,
    and external-reference payloads never cross the transient inventory boundary.
13. Repeated fingerprint observations remain distinct immutable occurrences, and replay
    succeeds only for the exact complete ordered ledger in the same tenant/repository scope.
14. A lineage can change target lifecycle only from a verified newer complete coverage
    decision over the exact durable observation-batch set; T037 cannot calculate that
    decision or infer absence from missing data.
15. A T039-complete scan gains no external or lifecycle eligibility unless a monotonic,
    provider-authoritative target observation proves the exact fixed commit and a durable
    prior complete scan proves exact comparability.
16. Attempt two cannot start without a durable infrastructure-only retry decision bound to
    attempt-one failure/completion/final-audit state, current scanner-set and kill-switch
    authority, and a new attempt/sandbox/workload identity; attempt three is impossible.
17. An accepted-finding evidence pack records only the durable accepted occurrence under
    verified, fresh, and comparable authority. It contains no raw source or secret value and
    grants no dashboard, AI, policy, publication, or lifecycle mutation authority.
18. Dashboard and AI evidence access are separately classified after access-time redaction and
    durable rebinding. Expiry or a deletion claim revokes both; content is deleted only after a
    fenced provider receipt and the retained canonical proof cannot restore access.
19. Advisory AI input is derived only from the exact T042/T037 durable chain. Its ledger is
    reference-only, its runtime request contains no snippets or retrievable content, and it
    grants no policy, publication, lifecycle, finding, tool, retrieval, or SCM authority.
20. Advisory output can create only one immutable T044 proof under a tenant-bound internal
    credential. Shared database fences hold one authoritative snapshot whose before/after digest
    projections are identical; policy accepts only a tenant/finding-bound display reference, and
    lifecycle endpoints persist to the covered tables while rejecting every advisory/proof field.
21. Affected work cannot pass a T049 side-effect boundary from an old clear plan. Signed
    append-only selector authority and the plan-derived complete selector set are revalidated
    under locks at queue admission and freshly at
    scanner start, artifact acceptance, retry, coverage, publication, and AI; active or
    unavailable state fails closed, historical truth is unchanged, and emergency authority can
    only suspend the exact latest matching bundle.
22. Rollback cannot select its own target or reuse stale authority. T050 derives the target from
    the original T047 evidence, requires an exact T049-suspended candidate and still-active T045
    baseline plus fresh signed independent dual approval, locks both heads canonically, and
    appends only one `ROLLED_BACK` transition. The receipt has no scanner-set or downstream
    authority and every baseline and historical row remains unchanged.
23. Golden qualification input cannot drift between review and use. T051 validates a separately
    manifested and code-pinned historical denominator before regenerating one exact platform-owned
    snapshot, requires complete paired profile/rule/prior denominators,
    rebinds all source bytes, ranges, anchors, and unique root-confined materialization paths, and
    rejects links, ambiguous text, extra files, mutable metadata, or executable/customer inputs.
    Successful validation grants no detection, finding, promotion, or deployment authority.

## Required Security Test Corpus

- path traversal, absolute/UNC/drive paths, NUL and control characters
- Unicode normalization and case-fold collisions
- root-escaping, cyclic, and deeply nested symlinks
- oversized files, excessive file count/depth, sparse files, inode exhaustion
- T051 prior-manifest deletion/mutation/forgery, later-positive denominator separation,
  negative-kind semantic mismatch, snapshot/count/digest/pair/profile/rule-floor drift, unknown
  fields, duplicate scan paths, source-byte/range/anchor drift, CRLF/BOM/NUL/non-UTF-8/non-NFC
  text, extra root/source entries, symlink/junction traversal, and filesystem identity substitution
- archive and compression bombs even though expansion is disabled
- malformed SARIF, Trivy JSON, CycloneDX JSON, deep nesting, duplicate keys, invalid UTF-8
- foreign/multi-run OpenGrep SARIF, notification-bearing invocation, duplicate/missing rule
  descriptors, multiple primary locations, invalid `%SRCROOT%`, and content rebinding
- Trivy direct and modified vulnerability/secret/IaC records, unsupported modified licenses,
  unknown disposition/status enums, cross-capability result arrays, duplicate semantic
  identities, package/database/check-bundle rebinding, and omitted dependency coordinates
- Trivy secret fixtures with sentinel values in `Match`, neighboring `Code`, modified-finding
  `Statement`/`Source`, and untrusted misconfiguration message/trace/rendered-cause fields
- T042 purpose-swap, platform-registry drift, known-format/entropy secret, unsafe path and
  identifier, cross-tenant/repository, before/during-read expiry, late-reader, concurrent
  classification/deletion, unavailable-provider, stale-fence, changed-receipt, exact-replay,
  and clock-rollback fixtures
- T043 caller-supplied finding/evidence/prompt and unknown-field rejection; T042 decision or
  reduced-reference drift; cross-tenant/repository/scan/occurrence/fingerprint rebinding;
  expired and non-monotonic clocks; changed model version; exact retry; snippets/content;
  forbidden secret keys; request/tenant/scan/finding correlation drift; retrieval, tool,
  policy, publication, lifecycle, and SCM authority widening; duplicate/reordered CWE/CVE sets;
  oversized advisory/signal/text output; excessive response depth/breadth; latency overflow;
  provider-error reflection; and unauthorized immutable-ledger purge
- T044 caller-supplied status/severity/lifecycle/waiver/suppression/policy/proof rejection;
  cross-tenant advisory or finding binding; missing/multiple/changed lifecycle state;
  normalized-finding, policy-decision, waiver, and suppression set drift; over-limit sets;
  exact replay and conflict; forged proof/reference digest; legacy `suggestedAction`, block,
  resolve, waive, and suppress fields; zero authoritative model writes; content/secret sentinel
  absence; immutable update/delete; and controlled hard-purge enforcement
- CycloneDX schema/tool/version/source-component rebinding, metadata-tool component
  count smuggling, vulnerability/VEX and nested/file component extensions, duplicate or
  mismatched PURL/BOM references, invalid CPE part/field/quoting/wildcard/language forms,
  invented SPDX IDs or exceptions, malformed SPDX expressions and LicenseRefs, malformed
  SWID/hash structures, URL-empty Java `build-meta` references, repeated license identities
  from multiple URLs, dangling/duplicate/self/non-canonical dependency edges, and
  zero-component inventories
- CycloneDX properties and source-location paths, attached license text, URLs, prose, external
  references, and serial/BOM-reference sentinels that must be absent or SHA-256-only in the
  transient inventory and every rejection/log/audit/AI surface
- malicious filenames, package names, symbols, rule messages, HTML, Markdown, and ANSI codes
- known token formats and high-entropy secret fixtures
- registered platform values, private-key blocks, authorization/URL credentials, documented
  provider prefixes, JWTs, contextual assignments, overlapping/adjacent spans, Unicode text,
  forged markers, invalid/duplicate/over-limit value sets, and detector-order permutations
- secrets in normalized path, semantic rule identity, symbol anchor, sink kind, scanner
  version/match identity, rule provenance identifier/revision, dependency
  vulnerability/package/type/installed/fixed-version identity, secret category, IaC check
  type/AVD identity, and zero-finding ingestion/scope/preflight bindings; every rejection
  surface must omit the value, length, matched-value hash, source-candidate digest, and
  rejected binding
- event-loop starvation or CPU amplification from maximum-size candidate batches; reject
  above 8,000,000 inspected UTF-16 code units and yield at the 64-candidate or
  32,768-code-unit chunk boundary
- scanner crash/timeout/output bomb/truncation and result replay
- signed-envelope tenant/scan/commit/digest tampering
- cross-tenant object and query access
- stale commit, force-push, and duplicate delivery
- unavailable/malformed/future/non-monotonic target observations, same-sequence replay,
  force-pushed head mismatch, cross-provider/repository/target observation reuse, missing
  previous complete scan, profile-family/capability/fingerprint/lifecycle-scope drift
- retry attempt three, non-infrastructure/cleanup/capacity/input/scanner/security failure,
  false retry-eligible flag, missing/mismatched final audit, changed/unavailable scanner set,
  active/unavailable kill-switch authority, and reused attempt/sandbox/workload identity
- T049 signed activation/deactivation and exact replay for every selector; unsigned/mismatched
  verification, forked chain, future activation, active expiry, absent-head first-activation race,
  stale plan/queue snapshot, between-gate activation, scanner cancellation before provider read,
  artifact quarantine, retry/AI/publication denial, effective-coverage mapping, immutable T039
  history, caller-target-free T048 paused/zero-tolerance signal derivation, and cross-bundle/
  stale/deactivated/expired emergency-suspension receipt replay
- repeated fingerprints, exact replay, missing/extra/reordered occurrence rows, cross-tenant
  source-identity reuse, concurrent lineage creation, and serialization retry exhaustion
- verified rename and rename-back, missing predecessor aliases, duplicate/ambiguous mappings,
  chains/cycles, wrong fixed commit/target/profile/context, invalid signature/provenance, and
  unavailable rename verification
- isolated target contexts plus created/fixed/reopened event revision sequences; partial,
  pending, failed, stale, incomparable, missing/extra/out-of-order coverage and omitted or
  forged zero-finding batches must produce exactly zero lifecycle mutations
- prompt-injection strings in reduced evidence
- sandbox escape and prohibited egress regression suites
