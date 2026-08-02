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
| Retention clock rollback | A caller supplies a past payload timestamp to normalize an expired accepted object | Adapter-owned default clock checked before and after streaming; trusted test/task clock seam only; require monotonic time at or after disposition | Expiry, stream-crossing, and pre-decision clock tests |
| Stored XSS | Rule message/path/package contains markup | Treat all strings as text; output encoding; sanitized Markdown only | Stored-XSS corpus; presentation CSP |
| Secret leakage | Finding or zero-finding binding includes a detected/platform secret | Scanner discard plus T035 display redaction, batch-binding inspection, identity fail-close, and T042 evidence re-redaction | Secret-leak gate must remain zero |
| Cross-tenant object access | Object key or query omits tenant | Tenant/scan prefix, encryption context, tenant predicate, purpose-bound reads | Negative tests and access audit |
| Cache poisoning | Customer content enters shared cache | Shared cache only for signed public tool/rule/database assets | Cache inventory and digest monitoring |
| Rule supply-chain attack | Malicious rule or database promoted | Signed digest, provenance, two-person security approval, corpus gates, canary | Automatic rollback/kill switch |
| Dependency database drift | Sandbox downloads latest data | Mirror and pin digest outside runtime | Audit version per finding/scan |
| Retry replay | Same attempt/result is processed twice | Canonical scan identity, unique attempt, artifact digest idempotency | Duplicate events ignored and audited |
| Stale publication | Old commit result comments on newer PR | Latest-context comparison before policy/comment | Target stale publication count = zero |
| Incomplete coverage | Successful tool hides required tool failure | Explicit required coverage state | Comment/block/AI denied |
| Evidence reconstruction | Multiple snippets rebuild source | Total/fragment/context caps and reconstruction-risk check | Evidence build reject and audit |
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

## Required Security Test Corpus

- path traversal, absolute/UNC/drive paths, NUL and control characters
- Unicode normalization and case-fold collisions
- root-escaping, cyclic, and deeply nested symlinks
- oversized files, excessive file count/depth, sparse files, inode exhaustion
- archive and compression bombs even though expansion is disabled
- malformed SARIF, Trivy JSON, CycloneDX JSON, deep nesting, duplicate keys, invalid UTF-8
- foreign/multi-run OpenGrep SARIF, notification-bearing invocation, duplicate/missing rule
  descriptors, multiple primary locations, invalid `%SRCROOT%`, and content rebinding
- Trivy direct and modified vulnerability/secret/IaC records, unsupported modified licenses,
  unknown disposition/status enums, cross-capability result arrays, duplicate semantic
  identities, package/database/check-bundle rebinding, and omitted dependency coordinates
- Trivy secret fixtures with sentinel values in `Match`, neighboring `Code`, modified-finding
  `Statement`/`Source`, and untrusted misconfiguration message/trace/rendered-cause fields
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
