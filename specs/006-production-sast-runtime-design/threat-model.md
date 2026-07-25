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
| Trivy disposition smuggling | `ExperimentalModifiedFindings` status is treated as a platform waiver, suppression, or lifecycle decision | Normalize supported modified records; preserve status only with `platformPolicyAuthority=false`; reject unknown type/status | Direct/modified golden parity and unsupported-license/status corpus |
| Trivy capability forgery | Scanner-local metadata changes dependency, secret, or IaC semantic authority | DB-derived dependency identity; signed checks-manifest identity for secret/IaC; exact capability/result class allowlist | Cross-capability/rule/database mismatch corpus; whole-batch rejection |
| Trivy secret-context leakage | Masked `Match` is accepted while nearby `Code`, `Statement`, or `Source` contains the secret | Never collect raw secret/context scalar values; emit deterministic platform text and explicit discard flags | Sentinel secret corpus; zero occurrence in candidates/digests/rejections |
| Trivy coordinate identity split | A line-only edit changes secret/IaC structural identity and breaks later finding lineage | Exclude coordinates from identity preimages; use deterministic producer-order occurrence ordinals; reject exact-coordinate ambiguity | Line-shift invariance and repeated-occurrence golden corpus |
| Canonical Unicode collapse | An escaped unpaired surrogate is decoded to a replacement character before hashing | Validate raw JSON escape pairs before token decoding; NFC plus scalar-value checks | One-byte-chunk paired/unpaired surrogate corpus |
| Retention clock rollback | A caller supplies a past payload timestamp to normalize an expired accepted object | Adapter-owned default clock checked before and after streaming; trusted test/task clock seam only; require monotonic time at or after disposition | Expiry, stream-crossing, and pre-decision clock tests |
| Stored XSS | Rule message/path/package contains markup | Treat all strings as text; output encoding; sanitized Markdown only | Stored-XSS corpus; presentation CSP |
| Secret leakage | Secret finding includes detected value | Scanner and platform redaction; fingerprints; no raw value in finding/audit/evidence | Secret-leak gate must remain zero |
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
- malicious filenames, package names, symbols, rule messages, HTML, Markdown, and ANSI codes
- known token formats and high-entropy secret fixtures
- scanner crash/timeout/output bomb/truncation and result replay
- signed-envelope tenant/scan/commit/digest tampering
- cross-tenant object and query access
- stale commit, force-push, and duplicate delivery
- prompt-injection strings in reduced evidence
- sandbox escape and prohibited egress regression suites
