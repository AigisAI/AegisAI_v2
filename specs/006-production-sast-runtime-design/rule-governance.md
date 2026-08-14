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
- `sast-canonical-scan-key-v2` commits the verified tenant-policy receipt. Deployment is a
  fail-closed cutover: every non-terminal v1 SAST plan and queue reservation must first finish
  or be explicitly canceled. Terminal v1 rows remain immutable audit history and are never
  rewritten or replayed as v2 work.
- T046 grants no rule promotion, canary, kill-switch, rollback, scanner execution, waiver
  creation, finding mutation, publication, AI, or SCM authority. Those remain T047-T050 and
  later runtime gates.

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
7. no more than 2% scanner failure rate and no more than 20% p95 latency regression;
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

Canary assignment is deterministic from a platform-secret keyed hash of tenant ID,
repository binding ID, profile ID, and rollout ID. It must not use repository content,
finding counts, severity, or customer identity attributes.

- Default cohort progression: internal corpus -> internal repositories -> 1% -> 5% -> 25%
  -> 100% of eligible repository bindings.
- Each step observes at least 24 hours and the minimum completed scan count in
  `quality-gates.md`; the slower requirement wins.
- A canonical scan uses exactly one bundle version. Retries retain that version.
- A repository binding remains in one cohort for the rollout duration.
- Tenants may be excluded for contractual or residency reasons, never silently forced into
  an experimental cohort.
- Canary findings are authoritative only when the bundle is `CANARY`, its gates remain
  healthy, and selected profile coverage is complete.
- Every security zero-tolerance counter in `quality-gates.md`, including unauthorized egress,
  missing destruction evidence, evidence-policy violations, and unsigned artifact execution,
  must remain exactly zero at every step or the canary pauses immediately.

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
binding, capability, profile, external publication, and global SAST runtime scope. A switch is a
versioned, signed control-plane decision with actor, reason, incident reference, activation time,
expiry/review time, and rollback target.

- A disabled required scanner or required rule capability makes coverage partial/failed;
  it never silently reports complete coverage.
- A repository-binding switch stops new attempts for that binding and denies reuse, publication,
  and AI advisory for its existing affected scans without affecting unrelated repositories.
- A capability switch removes that capability from authoritative coverage; a profile that
  requires it becomes partial/failed even when its scanner process succeeds.
- An external-publication switch denies comments and blocking decisions at the selected target
  scope while allowing safe internal normalization and dashboard processing to continue.
- A global or scanner kill switch stops new plans and cancels only attempts that have not
  crossed the safe cancellation boundary.
- Accepted artifacts from a killed version are quarantined until reviewed.
- External comments, blocking decisions, and AI requests are denied for affected scans.
- Kill-switch evaluation occurs at planning, immediately before scanner start, artifact
  acceptance, and external publication.

## Rollback

Every canary/active bundle records a tested last-known-good digest. Rollback creates a new
rollout decision; it does not mutate old scan plans or rewrite historical findings.

1. Activate the affected kill switch and stop new affected plans.
2. Select the compatible last-known-good scanner set and verify signature/provenance again.
3. Route new plans to that digest and invalidate reusable scan results whose canonical key
   included the faulty digest.
4. Mark the faulty bundle `ROLLED_BACK`, preserve artifacts and decisions under retention
   policy, and identify affected scans/findings.
5. Re-evaluate external policy decisions where the faulty bundle changed authority; never
   erase history.
6. Close rollback only after production gates remain healthy for the required window.

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
