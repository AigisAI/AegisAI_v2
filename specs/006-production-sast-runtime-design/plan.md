# Plan: Production SAST Runtime and Rule Governance

## Approach

Convert the completed production Scan Plane architecture into an implementation-ready SAST
runtime contract before live Kubernetes rollout. Work proceeds in fail-closed slices: shared
contracts and profiles, scanner wrappers, hostile-input preflight, artifact ingestion,
normalization/identity, coverage/evidence, rule governance, then production qualification.

The first delivery is design and contract enforcement. It does not claim that a scanner
microVM platform is live. Provider-specific deployment execution remains governed by
`005-production-deployment-operations`.

Issue #276 is an explicitly reclassified adjacent bootstrap, not a new production slice.
Its `ontology/` Neo4j and MITRE CWE work remains local dev/demo data tooling with no Scan,
AI, policy, finding, evidence, publication, SCM, tenant, or deployment authority. Work on
that bootstrap did not advance or satisfy T040; the formal 006 sequence has since completed
T040, T041, T042, T043, T044, T045, T046, and T047 independently and now proceeds to T048.

## Target Boundaries

- `packages/shared`: scanner/profile/plan/artifact/finding/coverage/freshness/retry/evidence/rule contracts
- `apps/api`: planning, repository binding, policy, canonical identity, and user-facing state
- `services/scan-orchestrator`: lane queues, attempt state, isolation requests, retries,
  coverage, correlation, evidence, and cleanup coordination
- `services/scanner-worker`: production wrapper entrypoint only; no mock-analysis fallback
- Scan Plane result ingress: write-only artifact intake and independent validation
- Data/Security Plane: artifact/evidence storage, encryption, retention, audit, and KMS
- AI Plane: advisory consumer of normalized findings and reduced evidence only
- `deploy/scanner-sandbox`: immutable runtime profiles and provider-specific microVM rollout
- `specs/006-production-sast-runtime-design`: canonical design and verification package

## Non-Negotiable Invariants

1. Resolve and bind a fixed commit SHA before queueing execution.
2. One scan attempt receives one non-reused hardened/restricted microVM.
3. No customer code execution, package installation, repository build, dynamic test, direct
   source upload, SCM write/admin access, or unrestricted egress.
4. Scanner commands and rules are platform owned, versioned, signed, and digest pinned.
5. Raw scanner output is untrusted and never returned by user-facing APIs.
6. Incomplete, stale, quarantined, or security-blocked scans cannot publish externally,
   resolve findings, or invoke AI.
7. AI is advisory-only and has no SCM credentials or repository access.
8. Workspace destruction and retention expiry are measured security outcomes.

## Implementation Slices

### Slice 1 - Shared Contract Baseline

Define scanner responsibility, Java Fast/Deep and Common Deep profiles, resource/path limits,
plan and artifact envelopes, normalized finding/provenance, stable identity, coverage,
evidence, rule promotion, quality measurements, and failure decisions. Contract tests prove
forbidden capabilities, fail-closed coverage, bounded evidence, and quantitative gates.

### Slice 2 - Planner and Canonical Scan Identity

Implement deterministic profile selection from trusted repository metadata and policy. Bind
fixed commit, profile digest, scanner-set digest, rule/database/schema versions, isolation
class, and tenant-scoped ingress references into the canonical key. Reject unsupported
languages/profiles and missing required artifacts explicitly.

### Slice 3 - Runtime Wrapper and Hostile Preflight

Replace production use of mock analysis with a wrapper that accepts only a signed plan/profile.
Fetch a shallow fixed commit with short-lived repo-read credentials, enforce path/symlink/
case/depth/size/count policies, and run pinned OpenGrep, Trivy, and Syft without build or
network enrichment. Capture exit/resource/provenance metadata and destroy the microVM.

### Slice 4 - Result Ingress and Normalization

Use per-scan write-only result ingress. Revalidate workload identity, plan binding, digests,
schema, size/count, encoding, coordinates, paths, enums, and status outside the sandbox.
Quarantine invalid artifacts. Normalize only through versioned adapters with golden fixtures;
emit only transient `durablePersistenceAllowed=false` candidates, and redact detected secret
values before durable normalized storage. T032's OpenGrep adapter is scalar-streaming and is
not wired to a production artifact reader or persistence worker; the T035 component remains
an internal handoff consumed only by T036 until Data/Security orchestration exists. Its candidate
batch retains immutable plan/attestation digests and resolves semantic rule identity only from
the signed rule-bundle manifest. T033's Trivy adapter applies the same transient boundary to
dependency, secret, and IaC records, including supported `ExperimentalModifiedFindings`.
Dependency authority is database-derived; secret/IaC authority is checks-manifest-derived;
scanner disposition remains non-authoritative, and raw secret/context/prose fields are
discarded before candidate construction. T034's Syft adapter pins the v1.44.0 directory
producer and CycloneDX JSON 1.6 schema, shares the same bounded scalar-streaming core, and
emits only a transient SBOM inventory with hashed producer references. Raw properties,
source locations, license text, prose, external references, and the raw artifact are excluded;
the inventory has no finding, vulnerability, policy, persistence, or AI authority. T035's
`sast-secret-redaction-v1` gate verifies canonical OpenGrep/Trivy batch and accepted
disposition digests, rechecks retention on both sides, and scans both non-empty candidates
and zero-finding batch bindings. It replaces only display text with a fixed marker; a match
in normalized path, semantic rule identity, symbol anchor, sink kind, scanner version/match
identity, rule provenance identifier/revision, dependency
vulnerability/package/type/installed/fixed-version identity, secret category, or IaC check
type/AVD identity rejects the entire batch. The async gate has an 8,000,000 inspected
UTF-16 code-unit ceiling, yields at bounded 64-candidate/32,768-code-unit chunks, and requires
trusted canonical SHA-256 recomputation at receiving boundaries. Its fresh output exposes
safe counts and sanitized-only decision digests, never matched values, matched-value hashes, or the
source-candidate digest, and remains non-durable until T036 verifies it.

### Slice 5 - Identity, Correlation, and Lifecycle

T036 now recomputes the exact T035 handoff and sanitized decisions, projects the seven
canonical identity fields with NFC and UTF-8 byte-length framing, and computes
`sast-fingerprint-v1`. It maps `UNKNOWN` to the explicit empty path, preserves OpenGrep/Trivy
provenance in a fresh persistence-eligible handoff, allows byte-identical repeated
observations, and rejects digest collisions, forged inputs, clock rollback, expiry, and
over-limit batches. It exports no occurrence, lifecycle, correlation, coverage, evidence,
policy, publication, or AI authority. T037 now revalidates that complete handoff against
durable scan state, persists one repository-scoped lineage plus every ordered occurrence,
and keeps lifecycle state separate per target ref. Exact aliases update one lineage; a
path-only alias is added only from a verified fixed-commit, one-to-one rename attestation.
Append-only `CREATED`, `RENAMED`, `FIXED`, and `REOPENED` events are serialized with the
observation/reconciliation ledger. Fixed/reopened transitions consume, but never calculate,
a T039-owned complete, non-stale, comparable coverage decision and verify its exact
observation-batch set. T038 now closes that complete durable source set, applies the scanner
responsibility/profile authority matrix, and stores bounded deterministic correlation edges
with both occurrence provenance records. It never merges capability families or inherits
severity, lifecycle, coverage, policy, publication, evidence, or AI authority. T039 now
rebinds that T038 batch to immutable plan, scanner-run, artifact-ingestion/disposition, and
scanner-responsibility state. It stores canonical scanner records plus a coverage decision
in one serializable transaction and persists zero publication authority even when coverage
is complete. T040 now independently rebinds that immutable coverage source to a monotonic,
provider-authoritative latest-target observation and an exact prior-scan comparison. It also
persists a bounded attempt-two infrastructure-only retry decision before sandbox admission,
with scanner-set and kill-switch revalidation plus new sandbox/workload identity. T041 now
rebinds that exact fresh decision to one durable accepted occurrence and its fingerprinted
source finding before any evidence source read. The internal source authority defaults to
unavailable; verified source is scanner-redacted and platform-redacted in memory, then a
canonical pack is limited to 32 KiB, five fragments, 8 KiB per fragment, and five context
lines. Full-file spans, more than two fragments per file, overlapping/adjacent intervals, or
25% or greater per-file line coverage reject the complete build. T042 now creates an immutable
seven-day deletion schedule with every accepted pack and rebinds the complete T041 pack before
each purpose-specific dashboard or AI decision. It reruns known-format, registered-platform,
and entropy redaction at access time, rejects unsafe paths and identifiers, and exposes only an
authenticated tenant/repository-scoped dashboard projection or a reduced AI reference with an
at-most-24-hour eligibility window. The T041 pack flags remain unchanged. Expiry claims are
leased and fenced; a verified provider receipt is required before content deletion and an
immutable proof, while the T041 build decision remains retained. The default secret registry
and deletion provider authorities fail closed. Only `SastEvidenceAccessService` crosses the
Scan Plane module boundary. T043 now accepts only tenant/repository/evidence-pack/model intent,
classifies access before and after rebinding the exact T037 occurrence and normalized finding,
and derives deterministic `sast-ai-advisory-handoff-v1` identities. Its immutable ledger stores
only scope references, digests, expiry, and fixed authority/audit bits; request payload, source,
secret values, and evidence fragments are absent. The AI runtime receives normalized metadata
plus one opaque reduced-evidence reference, an empty snippets array, and zero retrieval, tool,
policy, publication, lifecycle, or SCM authority. T044 now accepts only tenant/advisory identity
bound to the authenticated internal tenant,
rebinds the complete T043/T037 scope, and captures bounded finding, lifecycle, policy, waiver,
and suppression digests from one database-fenced authoritative snapshot projected identically
before and after the only permitted immutable proof write in one serializable transaction. Its
content-free ledger fixes every authoritative mutation bit false. Bulk normalized-finding and
lifecycle statements deduplicate affected fence keys before advancing their versions.
Policy accepts only a verified advisory/proof reference for visibility while exact waiver and
suppression request shapes reject AI/proof fields. T045 now records canonical content-free
rule-bundle manifests, trusted signature/provenance attestations, and exact immutable
scanner/image/wrapper/schema/normalizer/profile compatibility receipts. Planning rejects
unverified, drifted, unsupported, or unavailable verification before queue reservation. T046
now separates reusable semantic metadata from byte-exact signed-manifest bindings, resolves
only monotonic declarative tenant policy, and commits the immutable resolution receipt to the
canonical plan before queue reservation. T047 now binds quantitative candidate/baseline evidence
to the exact T045 supply-chain records, enforces independent human approvals and the legal
append-only lifecycle graph, and admits only the latest `CANARY` or `ACTIVE` transition through
an immutable selection receipt before tenant-policy resolution. That receipt enters
`sast-canonical-scan-key-v3`; external canary-observation, emergency-suspension, and rollback
authorities remain fail-closed seams for T048, T049, and T050. T048 deterministic tenant-safe
canary cohorts and observation gates are the next implementation task.

### Slice 6 - Coverage, Failure, Policy, and Evidence

Track every required scanner/capability. Apply the explicit failure/retry matrix and deny all
external actions until complete coverage. Build bounded, redacted, reconstruction-checked
evidence from accepted findings, enforce retention, then pass references to policy and
eligible AI advisory flows.

### Slice 7 - Rule Governance and Supply Chain

Implement immutable bundle manifests, semantic rule identity, signatures/provenance,
compatibility, tenant policy/waiver metadata, promotion states, deterministic canary,
kill switches, rollback, and audit. Scanner/database/schema assets are pre-mirrored and pinned.

### Slice 8 - Production Qualification and Rollout Handoff

Run golden, regression, malicious, parser, privacy, performance, integration, and end-to-end
gates. Produce a machine-readable go/no-go record. Hand live cluster/microVM rollout to the
005 operations flow only after every 006 design/implementation gate is satisfied.

## Key Interfaces

- `SastScanProfile` and `ScannerSetDescriptor`
- `SastScanPlan` and canonical scan key
- `ScannerArtifactEnvelope` and result-ingress decision
- `SastNormalizedFindingCandidate`, `opengrep-sarif-normalizer-v1`, and
  `trivy-json-normalizer-v1`
- `SastSecretRedactionBatch`, `sast-secret-redaction-v1`, and bounded audit projection
- `NormalizedSastFinding`, provenance, occurrence, and correlation
- `ScannerCoverageRecord` and `SastCoverageDecision`
- `SastEvidencePolicy` and evidence pack reference
- `SastAiAdvisoryIntent`, `SastAiAdvisoryHandoff`, reference-only advisory ledger,
  `SastAiAdvisoryAuthorityProof`, and display-only policy reference
- `RuleBundleDescriptor`, promotion evidence, tenant policy, and kill switch
- `SastFailureDecision` and sandbox destruction evidence
- `SastQualityMeasurements` and immutable go/no-go record

## Migration Strategy

The current mock scanner remains a test fixture only. Production traffic must not route to
it. Introduce the new path behind a fail-closed platform flag, dual-read state only where
needed for migration, and no dual authoritative findings. Backfill metadata/provenance only
when source artifacts and digests are verifiable; otherwise label historical findings as
legacy and do not use them to resolve new SAST findings.

Rollout order is internal repositories, deterministic canary cohorts, then compatible tenants.
Rollback selects the recorded last-known-good immutable scanner set. Historical plans,
artifacts, and findings are never rewritten.

## Verification Strategy

- Shared type/contract tests enforce invariants before runtime implementation.
- Parser/normalizer/fingerprint fixtures verify deterministic data semantics.
- Malicious repositories execute only inside the production-equivalent microVM boundary.
- End-to-end tests include queue, fixed fetch, wrapper, ingress, policy, evidence, cleanup,
  and denied external actions.
- Supply-chain tests verify signature, provenance, digest, compatibility, kill switch, and
  rollback behavior.
- Performance and reliability use the quantitative gates in `quality-gates.md`.

## Completion Strategy

Implement tasks in `tasks.md` with tests first. Re-read the product baseline when any change
touches security, retention, scanner scope, AI access, or deployment boundaries. Re-run the
entire `quickstart.md` completion path before claiming the 006 milestone complete or handing
provider-specific execution back to the Kubernetes deployment flow.
