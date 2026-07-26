# Plan: Production SAST Runtime and Rule Governance

## Approach

Convert the completed production Scan Plane architecture into an implementation-ready SAST
runtime contract before live Kubernetes rollout. Work proceeds in fail-closed slices: shared
contracts and profiles, scanner wrappers, hostile-input preflight, artifact ingestion,
normalization/identity, coverage/evidence, rule governance, then production qualification.

The first delivery is design and contract enforcement. It does not claim that a scanner
microVM platform is live. Provider-specific deployment execution remains governed by
`005-production-deployment-operations`.

## Target Boundaries

- `packages/shared`: scanner/profile/plan/artifact/finding/coverage/evidence/rule contracts
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
not wired to a production artifact reader or persistence worker ahead of T035. Its candidate
batch retains immutable plan/attestation digests and resolves semantic rule identity only from
the signed rule-bundle manifest. T033's Trivy adapter applies the same transient boundary to
dependency, secret, and IaC records, including supported `ExperimentalModifiedFindings`.
Dependency authority is database-derived; secret/IaC authority is checks-manifest-derived;
scanner disposition remains non-authoritative, and raw secret/context/prose fields are
discarded before candidate construction. T034's Syft adapter pins the v1.44.0 directory
producer and CycloneDX JSON 1.6 schema, shares the same bounded scalar-streaming core, and
emits only a transient SBOM inventory with hashed producer references. Raw properties,
source locations, license text, prose, external references, and the raw artifact are excluded;
the inventory has no finding, vulnerability, policy, persistence, or AI authority.

### Slice 5 - Identity, Correlation, and Lifecycle

Compute `sast-fingerprint-v1`, preserve all scanner provenance, correlate only compatible
authoritative capabilities, and represent occurrences separately from stable findings. Mark
fixed/reopened only from later complete, non-stale comparable scans.

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
- `NormalizedSastFinding`, provenance, occurrence, and correlation
- `ScannerCoverageRecord` and `SastCoverageDecision`
- `SastEvidencePolicy` and evidence pack reference
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
