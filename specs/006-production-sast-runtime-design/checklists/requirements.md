# Requirements Checklist: Production SAST Runtime and Rule Governance

## Architecture and Scope

- [x] 006 has a canonical quickstart and explicit read/validation order.
- [x] Scan Plane, AI Plane, and Data/Security Plane boundaries remain explicit.
- [x] OpenGrep owns SAST, Trivy owns dependency/secret/IaC findings, and Syft owns SBOM inventory.
- [x] Java Fast/Deep and Common Deep profiles state claimed and unclaimed coverage.
- [x] Languages after Java require a versioned profile, corpus, normalization, rollout, and coverage-admission contract.
- [x] Customer code execution, package installation, build, dynamic test, and direct upload are prohibited.
- [x] Live Kubernetes and provider microVM execution remain in the 005 operations boundary.

## Isolation and Input Safety

- [x] Every attempt uses one non-reused hardened/restricted microVM.
- [x] Fixed-commit shallow fetch and short-lived repo-read credentials are required.
- [x] Submodule, LFS, archive, path, symlink, collision, depth, size, file, process, and time behavior is explicit.
- [x] Scanner assets are pre-mirrored and runtime updates/unrestricted egress are prohibited.
- [x] Destruction evidence and cleanup alert behavior are defined.

## Artifact and Finding Integrity

- [x] Artifact ingress independently verifies attribution, identity, digest, schema, limits, and status.
- [x] Raw output is treated as untrusted and never exposed by user-facing APIs.
- [x] Versioned normalization, quarantine, secret redaction, and provenance are defined.
- [x] Stable fingerprint inputs exclude line, branch, and commit while preserving repository scope.
- [x] Correlation preserves every provenance record and authoritative severity.
- [x] Fixed/reopen transitions require later complete comparable coverage.

## Coverage, Evidence, and AI

- [x] Required scanner failure, timeout, absence, quarantine, and stale state fail closed.
- [x] Retry is limited to infrastructure failure and at most two attempts.
- [x] External publication and AI advisory require complete non-stale coverage.
- [x] Evidence is bounded, redacted, reconstruction-checked, and retained no longer than seven days.
- [x] AI receives no full repository or SCM credential and remains advisory-only.

## Rule and Supply-Chain Governance

- [x] Scanner, rule, database, schema, and normalizer artifacts are immutable and digest pinned.
- [x] Signature, provenance, compatibility, semantic rule identity, and rollback are required.
- [x] Rule promotion, separation of duties, deterministic canary, kill switches, and rollback are explicit.
- [x] Signed append-only kill-switch authority is enforced at planning, queue, scanner, artifact, retry, coverage, publication, AI, and emergency suspension boundaries.
- [x] Tenant policy and waiver metadata cannot mutate or inject executable rule content.
- [x] Disabled required coverage cannot be silently reported complete.

## Quantitative Readiness

- [x] Correctness, precision, recall, regression, parser, malicious, privacy, and supply-chain gates are measurable.
- [x] Corpus sample sufficiency and exact metric denominators are defined.
- [x] T052 pins exactly 84 non-executable multi-class qualification inputs and grants no execution or readiness authority.
- [x] T053 repository handoff pins exactly 123 isolated execution cells, dual approvals/signatures, zero-effect and 60-second destruction evidence, and remains pending without real provider receipts.
- [x] T054 repository handoff pins exactly 3,462 candidate/baseline cells, requires a signed T053 pass plus exact same-provider dependency evidence, independently pins its trust root, loads and individually verifies every artifact signature and provenance statement before verifying the closed supply-chain-signed set, recomputes every gate from signed receipts, and remains blocked without external evidence.
- [x] T055 repository handoff pins exactly 169 supply-chain/database/schema/rollback cells, requires the exact signed same-provider T054 chain and an independently pinned trust root, reverifies every artifact envelope, recomputes the 115 pre-execution rejections and 39 invocations from three-role-signed receipts, authenticates each durable prior rollback-ledger head and sequence with independent Qualification Authority and Supply Chain Authority signatures before plan approval, accepts only the exact next append, and remains blocked without external evidence.
- [x] Fast/Deep absolute SLOs and relative candidate regression limits are defined.
- [x] Cross-tenant leak, secret leak, sandbox escape, and stale publication tolerance is zero.
- [x] Canary observation windows, minimum scans, automatic pause, and production rolling windows are defined.
- [x] A machine-readable immutable go/no-go record is required.

## Repository Workflow

- [x] AGENTS, README, and GitHub conventions point to 006 as active.
- [x] Active-feature tests cover every required 006 design artifact and completed baseline.
- [x] The complete quickstart validation path passes.
- [x] Issue, branch, commit, and Draft PR follow repository naming and template conventions.
