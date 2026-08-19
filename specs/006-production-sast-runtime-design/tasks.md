# Tasks: Production SAST Runtime and Rule Governance

## Phase 1: Detailed Design Baseline

- [x] T001 Create the canonical 006 quickstart and required read order
- [x] T002 Define scanner responsibilities, profiles, limits, and prohibited execution scope
- [x] T003 Define runtime, artifact, finding, coverage, evidence, and rule data models
- [x] T004 Define queue, fixed-fetch, wrapper, ingress, normalization, failure, and cleanup contracts
- [x] T005 Define hostile-repository threat controls and required malicious corpus
- [x] T006 Define immutable rule governance, canary, kill switch, and rollback
- [x] T007 Define quantitative gates and the mandatory admission contract for language profiles after Java v1

## Phase 2: Shared Contract Enforcement

- [x] T008 Add shared scanner/profile/responsibility contracts
- [x] T009 Add shared plan, artifact, finding provenance, and stable fingerprint contracts
- [x] T010 Add fail-closed coverage, failure, and publication decisions
- [x] T011 Add bounded evidence policy and safety validation
- [x] T012 Add rule-bundle promotion and production-quality gate contracts
- [x] T013 Add static and executable behavior tests for SAST design invariants

## Phase 3: Repository Entry and Completion Guardrails

- [x] T014 Point AGENTS, README, and GitHub conventions at the 006 quickstart
- [x] T015 Add active-feature tests for all 006 documents and completed baselines
- [x] T016 Run the 006 quickstart validation path and resolve every failure
- [x] T017 Publish the issue-linked branch and Draft PR using repository templates

## Phase 4: Planner and Profile Runtime

- [x] T018 Implement deterministic trusted-metadata profile selection
- [x] T019 Bind fixed commit, profile/scanner-set/rule/schema digests into canonical scan keys
- [x] T020 Add Fast and Deep atomic queue reservation, quota, stale-snapshot denial, and fairness policies
- [x] T021 Add unsupported-language/profile and over-limit reason codes to user-visible state

## Phase 5: Hardened Fetch and Scanner Wrapper

- [x] T022 Implement per-attempt short-lived repo-read token handoff
- [x] T023 Implement shallow fixed-commit fetch with submodule/LFS/archive defaults
- [x] T024 Implement hostile path, symlink, case-collision, size, count, and file-type preflight
- [x] T025 Implement pinned OpenGrep, Trivy, and Syft wrapper commands from signed profiles
- [x] T026 Enforce no build, install, dynamic execution, runtime update, or unrestricted egress
- [x] T027 Remove production routing to the mock-analysis path while preserving test fixtures
- [x] T028 Capture scanner exit, resource, digest, and sandbox destruction audit signals

## Phase 6: Artifact Ingress and Normalization

- [x] T029 Implement per-scan write-only artifact ingress and workload identity validation
- [x] T030 Verify plan binding, schema, digest, byte/count, encoding, path, and coordinate limits
- [x] T031 Quarantine malformed, mismatched, oversized, and security-violating artifacts
- [x] T032 Implement versioned OpenGrep SARIF normalization with golden fixtures
- [x] T033 Implement versioned Trivy JSON normalization with golden fixtures
- [x] T034 Implement versioned CycloneDX SBOM validation and inventory ingestion
- [x] T035 Redact secret values before normalized persistence, logs, audit, or evidence

## Phase 7: Finding Identity and Coverage

- [x] T036 Implement `sast-fingerprint-v1` with Unicode/path canonicalization
- [x] T037 Implement occurrences, exact lineage updates, rename handling, and fixed/reopen rules
- [x] T038 Implement authority-aware cross-tool correlation with full provenance preservation
- [x] T039 Persist scanner/capability coverage and apply fail-closed external publication
- [x] T040 Implement stale-scan denial and bounded infrastructure-only retries; drop and replace `SastExternalPublicationDecision_contract_check` before accepting independently validated freshness and comparability authority rows

## Approved Adjacent Bootstrap (Does Not Advance 006)

- [x] A001 Reclassify issue #276 as a local-only Neo4j/MITRE CWE dev/demo bootstrap with no production, Scan Plane, AI Plane, policy, finding, evidence, publication, SCM, or tenant authority
- [x] A002 Add bounded deterministic CWE ingestion, importer-owned snapshot reconciliation, and hostile archive/XML regression tests under `ontology/`
- [x] A003 Keep T040 as the next formal active-milestone task

## Phase 8: Evidence, Policy, and AI Boundary

- [x] T041 Build bounded accepted-finding evidence with reconstruction-risk checks
- [x] T042 Enforce dashboard/AI classification, secret redaction, seven-day expiry, and deletion proof
- [x] T043 Send only normalized findings and reduced evidence references to the advisory AI Plane
- [x] T044 Prove AI cannot create, suppress, waive, resolve, or override authoritative findings/policy

## Phase 9: Rule Governance Runtime

- [x] T045 Implement signed immutable bundle manifests and compatibility validation
- [x] T046 Implement semantic rule identity and non-executable tenant policy metadata
- [x] T047 Implement promotion evidence, approvals, and state transitions
- [x] T048 Implement deterministic tenant-safe canary cohorts and observation gates
- [x] T049 Implement scanner/bundle/rule/profile/tenant/global kill switches
- [x] T050 Implement last-known-good rollback without historical mutation

## Phase 10: Production Qualification

- [x] T051 Build versioned golden positive/negative and prior must-detect corpora
- [x] T052 Build schema/parser, malicious-repository, fingerprint, evidence/privacy, and performance corpora
- [ ] T053 Run production-equivalent microVM integration and destruction-evidence tests
  - [x] Repository-side exact 123-cell manifest, dependency/plan/receipt/result contracts,
    closed materialization policy, filesystem validator, provider plan generator, and Ed25519
    offline verifier are package-ready and fail closed as `PENDING_PROVIDER_EXECUTION`.
  - [ ] Execute all 123 cells on a real production-equivalent provider and verify provider/runtime
    signatures plus complete destruction evidence; do not replace this with CI or local fixtures.
- [ ] T054 Run Fast/Deep end-to-end, latency, reliability, and capacity gates
- [ ] T055 Run signature/provenance/database/schema supply-chain and rollback drills
- [ ] T056 Produce immutable go/no-go evidence satisfying every `quality-gates.md` threshold

## Deferred to Explicit Operations Execution

- [ ] Provision the live production Kubernetes cluster through `005-production-deployment-operations`
- [ ] Roll out the provider-specific production microVM platform through `005-production-deployment-operations`
- [ ] Install provider-backed GitHub App/GitLab repo-read credential minting adapters during live provider rollout
- [ ] Add language-specific SAST profiles beyond Java after independent corpus and gate approval
- [ ] Add build-assisted or dynamic analysis; prohibited in v1 and requires a separate threat model
