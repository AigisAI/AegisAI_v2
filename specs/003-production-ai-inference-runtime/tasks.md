# Tasks: Production AI Inference Runtime

## Phase 1: Feature Package Re-Baseline

- [x] T001 Add 003 production AI inference runtime feature package skeleton
- [x] T002 Point AGENTS, README, and GitHub conventions at the 003 quickstart
- [x] T003 Add active feature tests for the 003 entrypoint and 002 baseline preservation
- [x] T004 Point README completion guidance at the 003 quickstart and CI workflow without duplicating command checklists

## Phase 2: Shared Contract Slice

- [ ] T005 Add `AiInferenceRequest`, `AiInferenceResponse`, and `ReducedEvidence` contracts to `packages/shared`
- [ ] T006 Add contract tests proving AI inference contracts exclude SCM credentials, source archives, and raw scanner payloads

## Phase 3: Model Gateway Slice

- [ ] T007 Add model gateway interface in `apps/ai`
- [ ] T008 Add deterministic fallback provider for local/dev execution
- [ ] T009 Add runtime provider configuration guardrails

## Phase 4: Reduced Evidence Validation Slice

- [ ] T010 Reject unredacted, full repository, SCM credential, source archive, and raw scanner payload inputs
- [ ] T011 Add audit events for accepted, rejected, fallback, completed, and failed inference requests

## Phase 5: API Integration Slice

- [ ] T012 Wire API advisory client to the model gateway response shape
- [ ] T013 Persist advisory metadata without granting finding or policy authority

## Deferred

- [ ] Kubernetes production AI Plane deployment manifests and runtime autoscaling
- [ ] microVM-backed scanner provisioning
