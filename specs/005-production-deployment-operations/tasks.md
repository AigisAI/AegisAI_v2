# Tasks: Production Deployment Operations

## Phase 1: Feature Package Re-Baseline

- [x] T001 Add 005 production deployment operations feature package skeleton
- [x] T002 Point AGENTS, README, and GitHub conventions at the 005 quickstart
- [x] T003 Add active feature tests for the 005 entrypoint and 004 baseline preservation
- [x] T004 Point README completion guidance at the 005 quickstart and CI workflow without duplicating command checklists

## Phase 2: Production Cluster Provisioning Contract Slice

- [x] T005 Add provider-neutral production cluster provisioning contract in shared package
- [x] T006 Add tests proving provider credentials are not local development defaults

## Phase 3: Provider microVM Rollout Contract Slice

- [x] T007 Add provider-neutral microVM platform rollout contract in shared package
- [x] T008 Add tests proving scanner isolation and AI repository access guardrails remain enforced

## Phase 4: Live Operation Preflight Slice

- [x] T009 Add deployment operation preflight contract in shared package
- [x] T010 Add tests proving live execution inputs do not persist provider credentials or forbidden payloads

## Phase 5: Live Operation Handoff Manifest Slice

- [x] T011 Add deployment operation handoff manifest contract in shared package
- [x] T012 Add tests proving credential handoff remains reference-only before live execution

## Phase 6: Detailed SAST Runtime Handoff

- [x] T013 Hand the SAST runtime and rule-governance follow-up to `006-production-sast-runtime-design` before live scanner rollout

## Phase 7: T056 GO-Bound Deployment Entry

- [x] T014 Require a fresh Qualification Authority Ed25519 attestation over the exact valid T056 `GO`, repository commit, provider/adapter, rollback, kill-switch evidence, and current 005 contract
- [x] T015 Require the immutable qualification binding, exact credential scopes and approvals, trusted-time audit signal, bounded execution window, and reference-only rollback handoff in 005 preflight
- [x] T016 Add passing and fail-closed tests for non-GO, signature failure, expiry, provider/approval drift, unknown fields, rollback drift, and zero deployment/Kubernetes/readiness authority
- [x] T017 Bump and regenerate T056 assets so the manifest and policy pin the exact current 005 contract digest

## Deferred

- [ ] Execute live production Kubernetes cluster provisioning
- [ ] Execute provider-specific microVM platform rollout
