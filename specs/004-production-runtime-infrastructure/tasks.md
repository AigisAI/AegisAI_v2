# Tasks: Production Runtime Infrastructure

## Phase 1: Feature Package Re-Baseline

- [x] T001 Add 004 production runtime infrastructure feature package skeleton
- [x] T002 Point AGENTS, README, and GitHub conventions at the 004 quickstart
- [x] T003 Add active feature tests for the 004 entrypoint and 003 baseline preservation
- [x] T004 Point README completion guidance at the 004 quickstart and CI workflow without duplicating command checklists

## Phase 2: Kubernetes AI Plane Manifest Slice

- [x] T005 Add Kubernetes AI Plane deployment and service manifest skeletons
- [x] T006 Add manifest tests proving AI containers do not receive SCM credentials, repository archives, full repositories, source archives, or raw scanner payloads

## Phase 3: Runtime Autoscaling Slice

- [x] T007 Add runtime autoscaling policy skeleton for latency, queue pressure, provider health, fallback, CPU, and memory signals
- [x] T008 Add autoscaling tests proving policy cannot grant finding or policy authority

## Phase 4: Scanner Sandbox Provisioning Slice

- [x] T009 Add microVM scanner sandbox provisioning contract skeleton
- [x] T010 Add scanner sandbox tests proving package install/build, dynamic testing, direct source upload, and AI repository access remain forbidden

## Deferred

- [ ] Live production Kubernetes cluster provisioning
- [ ] Provider-specific microVM platform rollout
