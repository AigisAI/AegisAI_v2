# Tasks: Production Scan Architecture

## Phase 1: Documentation Re-Baseline

- [x] T001 Add `specs/002-production-scan-architecture/quickstart.md`
- [x] T002 Add active spec, research, data model, contract, plan, checklist, and tasks docs
- [x] T003 Update `AGENTS.md`, `README.md`, and `docs/github-conventions.md`

## Phase 2: Contract Skeleton

- [x] T004 Add shared production scan architecture types and helpers in `packages/shared`
- [x] T005 Add backend contract tests that import shared architecture contracts

## Phase 3: Persistence Skeleton

- [x] T006 Extend Prisma with tenant-attributed production architecture models
- [x] T007 Add schema tests for tenant attribution and architecture entities

## Phase 4: Validation

- [x] T008 Run `corepack pnpm lint`
- [x] T009 Run `corepack pnpm test`
- [x] T010 Run `corepack pnpm typecheck`
- [x] T011 Run `corepack pnpm build`
- [x] T012 Run `corepack pnpm --filter @aegisai/api prisma:validate`

## Phase 5: Control Plane API Skeleton

- [x] T013 Update API bootstrap metadata to point to `002-production-scan-architecture`
- [x] T014 Add in-memory Control Plane service skeleton for integration, repository binding, and scan request flows
- [x] T015 Add GitHub App and GitLab Cloud integration install endpoints without external SCM calls
- [x] T016 Add tenant-scoped repository binding list endpoint
- [x] T017 Add scan request create/status endpoints with canonical scan key and isolation escalation
- [x] T018 Add e2e coverage for Control Plane skeleton behavior

## Phase 6: Token Broker & Audit Skeleton

- [x] T019 Add Token Broker issue endpoint returning credential metadata only
- [x] T020 Add tenant-scoped audit event read endpoint
- [x] T021 Record token issuance audit events without persisting token values
- [x] T022 Add e2e coverage for token non-persistence and audit reads

## Phase 7: Scan Plane Mock Pipeline Skeleton

- [x] T023 Add mock Scan Plane run endpoint for deterministic scanner metadata
- [x] T024 Emit Opengrep, Trivy, and Syft scanner run records
- [x] T025 Emit one normalized finding and one redacted short-lived evidence pack
- [x] T026 Add tenant-scoped scanner run, finding, and evidence read endpoints
- [x] T027 Add e2e coverage for Scan Plane mock pipeline behavior and leakage guardrails

## Phase 8: GitHub App Installation Runtime Slice

- [x] T028 Add GitHub App installation client for app JWT, installation token exchange, and repository listing
- [x] T029 Allow GitHub App install endpoint to build repository bindings from installation metadata
- [x] T030 Add GitHub App runtime configuration placeholders without making token values persistent
- [x] T031 Add e2e coverage for installation repository binding and missing credential guardrails

## Phase 9: GitHub App Installation State and Webhook Slice

- [x] T032 Persist GitHub App installation metadata through tenant-scoped Prisma upserts without token values
- [x] T033 Add GitHub installation repository webhook acknowledgement endpoint
- [x] T034 Reconcile GitHub installation repository added/removed events into repository bindings
- [x] T035 Add e2e coverage for installation persistence, webhook reconciliation, and token leakage guardrails

## Deferred

- [ ] Implement GitLab Cloud integration runtime
- [ ] Implement Token Broker credential issuance
- [ ] Implement Opengrep/Trivy/Syft sandbox execution
- [ ] Implement evidence object storage and TTL deletion
- [ ] Implement policy-as-code engine
- [ ] Implement AI detector/planner inference
