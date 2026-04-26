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

## Deferred

- [ ] Implement GitHub App installation runtime
- [ ] Implement GitLab Cloud integration runtime
- [ ] Implement Token Broker credential issuance
- [ ] Implement Opengrep/Trivy/Syft sandbox execution
- [ ] Implement evidence object storage and TTL deletion
- [ ] Implement policy-as-code engine
- [ ] Implement AI detector/planner inference
