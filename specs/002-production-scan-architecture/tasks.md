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

## Phase 10: GitLab Cloud Integration Runtime Slice

- [x] T036 Add GitLab Cloud integration client for runtime token repository listing
- [x] T037 Allow GitLab install endpoint to build repository bindings from GitLab project metadata
- [x] T038 Add GitLab runtime configuration placeholder without persisting runtime token values
- [x] T039 Add e2e coverage for GitLab repository binding and runtime token leakage guardrails

## Phase 11: Token Broker Credential Issuance Slice

- [x] T040 Add scan-scoped short-lived credential value issuance
- [x] T041 Return credential value only to the Token Broker issue caller with explicit expiration metadata
- [x] T042 Keep token values out of tenant-scoped audit events
- [x] T043 Add e2e coverage for unique credential values and audit leakage guardrails

## Phase 12: Sandbox Scanner Execution Adapter Slice

- [x] T044 Add Opengrep, Trivy, and Syft sandbox scanner adapter invocation boundary
- [x] T045 Return scanner run metadata for sandboxed scanner execution requests
- [x] T046 Attach read-only workspace, no-network, no-package-install, and no-build sandbox metadata
- [x] T047 Add e2e coverage for scanner adapter execution and credential/source leakage guardrails

## Phase 13: Evidence Object Storage and TTL Deletion Slice

- [x] T048 Add local dev/demo evidence object storage adapter with tenant/scan scoped object keys
- [x] T049 Add metadata-only evidence access request endpoint
- [x] T050 Add TTL deletion task for expired evidence objects
- [x] T051 Add e2e coverage for evidence storage, TTL deletion, and credential/source leakage guardrails

## Phase 14: Policy Engine Decision Skeleton Slice

- [x] T052 Add deterministic policy engine evaluator for scanner-first findings
- [x] T053 Add policy decision evaluate and tenant-scoped read endpoints
- [x] T054 Keep AI advisory metadata visible but non-authoritative for enforcement decisions
- [x] T055 Add e2e coverage for policy decision shape, coverage requirements, and leakage guardrails

## Phase 15: AI Advisory Detector Planner Skeleton Slice

- [x] T056 Add AI advisory result contract for advisory-only detector/planner output
- [x] T057 Add mock AI Plane advisory service over normalized findings and redacted evidence
- [x] T058 Add AI advisory create and tenant-scoped read endpoints
- [x] T059 Add e2e coverage for reduced evidence input and policy/finding non-authority guardrails

## Phase 16: AI Advisory Runtime Adapter Boundary Slice

- [x] T060 Add AI advisory runtime client for `AI_SERVER_URL` detector/planner calls
- [x] T061 Route `USE_INTERNAL_AI=true` advisory requests through the runtime adapter
- [x] T062 Validate runtime responses as advisory-only metadata
- [x] T063 Add e2e coverage for reduced request forwarding, runtime response validation, and leakage guardrails

## Phase 17: AI Model Service Runtime Skeleton Slice

- [x] T064 Add standalone `apps/ai` runtime package for detector/planner advisory service
- [x] T065 Add `/ai/advisories` HTTP handler over normalized finding and redacted evidence inputs
- [x] T066 Reject credentials, full repository content, source archives, raw scanner payloads, and policy/finding authority fields
- [x] T067 Add dev/demo Docker image, Oracle Compose service, env examples, and runtime tests

## Phase 18: Waiver and Suppression Lifecycle API Slice

- [x] T068 Add shared create/update input contracts for waivers and suppressions
- [x] T069 Add tenant-scoped waiver create and update endpoints
- [x] T070 Add tenant-scoped suppression create endpoint
- [x] T071 Add e2e coverage for lifecycle metadata, tenant scoping, and leakage guardrails

## Phase 19: Comment Dispatcher Boundary Slice

- [x] T072 Add shared comment dispatch plan request/result contracts
- [x] T073 Add Control Plane comment dispatch plan endpoint
- [x] T074 Require policy `commentAllowed` and SCM comment-write principal metadata
- [x] T075 Add e2e coverage for dispatch metadata and credential/source leakage guardrails

## Phase 20: Comment Dispatch Audit Event Boundary Slice

- [x] T076 Add shared comment dispatch audit event contract
- [x] T077 Record tenant-scoped `comment_dispatch.planned` audit events
- [x] T078 Add comment dispatch audit event read endpoint
- [x] T079 Add e2e coverage for tenant scoping and credential/source leakage guardrails

## Phase 21: Comment Dispatch Idempotency Boundary Slice

- [x] T080 Add deterministic comment dispatch idempotency key contract
- [x] T081 Return existing plans for identical dispatch planning retries
- [x] T082 Avoid duplicate `comment_dispatch.planned` audit events for idempotent retries
- [x] T083 Add e2e coverage for retry safety and credential/source leakage guardrails

## Phase 22: Comment Dispatch Outbox Boundary Slice

- [x] T084 Add comment dispatch enqueue request and outbox item contracts
- [x] T085 Add metadata-only outbox enqueue endpoint
- [x] T086 Add tenant-scoped outbox read endpoint
- [x] T087 Add e2e coverage for enqueue idempotency, tenant scoping, and credential/source leakage guardrails

## Phase 23: Comment Dispatch Outbox Audit Event Boundary Slice

- [x] T088 Extend comment dispatch audit event contract for outbox enqueue events
- [x] T089 Record one tenant-scoped `comment_dispatch.enqueued` audit event per outbox item
- [x] T090 Avoid duplicate enqueue audit events for idempotent enqueue retries
- [x] T091 Add e2e coverage for enqueue audit metadata and credential/source leakage guardrails

## Phase 24: Comment Dispatch Outbox Failure Status Boundary Slice

- [x] T092 Add comment dispatch outbox failure status update contract
- [x] T093 Add tenant-scoped outbox status update endpoint
- [x] T094 Allow `FAILED` and `CANCELED` metadata transitions while deferring `PUBLISHED`
- [x] T095 Add e2e coverage for tenant scoping, publish deferral, and credential/source leakage guardrails

## Phase 25: Comment Dispatch Outbox Status Audit Event Boundary Slice

- [x] T096 Extend comment dispatch audit event contract for outbox status updates
- [x] T097 Record one tenant-scoped `comment_dispatch.outbox_status_updated` audit event per status transition
- [x] T098 Avoid duplicate status audit events for idempotent status update retries
- [x] T099 Add e2e coverage for status audit metadata and credential/source leakage guardrails

## Deferred

- [ ] Implement trained production AI detector/planner model inference
