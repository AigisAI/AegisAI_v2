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

## Phase 7A: Pre-Phase-8 Architecture Hardening

- [x] T037 Fix the shared-package boundary and enforce a clean `dist/main.js` API runtime layout
- [x] T038 Add Redis-backed sessions, CSRF protection, throttling, security headers, and health checks
- [x] T039 Derive tenant context from authenticated sessions and protect internal plane endpoints separately
- [x] T040 Add DTO validation, collision-safe idempotency, immutable scan scope checks, and bounded token/evidence TTLs
- [x] T041 Add deployable production-model migrations and remove long-lived OAuth token storage
- [x] T042 Initialize frontend auth from a credentialed same-origin API session
- [x] T043 Apply migrations and verify clean runtime output in CI; add deploy dependency health gates
- [x] T044 Add negative e2e coverage for CSRF, authentication, tenant isolation, internal auth, and scope mismatch

## Phase 8: Java-First Scan Planning Metadata

- [x] T028 Add shared language, scan profile, repository manifest, and Java-only AI advisory eligibility contract types
- [x] T029 Add deterministic repository manifest classification helpers for Java, common non-Java surfaces, and unknown files
- [x] T030 Extend the mock Scan Plane run input with optional repository manifest metadata while preserving existing no-manifest behavior
- [x] T031 Mark Java manifest runs as `JAVA_DETAILED` across Opengrep, Trivy, and Syft scanner metadata
- [x] T032 Keep non-Java-only manifest runs on `COMMON` scanner metadata without Java normalized findings or AI advisory eligibility
- [x] T033 Restrict AI advisory request contracts to Java detailed normalized findings plus reduced redacted evidence metadata
- [x] T034 Add contract tests for Java profile classification, common-only classification, and AI request leakage guardrails
- [x] T035 Add Scan Plane e2e coverage for legacy no-manifest behavior, Java detailed behavior, and non-Java common-only behavior
- [x] T036 Re-run the quickstart validation path after the metadata slice is implemented

### Validation checkpoint 2026-09-08

- Lint, typecheck, and workspace build passed.
- Full default test command passed: shared 8, API 41, web 61, workflow checks 3.
- Runtime validation passed: 2 checks covering build layout and compiled API health.
- Prisma schema validation passed with a command-local placeholder `DATABASE_URL`;
  no database connection or migration application was performed locally. Clean database
  migration application remains an additional CI gate.
- The first focused API run timed out during setup. A diagnostic rerun passed, and the
  final full run passed with default timeout settings and no test-runner changes.
- Entrypoints still target this feature package, Oracle remains dev/demo only, and the
  legacy MVP package is preserved.
- T001-T044 are complete for this skeleton milestone. This is not production go-live;
  deferred runtime work below requires a follow-on implementation package.

## Deferred

- [ ] Implement GitHub App installation runtime
- [ ] Implement GitLab Cloud integration runtime
- [ ] Implement Token Broker credential issuance
- [ ] Implement Opengrep/Trivy/Syft sandbox execution
- [ ] Implement evidence object storage and TTL deletion
- [ ] Implement policy-as-code engine
- [ ] Implement AI detector/planner inference
- [ ] Implement language-specific SAST profiles beyond Java
