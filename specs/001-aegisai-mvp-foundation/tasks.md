---

description: "Executable baseline task list for the AegisAI MVP foundation"
---

# Tasks: AegisAI Platform MVP Foundation

**Input**: Design documents from `/specs/001-aegisai-mvp-foundation/`  
**Prerequisites**: `plan.md`, `spec.md`, `research.md`, `data-model.md`, `contracts/`

**Tests**: Tests are required for all touched critical flows, especially auth, session,
CSRF, provider integration, queue processing, dashboarding, vulnerability review, and PDF
reporting.

**Organization**: Tasks are grouped by user story to enable independent implementation and
validation of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel
- **[Story]**: Which user story the task belongs to
- Include exact file paths in descriptions

## Path Conventions

- **Backend API**: `apps/api/src/`, `apps/api/prisma/`, `apps/api/test/` or `apps/api/tests/`
- **Frontend Web**: `apps/web/src/`, `apps/web/tests/` or colocated `*.test.tsx`
- **Shared Contracts**: `packages/shared/src/`
- **Optional AI Service**: `apps/ai/`

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Create the pnpm workspace, package boundaries, and local development shell.

- [x] T001 Create root workspace files in `package.json`, `pnpm-workspace.yaml`, `.npmrc`, and `docker-compose.yml`
- [x] T002 Create backend package scaffolding in `apps/api/package.json`, `apps/api/tsconfig.json`, `apps/api/nest-cli.json`, and `apps/api/src/main.ts`
- [x] T003 [P] Create frontend package scaffolding in `apps/web/package.json`, `apps/web/tsconfig.json`, `apps/web/vite.config.ts`, and `apps/web/src/main.tsx`
- [x] T004 [P] Create shared package scaffolding in `packages/shared/package.json`, `packages/shared/tsconfig.json`, and `packages/shared/src/index.ts`
- [x] T005 Configure top-level developer commands in root `package.json` and add baseline environment examples in `.env.example`, `apps/api/.env.example`, and `apps/web/.env.example`
- [x] T006 [P] Add workspace lint, test, and typecheck configuration in `apps/api/package.json`, `apps/web/package.json`, and any root config files selected in the plan

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Build the core architecture that every user story depends on.

**⚠️ CRITICAL**: No user story work should begin until this phase is complete.

- [x] T007 Create Prisma baseline schema and initial migration in `apps/api/prisma/schema.prisma` and `apps/api/prisma/migrations/`
- [x] T008 [P] Create shared contract types in `packages/shared/src/types/common.ts`, `packages/shared/src/types/auth.ts`, `packages/shared/src/types/repo.ts`, `packages/shared/src/types/scan.ts`, `packages/shared/src/types/vulnerability.ts`, `packages/shared/src/types/dashboard.ts`, and `packages/shared/src/types/report.ts`
- [x] T009 [P] Create config and Prisma infrastructure in `apps/api/src/config/config.module.ts`, `apps/api/src/config/config.service.ts`, `apps/api/src/prisma/prisma.module.ts`, and `apps/api/src/prisma/prisma.service.ts`
- [x] T010 Implement auth and session foundation in `apps/api/src/auth/auth.module.ts`, `apps/api/src/auth/auth.service.ts`, `apps/api/src/auth/auth.serializer.ts`, `apps/api/src/auth/guards/session-auth.guard.ts`, `apps/api/src/auth/decorators/current-user.decorator.ts`, and `apps/api/src/auth/utils/token-crypto.util.ts`
- [x] T011 [P] Implement OAuth provider strategies in `apps/api/src/auth/strategies/github.strategy.ts` and `apps/api/src/auth/strategies/gitlab.strategy.ts`
- [x] T012 Implement provider client abstractions in `apps/api/src/client/git/git-provider-client.interface.ts`, `apps/api/src/client/git/github.client.ts`, `apps/api/src/client/git/gitlab.client.ts`, `apps/api/src/client/git/git-client.registry.ts`, and `apps/api/src/client/git/git-client.module.ts`
- [x] T013 [P] Implement language and analysis abstractions in `apps/api/src/language/language-handler.interface.ts`, `apps/api/src/language/language-handler.registry.ts`, `apps/api/src/language/handlers/java.language-handler.ts`, `apps/api/src/client/analysis/analysis-api-client.interface.ts`, `apps/api/src/client/analysis/analysis-api.dto.ts`, `apps/api/src/client/analysis/mock-analysis-api.client.ts`, and `apps/api/src/client/analysis/analysis-api.module.ts`
- [x] T014 Implement scan infrastructure in `apps/api/src/scan/scan.module.ts`, `apps/api/src/scan/scan.service.ts`, `apps/api/src/scan/scan.processor.ts`, `apps/api/src/scan/stuck-scan-recovery.task.ts`, and `apps/api/src/scan/services/code-collector.service.ts`
- [ ] T015 [P] Implement report infrastructure in `apps/api/src/report/report.module.ts`, `apps/api/src/report/report.service.ts`, `apps/api/src/report/report.processor.ts`, and a PDF generator service file under `apps/api/src/report/`
- [x] T016 Implement common backend behavior in `apps/api/src/common/filters/global-exception.filter.ts`, `apps/api/src/common/interceptors/response-transform.interceptor.ts`, `apps/api/src/common/decorators/skip-transform.decorator.ts`, `apps/api/src/common/guards/session-aware-throttler.guard.ts`, and `apps/api/src/health/health.controller.ts`
- [x] T017 [P] Create frontend application shell and API foundation in `apps/web/src/App.tsx`, `apps/web/src/router.tsx`, `apps/web/src/api/client.ts`, `apps/web/src/hooks/useAuth.ts`, `apps/web/src/store/auth.store.ts`, and `apps/web/src/components/layout/AppShell.tsx`
- [x] T018 Create baseline backend and frontend test harnesses in `apps/api/test/`, `apps/web/src/**/*.test.tsx`, and any shared test setup files selected by the implementation

**Checkpoint**: Foundation ready. User stories can now proceed with clear contracts and shared infrastructure.

---

## Phase 3: User Story 1 - Connect and Scan a Repository (Priority: P1) 🎯 MVP

**Goal**: Users can authenticate, connect a repository, request a scan, and observe the scan complete.

**Independent Test**: Mock OAuth login, connect a repository, fetch branches, request a scan,
wait for the worker to finish, and verify the scan summary is returned.

### Tests for User Story 1 ⚠️

- [x] T019 [P] [US1] Add auth and session integration coverage in `apps/api/test/auth/auth.e2e-spec.ts`
- [x] T020 [P] [US1] Add repository and branch contract coverage in `apps/api/test/repo/repo.e2e-spec.ts`
- [x] T021 [P] [US1] Add queue-backed scan processing coverage in `apps/api/test/scan/scan.e2e-spec.ts`
- [x] T022 [P] [US1] Add login and scan page interaction coverage in `apps/web/src/pages/LoginPage.test.tsx` and `apps/web/src/pages/ScanPage.test.tsx`

### Implementation for User Story 1

- [x] T023 [US1] Implement auth controller endpoints in `apps/api/src/auth/auth.controller.ts`
- [x] T024 [US1] Implement repository service and controller in `apps/api/src/repo/repo.service.ts`, `apps/api/src/repo/repo.controller.ts`, and `apps/api/src/repo/repo.module.ts`
- [x] T025 [US1] Implement scan controller request and status endpoints in `apps/api/src/scan/scan.controller.ts`
- [x] T026 [US1] Wire backend modules and global middleware in `apps/api/src/app.module.ts`
- [x] T027 [P] [US1] Implement frontend auth flow in `apps/web/src/pages/LoginPage.tsx`, `apps/web/src/components/layout/ProtectedRoute.tsx`, and `apps/web/src/hooks/useAuth.ts`
- [x] T028 [P] [US1] Implement repository connection UX in `apps/web/src/pages/ReposPage.tsx`, `apps/web/src/components/scan/RepoSelector.tsx`, and `apps/web/src/api/repos.ts`
- [x] T029 [US1] Implement scan request and polling UX in `apps/web/src/pages/ScanPage.tsx`, `apps/web/src/components/scan/ScanStatusBadge.tsx`, `apps/web/src/hooks/useScan.ts`, and `apps/web/src/api/scans.ts`
- [x] T030 [US1] Validate duplicate-scan prevention, branch validation, and provider error mapping across `apps/api/src/scan/scan.service.ts` and `apps/api/src/client/git/`

**Checkpoint**: User Story 1 is fully functional and testable independently.

---

## Phase 4: User Story 2 - Review Vulnerabilities and Feedback (Priority: P2)

**Goal**: Users can inspect detailed findings and submit review feedback.

**Independent Test**: Load a completed scan, fetch paginated findings, open one detail page,
and persist feedback updates.

### Tests for User Story 2 ⚠️

- [x] T031 [P] [US2] Add vulnerability list and detail API coverage in `apps/api/test/vulnerability/vulnerability.e2e-spec.ts`
- [x] T032 [P] [US2] Add frontend vulnerability flow tests in `apps/web/src/pages/VulnerabilityReviewPage.test.tsx` and supporting scan/router tests under `apps/web/src/`

### Implementation for User Story 2

- [x] T033 [P] [US2] Implement vulnerability backend module in `apps/api/src/vulnerability/vulnerability.module.ts`, `apps/api/src/vulnerability/vulnerability.service.ts`, and `apps/api/src/vulnerability/vulnerability.controller.ts`
- [x] T034 [P] [US2] Implement vulnerability API clients and review data loading in `apps/web/src/api/vulnerabilities.ts` and `apps/web/src/pages/VulnerabilityReviewPage.tsx`
- [x] T035 [US2] Implement vulnerability list UX in `apps/web/src/pages/VulnerabilityReviewPage.tsx` and associated review workspace styles in `apps/web/src/styles.css`
- [x] T036 [US2] Implement vulnerability detail UX in `apps/web/src/pages/VulnerabilityReviewPage.tsx` for code evidence, consensus, and model reasoning panels
- [x] T037 [US2] Implement feedback persistence and UI actions in `apps/api/src/vulnerability/vulnerability.service.ts`, `apps/api/src/vulnerability/vulnerability.controller.ts`, and `apps/web/src/pages/VulnerabilityReviewPage.tsx`

**Checkpoint**: User Stories 1 and 2 both work independently.

---

## Phase 5: User Story 3 - Monitor Progress and Export Reports (Priority: P3)

**Goal**: Users can understand scan trends and download PDF reports.

**Independent Test**: Open the dashboard, verify trend and summary data, request a report for
a completed scan, poll for readiness, and download the PDF.

### Tests for User Story 3 ⚠️

- [ ] T038 [P] [US3] Add dashboard and report API coverage in `apps/api/test/dashboard/dashboard.e2e-spec.ts` and `apps/api/test/report/report.e2e-spec.ts`
- [ ] T039 [P] [US3] Add dashboard and report UI tests in `apps/web/src/pages/DashboardPage.test.tsx` and `apps/web/src/components/report/DownloadReportButton.test.tsx`

### Implementation for User Story 3

- [ ] T040 [P] [US3] Implement dashboard backend module in `apps/api/src/dashboard/dashboard.module.ts`, `apps/api/src/dashboard/dashboard.service.ts`, and `apps/api/src/dashboard/dashboard.controller.ts`
- [ ] T041 [P] [US3] Implement dashboard frontend experience in `apps/web/src/pages/DashboardPage.tsx`, `apps/web/src/components/dashboard/StatCard.tsx`, `apps/web/src/components/dashboard/SeverityPieChart.tsx`, and `apps/web/src/components/dashboard/TrendLineChart.tsx`
- [ ] T042 [US3] Implement report request, status, and download endpoints in `apps/api/src/report/report.controller.ts` and `apps/api/src/report/report.service.ts`
- [ ] T043 [US3] Implement report frontend flow in `apps/web/src/api/reports.ts`, `apps/web/src/hooks/useReport.ts`, and `apps/web/src/components/report/DownloadReportButton.tsx`
- [ ] T044 [US3] Add report templates and file-lifecycle behavior in report generator files under `apps/api/src/report/`

**Checkpoint**: All three MVP user stories work independently.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Harden the MVP and align docs and validation paths.

- [ ] T045 [P] Update documentation entry points in `README.md`, `AGENTS.md`, and any package readmes created during implementation
- [ ] T046 Run security and behavior review for sessions, CSRF, throttling, raw health responses, and report download expiry across touched backend files
- [ ] T047 [P] Add or refine regression coverage for queue recovery, provider errors, and frontend error states in existing backend/frontend test paths
- [ ] T048 Validate the quickstart flow in `specs/001-aegisai-mvp-foundation/quickstart.md` against the implemented workspace commands

---

## Dependencies & Execution Order

### Phase Dependencies

- **Phase 1**: Starts immediately
- **Phase 2**: Depends on Phase 1 and blocks all user story work
- **Phase 3**: Depends on Phase 2
- **Phase 4**: Depends on Phase 2 and the shared results produced by User Story 1
- **Phase 5**: Depends on Phase 2 and completed scan data from User Story 1
- **Phase 6**: Depends on all desired user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Core MVP entry point and no dependency on later stories
- **User Story 2 (P2)**: Requires completed scan data from User Story 1
- **User Story 3 (P3)**: Requires completed scan data from User Story 1 and report infrastructure from Phase 2

### Within Each User Story

- Required tests should be written before or alongside implementation and must validate the touched flow before the story is considered done
- Backend contracts and shared types should land before dependent pages and hooks
- API clients and hooks should land before full UI assembly
- Story-specific validation and regression work completes before moving to the next phase

### Parallel Opportunities

- Phase 1 setup tasks marked `[P]` can proceed in parallel
- Shared types, provider strategy work, and frontend shell setup in Phase 2 can proceed in parallel after the workspace exists
- Backend and frontend work inside each user story can proceed in parallel once contracts are stable
- Dashboard and report work can partially proceed in parallel inside User Story 3

---

## Parallel Example: User Story 1

```text
Task: "Add auth and session integration coverage in apps/api/test/auth/auth.e2e-spec.ts"
Task: "Add login and scan page interaction coverage in apps/web/src/pages/LoginPage.test.tsx and apps/web/src/pages/ScanPage.test.tsx"
Task: "Implement repository connection UX in apps/web/src/pages/ReposPage.tsx, apps/web/src/components/scan/RepoSelector.tsx, and apps/web/src/api/repos.ts"
```

---

## Implementation Strategy

### MVP First

1. Complete Phase 1
2. Complete Phase 2
3. Complete User Story 1
4. Validate the end-to-end scan loop
5. Continue with User Story 2 and User Story 3 only after the scan loop is stable

### Incremental Delivery

1. Foundation
2. Auth plus repo plus scan
3. Vulnerability review and feedback
4. Dashboard plus report export
5. Cross-cutting hardening

### Parallel Team Strategy

1. One agent owns workspace and backend foundations
2. One agent owns frontend shell and auth UX once contracts stabilize
3. One agent can take vulnerability and report UI work after User Story 1 contracts are available

---

## Notes

- Keep roadmap work out of scope unless the spec changes
- Preserve `MockAnalysisApiClient` as the default MVP target
- Keep `apps/ai` behind interfaces and optional
- Use `packages/shared` as the shared contract source of truth
