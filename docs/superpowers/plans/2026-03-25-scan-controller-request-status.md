# Scan Controller Request/Status Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add authenticated scan request and status endpoints for User Story 1, including branch validation and repository-scoped scan history.

**Architecture:** Extend the existing `ScanService` as the single scan application boundary, then add a thin `ScanController` that exposes the shared contracts already defined in `packages/shared`. Keep ownership checks and provider validation in the service so controller logic stays declarative and matches the current repo/auth patterns.

**Tech Stack:** NestJS controllers/services, Prisma, BullMQ, shared TypeScript contracts, Jest e2e tests, Supertest

---

## Chunk 1: Contracts and Scan Service Query Surface

### Task 1: Extend shared scan contracts for repo scan paging

**Files:**
- Modify: `C:\Users\권태욱\.config\superpowers\worktrees\aegisai_v2\codex-feat-62-scan-controller-endpoints\packages\shared\src\types\scan.ts`
- Test: `C:\Users\권태욱\.config\superpowers\worktrees\aegisai_v2\codex-feat-62-scan-controller-endpoints\packages\shared\test\shared-contract-exports.test.mjs`

- [ ] Add any missing page response alias or query type needed by `GET /api/repos/:repoId/scans`.
- [ ] Update the shared export regression test if the scan contract surface changes.
- [ ] Run `corepack pnpm --filter @aegisai/shared test`.

### Task 2: Add failing service tests for scan detail and repo scan listing

**Files:**
- Modify: `C:\Users\권태욱\.config\superpowers\worktrees\aegisai_v2\codex-feat-62-scan-controller-endpoints\apps\api\test\scan\scan.service.e2e-spec.ts`

- [ ] Write a failing test for `getScanDetail` returning the mapped `ScanDetail`.
- [ ] Write a failing test for `listRepoScans` returning a paginated `PageResponse<ScanSummary>`.
- [ ] Write a failing test for branch validation in `createScan`.
- [ ] Run `corepack pnpm --filter @aegisai/api test -- --runInBand test/scan/scan.service.e2e-spec.ts` and confirm the new tests fail for the intended reason.

### Task 3: Implement the minimal `ScanService` changes to satisfy the new tests

**Files:**
- Modify: `C:\Users\권태욱\.config\superpowers\worktrees\aegisai_v2\codex-feat-62-scan-controller-endpoints\apps\api\src\scan\scan.service.ts`

- [ ] Add provider-backed branch validation inside `createScan`.
- [ ] Add `getScanDetail`.
- [ ] Add `listRepoScans`.
- [ ] Add focused private mapping helpers instead of duplicating summary conversion logic.
- [ ] Re-run `corepack pnpm --filter @aegisai/api test -- --runInBand test/scan/scan.service.e2e-spec.ts` until green.

## Chunk 2: Scan Controller and Endpoint Coverage

### Task 4: Add failing controller e2e tests for the scan endpoints

**Files:**
- Create: `C:\Users\권태욱\.config\superpowers\worktrees\aegisai_v2\codex-feat-62-scan-controller-endpoints\apps\api\test\scan\scan.e2e-spec.ts`

- [ ] Add a failing test for `POST /api/scans` returning HTTP 202 with the wrapped scan request payload.
- [ ] Add a failing test for `GET /api/scans/:scanId`.
- [ ] Add a failing test for `GET /api/repos/:repoId/scans`.
- [ ] Run `corepack pnpm --filter @aegisai/api test -- --runInBand test/scan/scan.e2e-spec.ts` and confirm failure before implementation.

### Task 5: Implement the scan controller and module wiring

**Files:**
- Create: `C:\Users\권태욱\.config\superpowers\worktrees\aegisai_v2\codex-feat-62-scan-controller-endpoints\apps\api\src\scan\scan.controller.ts`
- Modify: `C:\Users\권태욱\.config\superpowers\worktrees\aegisai_v2\codex-feat-62-scan-controller-endpoints\apps\api\src\scan\scan.module.ts`

- [ ] Add authenticated scan endpoints using `SessionAuthGuard` and `CurrentUser`.
- [ ] Return HTTP 202 for `POST /api/scans`.
- [ ] Keep page/size validation aligned with the repository controller behavior.
- [ ] Register the controller in `ScanModule`.
- [ ] Re-run `corepack pnpm --filter @aegisai/api test -- --runInBand test/scan/scan.e2e-spec.ts` until green.

## Chunk 3: Full Regression and Finish

### Task 6: Run the touched backend regression suite

**Files:**
- Verify only

- [ ] Run `corepack pnpm --filter @aegisai/api test -- --runInBand test/scan`.
- [ ] Run `corepack pnpm --filter @aegisai/api test -- --runInBand test/repo/repo.e2e-spec.ts`.
- [ ] If anything fails, fix the smallest responsible unit and rerun the failing command first.

### Task 7: Run full workspace verification

**Files:**
- Verify only

- [ ] Run `corepack pnpm lint`.
- [ ] Run `corepack pnpm test`.
- [ ] Run `corepack pnpm typecheck`.
- [ ] Run `corepack pnpm build`.

### Task 8: Prepare branch output

**Files:**
- Review diff only

- [ ] Review changed files for accidental scope creep.
- [ ] Commit with `feat: implement scan controller request and status endpoints`.
- [ ] Prepare the PR body using the repository template with issue `#62`.
