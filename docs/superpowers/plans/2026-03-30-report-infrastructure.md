# Report Infrastructure Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add report queue, generator, storage, and expiry infrastructure so completed scans can later expose report APIs and downloads without redesigning backend internals.

**Architecture:** A dedicated `ReportModule` will follow the existing `ScanModule` pattern: a queue-backed service creates or reuses report rows, a processor generates PDF bytes and stores them locally, and an expiry task cleans up ready files after their download window closes. Shared status types and Prisma schema move together so later controller/UI work consumes a stable contract.

**Tech Stack:** NestJS, BullMQ, Prisma, pdf-lib, local filesystem storage

---

## Chunk 1: Contracts And Data Model

### Task 1: Extend report status surface

**Files:**
- Modify: `apps/api/prisma/schema.prisma`
- Create: `apps/api/prisma/migrations/<timestamp>_report_status_expired/migration.sql`
- Modify: `packages/shared/src/types/report.ts`

- [ ] Add `EXPIRED` to Prisma `ReportStatus`.
- [ ] Add `EXPIRED` to the shared report status type.
- [ ] Keep report response types backward-compatible for later controller work.

## Chunk 2: Test-First Report Runtime

### Task 2: Add failing report service tests

**Files:**
- Create: `apps/api/test/report/report.service.e2e-spec.ts`

- [ ] Write tests for new report creation, generating reuse, ready reuse, invalid scan rejection, and queue failure compensation.
- [ ] Run only the new report service test file and confirm it fails.

### Task 3: Add failing processor, generator, and expiry tests

**Files:**
- Create: `apps/api/test/report/report.processor.e2e-spec.ts`
- Create: `apps/api/test/report/pdf-generator.service.e2e-spec.ts`
- Create: `apps/api/test/report/report-expiry.task.e2e-spec.ts`

- [ ] Write tests for successful READY transition, FAILED transition, valid PDF bytes, and expiry cleanup.
- [ ] Run those test files and confirm they fail for the expected missing implementation reasons.

## Chunk 3: Minimal Report Implementation

### Task 4: Create report module skeleton

**Files:**
- Create: `apps/api/src/report/report.constants.ts`
- Create: `apps/api/src/report/report.module.ts`

- [ ] Mirror the queue registration/test-double pattern from `apps/api/src/scan/scan.module.ts`.
- [ ] Register the `report-jobs` queue and export `ReportService`.

### Task 5: Implement report service

**Files:**
- Create: `apps/api/src/report/report.service.ts`

- [ ] Implement request/reuse logic for owned `DONE` scans.
- [ ] Reuse `GENERATING` and still-valid `READY` reports.
- [ ] Mark queue-enqueue failures as `FAILED`.

### Task 6: Implement PDF generator and storage helpers

**Files:**
- Create: `apps/api/src/report/services/pdf-generator.service.ts`
- Create: `apps/api/src/report/services/report-storage.service.ts`
- Modify: `apps/api/package.json`
- Modify: `pnpm-lock.yaml`

- [ ] Add `pdf-lib` dependency.
- [ ] Generate a minimal valid PDF buffer from scan data.
- [ ] Write and delete local report files under `REPORT_STORAGE_PATH`.

### Task 7: Implement report processor and expiry task

**Files:**
- Create: `apps/api/src/report/report.processor.ts`
- Create: `apps/api/src/report/report-expiry.task.ts`

- [ ] Generate READY reports with `filePath`, `downloadUrl`, and `expiresAt`.
- [ ] Mark failed jobs as `FAILED`.
- [ ] Expire old ready reports and mark them `EXPIRED`.

## Chunk 4: Runtime Wiring And Verification

### Task 8: Wire report module into app runtime

**Files:**
- Modify: `apps/api/src/app.module.ts`

- [ ] Import `ReportModule` into the runtime app graph.
- [ ] Keep queue behavior test-safe by following existing `manualRegistration` patterns.

### Task 9: Run targeted then full verification

**Files:**
- Modify: `specs/001-aegisai-mvp-foundation/tasks.md` (optional only if the repository convention in this branch is to keep task progress synced)

- [ ] Run targeted report tests first.
- [ ] Run `corepack pnpm lint`.
- [ ] Run `corepack pnpm test`.
- [ ] Run `corepack pnpm typecheck`.
- [ ] Run `corepack pnpm build`.
- [ ] Prepare PR summary with explicit note that controller/download endpoints remain a later task.
