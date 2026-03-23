# Scan Infrastructure Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the backend scan orchestration layer that can enqueue scans, collect Java source files, run mock analysis, persist findings, and recover stuck scans.

**Architecture:** Add a dedicated `scan` module that isolates request-time scan creation from asynchronous execution. `ScanService` owns validation and queue submission, `CodeCollectorService` owns repository file gathering, `ScanProcessor` owns async status transitions plus persistence, and `StuckScanRecoveryTask` owns cleanup of stale non-terminal scans.

**Tech Stack:** NestJS 10, Prisma 5, BullMQ 5, Redis 7, Jest, TypeScript

---

## Chunk 1: Queue And Service Foundation

### Task 1: Add queue dependencies and scan module skeleton

**Files:**
- Modify: `apps/api/package.json`
- Create: `apps/api/src/scan/scan.constants.ts`
- Create: `apps/api/src/scan/scan.module.ts`
- Modify: `apps/api/src/app.module.ts`
- Test: `apps/api/test/scan/scan.service.e2e-spec.ts`

- [ ] Step 1: Write a failing module/service test that expects `ScanService` to enqueue a new scan job.
- [ ] Step 2: Run `corepack pnpm --filter @aegisai/api test -- --runInBand test/scan/scan.service.e2e-spec.ts` and verify it fails for missing scan module/service behavior.
- [ ] Step 3: Add `@nestjs/bullmq` and `bullmq`, then create the scan constants/module skeleton and register the queue token.
- [ ] Step 4: Re-run the targeted test and verify the failure has moved to missing service logic instead of missing module wiring.

### Task 2: Implement scan creation and duplicate-scan blocking

**Files:**
- Create: `apps/api/src/scan/scan.service.ts`
- Test: `apps/api/test/scan/scan.service.e2e-spec.ts`

- [ ] Step 1: Extend the failing `scan.service` tests for duplicate active scan rejection and connected-repo validation.
- [ ] Step 2: Run the targeted test again and verify the expected red state.
- [ ] Step 3: Implement the minimal `ScanService` logic to load the connected repo, block duplicate `PENDING`/`RUNNING` scans, create a `PENDING` scan row, and enqueue a BullMQ job with the scan id.
- [ ] Step 4: Re-run the targeted service test and verify it passes.

## Chunk 2: Code Collection

### Task 3: Define collector payload and file filtering behavior

**Files:**
- Create: `apps/api/src/scan/services/code-collector.service.ts`
- Test: `apps/api/test/scan/code-collector.service.e2e-spec.ts`

- [ ] Step 1: Write failing collector tests for commit SHA propagation, Java-only filtering, and skipped unsupported files.
- [ ] Step 2: Run `corepack pnpm --filter @aegisai/api test -- --runInBand test/scan/code-collector.service.e2e-spec.ts` and verify the failures point to missing collector behavior.
- [ ] Step 3: Implement `CodeCollectorService` with `GitClientRegistry`, `LanguageHandlerRegistry`, and provider file/content retrieval.
- [ ] Step 4: Re-run the targeted collector test and verify it passes.

## Chunk 3: Asynchronous Processing

### Task 4: Implement processor success path

**Files:**
- Create: `apps/api/src/scan/scan.processor.ts`
- Test: `apps/api/test/scan/scan.processor.e2e-spec.ts`

- [ ] Step 1: Write a failing processor test that expects `PENDING -> RUNNING -> DONE`, summary persistence, and vulnerability replacement on success.
- [ ] Step 2: Run `corepack pnpm --filter @aegisai/api test -- --runInBand test/scan/scan.processor.e2e-spec.ts` and verify it fails for the missing processor.
- [ ] Step 3: Implement the minimal success-path processor using the collector and analysis client, including severity summary persistence and vulnerability insertion.
- [ ] Step 4: Re-run the targeted processor test and verify it passes.

### Task 5: Implement processor failure handling

**Files:**
- Modify: `apps/api/src/scan/scan.processor.ts`
- Test: `apps/api/test/scan/scan.processor.e2e-spec.ts`

- [ ] Step 1: Add failing tests for collector or analysis errors transitioning scans to `FAILED`.
- [ ] Step 2: Run the targeted processor test and verify the red state matches the expected failure handling gap.
- [ ] Step 3: Implement failure-path status updates and terminal error persistence.
- [ ] Step 4: Re-run the targeted processor test and verify the suite is green.

## Chunk 4: Recovery And Integration

### Task 6: Implement stuck-scan recovery behavior

**Files:**
- Create: `apps/api/src/scan/stuck-scan-recovery.task.ts`
- Test: `apps/api/test/scan/stuck-scan-recovery.task.e2e-spec.ts`

- [ ] Step 1: Write failing recovery-task tests for expiring old active scans while leaving fresh ones unchanged.
- [ ] Step 2: Run `corepack pnpm --filter @aegisai/api test -- --runInBand test/scan/stuck-scan-recovery.task.e2e-spec.ts` and verify it fails for missing task behavior.
- [ ] Step 3: Implement the recovery task with a fixed stale-age threshold and `FAILED` transition message.
- [ ] Step 4: Re-run the targeted recovery test and verify it passes.

### Task 7: Finish module wiring and regression verification

**Files:**
- Modify: `apps/api/src/scan/scan.module.ts`
- Modify: `apps/api/src/app.module.ts`
- Modify: `docs/superpowers/specs/2026-03-23-scan-infrastructure-design.md`
- Test: `apps/api/test/scan/*.e2e-spec.ts`

- [ ] Step 1: Ensure queue registration, module exports, and providers all match the implemented service boundaries.
- [ ] Step 2: Run `corepack pnpm --filter @aegisai/api test -- --runInBand test/scan`
- [ ] Step 3: Run `corepack pnpm lint`
- [ ] Step 4: Run `corepack pnpm test`
- [ ] Step 5: Run `corepack pnpm typecheck`
- [ ] Step 6: Run `corepack pnpm build`
- [ ] Step 7: Commit with `feat: implement scan infrastructure`
