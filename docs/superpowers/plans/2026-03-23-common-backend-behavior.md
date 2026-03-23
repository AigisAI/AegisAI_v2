# Common Backend Behavior Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the common backend primitives for error normalization, response transformation, session-aware throttling, and health reporting.

**Architecture:** Implement the shared behavior as small focused units that can be tested without global app wiring. The health endpoint gets its own module boundary, while the filter, interceptor, decorator, and throttler guard remain reusable pieces that T026 can later register globally.

**Tech Stack:** NestJS 10, Prisma 5, Redis 4, `@nestjs/throttler`, Jest, TypeScript

---

## Chunk 1: Response And Error Primitives

### Task 1: Add the skip-transform decorator and response interceptor

**Files:**
- Create: `apps/api/src/common/decorators/skip-transform.decorator.ts`
- Create: `apps/api/src/common/interceptors/response-transform.interceptor.ts`
- Test: `apps/api/test/common/response-transform.interceptor.e2e-spec.ts`

- [ ] Step 1: Write failing interceptor tests for wrapped success responses, skipped handlers, and `204` / `undefined` bypass behavior.
- [ ] Step 2: Run `corepack pnpm --filter @aegisai/api test -- --runInBand test/common/response-transform.interceptor.e2e-spec.ts` and verify the expected red state.
- [ ] Step 3: Implement `SkipTransform` and the minimal interceptor logic to satisfy those tests.
- [ ] Step 4: Re-run the targeted interceptor test and verify it passes.

### Task 2: Add the global exception filter

**Files:**
- Create: `apps/api/src/common/filters/global-exception.filter.ts`
- Test: `apps/api/test/common/global-exception.filter.e2e-spec.ts`

- [ ] Step 1: Write failing filter tests for `HttpException` normalization and generic `500` fallback behavior.
- [ ] Step 2: Run `corepack pnpm --filter @aegisai/api test -- --runInBand test/common/global-exception.filter.e2e-spec.ts` and verify the failures are due to missing filter behavior.
- [ ] Step 3: Implement the minimal filter to emit the shared `ErrorResponse` contract and log 5xx errors.
- [ ] Step 4: Re-run the targeted filter test and verify it passes.

## Chunk 2: Session-Aware Throttling

### Task 3: Add the custom throttler guard

**Files:**
- Modify: `apps/api/package.json`
- Create: `apps/api/src/common/guards/session-aware-throttler.guard.ts`
- Test: `apps/api/test/common/session-aware-throttler.guard.e2e-spec.ts`

- [ ] Step 1: Write failing guard tests for session-backed tracker selection and unauthenticated IP fallback.
- [ ] Step 2: Run `corepack pnpm --filter @aegisai/api test -- --runInBand test/common/session-aware-throttler.guard.e2e-spec.ts` and verify the red state.
- [ ] Step 3: Add `@nestjs/throttler` if needed and implement the minimal custom guard behavior.
- [ ] Step 4: Re-run the targeted guard test and verify it passes.

## Chunk 3: Health Endpoint

### Task 4: Add the health controller and module

**Files:**
- Create: `apps/api/src/health/health.controller.ts`
- Create: `apps/api/src/health/health.module.ts`
- Test: `apps/api/test/health/health.controller.e2e-spec.ts`

- [ ] Step 1: Write failing health tests for `ok` and `degraded` responses and the raw response shape.
- [ ] Step 2: Run `corepack pnpm --filter @aegisai/api test -- --runInBand test/health/health.controller.e2e-spec.ts` and verify the red state.
- [ ] Step 3: Implement the controller and module with Prisma and Redis dependency checks plus `@SkipTransform()`.
- [ ] Step 4: Re-run the targeted health test and verify it passes.

## Chunk 4: Final Regression Verification

### Task 5: Confirm scope boundaries and run the full suite

**Files:**
- Modify: `docs/superpowers/specs/2026-03-23-common-backend-behavior-design.md`
- Test: `apps/api/test/common/*.e2e-spec.ts`
- Test: `apps/api/test/health/*.e2e-spec.ts`

- [ ] Step 1: Confirm the implementation still leaves global `AppModule` registration to T026.
- [ ] Step 2: Run `corepack pnpm --filter @aegisai/api test -- --runInBand test/common test/health`
- [ ] Step 3: Run `corepack pnpm lint`
- [ ] Step 4: Run `corepack pnpm test`
- [ ] Step 5: Run `corepack pnpm typecheck`
- [ ] Step 6: Run `corepack pnpm build`
- [ ] Step 7: Commit with `feat: implement common backend behavior`
