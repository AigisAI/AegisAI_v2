# Backend Global Wiring Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Attach the existing backend modules and cross-cutting behavior to the Nest runtime so app-level responses, health checks, queue wiring, and throttling behave consistently.

**Architecture:** Keep component implementations where they already live and limit this issue to application assembly in `AppModule` plus minimal bootstrap adjustments. Use TDD at the app boundary by updating e2e tests first, then wire BullMQ, throttling, and global `APP_*` providers until the new expectations pass.

**Tech Stack:** NestJS 10, BullMQ, @nestjs/throttler, express-session, Passport, Jest, Supertest

---

### Task 1: Lock the app-level response contract

**Files:**
- Modify: `apps/api/test/app.e2e-spec.ts`
- Modify: `apps/api/test/auth/auth.e2e-spec.ts`

- [ ] Write failing e2e assertions for wrapped `/api`, raw `/api/health`, wrapped auth success, and wrapped auth errors.
- [ ] Run targeted auth/app e2e tests to verify the new assertions fail for the expected contract mismatch.

### Task 2: Wire root modules and global providers

**Files:**
- Modify: `apps/api/src/app.module.ts`
- Modify: `apps/api/src/common/guards/session-aware-throttler.guard.ts`

- [ ] Add `ScanModule`, `HealthModule`, `BullModule.forRootAsync`, and `ThrottlerModule.forRoot`.
- [ ] Register `APP_FILTER`, `APP_INTERCEPTOR`, and `APP_GUARD` with the existing common backend components.
- [ ] Make the throttler guard DI-safe for real `APP_GUARD` construction.

### Task 3: Align bootstrap behavior with the wired app

**Files:**
- Modify: `apps/api/src/bootstrap/configure-app.ts`
- Modify: `apps/api/src/main.ts` if needed

- [ ] Keep session and Passport setup centralized in `configureApp`.
- [ ] Apply only the minimal bootstrap adjustments needed for the wired runtime behavior.

### Task 4: Verify the integrated runtime

**Files:**
- Verify touched runtime and e2e files above

- [ ] Re-run the targeted e2e suite and confirm the new app-level contract passes.
- [ ] Re-run workspace `lint`, `test`, `typecheck`, and `build`.
- [ ] Commit with `feat: implement backend global wiring` and prepare the PR body once verification is fresh.
