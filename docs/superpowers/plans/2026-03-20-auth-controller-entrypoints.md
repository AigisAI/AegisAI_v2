# Auth Controller and OAuth Entrypoints Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the existing auth/session foundation and OAuth strategies into a working backend login flow.

**Architecture:** Add a thin `AuthController`, runtime session middleware wiring in `main.ts`, and minimal `AppModule` imports so Passport callbacks can create sessions and authenticated routes can return the shared auth contract. Keep repository and scan modules out of scope.

**Tech Stack:** NestJS, Passport, Prisma, Redis, express-session, Jest, Supertest

---

## Chunk 1: Runtime Dependencies And Red Tests

### Task 1: Add auth entrypoint coverage

**Files:**
- Modify: `apps/api/package.json`
- Create: `apps/api/test/auth/auth.e2e-spec.ts`

- [ ] **Step 1: Add runtime dependencies for session cookies and Redis-backed sessions**
- [ ] **Step 2: Write failing tests for `GET /api/auth/me` unauthorized and authenticated flows**
- [ ] **Step 3: Write a failing test for `POST /api/auth/logout` with CSRF validation**
- [ ] **Step 4: Write a failing test for OAuth callback success redirect and CSRF cookie issuance**
- [ ] **Step 5: Run `corepack pnpm --filter @aegisai/api test -- --runInBand test/auth/auth.e2e-spec.ts` and confirm the new cases fail for missing controller/wiring behavior**

## Chunk 2: Auth Controller Surface

### Task 2: Implement controller endpoints

**Files:**
- Create: `apps/api/src/auth/auth.controller.ts`
- Modify: `apps/api/src/auth/auth.module.ts`

- [ ] **Step 1: Add provider start and callback endpoints guarded by Passport provider auth**
- [ ] **Step 2: Add `GET /auth/me` using `SessionAuthGuard` and `CurrentUser`**
- [ ] **Step 3: Add `POST /auth/logout` to destroy the session and clear auth/CSRF cookies**
- [ ] **Step 4: Re-run `apps/api/test/auth/auth.e2e-spec.ts` and make the controller tests advance to middleware/runtime failures**

## Chunk 3: Runtime Wiring

### Task 3: Enable session and passport middleware

**Files:**
- Modify: `apps/api/src/main.ts`
- Modify: `apps/api/src/app.module.ts`

- [ ] **Step 1: Add `cookie-parser`, Redis client, `express-session`, and Passport middleware in the required order**
- [ ] **Step 2: Preserve the existing `/api` bootstrap route while importing `ConfigModule`, `PrismaModule`, and `AuthModule`**
- [ ] **Step 3: Re-run `apps/api/test/auth/auth.e2e-spec.ts` and make the new auth flow tests pass**

## Chunk 4: Verification

### Task 4: Prove the feature is stable

**Files:**
- Verify: `apps/api/src/auth/*.ts`
- Verify: `apps/api/src/main.ts`
- Verify: `apps/api/src/app.module.ts`
- Verify: `apps/api/test/auth/*.ts`

- [ ] **Step 1: Run `corepack pnpm --filter @aegisai/api test -- --runInBand test/auth`**
- [ ] **Step 2: Run `corepack pnpm lint`**
- [ ] **Step 3: Run `corepack pnpm test`**
- [ ] **Step 4: Run `corepack pnpm typecheck`**
- [ ] **Step 5: Run `corepack pnpm build`**
- [ ] **Step 6: Commit with `feat: implement auth controller entrypoints`**
