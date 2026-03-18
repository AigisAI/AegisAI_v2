# Auth And Session Foundation Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the NestJS auth/session core infrastructure required before OAuth strategies and full bootstrap wiring.

**Architecture:** Keep the issue aligned to `T010` only. `AuthModule` owns reusable auth services, Passport session serialization, CSRF-aware session guard behavior, and token encryption. Global middleware setup and provider strategies remain outside this issue.

**Tech Stack:** NestJS 10.x, Passport session patterns, Prisma 5.x, Node crypto, Jest, pnpm workspace

---

### Task 1: Write Failing Tests For Auth Core

**Files:**
- Create: `apps/api/test/auth/auth.serializer.e2e-spec.ts`
- Create: `apps/api/test/auth/session-auth.guard.e2e-spec.ts`
- Create: `apps/api/test/auth/token-crypto.util.e2e-spec.ts`

- [ ] **Step 1: Write the failing tests**

Cover:
- `TokenCryptoUtil` encrypts and decrypts a token using `TOKEN_ENCRYPTION_KEY`
- `AuthSerializer.serializeUser()` stores the user id
- `AuthSerializer.deserializeUser()` loads a user and maps connected providers to lowercase strings
- `SessionAuthGuard` rejects unauthenticated requests with `401`
- `SessionAuthGuard` rejects mutating authenticated requests with missing or mismatched CSRF values using `403`
- `SessionAuthGuard` allows authenticated safe requests and valid CSRF-protected mutating requests

- [ ] **Step 2: Run targeted tests to verify they fail**

Run:
- `corepack pnpm --filter @aegisai/api exec jest --config ./test/jest-e2e.json --runInBand test/auth/token-crypto.util.e2e-spec.ts`
- `corepack pnpm --filter @aegisai/api exec jest --config ./test/jest-e2e.json --runInBand test/auth/auth.serializer.e2e-spec.ts`
- `corepack pnpm --filter @aegisai/api exec jest --config ./test/jest-e2e.json --runInBand test/auth/session-auth.guard.e2e-spec.ts`

Expected: FAIL because auth files do not exist yet

### Task 2: Implement Token Encryption And Auth Service

**Files:**
- Modify: `apps/api/package.json`
- Create: `apps/api/src/auth/auth.service.ts`
- Create: `apps/api/src/auth/utils/token-crypto.util.ts`

- [ ] **Step 3: Write minimal implementation**

Implement:
- auth service method for fetching a user by id with provider metadata
- auth service helper for generating CSRF token values
- AES-256-GCM token encryption/decryption with key validation against the configured 64-hex secret

- [ ] **Step 4: Run targeted token crypto test**

Run:
- `corepack pnpm --filter @aegisai/api exec jest --config ./test/jest-e2e.json --runInBand test/auth/token-crypto.util.e2e-spec.ts`

Expected: token crypto test passes while serializer/guard tests still fail

### Task 3: Implement Serializer, Guard, And Decorator

**Files:**
- Create: `apps/api/src/auth/auth.serializer.ts`
- Create: `apps/api/src/auth/guards/session-auth.guard.ts`
- Create: `apps/api/src/auth/decorators/current-user.decorator.ts`
- Create: `apps/api/src/auth/auth.module.ts`

- [ ] **Step 5: Write minimal implementation**

Implement:
- Passport serializer/deserializer backed by `AuthService`
- session guard with safe-method bypass for CSRF and explicit `CSRF_TOKEN_INVALID` failure payload
- current-user decorator reading `req.user`
- auth module exporting the reusable auth pieces

- [ ] **Step 6: Run targeted auth tests**

Run:
- `corepack pnpm --filter @aegisai/api exec jest --config ./test/jest-e2e.json --runInBand test/auth/auth.serializer.e2e-spec.ts`
- `corepack pnpm --filter @aegisai/api exec jest --config ./test/jest-e2e.json --runInBand test/auth/session-auth.guard.e2e-spec.ts`

Expected: all targeted auth tests pass

### Task 4: Verify Workspace Baseline

**Files:**
- Modify if needed: `pnpm-lock.yaml`

- [ ] **Step 7: Run workspace verification**

Run:
- `corepack pnpm lint`
- `corepack pnpm test`
- `corepack pnpm typecheck`
- `corepack pnpm build`

Expected: all commands exit successfully

- [ ] **Step 8: Commit**

Run:
`git add apps/api/package.json apps/api/src/auth apps/api/test/auth pnpm-lock.yaml docs/superpowers/specs/2026-03-18-auth-session-foundation-design.md docs/superpowers/plans/2026-03-18-auth-session-foundation.md`

Commit:
`git commit -m "feat: implement auth and session foundation"`
