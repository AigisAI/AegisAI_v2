# Prisma Initial Setup Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add validated config loading and reusable Prisma runtime infrastructure for the NestJS API.

**Architecture:** Keep this issue limited to infrastructure. `ConfigModule` owns validated environment loading and typed access, while `PrismaModule` owns the shared database client lifecycle. Full application wiring remains outside this issue so the branch stays aligned with `T009`.

**Tech Stack:** NestJS 10.x, Prisma 5.x, PostgreSQL config, Jest, pnpm workspace

---

### Task 1: Add Failing Tests For Infrastructure Behavior

**Files:**
- Create: `apps/api/test/config/config.service.spec.ts`
- Create: `apps/api/test/prisma/prisma.service.spec.ts`

- [ ] **Step 1: Write the failing tests**

Cover:
- `ConfigService.get()` returns a required value and throws when missing
- `ConfigService.isProduction()` and `isDevelopment()` reflect `NODE_ENV`
- `PrismaService` calls `$connect()` on module init
- `PrismaService` calls `$disconnect()` on module destroy

- [ ] **Step 2: Run test to verify it fails**

Run: `corepack pnpm --filter @aegisai/api test -- --runInBand`
Expected: FAIL because config/prisma infrastructure files do not exist yet

### Task 2: Implement Config Infrastructure

**Files:**
- Modify: `apps/api/package.json`
- Create: `apps/api/src/config/config.module.ts`
- Create: `apps/api/src/config/config.service.ts`

- [ ] **Step 3: Write minimal implementation**

Add:
- `@nestjs/config`
- `joi`

Implement:
- global config module
- schema validation for the MVP backend env vars already defined in repo docs
- local typed wrapper service with `get`, `getOptional`, `isProduction`, and `isDevelopment`

- [ ] **Step 4: Run targeted tests**

Run: `corepack pnpm --filter @aegisai/api test -- --runInBand`
Expected: config tests pass, prisma tests still fail

### Task 3: Implement Prisma Infrastructure

**Files:**
- Create: `apps/api/src/prisma/prisma.module.ts`
- Create: `apps/api/src/prisma/prisma.service.ts`

- [ ] **Step 5: Write minimal implementation**

Implement:
- `PrismaService extends PrismaClient`
- `OnModuleInit` calls `$connect()`
- `OnModuleDestroy` calls `$disconnect()`
- `PrismaModule` exports the service

- [ ] **Step 6: Run targeted tests**

Run: `corepack pnpm --filter @aegisai/api test -- --runInBand`
Expected: targeted infrastructure tests pass

### Task 4: Verify Workspace Baseline

**Files:**
- Modify if needed: `pnpm-lock.yaml`

- [ ] **Step 7: Run workspace verification**

Run:
- `corepack pnpm lint`
- `corepack pnpm test`
- `corepack pnpm typecheck`

Expected: all commands exit successfully

- [ ] **Step 8: Commit**

Run:
`git add apps/api/package.json apps/api/src/config apps/api/src/prisma apps/api/test/config apps/api/test/prisma pnpm-lock.yaml docs/superpowers/specs/2026-03-15-prisma-initial-setup-design.md docs/superpowers/plans/2026-03-15-prisma-initial-setup.md`

Commit:
`git commit -m "Feat: Prisma 초기 설정"`
