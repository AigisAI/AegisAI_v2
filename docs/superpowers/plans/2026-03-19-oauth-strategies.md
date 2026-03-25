# OAuth Strategies Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement GitHub and GitLab Passport strategies that normalize provider profiles, persist OAuth tokens, and return shared session users.

**Architecture:** Keep the strategy classes provider-thin and push profile normalization plus Prisma persistence into `AuthService`. Cover the behavior with focused auth tests so controller and middleware wiring can be added in a later issue without reworking provider internals.

**Tech Stack:** NestJS, Passport, Prisma, Jest

---

## Chunk 1: Provider Dependencies And Regression Tests

### Task 1: Add failing OAuth strategy tests

**Files:**
- Modify: `apps/api/package.json`
- Modify: `apps/api/test/auth/auth.service.e2e-spec.ts`
- Create: `apps/api/test/auth/github.strategy.e2e-spec.ts`
- Create: `apps/api/test/auth/gitlab.strategy.e2e-spec.ts`

- [ ] **Step 1: Add provider package dependencies needed for GitHub and GitLab strategies**
- [ ] **Step 2: Write failing tests for provider profile mapping in `AuthService`**
- [ ] **Step 3: Write failing tests for GitHub strategy configuration and validate delegation**
- [ ] **Step 4: Write failing tests for GitLab strategy configuration and validate delegation**
- [ ] **Step 5: Run targeted auth tests and confirm the new cases fail for the expected missing behavior**

## Chunk 2: Auth Service Provider Flow

### Task 2: Normalize provider profiles and persist OAuth identities

**Files:**
- Modify: `apps/api/src/auth/auth.service.ts`

- [ ] **Step 1: Add provider profile normalization helpers for GitHub and GitLab**
- [ ] **Step 2: Add `findOrCreateUser` flow that upserts `User` and encrypted `OAuthToken` records**
- [ ] **Step 3: Return the shared `AuthUser` shape with connected providers after persistence**
- [ ] **Step 4: Re-run the targeted auth service tests and make them pass**

## Chunk 3: Passport Strategies

### Task 3: Implement GitHub and GitLab strategy classes

**Files:**
- Modify: `apps/api/src/auth/auth.module.ts`
- Create: `apps/api/src/auth/strategies/github.strategy.ts`
- Create: `apps/api/src/auth/strategies/gitlab.strategy.ts`

- [ ] **Step 1: Implement GitHub strategy with config-driven callback URL, state, and scopes**
- [ ] **Step 2: Implement GitLab strategy with config-driven callback URL, state, and scopes**
- [ ] **Step 3: Register both strategies in `AuthModule`**
- [ ] **Step 4: Re-run targeted strategy tests and make them pass**

## Chunk 4: Verification

### Task 4: Prove the feature is stable

**Files:**
- Verify: `apps/api/test/auth/*.e2e-spec.ts`
- Verify: `apps/api/src/auth/*.ts`

- [ ] **Step 1: Run `corepack pnpm --filter @aegisai/api test -- --runInBand test/auth`**
- [ ] **Step 2: Run `corepack pnpm lint`**
- [ ] **Step 3: Run `corepack pnpm test`**
- [ ] **Step 4: Run `corepack pnpm typecheck`**
- [ ] **Step 5: Run `corepack pnpm build`**
- [ ] **Step 6: Commit with `feat: implement oauth provider strategies`**
