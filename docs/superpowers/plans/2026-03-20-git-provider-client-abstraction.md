# Git Provider Client Abstraction Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a reusable GitHub/GitLab provider client layer that later repo and scan modules can use through one shared interface.

**Architecture:** Introduce a `client/git` module with a shared provider interface, typed provider errors, concrete GitHub/GitLab HTTP clients, and a registry that resolves clients by shared provider key. Keep token loading and persistence out of the client layer.

**Tech Stack:** NestJS, `@nestjs/axios`, Axios, Jest, RxJS

---

## Chunk 1: Dependencies And Red Tests

### Task 1: Add the provider-client test surface

**Files:**
- Modify: `apps/api/package.json`
- Modify: `pnpm-lock.yaml`
- Create: `apps/api/test/client/git/github.client.e2e-spec.ts`
- Create: `apps/api/test/client/git/gitlab.client.e2e-spec.ts`
- Create: `apps/api/test/client/git/git-client.registry.e2e-spec.ts`

- [ ] **Step 1: Add `@nestjs/axios` and `axios` to `apps/api/package.json`.**
- [ ] **Step 2: Write a failing GitHub client test for repository and branch normalization.**
- [ ] **Step 3: Write a failing GitLab client test for repository and file lookup normalization.**
- [ ] **Step 4: Write a failing registry test for provider lookup and unsupported provider rejection.**
- [ ] **Step 5: Run `corepack pnpm --filter @aegisai/api test -- --runInBand test/client/git` and confirm the new cases fail for missing module/client behavior.**

## Chunk 2: Interface And Core Client Layer

### Task 2: Add the shared provider abstraction

**Files:**
- Create: `apps/api/src/client/git/git-provider-client.interface.ts`
- Create: `apps/api/src/client/git/git-provider-client.errors.ts`
- Create: `apps/api/src/client/git/git-client.registry.ts`

- [ ] **Step 1: Add the provider interface and result types that match the MVP spec.**
- [ ] **Step 2: Add typed provider client errors for unauthorized, not found, rate limit, and unavailable cases.**
- [ ] **Step 3: Add a registry that returns clients by shared provider key and throws for unsupported providers.**
- [ ] **Step 4: Re-run `test/client/git/git-client.registry.e2e-spec.ts` and make the registry tests pass while provider tests still fail.**

## Chunk 3: Provider Implementations

### Task 3: Implement GitHub and GitLab clients

**Files:**
- Create: `apps/api/src/client/git/github.client.ts`
- Create: `apps/api/src/client/git/gitlab.client.ts`

- [ ] **Step 1: Implement GitHub repository, branch, commit, tree, and file-content lookups with `Link` header pagination parsing.**
- [ ] **Step 2: Implement GitLab repository, branch, commit, tree, and file-content lookups with `X-Next-Page` parsing and encoded project paths.**
- [ ] **Step 3: Normalize provider HTTP failures into typed provider client errors.**
- [ ] **Step 4: Re-run `corepack pnpm --filter @aegisai/api test -- --runInBand test/client/git` and make the provider tests pass.**

## Chunk 4: Module Wiring And Verification

### Task 4: Export the abstraction for later features

**Files:**
- Create: `apps/api/src/client/git/git-client.module.ts`
- Modify: `apps/api/src/app.module.ts`
- Verify: `apps/api/test/client/git/*.ts`

- [ ] **Step 1: Add `GitClientModule` with `HttpModule`, provider clients, and registry exports.**
- [ ] **Step 2: Import `GitClientModule` into `AppModule` so later repo and scan modules can resolve it without re-wiring infrastructure.**
- [ ] **Step 3: Run `corepack pnpm --filter @aegisai/api test -- --runInBand test/client/git`.**
- [ ] **Step 4: Run `corepack pnpm lint`.**
- [ ] **Step 5: Run `corepack pnpm test`.**
- [ ] **Step 6: Run `corepack pnpm typecheck`.**
- [ ] **Step 7: Run `corepack pnpm build`.**
- [ ] **Step 8: Commit with `feat: implement git provider client abstraction`.**
