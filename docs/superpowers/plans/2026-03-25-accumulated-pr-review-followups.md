# Accumulated PR Review Follow-ups Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the still-valid review findings left across merged PRs without expanding the MVP feature set.

**Architecture:** Apply narrowly scoped hardening fixes where review comments revealed correctness, security, or robustness gaps. Preserve existing contracts unless the review issue itself requires a contract-safe adjustment.

**Tech Stack:** NestJS, Prisma, BullMQ, Redis, React, TanStack Query, Axios, GitHub Actions

---

### Task 1: Auth and runtime follow-ups

**Files:**
- Modify: `apps/api/src/auth/auth.serializer.ts`
- Modify: `apps/api/src/bootstrap/configure-app.ts`
- Modify: `apps/api/src/common/guards/session-aware-throttler.guard.ts`
- Test: `apps/api/test/auth/auth.serializer.e2e-spec.ts`
- Test: `apps/api/test/common/session-aware-throttler.guard.e2e-spec.ts`
- Test: `apps/api/test/bootstrap/configure-app.e2e-spec.ts`

- [ ] Add failing tests for anonymous deserialization, authenticated-only throttling, and Redis session cleanup.
- [ ] Implement the minimal auth/runtime fixes.
- [ ] Run focused API tests for these files.

### Task 2: Provider, repo, and scan robustness

**Files:**
- Modify: `apps/api/src/client/git/github.client.ts`
- Modify: `apps/api/src/client/git/gitlab.client.ts`
- Modify: `apps/api/src/repo/repo.service.ts`
- Modify: `apps/api/src/scan/scan.service.ts`
- Modify: `apps/api/src/scan/services/code-collector.service.ts`
- Modify: `apps/api/src/scan/scan.controller.ts`
- Add: `apps/api/prisma/migrations/20260325_active_scan_unique/migration.sql`
- Test: `apps/api/test/client/git/github.client.e2e-spec.ts`
- Test: `apps/api/test/client/git/gitlab.client.e2e-spec.ts`
- Test: `apps/api/test/repo/repo.service.e2e-spec.ts`
- Test: `apps/api/test/scan/scan.service.e2e-spec.ts`
- Test: `apps/api/test/scan/code-collector.service.e2e-spec.ts`
- Test: `apps/api/test/scan/scan.e2e-spec.ts`

- [ ] Add failing tests for truncated trees, submodule commits, canonical repo dedupe, scan enqueue compensation, immutable commit pinning, and malformed request validation.
- [ ] Implement the minimal backend fixes and migration.
- [ ] Run focused API tests for provider/repo/scan behavior.

### Task 3: Frontend and deployment hardening

**Files:**
- Modify: `apps/web/src/api/auth.ts`
- Modify: `apps/web/src/hooks/useAuth.ts`
- Test: `apps/web/src/api/client.test.ts`
- Test: `apps/web/src/hooks/useAuth.test.ts`
- Modify: `.github/workflows/cd.yml`
- Modify: `deploy/oracle/BOOTSTRAP.md`
- Test: `test/github-actions/cd-workflow.test.mjs`

- [ ] Add failing tests for relative API URLs, auth hydration loading, and CD secret-handling expectations.
- [ ] Implement the minimal frontend and workflow/runbook fixes.
- [ ] Run focused web and workflow regression tests.

### Task 4: Environment-stable app regression

**Files:**
- Modify: `apps/api/test/app.e2e-spec.ts`

- [ ] Relax health assertions so the test validates shape and allowed states instead of a machine-specific Redis status.
- [ ] Run the focused app bootstrap test.

### Task 5: Final verification

**Files:**
- Verify only

- [ ] Run `corepack pnpm lint`
- [ ] Run `corepack pnpm test`
- [ ] Run `corepack pnpm typecheck`
- [ ] Run `corepack pnpm build`
