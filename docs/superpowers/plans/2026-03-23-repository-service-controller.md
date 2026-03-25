# Repository Service and Controller Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the repository backend flows that let a signed-in user browse provider repos, connect one, inspect branches, list connected repos, and disconnect it.

**Architecture:** Keep provider API concerns behind `GitClientRegistry` and extend that abstraction with a direct repository lookup needed for connection. Implement repository behavior in a focused `RepoService` and surface it through a thin `RepoController` that relies on the existing auth/session and global middleware stack.

**Tech Stack:** NestJS 10, Prisma, provider HTTP clients, Jest, Supertest

---

### Task 1: Lock repository behavior with tests

**Files:**
- Create: `apps/api/test/repo/repo.service.e2e-spec.ts`
- Create: `apps/api/test/repo/repo.e2e-spec.ts`

- [ ] Write failing service tests for connected repo mapping, available repo lookup, duplicate connect prevention, branch listing, and disconnect behavior.
- [ ] Write failing controller/e2e tests for `GET /api/repos`, `GET /api/repos/available`, `POST /api/repos`, `DELETE /api/repos/:repoId`, and `GET /api/repos/:repoId/branches`.
- [ ] Run the targeted repo tests and verify the failures are caused by missing repo module behavior.

### Task 2: Extend provider client capabilities and shared contracts

**Files:**
- Modify: `apps/api/src/client/git/git-provider-client.interface.ts`
- Modify: `apps/api/src/client/git/github.client.ts`
- Modify: `apps/api/src/client/git/gitlab.client.ts`
- Modify: `apps/api/test/client/git/github.client.e2e-spec.ts`
- Modify: `apps/api/test/client/git/gitlab.client.e2e-spec.ts`
- Modify: `packages/shared/src/types/repo.ts`

- [ ] Add a direct repository metadata lookup to the provider client interface.
- [ ] Implement the lookup in GitHub and GitLab clients with failing tests first.
- [ ] Add any shared repo request/query contract types needed by the new controller surface.

### Task 3: Implement the repository module

**Files:**
- Create: `apps/api/src/repo/repo.module.ts`
- Create: `apps/api/src/repo/repo.service.ts`
- Create: `apps/api/src/repo/repo.controller.ts`
- Modify: `apps/api/src/app.module.ts`

- [ ] Implement token resolution, provider client access, connected repo queries, and exception mapping in `RepoService`.
- [ ] Implement authenticated endpoints and query parsing in `RepoController`.
- [ ] Register `RepoModule` in `AppModule`.

### Task 4: Verify and finish

**Files:**
- Verify touched repo/client/shared files above

- [ ] Re-run targeted repo/client tests and confirm green.
- [ ] Re-run workspace `lint`, `test`, `typecheck`, and `build`.
- [ ] Commit with `feat: implement repository service and controller` and prepare the PR template after fresh verification.
