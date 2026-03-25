# Frontend Application Shell and API Foundation Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the web app routing, shell, API client, and auth state foundation needed by later login, repo, and scan pages.

**Architecture:** The implementation keeps the app entry thin and moves concerns into focused units: query client setup, router definition, shell layout, API modules, and auth synchronization. Placeholder pages are intentionally lightweight so this issue can finish the frontend backbone without drifting into feature-specific UI design.

**Tech Stack:** React 18, Vite, React Router, TanStack Query, Axios, Zustand, Vitest, React Testing Library

---

## Chunk 1: Foundation Setup and Contracts

### Task 1: Add frontend foundation dependencies

**Files:**
- Modify: `C:\Users\권태욱\.config\superpowers\worktrees\aegisai_v2\codex-feat-64-frontend-foundation\apps\web\package.json`

- [ ] Add `react-router-dom`, `@tanstack/react-query`, `axios`, and `zustand`.
- [ ] Run `corepack pnpm install`.

### Task 2: Add failing tests for protected routing and app shell behavior

**Files:**
- Create: `C:\Users\권태욱\.config\superpowers\worktrees\aegisai_v2\codex-feat-64-frontend-foundation\apps\web\src\components\layout\ProtectedRoute.test.tsx`
- Create: `C:\Users\권태욱\.config\superpowers\worktrees\aegisai_v2\codex-feat-64-frontend-foundation\apps\web\src\components\layout\AppShell.test.tsx`

- [ ] Write a failing test for redirecting unauthenticated users to `/login`.
- [ ] Write a failing test for rendering shell navigation and outlet content.
- [ ] Run `corepack pnpm --filter @aegisai/web test -- ProtectedRoute AppShell` and confirm failure.

## Chunk 2: API/Auth Foundation

### Task 3: Add failing tests for API client helpers and auth initialization

**Files:**
- Create: `C:\Users\권태욱\.config\superpowers\worktrees\aegisai_v2\codex-feat-64-frontend-foundation\apps\web\src\api\client.test.ts`
- Create: `C:\Users\권태욱\.config\superpowers\worktrees\aegisai_v2\codex-feat-64-frontend-foundation\apps\web\src\hooks\useAuth.test.tsx`

- [ ] Write a failing test for CSRF header attachment.
- [ ] Write a failing test for unauthorized redirect eligibility logic.
- [ ] Write a failing test for `useAuth` syncing a fetched user into auth state.
- [ ] Run the focused test command and confirm failure.

### Task 4: Implement the minimal API/auth layer to satisfy the tests

**Files:**
- Create: `C:\Users\권태욱\.config\superpowers\worktrees\aegisai_v2\codex-feat-64-frontend-foundation\apps\web\src\api\client.ts`
- Create: `C:\Users\권태욱\.config\superpowers\worktrees\aegisai_v2\codex-feat-64-frontend-foundation\apps\web\src\api\auth.ts`
- Create: `C:\Users\권태욱\.config\superpowers\worktrees\aegisai_v2\codex-feat-64-frontend-foundation\apps\web\src\api\repos.ts`
- Create: `C:\Users\권태욱\.config\superpowers\worktrees\aegisai_v2\codex-feat-64-frontend-foundation\apps\web\src\api\scans.ts`
- Create: `C:\Users\권태욱\.config\superpowers\worktrees\aegisai_v2\codex-feat-64-frontend-foundation\apps\web\src\store\auth.store.ts`
- Create: `C:\Users\권태욱\.config\superpowers\worktrees\aegisai_v2\codex-feat-64-frontend-foundation\apps\web\src\hooks\useAuth.ts`

- [ ] Implement the Axios client, auth API helpers, repo/scan API stubs, auth store, and auth hook.
- [ ] Re-run the focused tests until green.

## Chunk 3: Router and Shell

### Task 5: Implement router, protected route, shell, and placeholder pages

**Files:**
- Create: `C:\Users\권태욱\.config\superpowers\worktrees\aegisai_v2\codex-feat-64-frontend-foundation\apps\web\src\router.tsx`
- Create: `C:\Users\권태욱\.config\superpowers\worktrees\aegisai_v2\codex-feat-64-frontend-foundation\apps\web\src\components\layout\AppShell.tsx`
- Create: `C:\Users\권태욱\.config\superpowers\worktrees\aegisai_v2\codex-feat-64-frontend-foundation\apps\web\src\components\layout\ProtectedRoute.tsx`
- Create: `C:\Users\권태욱\.config\superpowers\worktrees\aegisai_v2\codex-feat-64-frontend-foundation\apps\web\src\pages\LoginPage.tsx`
- Create: `C:\Users\권태욱\.config\superpowers\worktrees\aegisai_v2\codex-feat-64-frontend-foundation\apps\web\src\pages\DashboardPage.tsx`
- Create: `C:\Users\권태욱\.config\superpowers\worktrees\aegisai_v2\codex-feat-64-frontend-foundation\apps\web\src\pages\ReposPage.tsx`
- Create: `C:\Users\권태욱\.config\superpowers\worktrees\aegisai_v2\codex-feat-64-frontend-foundation\apps\web\src\pages\ScanPage.tsx`
- Create: `C:\Users\권태욱\.config\superpowers\worktrees\aegisai_v2\codex-feat-64-frontend-foundation\apps\web\src\styles.css`

- [ ] Implement the route tree and shell skeleton.
- [ ] Keep placeholders intentionally minimal and non-final.
- [ ] Re-run the shell/protected route tests until green.

### Task 6: Wire app entry and providers

**Files:**
- Modify: `C:\Users\권태욱\.config\superpowers\worktrees\aegisai_v2\codex-feat-64-frontend-foundation\apps\web\src\App.tsx`
- Modify: `C:\Users\권태욱\.config\superpowers\worktrees\aegisai_v2\codex-feat-64-frontend-foundation\apps\web\src\main.tsx`
- Modify: `C:\Users\권태욱\.config\superpowers\worktrees\aegisai_v2\codex-feat-64-frontend-foundation\apps\web\src\App.test.tsx`

- [ ] Add the query client, router provider, and minimal error boundary wiring.
- [ ] Update the app test to assert the new foundation entry behavior.
- [ ] Run `corepack pnpm --filter @aegisai/web test`.

## Chunk 4: Verification and Finish

### Task 7: Run full workspace verification

**Files:**
- Verify only

- [ ] Run `corepack pnpm lint`.
- [ ] Run `corepack pnpm test`.
- [ ] Run `corepack pnpm typecheck`.
- [ ] Run `corepack pnpm build`.

### Task 8: Prepare branch output

**Files:**
- Review diff only

- [ ] Review changed files for scope creep into real page UX.
- [ ] Commit with `feat: implement frontend application shell and api foundation`.
- [ ] Prepare the PR body using the repository template for `#64`.
