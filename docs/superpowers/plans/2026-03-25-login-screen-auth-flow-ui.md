# Login Screen and Auth Flow UI Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the frontend login placeholder with a real OAuth login UI and wire the `/login` route to the existing session bootstrap flow.

**Architecture:** Keep the current route tree and auth foundation intact, then layer a focused login-page UI on top. Use the Stitch-generated desktop login direction as the visual source of truth, then translate it into `LoginPage`, the existing auth foundation, and targeted tests without broadening the redesign beyond this route.

**Tech Stack:** React, React Router, TanStack Query, Zustand, Vitest, Testing Library

---

## Chunk 1: Login Auth UI Surface

### Task 1: Define the login-page behavior contract

**Files:**
- Modify: `apps/web/src/hooks/useAuth.ts`
- Test: `apps/web/src/hooks/useAuth.test.tsx`

- [ ] Add the smallest failing test coverage needed for login bootstrap state exposure.
- [ ] Run the focused auth hook test and confirm the new expectation fails first.
- [ ] Extend `useAuth` to expose the minimal state the login page needs without changing existing logout/refresh behavior.
- [ ] Re-run the focused auth hook test and confirm it passes.

### Task 2: Replace the login placeholder with the designed login page

**Files:**
- Modify: `apps/web/src/pages/LoginPage.tsx`
- Modify: `apps/web/src/styles.css`
- Test: `apps/web/src/pages/LoginPage.test.tsx`

- [ ] Write failing login-page tests for unauthenticated render, provider CTAs, loading state, error hint render, and authenticated redirect.
- [ ] Write failing login-page tests for unauthenticated render, provider CTAs, loading state, error hint render, authenticated redirect, and session bootstrap failure guidance.
- [ ] Run the focused login-page test file and confirm the new cases fail against the placeholder.
- [ ] Implement the login-page UI with hero copy, provider buttons, loading state, and retry/error presentation.
- [ ] Add only the login-page-specific styles needed to support the new layout and states.
- [ ] Re-run the focused login-page test file and confirm it passes.

## Chunk 2: Auth Flow Integration

### Task 3: Add provider login URL helpers and route-safe behavior

**Files:**
- Modify: `apps/web/src/api/auth.ts`
- Modify: `apps/web/src/router.tsx`
- Test: `apps/web/src/api/client.test.ts`
- Test: `apps/web/src/pages/LoginPage.test.tsx`

- [ ] Add the smallest failing coverage for provider login URL generation if helper behavior is introduced.
- [ ] Make provider login URLs resolve to the existing `/api/auth/<provider>` backend entrypoints and lock that behavior in tests.
- [ ] Run the focused tests and confirm the new expectation fails first.
- [ ] Implement provider login navigation in the simplest way that matches the backend auth controller endpoints.
- [ ] Treat querystring auth errors as optional passive UI hints only, without introducing a new backend callback dependency in this issue.
- [ ] Keep `/login` public and rely on the page-level redirect for authenticated users instead of route duplication.
- [ ] Re-run the focused tests and confirm they pass.

### Task 4: Run full verification and finish the branch

**Files:**
- Review only

- [ ] Run `corepack pnpm --filter @aegisai/web test`.
- [ ] Run `corepack pnpm lint`.
- [ ] Run `corepack pnpm test`.
- [ ] Run `corepack pnpm typecheck`.
- [ ] Run `corepack pnpm build`.
- [ ] Review the git diff for `apps/web` and the new docs.
- [ ] Commit with `feat: implement login screen and auth flow ui`.
- [ ] Push the local branch to `origin feat/66-login-screen-auth-ui`.
