# Repository Connection Page Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the protected repository connection page UI at `/repositories`, using the Stitch desktop repository connection design as the baseline while wiring it to the existing repo APIs.

**Architecture:** Keep the existing protected app shell intact and replace the page body with a Stitch-aligned repository connection workspace. Use React Query for connected, available, and branch queries, and keep connect/disconnect actions inside the same page state loop.

**Tech Stack:** React, React Router, TanStack Query, Axios API helpers, Vitest, CSS, Stitch screen references

---

## Chunk 1: Lock The Repository UX In Tests

### Task 1: Add failing tests for connection workflows

**Files:**
- Add: `apps/web/src/pages/ReposPage.test.tsx`
- Add: `apps/web/src/api/repos.test.ts`

- [ ] Cover connected and available repository rendering
- [ ] Cover provider filter switching
- [ ] Cover connect and disconnect action wiring
- [ ] Cover empty-state rendering
- [ ] Run the targeted web tests and confirm they fail for the expected reasons

## Chunk 2: Wire Missing Repo Client Actions

### Task 2: Extend the repo API helper surface

**Files:**
- Modify: `apps/web/src/api/repos.ts`

- [ ] Add `connectRepo()` using the existing shared request/response contract
- [ ] Add `disconnectRepo()` using the existing repo delete endpoint
- [ ] Keep response unwrapping aligned with the shared API envelope

## Chunk 3: Build The Stitch-Aligned Page Body

### Task 3: Replace the repository placeholder with the connection workspace

**Files:**
- Modify: `apps/web/src/pages/ReposPage.tsx`

- [ ] Add the editorial hero and provider filter
- [ ] Load connected repositories and available repositories with React Query
- [ ] Add connect and disconnect mutations with query invalidation
- [ ] Add branch insight tied to the currently selected connected repository
- [ ] Preserve loading, empty, and error states inside the page body

### Task 4: Add repository page styling based on the Stitch composition

**Files:**
- Modify: `apps/web/src/styles.css`

- [ ] Add repository page layout, card, aside, and state styling
- [ ] Keep the page visually aligned with the warm editorial protected-shell tone
- [ ] Preserve responsive behavior without redesigning the app shell

## Chunk 4: Verify The Page In Isolation And In Workspace Context

### Task 5: Run targeted and workspace validation

**Files:**
- Verify only

- [ ] Run `corepack pnpm --filter @aegisai/web test -- ReposPage repos.test`
- [ ] Run `corepack pnpm lint`
- [ ] Run `corepack pnpm test`
- [ ] Run `corepack pnpm typecheck`
- [ ] Run `corepack pnpm build`
