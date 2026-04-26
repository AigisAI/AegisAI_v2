# Scan Request And Status Page UI Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the `/scan` placeholder with a real scan orchestration workspace that lets users queue a scan and monitor recent scan status inside the protected shell.

**Architecture:** Reuse the existing protected route and API helpers. Load connected repositories, branch options, recent scans, and selected scan detail with React Query. Use the protected Stitch repository workspace composition as the visual baseline and adapt it into a scan-centric flow.

**Tech Stack:** React, React Router, TanStack Query, Vitest, CSS, existing repo/scan API helpers, Stitch screen references

---

## Chunk 1: Lock The Page Contract In Tests

### Task 1: Add failing scan page tests

**Files:**
- Add: `apps/web/src/pages/ScanPage.test.tsx`

- [ ] Cover rendering of the scan request form, recent scans, and selected scan detail
- [ ] Cover queuing a scan for the selected repository and branch
- [ ] Cover the connect-first empty state when no repositories are available
- [ ] Run targeted web tests and confirm they fail for the placeholder page

## Chunk 2: Build The Scan Workspace

### Task 2: Replace the placeholder scan page with a request-and-status workspace

**Files:**
- Modify: `apps/web/src/pages/ScanPage.tsx`

- [ ] Load connected repositories and default the page to the first available source
- [ ] Load branch options for the selected repository
- [ ] Load recent scans and selected scan detail for the active repository
- [ ] Add request-scan mutation and invalidate scan history/detail after success
- [ ] Add active scan polling for `PENDING` and `RUNNING` states
- [ ] Preserve accessible selection state and inline error handling

### Task 3: Add Stitch-aligned styling for the scan workspace

**Files:**
- Modify: `apps/web/src/styles.css`

- [ ] Add scan hero, request card, history list, status panel, and trust-panel styling
- [ ] Keep the warm editorial protected-workspace tone established by prior issues
- [ ] Preserve responsive behavior without redesigning the app shell

## Chunk 3: Verify The Frontend Foundation Still Holds

### Task 4: Run targeted and workspace validation

**Files:**
- Verify only

- [ ] Run `corepack pnpm --filter @aegisai/web test -- ScanPage`
- [ ] Run `corepack pnpm lint`
- [ ] Run `corepack pnpm test`
- [ ] Run `corepack pnpm typecheck`
- [ ] Run `corepack pnpm build`
