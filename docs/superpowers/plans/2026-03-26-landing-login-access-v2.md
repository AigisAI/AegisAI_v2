# Landing Page And Login Access Page V2 Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Update the public landing page and `/login` access page to match the approved Stitch V2 public-entry direction while preserving existing auth behavior.

**Architecture:** Reuse the existing public route structure from `#78`, but replace the current landing and login view structure with the Stitch V2 information architecture. Keep runtime auth logic in place and confine visual changes to the public pages and their styles.

**Tech Stack:** React, React Router, Vitest, CSS, Stitch-generated screen references

---

## Chunk 1: Lock The V2 Surface In Tests

### Task 1: Update landing and login tests to the new Stitch V2 content

**Files:**
- Modify: `apps/web/src/pages/LandingPage.test.tsx`
- Modify: `apps/web/src/pages/LoginPage.test.tsx`

- [ ] Update landing page expectations to the V2 navigation, hero, trust, workflow, and final CTA content
- [ ] Update login page expectations to the V2 heading and trust chip content
- [ ] Run the targeted web tests and confirm they fail for the expected reasons

## Chunk 2: Rebuild Public Screens Around Stitch V2

### Task 2: Replace the landing page structure with the V2 editorial layout

**Files:**
- Modify: `apps/web/src/pages/LandingPage.tsx`

- [ ] Update the public nav structure to the V2 top bar
- [ ] Replace the current hero copy and CTA arrangement with the V2 editorial hero
- [ ] Add the V2 trust strip, workflow section, security story section, and final CTA
- [ ] Keep provider CTA destinations wired through `getProviderLoginUrl()`

### Task 3: Replace the login page structure with the V2 access portal layout

**Files:**
- Modify: `apps/web/src/pages/LoginPage.tsx`

- [ ] Update the page heading and top navigation to the V2 secure access structure
- [ ] Rebuild the central access card around the Stitch V2 CTA rows
- [ ] Preserve loading, OAuth error, session bootstrap error, and authenticated redirect behavior
- [ ] Keep provider CTA destinations wired through `getProviderLoginUrl()`

## Chunk 3: Align Styles To Stitch Without Re-Designing

### Task 4: Rework public page styles to match the Stitch V2 editorial system

**Files:**
- Modify: `apps/web/src/styles.css`

- [ ] Update landing-specific styles to reflect the V2 editorial hierarchy, spacing, and trust sections
- [ ] Update login-specific styles to reflect the V2 centered access-card composition
- [ ] Preserve responsive behavior and avoid unnecessary divergence from Stitch

## Chunk 4: Verify The Public Entry Flow End To End

### Task 5: Run targeted and workspace validation

**Files:**
- Verify only

- [ ] Run `corepack pnpm --filter @aegisai/web test -- LandingPage LoginPage`
- [ ] Run `corepack pnpm lint`
- [ ] Run `corepack pnpm test`
- [ ] Run `corepack pnpm typecheck`
- [ ] Run `corepack pnpm build`
