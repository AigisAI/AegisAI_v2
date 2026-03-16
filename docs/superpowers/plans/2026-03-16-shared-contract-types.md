# Shared Contract Types Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the baseline `@aegisai/shared` contract modules used by both the API and web apps.

**Architecture:** Split shared contracts by domain under `packages/shared/src/types/`, keep common pagination and envelope contracts in `common.ts`, and re-export everything from the package root. Lock the surface with a source-level regression test so future changes cannot silently drop files or exports.

**Tech Stack:** TypeScript, pnpm workspaces, Node test runner

---

### Task 1: Lock the export surface with a failing regression test

**Files:**
- Create: `packages/shared/test/shared-contract-exports.test.mjs`
- Modify: `packages/shared/package.json`

- [ ] Add a Node test that expects all shared type modules to exist.
- [ ] Assert the package root re-exports each shared type module.
- [ ] Run the targeted shared test and confirm it fails before implementation.

### Task 2: Implement shared type modules

**Files:**
- Create: `packages/shared/src/types/common.ts`
- Create: `packages/shared/src/types/auth.ts`
- Create: `packages/shared/src/types/repo.ts`
- Create: `packages/shared/src/types/scan.ts`
- Create: `packages/shared/src/types/vulnerability.ts`
- Create: `packages/shared/src/types/dashboard.ts`
- Create: `packages/shared/src/types/report.ts`
- Modify: `packages/shared/src/index.ts`

- [ ] Add pagination and API envelope contracts in `common.ts`.
- [ ] Add auth, repo, scan, vulnerability, dashboard, and report DTOs around the MVP API payloads.
- [ ] Re-export the full surface from `index.ts`.

### Task 3: Verify package and workspace health

**Files:**
- Modify: `docs/superpowers/specs/2026-03-16-shared-contract-types-design.md`
- Modify: `docs/superpowers/plans/2026-03-16-shared-contract-types.md`

- [ ] Run the targeted shared regression test and confirm it passes.
- [ ] Run `corepack pnpm --filter @aegisai/shared lint`.
- [ ] Run `corepack pnpm --filter @aegisai/shared test`.
- [ ] Run `corepack pnpm --filter @aegisai/shared typecheck`.
- [ ] Run workspace `lint`, `test`, `typecheck`, and `build`.
