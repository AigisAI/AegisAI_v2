# PrismaService Spy Type Fix Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ensure the API workspace generates the Prisma client before build, test, dev, and typecheck commands so `PrismaService` and its tests stay type-safe on fresh installs.

**Architecture:** Treat this as a tooling contract fix rather than a service refactor. Keep the Prisma service code intact, add a regression test around package scripts, and make the API scripts invoke `corepack pnpm prisma:generate` before any command that depends on generated Prisma types.

**Tech Stack:** pnpm workspaces, Prisma CLI, NestJS, Jest, Node test runner

---

### Task 1: Lock the regression with a script contract test

**Files:**
- Create: `test/github-actions/prisma-client-generation.test.mjs`

- [ ] Add a test that reads `apps/api/package.json`.
- [ ] Assert that `build`, `dev`, `test`, `test:e2e`, and `typecheck` all invoke `corepack pnpm prisma:generate`.
- [ ] Run the targeted Node test and confirm it fails before the package scripts are updated.

### Task 2: Update API commands to prepare Prisma client output

**Files:**
- Modify: `apps/api/package.json`

- [ ] Prefix the TypeScript-dependent API scripts with `corepack pnpm prisma:generate`.
- [ ] Keep `lint` and Prisma helper scripts unchanged.
- [ ] Re-run the targeted Node test and confirm it passes.

### Task 3: Verify the real failure path

**Files:**
- Modify: `docs/superpowers/specs/2026-03-16-prisma-service-spy-types-design.md`
- Modify: `docs/superpowers/plans/2026-03-16-prisma-service-spy-types.md`

- [ ] Run `corepack pnpm --filter @aegisai/api typecheck`.
- [ ] Run `corepack pnpm --filter @aegisai/api test -- --runInBand`.
- [ ] Run workspace `lint`, `test`, `typecheck`, and `build`.
- [ ] Document any verification limits if Prisma engine download is blocked by the current environment.
