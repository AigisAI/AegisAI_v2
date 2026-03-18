# Prisma Baseline Schema Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the baseline Prisma schema and initial migration for the MVP data model without taking on Prisma runtime wiring.

**Architecture:** Use Prisma with PostgreSQL as the source of truth for persistence. Capture the full MVP core entity set now so later issues can build services and controllers on a stable schema instead of repeatedly rewriting migrations.

**Tech Stack:** Prisma 5.x, PostgreSQL 16, NestJS 10.x, pnpm workspace

---

### Task 1: Prepare Prisma Tooling

**Files:**
- Modify: `apps/api/package.json`

- [ ] Add `prisma` and `@prisma/client` dependencies and basic Prisma scripts.
- [ ] Verify the package manifest still installs cleanly.

### Task 2: Add the Baseline Schema

**Files:**
- Create: `apps/api/prisma/schema.prisma`

- [ ] Define datasource and generator blocks.
- [ ] Add MVP enums and models from the approved baseline docs.
- [ ] Keep service-layer-only rules out of schema constraints.

### Task 3: Generate the Initial Migration

**Files:**
- Create: `apps/api/prisma/migrations/*`

- [ ] Run Prisma validation.
- [ ] Generate the initial migration from the schema.
- [ ] Confirm the generated SQL matches the intended entities and indexes.

### Task 4: Verify the Workspace

**Files:**
- Modify if needed: lockfile artifacts from dependency changes

- [ ] Run targeted Prisma validation.
- [ ] Run workspace `lint`.
- [ ] Run workspace `test`.
- [ ] Run workspace `typecheck`.
