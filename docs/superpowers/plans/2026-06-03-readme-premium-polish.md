# README Premium Polish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refine `README.md` into a polished, scan-friendly first page while preserving the
active 004 runtime infrastructure milestone.

**Architecture:** This is a documentation-only change. `README.md` remains a landing page;
`AGENTS.md` and `specs/004-production-runtime-infrastructure/quickstart.md` remain the
canonical execution entrypoints.

**Tech Stack:** GitHub-flavored Markdown in a pnpm monorepo.

---

### Task 1: Polish README Structure

**Files:**
- Modify: `README.md`

- [ ] Replace the opening with a concise product identity and at-a-glance table.
- [ ] Move `Start Here` immediately after the overview.
- [ ] Convert long status and architecture bullets into tables.
- [ ] Group guardrails by Source, Credentials, Scan Plane, AI Plane, and Platform.
- [ ] Keep local development, validation, deployment, GitHub workflow, and precedence
      sections copyable and compact.

### Task 2: Preserve Doc Contracts

**Files:**
- Verify: `README.md`

- [ ] Ensure README contains `AGENTS.md -> quickstart.md ->`.
- [ ] Ensure README contains `hardening-review.md`.
- [ ] Ensure README points to `004-production-runtime-infrastructure`.
- [ ] Ensure Oracle VPS is dev/demo only.

### Task 3: Validate

**Files:**
- Verify: repository

- [ ] Run `corepack pnpm lint`.
- [ ] Run `corepack pnpm test`.
- [ ] Run `corepack pnpm typecheck`.
- [ ] Run `corepack pnpm build`.
- [ ] Run `corepack pnpm --filter @aegisai/api prisma:validate` with a temporary
      `DATABASE_URL` if the shell does not already define one.
- [ ] Run `git diff --check`.
