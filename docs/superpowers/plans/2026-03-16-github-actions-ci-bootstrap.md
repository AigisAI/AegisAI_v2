# GitHub Actions CI Bootstrap Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a baseline GitHub Actions CI workflow that verifies the pnpm workspace on PRs and pushes.

**Architecture:** Use a single GitHub Actions workflow with one verification job that installs dependencies once and runs the same root commands developers use locally. Keep the workflow intentionally narrow so CI is stable before CD and Docker automation are introduced.

**Tech Stack:** GitHub Actions, Node.js 20, pnpm 10, Node built-in test runner

---

### Task 1: Add CI Workflow Regression Test

**Files:**
- Create: `test/github-actions/ci-workflow.test.mjs`

- [ ] Add a file-level regression test that expects `.github/workflows/ci.yml` to exist.
- [ ] Assert the workflow includes PR/push triggers, pnpm setup, install, lint, test, typecheck, and build steps.
- [ ] Run the targeted Node test and verify it fails before the workflow exists.

### Task 2: Implement GitHub Actions Workflow

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] Add a single CI workflow triggered by pushes and pull requests for `dev` and `main`.
- [ ] Configure checkout, pnpm setup, Node setup with pnpm cache, and the workspace verification commands.
- [ ] Add concurrency cancellation for duplicate runs on the same branch or PR.

### Task 3: Verify and Document

**Files:**
- Modify if needed: `README.md`

- [ ] Run the targeted workflow regression test and verify it passes.
- [ ] Run workspace `lint`, `test`, `typecheck`, and `build`.
- [ ] Update lightweight docs only if the new CI entry point would otherwise be unclear.
