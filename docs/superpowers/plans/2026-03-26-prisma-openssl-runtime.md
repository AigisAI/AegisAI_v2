# Prisma OpenSSL Runtime Dependency Fix Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop the production API container from crashing by switching its Docker runtime to a Prisma-compatible OpenSSL environment.

**Architecture:** Keep the fix constrained to the API Docker image. Replace Alpine with Debian slim in both build and runtime stages, install OpenSSL explicitly, and update the existing GitHub Actions Dockerfile regressions to lock the new runtime contract.

**Tech Stack:** Docker, Prisma, GitHub Actions regression tests

---

## Chunk 1: Lock The Failure With Tests

### Task 1: Update Dockerfile regression expectations

**Files:**
- Modify: `test/github-actions/api-dockerfile.test.mjs`
- Modify: `test/github-actions/cd-workflow.test.mjs`

- [ ] Add failing expectations for Debian slim stages and explicit OpenSSL installation.
- [ ] Run the focused Dockerfile regression and verify it fails against the Alpine image.

## Chunk 2: Apply The Runtime Fix

### Task 2: Update the API Docker image base

**Files:**
- Modify: `apps/api/Dockerfile`

- [ ] Replace Alpine builder and runner stages with Debian slim.
- [ ] Install `openssl` and `ca-certificates` in both stages.
- [ ] Re-run the focused Dockerfile regression and confirm it passes.

## Chunk 3: Full Verification

### Task 3: Run repository validation

**Files:**
- Review only

- [ ] Run `corepack pnpm lint`.
- [ ] Run `corepack pnpm test`.
- [ ] Run `corepack pnpm typecheck`.
- [ ] Run `corepack pnpm build`.
- [ ] Commit with `fix: switch api docker runtime to debian slim`.
