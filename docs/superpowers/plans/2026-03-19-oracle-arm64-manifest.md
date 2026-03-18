# Oracle ARM64 Manifest Guard Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fail CD before SSH deploy whenever a pushed GHCR image tag is missing either the `amd64` or `arm64` manifest needed by Oracle ARM64 production.

**Architecture:** Keep the current build-and-push workflow, then add an explicit manifest verification gate inside the same job so deploy cannot start with an incomplete image tag. Back the guard with a regression test that asserts the workflow contains the inspection step and architecture checks.

**Tech Stack:** GitHub Actions, Docker Buildx, Node test runner

---

## Chunk 1: Regression Test

### Task 1: Require Manifest Guard In Workflow Test

**Files:**
- Modify: `test/github-actions/cd-workflow.test.mjs`

- [ ] **Step 1: Write the failing test**
- [ ] **Step 2: Run the targeted workflow test to verify it fails**
- [ ] **Step 3: Update assertions only as needed to express the intended guard**
- [ ] **Step 4: Re-run the targeted workflow test and keep it red until workflow code is added**

## Chunk 2: Workflow Guard

### Task 2: Verify Multi-Arch Manifests Before Deploy

**Files:**
- Modify: `.github/workflows/cd.yml`

- [ ] **Step 1: Add a manifest verification step after both image pushes**
- [ ] **Step 2: Inspect both API and web tags with `docker buildx imagetools inspect`**
- [ ] **Step 3: Assert both `linux/amd64` and `linux/arm64` exist for each image**
- [ ] **Step 4: Keep deploy blocked if verification fails**

## Chunk 3: Verification

### Task 3: Prove The Guard Works

**Files:**
- Verify: `test/github-actions/cd-workflow.test.mjs`
- Verify: `.github/workflows/cd.yml`

- [ ] **Step 1: Run `node --test test/github-actions/cd-workflow.test.mjs`**
- [ ] **Step 2: Run `corepack pnpm test`**
- [ ] **Step 3: Run `corepack pnpm lint`**
- [ ] **Step 4: Run `corepack pnpm typecheck`**
- [ ] **Step 5: Run `corepack pnpm build`**
- [ ] **Step 6: Commit with `fix: verify multi-arch manifests before deploy`**
