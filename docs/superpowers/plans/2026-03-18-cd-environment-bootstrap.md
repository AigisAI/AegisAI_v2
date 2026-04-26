# CD Environment Bootstrap Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a repository-tracked Oracle Cloud CD bootstrap runbook and minimal helper artifacts so the existing GitHub Actions deployment can be connected to a real VPS reproducibly.

**Architecture:** Keep this issue documentation-first. The repository will own the Oracle bootstrap runbook, one helper script for first infra bring-up, and a regression check that keeps the bootstrap contract aligned with the split `infra` / `app` deployment model. Actual Oracle Cloud provisioning, GitHub secret entry, and production `.env` creation remain manual operator steps.

**Tech Stack:** Markdown docs, POSIX shell, Docker Compose, Node test runner, GitHub Actions CD

---

### Task 1: Add Failing Regression Test For Bootstrap Artifacts

**Files:**
- Modify: `test/github-actions/cd-workflow.test.mjs`

- [ ] **Step 1: Write the failing test**

Cover:
- `deploy/oracle/BOOTSTRAP.md` exists
- `deploy/oracle/bootstrap-infra.sh` exists
- the bootstrap doc references GitHub secrets, `.env`, `docker-compose.infra.yml`, and the one-time infra bring-up path
- the helper script runs `docker compose -f docker-compose.infra.yml up -d`

- [ ] **Step 2: Run targeted test to verify it fails**

Run:
- `node test/github-actions/cd-workflow.test.mjs`

Expected: FAIL because the bootstrap doc and helper script do not exist yet

### Task 2: Add Oracle Bootstrap Runbook And Helper Script

**Files:**
- Create: `deploy/oracle/BOOTSTRAP.md`
- Create: `deploy/oracle/bootstrap-infra.sh`

- [ ] **Step 3: Write minimal implementation**

Add:
- Oracle Cloud VPS creation checklist
- required GitHub secrets list
- server-side `.env` preparation instructions
- exact first-time infra bootstrap command flow
- post-deploy smoke checks
- a small helper script that validates required files and starts the infra compose stack

- [ ] **Step 4: Run targeted regression test**

Run:
- `node test/github-actions/cd-workflow.test.mjs`

Expected: PASS

### Task 3: Align Root Docs With The Bootstrap Source Of Truth

**Files:**
- Modify: `README.md`

- [ ] **Step 5: Update repository documentation**

Make README:
- point to `deploy/oracle/BOOTSTRAP.md`
- keep only the short CD summary at the root
- avoid duplicating the full bootstrap checklist inline

- [ ] **Step 6: Re-run targeted regression test**

Run:
- `node test/github-actions/cd-workflow.test.mjs`

Expected: PASS with the bootstrap references still aligned

### Task 4: Verify Workspace Baseline

**Files:**
- Modify if needed: none beyond the files above

- [ ] **Step 7: Run workspace verification**

Run:
- `corepack pnpm lint`
- `corepack pnpm test`
- `corepack pnpm typecheck`
- `corepack pnpm build`

Expected: all commands exit successfully

- [ ] **Step 8: Commit**

Run:
`git add deploy/oracle/BOOTSTRAP.md deploy/oracle/bootstrap-infra.sh test/github-actions/cd-workflow.test.mjs README.md docs/superpowers/specs/2026-03-18-cd-environment-bootstrap-design.md docs/superpowers/plans/2026-03-18-cd-environment-bootstrap.md`

Commit:
`git commit -m "chore: add oracle cd bootstrap runbook"`
