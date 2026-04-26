# Oracle Compose Stack Split Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split Oracle VPS deployment into infra and app compose stacks so CD only restarts application services.

**Architecture:** Keep `postgres` and `redis` in an infra compose file that owns the shared network and volumes. Move `api` and `web` into a separate app compose file that joins the shared network externally, then update the CD workflow and deploy script to upload both files but only pull/up the app stack.

**Tech Stack:** Docker Compose, GitHub Actions, GHCR, OpenSSH, Node test runner

---

### Task 1: Lock the split-stack regression

**Files:**
- Modify: `test/github-actions/cd-workflow.test.mjs`

- [ ] Change the CD regression test to expect `docker-compose.infra.yml` and `docker-compose.app.yml` instead of a single prod compose file.
- [ ] Assert the deploy script only pulls and restarts the app stack.
- [ ] Assert the workflow uploads both compose files.
- [ ] Run the targeted regression test and confirm it fails before implementation.

### Task 2: Split Oracle deployment files

**Files:**
- Create: `deploy/oracle/docker-compose.infra.yml`
- Create: `deploy/oracle/docker-compose.app.yml`
- Modify: `deploy/oracle/deploy.sh`
- Delete: `deploy/oracle/docker-compose.prod.yml`

- [ ] Move `postgres` and `redis` into the infra compose file with volumes and a named shared network.
- [ ] Move `api` and `web` into the app compose file and attach them to the shared network.
- [ ] Update the deploy script so CD only runs `pull` and `up` against the app compose file.

### Task 3: Update workflow and docs

**Files:**
- Modify: `.github/workflows/cd.yml`
- Modify: `README.md`
- Modify: `deploy/oracle/.env.example`

- [ ] Upload both compose files during CD.
- [ ] Document that infra bootstrap is a one-time/manual server task and app rollout is automated.
- [ ] Keep the existing secret model intact.

### Task 4: Verify end to end

**Files:**
- Modify: `docs/superpowers/specs/2026-03-16-oracle-compose-stack-split-design.md`
- Modify: `docs/superpowers/plans/2026-03-16-oracle-compose-stack-split.md`

- [ ] Run the targeted CD regression test.
- [ ] Run workspace `lint`, `test`, `typecheck`, and `build`.
- [ ] Review the diff to confirm only app deployment behavior changed.
