# GitHub Actions CD Deploy Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a GHCR-backed Oracle Cloud VPS deployment pipeline for the monorepo's API and web apps.

**Architecture:** Build API and web Docker images on GitHub Actions when `main` changes, push them to GHCR with SHA tags, then SSH into the Oracle Cloud VPS to pull and restart the Docker Compose stack. Keep runtime app secrets in a server-managed `.env` file while the workflow only handles image delivery and rollout.

**Tech Stack:** GitHub Actions, Docker multi-stage builds, GHCR, Docker Compose, OpenSSH

---

### Task 1: Add CD Regression Tests

**Files:**
- Create: `test/github-actions/cd-workflow.test.mjs`

- [ ] Add a regression test that expects the CD workflow, Dockerfiles, and Oracle deploy files to exist.
- [ ] Assert the workflow builds and pushes images to GHCR, then deploys over SSH on `main`.
- [ ] Run the targeted Node test and verify it fails before the CD files exist.

### Task 2: Add Production Container Files

**Files:**
- Create: `.dockerignore`
- Create: `apps/api/Dockerfile`
- Create: `apps/web/Dockerfile`
- Create: `apps/web/nginx.conf`
- Create: `deploy/oracle/docker-compose.prod.yml`
- Create: `deploy/oracle/deploy.sh`
- Create: `deploy/oracle/.env.example`

- [ ] Add minimal production Dockerfiles for the API and web apps.
- [ ] Add the Oracle VPS Docker Compose stack and remote deploy script.
- [ ] Add an example server `.env` file describing the runtime values required on the VPS.

### Task 3: Add GitHub Actions CD Workflow

**Files:**
- Create: `.github/workflows/cd.yml`

- [ ] Build and push API and web images to GHCR on `main` and `workflow_dispatch`.
- [ ] Add deploy steps that upload the Oracle deploy files and restart the remote Compose stack over SSH.
- [ ] Keep branch and secret usage explicit in the workflow.

### Task 4: Verify and Document

**Files:**
- Modify: `README.md`

- [ ] Run the targeted CD regression test and verify it passes.
- [ ] Run workspace `lint`, `test`, `typecheck`, and `build`.
- [ ] Document the required GitHub secrets and VPS setup path at a lightweight level.
