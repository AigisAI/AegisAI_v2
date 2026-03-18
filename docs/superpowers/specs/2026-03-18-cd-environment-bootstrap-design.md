# CD Environment Bootstrap Design

**Issue**: `#33`  
**Title**: `Chore: CD 환경 구축`  
**Date**: `2026-03-18`

## Goal

Make the Oracle Cloud production bootstrap path reproducible from the repository so the
existing GitHub Actions CD workflow can be connected to a real VPS without tribal knowledge.

## Scope

- Add a repo-tracked Oracle bootstrap runbook for first-time production setup
- Clarify which steps are manual infrastructure bootstrap versus automated app deployment
- Add one minimal helper script for first infra bring-up on the VPS
- Update repository docs so contributors know the exact GitHub secrets, server files, and
  smoke-check sequence required for CD
- Add a small regression check so the bootstrap artifacts remain present and aligned with the
  current split-stack deployment model

## Recommended Approach

Use a documentation-first bootstrap slice with one idempotent helper script.

- Add `deploy/oracle/BOOTSTRAP.md` as the single source of truth for Oracle VPS setup
- Add `deploy/oracle/bootstrap-infra.sh` for the one-time `postgres` and `redis` bring-up
- Update `README.md` to point readers to the detailed Oracle bootstrap runbook instead of
  keeping the full operational checklist inline
- Add a focused regression test that asserts the bootstrap artifacts exist and still describe
  the current split `infra` / `app` deployment contract

This keeps `#33` honest about what can be automated from the repo versus what still must be
performed in Oracle Cloud and GitHub settings by a human operator.

## Alternatives Considered

### 1. Docs only, no helper script

- Pros: smallest change
- Cons: leaves the first infra bootstrap as copy-paste shell knowledge and makes mistakes more
  likely on a fresh VPS

### 2. Fully automate VPS provisioning from the repo

- Pros: strongest automation story
- Cons: requires Terraform/cloud-init level scope, cloud credentials, and much larger review
  surface than this issue should own

### 3. Extend GitHub Actions to provision the server remotely

- Pros: fewer manual steps after secrets are set
- Cons: risky for first-time bootstrap, harder to audit, and mixes one-time server prep with
  normal application deployment

## Non-Goals

- No direct Oracle Cloud account provisioning from this repository
- No domain, HTTPS, reverse proxy, or TLS certificate setup in this issue
- No migration from VPS-hosted Postgres/Redis to managed cloud services
- No change to the current CD trigger model (`main` push / `workflow_dispatch`)

## Assumptions

- The deployment target remains a single Oracle Cloud VPS
- Docker Engine and Docker Compose plugin are the production runtime on that VPS
- `postgres` and `redis` remain in the manually bootstrapped infra stack
- `api` and `web` remain in the app stack rolled out by GitHub Actions CD

## Validation

- Local regression test proves the new bootstrap doc and helper script exist and mention the
  split-stack deployment path
- Workspace `test`, `lint`, `typecheck`, and `build` remain green after the documentation and
  helper-script updates
