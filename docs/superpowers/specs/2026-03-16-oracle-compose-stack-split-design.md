# Oracle Compose Stack Split Design

**Issue**: `#23`
**Title**: `Refactor: docker-compose 스택 분리`
**Date**: `2026-03-16`

## Goal

Split the Oracle Cloud VPS deployment into separate infrastructure and application Docker Compose stacks so routine app deployments do not touch PostgreSQL or Redis.

## Scope

- Replace the single production compose file with `docker-compose.infra.yml` and `docker-compose.app.yml`
- Keep PostgreSQL and Redis in the infra stack
- Keep API and web in the app stack
- Update the deploy script and CD workflow so GitHub Actions only pulls and restarts the app stack
- Update regression coverage and deployment documentation for the new split layout

## Design Choices

1. Use a named shared Docker network created by the infra stack so the app stack can attach to existing `postgres` and `redis` services without bundling them into app deploys.
2. Leave runtime secrets in the same server-managed `.env` file so the split is operational, not a secret-management redesign.
3. Upload both compose files on every CD run so the VPS always has the latest infra/app definitions, even though only the app stack is restarted automatically.
4. Keep infra lifecycle manual for now: the VPS bootstrap flow will bring up `docker-compose.infra.yml`, while GitHub Actions continues to handle only image rollout for `docker-compose.app.yml`.
5. Add repository regression tests that assert the workflow, compose files, and deploy script all preserve the split-stack contract.

## Non-Goals

- No managed database migration or backup automation in this issue
- No change to GHCR image naming or build behavior
- No staging environment or multi-host orchestration

## Validation

- Split-stack regression test passes locally
- Workspace `lint`, `test`, `typecheck`, and `build` still pass
- CD workflow uploads both compose files and only restarts the app stack
