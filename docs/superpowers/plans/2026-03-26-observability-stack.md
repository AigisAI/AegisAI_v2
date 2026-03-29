# Observability Stack With Teams, Loki, and Grafana Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Oracle VPS observability infrastructure plus Teams deployment/runtime notifications without disturbing the existing split app/infra deployment flow.

**Architecture:** Introduce a third deploy stack for observability, keep normal CD focused on app rollout, and add a small backend notifier that hooks into the existing global exception filter for 5xx alerts only. Documentation and workflow regressions should lock the new operator path in place.

**Tech Stack:** Docker Compose, GitHub Actions, NestJS, Grafana, Loki, Promtail

---

## Chunk 1: Observability Stack Files

### Task 1: Add Oracle observability compose and provisioning files

**Files:**
- Create: `deploy/oracle/docker-compose.observability.yml`
- Create: `deploy/oracle/bootstrap-observability.sh`
- Create: `deploy/oracle/loki-config.yml`
- Create: `deploy/oracle/promtail-config.yml`
- Create: `deploy/oracle/grafana/provisioning/datasources/loki.yml`

- [ ] Write workflow/deploy regression expectations for the observability files first.
- [ ] Run the focused workflow regression and confirm the new expectations fail.
- [ ] Add the observability compose stack, bootstrap helper, and provisioning files.
- [ ] Re-run the focused workflow regression and confirm the new files are locked in.

## Chunk 2: Teams Deployment Alerts and Docs

### Task 2: Extend CD workflow and deployment docs

**Files:**
- Modify: `.github/workflows/cd.yml`
- Modify: `deploy/oracle/BOOTSTRAP.md`
- Modify: `deploy/oracle/.env.example`
- Modify: `README.md`
- Modify: `test/github-actions/cd-workflow.test.mjs`

- [ ] Add failing expectations for observability uploads, bootstrap docs, and Teams workflow notifications.
- [ ] Run the focused workflow regression and confirm the new expectations fail first.
- [ ] Update CD to upload observability files and send best-effort Teams notifications on success/failure.
- [ ] Update Oracle runtime docs/examples for Grafana credentials, webhook setup, and observability bootstrap.
- [ ] Re-run the focused workflow regression and confirm it passes.

## Chunk 3: Backend Runtime Notifications

### Task 3: Add API observability module and Teams runtime notifier

**Files:**
- Create: `apps/api/src/observability/observability.module.ts`
- Create: `apps/api/src/observability/teams-notifier.service.ts`
- Modify: `apps/api/src/app.module.ts`
- Modify: `apps/api/src/common/filters/global-exception.filter.ts`
- Modify: `apps/api/src/config/config.module.ts`
- Modify: `apps/api/src/config/config.types.ts`
- Modify: `.env.example`
- Modify: `apps/api/.env.example`
- Test: `apps/api/test/observability/teams-notifier.service.e2e-spec.ts`
- Test: `apps/api/test/common/global-exception.filter.e2e-spec.ts`
- Test: `apps/api/test/config/config.service.typecheck.ts`

- [ ] Write failing tests for webhook no-op behavior, successful Teams payload delivery, and 5xx-only filter notifications.
- [ ] Run the focused backend tests and confirm the new expectations fail first.
- [ ] Add observability module/notifier/config support and wire the notifier into the global exception filter.
- [ ] Re-run the focused backend tests and confirm they pass.

## Chunk 4: Full Verification and Finish

### Task 4: Run repository validation and prepare branch output

**Files:**
- Review only

- [ ] Run `corepack pnpm lint`.
- [ ] Run `corepack pnpm test`.
- [ ] Run `corepack pnpm typecheck`.
- [ ] Run `corepack pnpm build`.
- [ ] Review the diff for deploy, workflow, API observability, docs, and tests.
- [ ] Commit with `feat: add observability stack and teams alerts`.
- [ ] Push `codex/feat-72-observability-stack` to origin.
