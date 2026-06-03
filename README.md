# AegisAI

AegisAI is a hosted security scan SaaS for GitHub Cloud and GitLab Cloud repositories.
It is being re-baselined around a production runtime architecture that treats customer
repositories as untrusted input, keeps scanner output deterministic-first, preserves
advisory-only AI, and separates Control, Scan, AI, and Data/Security planes.

## What This Is

AegisAI connects to customer repositories through GitHub App installations or GitLab
Cloud integrations, plans security scans, normalizes scanner results, applies policy
decisions, and exposes results through dashboards and PR/MR comments.

The product direction is defined by
`C:\Users\권태욱\Desktop\Security Scan SaaS Final Specification.docx`. That DOCX is the
highest-priority product, platform, security, and operations baseline for the current
production runtime infrastructure work.

## Current Baseline

The active implementation target is
[`specs/004-production-runtime-infrastructure/`](./specs/004-production-runtime-infrastructure/).
Start from its
[`quickstart.md`](./specs/004-production-runtime-infrastructure/quickstart.md), not from
`tasks.md` directly.

Current milestone focus:

- Repository entrypoints aligned to `004-production-runtime-infrastructure`
- Kubernetes AI Plane deployment and service manifest skeletons
- Runtime autoscaling policy skeletons for latency, queue pressure, provider health,
  fallback, CPU, memory, and tenant-aware audit signals
- microVM scanner sandbox provisioning contract skeletons
- Tests that preserve advisory-only AI boundaries and scanner sandbox prohibitions

Completed production baselines still matter:

- [`specs/003-production-ai-inference-runtime/`](./specs/003-production-ai-inference-runtime/)
  is the completed production AI inference baseline.
- [`specs/002-production-scan-architecture/`](./specs/002-production-scan-architecture/)
  is the completed production scan architecture baseline for scanner-first flows and
  plane separation.

Still deferred:

- Live production Kubernetes cluster provisioning
- Provider-specific microVM platform rollout
- Production cluster credentials as a local development default
- Customer code execution, package installation, repository builds, dynamic testing, or
  direct source upload

## Architecture At A Glance

Production is modeled as four explicit trust boundaries:

- **Control Plane**: tenant lifecycle, auth, SCM integration registry, webhook intake,
  scan planning, token broker, policy decisions, comment dispatch, and dashboard APIs
- **Scan Plane**: scan-scoped repository fetch, scanner adapter execution, normalization,
  correlation, evidence pack construction, scanner-run lineage, and microVM-backed
  scanner sandbox provisioning
- **AI Plane**: advisory-only triage, explanation, prioritization, and remediation planning
  over reduced, redacted, policy-classified evidence; no SCM credentials, full
  repositories, source archives, or raw scanner payloads
- **Data and Security Plane**: tenant-aware persistence, object storage with TTL, audit
  logs, KMS, secrets manager, queues, service identity, and runtime policy boundaries

Production readiness is defined around Kubernetes-compatible Control, Scan, AI, and
Data/Security plane boundaries with stronger-than-pod scan isolation. The current Oracle
VPS path is dev/demo only.

## Non-Negotiable Guardrails

- Do not add direct source upload.
- Do not execute customer code.
- Do not install packages or build customer repositories.
- Do not run dynamic tests against customer repositories.
- Keep user authentication separate from SCM integration credentials.
- Model GitHub Cloud repository access through GitHub App installation flows.
- Model GitLab Cloud repository access through scoped integration and webhook flows.
- Keep repo-read, comment-write, and integration-admin authority separated.
- Do not give the Scan Plane comment-write or integration-admin credentials.
- Do not send full repositories, raw unbounded scanner output, or SCM credentials to AI.
- Do not let AI create authoritative findings, override scanner output, or override policy.
- Keep Kubernetes AI Plane deployment and scanner sandbox provisioning inside the
  separated Control, Scan, AI, and Data/Security plane boundaries.
- Keep shared API contracts in `packages/shared`.
- Preserve sessions, CSRF protection, throttling, health checks, and critical integration
  tests for user-facing API work.

## Repository Map

```text
apps/api/       NestJS API, Prisma schema, Control Plane/API runtime, e2e tests
apps/ai/        AI Plane service runtime and model gateway boundaries
apps/web/       React/Vite frontend
packages/shared/ Shared TypeScript contracts and helpers
specs/004-production-runtime-infrastructure/
                Active production runtime infrastructure package
specs/003-production-ai-inference-runtime/
                Completed production AI inference baseline
specs/002-production-scan-architecture/
                Completed production scan architecture baseline
specs/001-aegisai-mvp-foundation/
                Legacy MVP package retained for historical reference
deploy/oracle/  Oracle VPS dev/demo deployment assets
docs/           Workflow conventions, reports, and implementation support docs
test/           Repository-level test support such as GitHub Actions workflow tests
```

## Start Here

This repository is organized around the active production runtime infrastructure baseline
for AegisAI. For development or agent work, use this path:

```text
AGENTS.md -> quickstart.md -> active feature docs
```

Expanded current path:

```text
AGENTS.md -> specs/004-production-runtime-infrastructure/quickstart.md -> active feature docs
```

[`AGENTS.md`](./AGENTS.md) defines repository entry rules and guardrails.
[`quickstart.md`](./specs/004-production-runtime-infrastructure/quickstart.md) defines the
canonical read order, execution flow, and completion validation path.

When working on a GitHub-style branch, set the active Spec Kit feature if helper scripts
need it:

```powershell
$env:SPECIFY_FEATURE = "004-production-runtime-infrastructure"
```

## Local Development

Requirements:

- Node.js `>=20.0.0 <23.0.0`
- Corepack-enabled pnpm workspace, currently `pnpm@10.0.0`
- PostgreSQL and Redis when exercising runtime paths that need them

Install dependencies:

```powershell
corepack enable
corepack pnpm install
```

Run API, AI, and web development servers through the workspace scripts that apply to the
current slice:

```powershell
corepack pnpm dev
corepack pnpm dev:api
corepack pnpm dev:web
```

Prisma helpers:

```powershell
corepack pnpm --filter @aegisai/api prisma:generate
corepack pnpm --filter @aegisai/api prisma:validate
corepack pnpm --filter @aegisai/api prisma:migrate:dev
```

Environment examples live in [`.env.example`](./.env.example),
[`apps/web/.env.example`](./apps/web/.env.example), and
[`deploy/oracle/.env.example`](./deploy/oracle/.env.example).

## Validation

Use the completion flow and validation command list in
[`specs/004-production-runtime-infrastructure/quickstart.md`](./specs/004-production-runtime-infrastructure/quickstart.md).
GitHub Actions runs the authoritative CI steps in
[`.github/workflows/ci.yml`](./.github/workflows/ci.yml).

Before claiming the production runtime infrastructure milestone complete, also confirm:

- `AGENTS.md`, `README.md`, and
  [`docs/github-conventions.md`](./docs/github-conventions.md) point to
  `004-production-runtime-infrastructure`
- [`specs/003-production-ai-inference-runtime/`](./specs/003-production-ai-inference-runtime/)
  remains available as the completed production AI inference baseline
- [`specs/002-production-scan-architecture/`](./specs/002-production-scan-architecture/)
  remains available as the completed production scan architecture baseline
- [`specs/001-aegisai-mvp-foundation/`](./specs/001-aegisai-mvp-foundation/) remains
  available as the legacy MVP baseline
- Oracle VPS wording remains dev/demo only
- Kubernetes AI Plane deployment preserves advisory-only AI boundaries
- Scanner sandbox provisioning does not permit package install/build, dynamic testing,
  direct source upload, or AI access to full repositories

The legacy MVP hardening review remains available for tasks that explicitly touch the
shipped MVP baseline:
[`specs/001-aegisai-mvp-foundation/hardening-review.md`](./specs/001-aegisai-mvp-foundation/hardening-review.md).

## Deployment Position

The Oracle Cloud VPS deployment path is retained for dev/demo operation and compatibility
with existing workflow settings. It is not the production topology for the production
runtime infrastructure architecture.

Dev/demo CD summary:

- Registry: `ghcr.io`
- Trigger: `main` push or manual `workflow_dispatch`
- Runtime: Docker Compose on the Oracle VPS
- Deploy path files: `deploy/oracle/docker-compose.infra.yml`,
  `deploy/oracle/docker-compose.app.yml`, `deploy/oracle/deploy.sh`,
  `deploy/oracle/bootstrap-infra.sh`, `deploy/oracle/install-alloy.sh`,
  `deploy/oracle/alloy/config.alloy`, and a server-managed `.env`
- Automated rollout scope: app stack only (`api`, `ai`, `web`)
- Manual bootstrap scope: infra stack (`postgres`, `redis`)
- Observability collector: Grafana Alloy on the Oracle VPS
- Observability surface: Grafana Cloud dashboards, Explore, and alerting
- Detailed runbook: [`deploy/oracle/BOOTSTRAP.md`](./deploy/oracle/BOOTSTRAP.md)

Required GitHub secrets for dev/demo CD:

- `ORACLE_VPS_HOST`
- `ORACLE_VPS_USER`
- `ORACLE_VPS_SSH_PRIVATE_KEY`
- `ORACLE_VPS_KNOWN_HOSTS`
- `ORACLE_DEPLOY_PATH`
- `GHCR_USERNAME`
- `GHCR_READ_TOKEN`

Optional production secret:

- `TEAMS_WEBHOOK_URL`

The deploy job currently targets the `production` GitHub environment for compatibility
with existing workflow settings, but architecturally this path is dev/demo. Set the
required secrets before running CD. If any are blank or missing, the workflow fails early
with a clear validation error instead of reaching the SSH steps.

When configured, CD posts a high-signal success/failure notification to Microsoft Teams
without blocking the deploy if the webhook itself fails.

For first-time Oracle Cloud setup, follow
[`deploy/oracle/BOOTSTRAP.md`](./deploy/oracle/BOOTSTRAP.md) rather than reproducing the
steps manually from memory.

## GitHub Workflow

The repository follows the convention in
[`docs/github-conventions.md`](./docs/github-conventions.md):

- `dev` is the default integration branch
- `main` is the release-ready branch
- Feature branches use `feat/<issue-number>-<short-feature>`
- Related branch prefixes use the same issue-number pattern: `fix/`, `refactor/`,
  `release/`, and `hotfix/`
- Commit messages use `<type>: <description>`
- Issue titles and PR titles should match

## Documentation Precedence

When documents disagree, resolve intent in this order:

1. [`AGENTS.md`](./AGENTS.md)
2. [`specs/004-production-runtime-infrastructure/quickstart.md`](./specs/004-production-runtime-infrastructure/quickstart.md)
3. `C:\Users\권태욱\Desktop\Security Scan SaaS Final Specification.docx`
4. [`specs/004-production-runtime-infrastructure/`](./specs/004-production-runtime-infrastructure/)
5. [`specs/003-production-ai-inference-runtime/`](./specs/003-production-ai-inference-runtime/)
6. [`specs/002-production-scan-architecture/`](./specs/002-production-scan-architecture/)
7. [`docs/github-conventions.md`](./docs/github-conventions.md)
8. Legacy references:
   [`specs/001-aegisai-mvp-foundation/`](./specs/001-aegisai-mvp-foundation/) and
   [`spec 2.2.md`](./spec%202.2.md)

If implementation-ready docs and baseline docs diverge on scope or acceptance, stop and
resolve the mismatch before coding.

## Legacy Baseline

[`specs/001-aegisai-mvp-foundation/`](./specs/001-aegisai-mvp-foundation/) and
[`spec 2.2.md`](./spec%202.2.md) remain available as the legacy MVP baseline. They are
historical references, not the default implementation target while
`004-production-runtime-infrastructure` is active.
