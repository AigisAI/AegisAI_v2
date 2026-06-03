# AegisAI

AegisAI is a hosted security scan SaaS for GitHub Cloud and GitLab Cloud repositories.
It is being re-baselined around a production architecture that treats customer
repositories as untrusted input, keeps scanner output deterministic-first, and uses AI
only as advisory metadata over reduced evidence.

## What This Is

AegisAI connects to customer repositories through GitHub App installations or GitLab
Cloud integrations, plans security scans, normalizes scanner results, applies policy
decisions, and exposes results through dashboards and PR/MR comments.

The product direction is defined by
`C:\Users\권태욱\Desktop\Security Scan SaaS Final Specification.docx`. That DOCX is the
highest-priority product, platform, security, and operations baseline for the current
production architecture work.

## Current Baseline

The active implementation target is
[`specs/002-production-scan-architecture/`](./specs/002-production-scan-architecture/).
Start from its
[`quickstart.md`](./specs/002-production-scan-architecture/quickstart.md), not from
`tasks.md` directly.

Current milestone scope:

- Repository entrypoints aligned to `002-production-scan-architecture`
- Shared production scan architecture contracts in `packages/shared`
- Tenant-attributed Prisma skeleton entities
- Control Plane API skeletons for integrations, repository bindings, and scan requests
- Token Broker and audit skeletons that avoid token persistence
- Mock Scan Plane pipeline skeleton for deterministic scanner metadata, normalized
  findings, and short-lived evidence metadata

Still deferred:

- Real Opengrep, Trivy, and Syft execution
- MicroVM, Kubernetes, or equivalent scan sandbox provisioning
- Runtime policy engine implementation
- Evidence object-storage TTL enforcement
- Private model inference
- Auto-fix PR/MR creation
- Customer code execution, package installation, or repository builds

The next active slice is Java-first scan planning metadata: Java repositories receive the
first detailed SAST profile, while non-Java repositories remain on common scanner coverage
until separate language profiles are specified.

## Architecture At A Glance

Production is modeled as four explicit trust boundaries:

- **Control Plane**: tenant lifecycle, auth, SCM integration registry, webhook intake,
  scan planning, token broker, policy decisions, comment dispatch, and dashboard APIs
- **Scan Plane**: scan-scoped repository fetch, scanner adapter execution, normalization,
  correlation, evidence pack construction, and scanner-run lineage
- **AI Plane**: advisory-only triage, explanation, prioritization, and remediation planning
  over reduced, redacted, policy-classified evidence
- **Data and Security Plane**: tenant-aware persistence, object storage with TTL, audit
  logs, KMS, secrets manager, queues, and service identity boundaries

The production topology assumes separated Control, Scan, AI, and Data/Security planes on
Kubernetes or equivalent isolation. The current Oracle VPS path is dev/demo only.

## Non-Negotiable Guardrails

- Do not add direct source upload.
- Do not execute customer code.
- Do not install packages or build customer repositories.
- Keep user authentication separate from SCM integration credentials.
- Model GitHub Cloud repository access through GitHub App installation flows.
- Model GitLab Cloud repository access through scoped integration and webhook flows.
- Keep repo-read, comment-write, and integration-admin authority separated.
- Do not give the Scan Plane comment-write or integration-admin credentials.
- Do not send full repositories, raw unbounded scanner output, or SCM credentials to AI.
- Do not let AI create authoritative findings, override scanner output, or override policy.
- Keep shared API contracts in `packages/shared`.
- Preserve sessions, CSRF protection, throttling, health checks, and critical integration
  tests for user-facing API work.

## Repository Map

```text
apps/api/       NestJS API, Prisma schema, Control Plane skeletons, e2e tests
apps/web/       React/Vite frontend
packages/shared/ Shared TypeScript contracts and helpers
specs/002-production-scan-architecture/
                Active production architecture package
specs/001-aegisai-mvp-foundation/
                Legacy MVP package retained for historical reference
deploy/oracle/  Oracle VPS dev/demo deployment assets
docs/           Workflow conventions, reports, and implementation support docs
test/           Repository-level test support such as GitHub Actions workflow tests
```

## Start Here

This repository is organized around the production scan architecture baseline for AegisAI.
For development or agent work, use this path:

```text
AGENTS.md -> specs/002-production-scan-architecture/quickstart.md -> active feature docs
```

[`AGENTS.md`](./AGENTS.md) defines repository entry rules and guardrails.
[`quickstart.md`](./specs/002-production-scan-architecture/quickstart.md) defines the
canonical read order, execution flow, and completion validation path.

When working on a GitHub-style branch, set the active Spec Kit feature if helper scripts
need it:

```powershell
$env:SPECIFY_FEATURE = "002-production-scan-architecture"
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

Run both API and web development servers:

```powershell
corepack pnpm dev
```

Run one app at a time:

```powershell
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

The quickstart completion gate uses this validation path:

```powershell
corepack pnpm lint
corepack pnpm test
corepack pnpm typecheck
corepack pnpm build
corepack pnpm --filter @aegisai/api prisma:validate
```

Before claiming the production architecture milestone complete, also confirm:

- `AGENTS.md`, `README.md`, and
  [`docs/github-conventions.md`](./docs/github-conventions.md) point to
  `002-production-scan-architecture`
- Oracle VPS wording remains dev/demo only
- [`specs/001-aegisai-mvp-foundation/`](./specs/001-aegisai-mvp-foundation/) remains
  available as the legacy MVP baseline

The legacy MVP hardening review remains available for tasks that explicitly touch the
shipped MVP baseline:
[`specs/001-aegisai-mvp-foundation/hardening-review.md`](./specs/001-aegisai-mvp-foundation/hardening-review.md).

## Deployment Position

The Oracle Cloud VPS deployment path is retained for dev/demo operation and compatibility
with existing workflow settings. It is not the production topology for the production scan
architecture.

Dev/demo CD summary:

- Registry: `ghcr.io`
- Trigger: `main` push or manual `workflow_dispatch`
- Runtime: Docker Compose on the Oracle VPS
- Deploy path files: `deploy/oracle/docker-compose.infra.yml`,
  `deploy/oracle/docker-compose.app.yml`, `deploy/oracle/deploy.sh`,
  `deploy/oracle/bootstrap-infra.sh`, `deploy/oracle/install-alloy.sh`,
  `deploy/oracle/alloy/config.alloy`, and a server-managed `.env`
- Automated rollout scope: app stack only (`api`, `web`)
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
2. [`specs/002-production-scan-architecture/quickstart.md`](./specs/002-production-scan-architecture/quickstart.md)
3. `C:\Users\권태욱\Desktop\Security Scan SaaS Final Specification.docx`
4. [`specs/002-production-scan-architecture/`](./specs/002-production-scan-architecture/)
5. [`docs/github-conventions.md`](./docs/github-conventions.md)
6. Legacy references:
   [`specs/001-aegisai-mvp-foundation/`](./specs/001-aegisai-mvp-foundation/) and
   [`spec 2.2.md`](./spec%202.2.md)

If implementation-ready docs and baseline docs diverge on scope or acceptance, stop and
resolve the mismatch before coding.

## Legacy Baseline

[`specs/001-aegisai-mvp-foundation/`](./specs/001-aegisai-mvp-foundation/) and
[`spec 2.2.md`](./spec%202.2.md) remain available as the legacy MVP baseline. They are
historical references, not the default implementation target while
`002-production-scan-architecture` is active.
