# AegisAI

**Hosted security scanning for GitHub Cloud and GitLab Cloud repositories.**

AegisAI is a production-oriented security scan SaaS that treats customer repositories as
untrusted input, keeps scanner output deterministic-first, preserves advisory-only AI,
and separates Control, Scan, AI, and Data/Security planes.

| Signal | Current Position |
| --- | --- |
| Active milestone | [`005-production-deployment-operations`](./specs/005-production-deployment-operations/) |
| Canonical start | [`AGENTS.md`](./AGENTS.md) -> [`quickstart.md`](./specs/005-production-deployment-operations/quickstart.md) |
| Product baseline | Security Scan SaaS final specification (private product baseline) |
| Runtime posture | Production Kubernetes and microVM rollout guardrails; Oracle VPS remains dev/demo only |
| Validation source | [`quickstart.md`](./specs/005-production-deployment-operations/quickstart.md) and [`.github/workflows/ci.yml`](./.github/workflows/ci.yml) |

## Start Here

For development or agent work, follow the canonical entry path before touching code:

```text
AGENTS.md -> quickstart.md -> active feature docs
```

Expanded current path:

```text
AGENTS.md -> specs/005-production-deployment-operations/quickstart.md -> active feature docs
```

When using Spec Kit helpers from a GitHub-style branch:

```powershell
$env:SPECIFY_FEATURE = "005-production-deployment-operations"
```

## Product Shape

AegisAI connects to customer repositories through GitHub App installations or GitLab
Cloud integrations, plans security scans, normalizes scanner results, applies policy
decisions, and exposes results through dashboards and PR/MR comments.

| Product Principle | Meaning |
| --- | --- |
| Deterministic-first | Scanner and policy outputs decide findings, blocking, and comment publication. |
| AI-second | AI assists triage, explanation, prioritization, and remediation planning only. |
| Untrusted-by-default | Repositories, scanner output, SCM payloads, paths, logs, and evidence are hostile input. |
| Ephemeral-by-default | Full repositories and raw artifacts are short-lived; durable data is normalized and scoped. |
| Least privilege | User auth, repo-read, comment-write, and integration-admin authority stay separated. |

## Current Baseline

The active implementation target is
[`specs/005-production-deployment-operations/`](./specs/005-production-deployment-operations/).
Start from its
[`quickstart.md`](./specs/005-production-deployment-operations/quickstart.md), not from
`tasks.md` directly.

| Area | Status |
| --- | --- |
| Deployment operations | Active 005 milestone |
| Production cluster provisioning | Provider-neutral contract and credential-boundary guardrails in scope |
| Provider microVM rollout | Provider-neutral rollout contract and scanner isolation guardrails in scope |
| Runtime infrastructure | Completed baseline in [`004-production-runtime-infrastructure`](./specs/004-production-runtime-infrastructure/) |
| Production AI inference | Completed baseline in [`003-production-ai-inference-runtime`](./specs/003-production-ai-inference-runtime/) |
| Production scan architecture | Completed baseline in [`002-production-scan-architecture`](./specs/002-production-scan-architecture/) |
| Legacy MVP | Historical baseline in [`001-aegisai-mvp-foundation`](./specs/001-aegisai-mvp-foundation/) and [`spec 2.2.md`](./spec%202.2.md) |

The 005 package moves live production Kubernetes cluster provisioning and
provider-specific microVM platform rollout into explicit operations planning.
Actual provider execution and production credentials remain deferred until an
operator-approved rollout task. Production cluster credentials must not become
local development defaults.

## Architecture

Production is modeled as four explicit trust boundaries.

| Plane | Responsibility | Hard Boundary |
| --- | --- | --- |
| Control Plane | Tenant lifecycle, auth, SCM registry, webhook intake, scan planning, token broker, policy decisions, comment dispatch, dashboard APIs | Does not directly process full repository content |
| Scan Plane | Repository fetch, scanner adapters, normalization, correlation, evidence packs, scanner-run lineage, sandbox provisioning | No comment-write or integration-admin authority |
| AI Plane | Advisory triage, explanation, prioritization, remediation planning over reduced evidence | No SCM credentials, full repositories, source archives, or raw scanner payloads |
| Data/Security Plane | Tenant-aware persistence, TTL object storage, audit logs, KMS, secrets, queues, service identity | Tenant attribution, retention, auditability, and least privilege are mandatory |

Production readiness is defined around Kubernetes-compatible Control, Scan, AI, and
Data/Security plane boundaries with stronger-than-pod scan isolation. Oracle VPS and
Docker Compose are retained for dev/demo operation only.

## Guardrails

| Category | Non-Negotiables |
| --- | --- |
| Source handling | No direct source upload. No customer code execution. No package install, repository build, or dynamic test execution. |
| SCM authority | User authentication stays separate from SCM credentials. GitHub Cloud uses GitHub App installation flows. GitLab Cloud uses scoped integration and webhook flows. |
| Credential boundaries | repo-read, comment-write, and integration-admin authority remain separated. Scan Plane never receives comment-write or integration-admin credentials. |
| AI boundary | AI never receives full repositories, raw unbounded scanner output, source archives, or SCM credentials. AI never creates authoritative findings or overrides policy. |
| Platform controls | Kubernetes AI Plane deployment and scanner sandbox provisioning must preserve separated Control, Scan, AI, and Data/Security planes. |
| Shared contracts | Shared API contracts belong in `packages/shared`. Sessions, CSRF protection, throttling, health checks, and critical integration tests remain required. |

## Repository Map

| Path | Purpose |
| --- | --- |
| [`apps/api/`](./apps/api/) | NestJS API, Prisma schema, Control Plane/API runtime, e2e tests |
| [`apps/ai/`](./apps/ai/) | AI Plane service runtime and model gateway boundaries |
| [`apps/web/`](./apps/web/) | React/Vite frontend |
| [`packages/shared/`](./packages/shared/) | Shared TypeScript contracts and helpers |
| [`specs/005-production-deployment-operations/`](./specs/005-production-deployment-operations/) | Active production deployment operations package |
| [`specs/004-production-runtime-infrastructure/`](./specs/004-production-runtime-infrastructure/) | Completed production runtime infrastructure baseline |
| [`specs/003-production-ai-inference-runtime/`](./specs/003-production-ai-inference-runtime/) | Completed production AI inference baseline |
| [`specs/002-production-scan-architecture/`](./specs/002-production-scan-architecture/) | Completed production scan architecture baseline |
| [`specs/001-aegisai-mvp-foundation/`](./specs/001-aegisai-mvp-foundation/) | Legacy MVP package retained for historical reference |
| [`deploy/oracle/`](./deploy/oracle/) | Oracle VPS dev/demo deployment assets |
| [`docs/`](./docs/) | Workflow conventions, reports, and implementation support docs |
| [`test/`](./test/) | Repository-level test support such as GitHub Actions workflow tests |

## Local Development

Requirements:

| Requirement | Version / Note |
| --- | --- |
| Node.js | `>=20.0.0 <23.0.0` |
| Package manager | Corepack-enabled pnpm workspace, currently `pnpm@10.0.0` |
| Runtime services | PostgreSQL and Redis when exercising paths that need them |

Install dependencies:

```powershell
corepack enable
corepack pnpm install
```

Run development servers:

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

Environment examples:

| File | Use |
| --- | --- |
| [`.env.example`](./.env.example) | Root application defaults |
| [`apps/web/.env.example`](./apps/web/.env.example) | Web runtime defaults |
| [`deploy/oracle/.env.example`](./deploy/oracle/.env.example) | Oracle VPS dev/demo deployment defaults |

## Validation

Use the completion flow and command list in
[`specs/005-production-deployment-operations/quickstart.md`](./specs/005-production-deployment-operations/quickstart.md).
GitHub Actions runs the authoritative CI steps in
[`.github/workflows/ci.yml`](./.github/workflows/ci.yml).

Before claiming the 005 milestone complete, confirm:

| Check | Expected State |
| --- | --- |
| Entrypoints | `AGENTS.md`, `README.md`, and [`docs/github-conventions.md`](./docs/github-conventions.md) point to `005-production-deployment-operations` |
| Completed baselines | `004-production-runtime-infrastructure`, `003-production-ai-inference-runtime`, and `002-production-scan-architecture` remain available |
| Legacy baseline | `001-aegisai-mvp-foundation` and `spec 2.2.md` remain available as historical references |
| Deployment wording | Oracle VPS stays dev/demo only |
| Credential boundary | Provider credentials are not introduced as local development defaults |
| Runtime boundary | Production Kubernetes and microVM rollout preserve separated plane boundaries |

The legacy MVP hardening review remains available only for tasks that explicitly touch the
shipped MVP baseline:
[`specs/001-aegisai-mvp-foundation/hardening-review.md`](./specs/001-aegisai-mvp-foundation/hardening-review.md).

## Deployment Position

Oracle Cloud VPS deployment is retained for dev/demo operation and compatibility with
existing workflow settings. It is not the production topology for the production runtime
infrastructure architecture.

| Dev/Demo CD Item | Current Setting |
| --- | --- |
| Registry | `ghcr.io` |
| Trigger | `main` push or manual `workflow_dispatch` |
| Runtime | Docker Compose on Oracle VPS |
| Automated rollout | app stack only: `api`, `ai`, `web` |
| Manual bootstrap | infra stack: `postgres`, `redis` |
| Observability collector | Grafana Alloy on Oracle VPS |
| Observability surface | Grafana Cloud dashboards, Explore, and alerting |
| Runbook | [`deploy/oracle/BOOTSTRAP.md`](./deploy/oracle/BOOTSTRAP.md) |

Deploy path files:

```text
deploy/oracle/docker-compose.infra.yml
deploy/oracle/docker-compose.app.yml
deploy/oracle/deploy.sh
deploy/oracle/bootstrap-infra.sh
deploy/oracle/install-alloy.sh
deploy/oracle/alloy/config.alloy
```

Required GitHub secrets:

| Secret | Purpose |
| --- | --- |
| `ORACLE_VPS_HOST` | SSH target host |
| `ORACLE_VPS_USER` | SSH deploy user |
| `ORACLE_VPS_SSH_PRIVATE_KEY` | SSH authentication |
| `ORACLE_VPS_KNOWN_HOSTS` | Strict host verification |
| `ORACLE_DEPLOY_PATH` | Remote deploy directory |
| `GHCR_USERNAME` | GHCR login username |
| `GHCR_READ_TOKEN` | GHCR read token |

Optional notification secret:

| Secret | Purpose |
| --- | --- |
| `TEAMS_WEBHOOK_URL` | High-signal deploy result notification |

The deploy job currently targets the `production` GitHub environment for compatibility
with existing workflow settings, but architecturally this path is dev/demo. Missing
required secrets fail early before SSH steps. Teams notification failures do not block the
deploy.

## GitHub Workflow

The repository follows [`docs/github-conventions.md`](./docs/github-conventions.md).

| Topic | Convention |
| --- | --- |
| Integration branch | `dev` |
| Release-ready branch | `main` |
| Feature branches | `feat/<issue-number>-<short-feature>` |
| Other branch prefixes | `fix/`, `refactor/`, `release/`, `hotfix/` with the same issue-number pattern |
| Commit messages | `<type>: <description>` |
| Issue and PR titles | Should match |

## Documentation Precedence

When documents disagree, resolve intent in this order:

1. [`AGENTS.md`](./AGENTS.md)
2. [`specs/005-production-deployment-operations/quickstart.md`](./specs/005-production-deployment-operations/quickstart.md)
3. Security Scan SaaS final specification (private product baseline)
4. [`specs/005-production-deployment-operations/`](./specs/005-production-deployment-operations/)
5. [`specs/004-production-runtime-infrastructure/`](./specs/004-production-runtime-infrastructure/)
6. [`specs/003-production-ai-inference-runtime/`](./specs/003-production-ai-inference-runtime/)
7. [`specs/002-production-scan-architecture/`](./specs/002-production-scan-architecture/)
8. [`docs/github-conventions.md`](./docs/github-conventions.md)
9. Legacy references:
   [`specs/001-aegisai-mvp-foundation/`](./specs/001-aegisai-mvp-foundation/) and
   [`spec 2.2.md`](./spec%202.2.md)

If implementation-ready docs and baseline docs diverge on scope or acceptance, stop and
resolve the mismatch before coding.
