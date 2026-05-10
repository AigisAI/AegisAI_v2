# AegisAI_v2

## Start Here

This repository is organized around the production scan architecture baseline for AegisAI.

- Agents should start with [`AGENTS.md`](./AGENTS.md).
- The canonical execution path lives in [`specs/002-production-scan-architecture/quickstart.md`](./specs/002-production-scan-architecture/quickstart.md).
- The production product baseline is `C:\Users\권태욱\Desktop\Security Scan SaaS Final Specification.docx`.
- The active implementation package lives in [`specs/002-production-scan-architecture/`](./specs/002-production-scan-architecture/).
- The legacy MVP baseline remains available in [`specs/001-aegisai-mvp-foundation/`](./specs/001-aegisai-mvp-foundation/) and [`spec 2.2.md`](./spec%202.2.md).

If you are starting development work, follow the agent path `AGENTS.md -> quickstart.md ->
feature package` instead of jumping directly to `tasks.md`.

## Completion

When validating the active production scan architecture milestone, use the completion flow in
[`specs/002-production-scan-architecture/quickstart.md`](./specs/002-production-scan-architecture/quickstart.md).
The legacy MVP hardening review remains available for tasks that explicitly touch the shipped
MVP baseline: [`specs/001-aegisai-mvp-foundation/hardening-review.md`](./specs/001-aegisai-mvp-foundation/hardening-review.md).

The final validation path is:

- `corepack pnpm lint`
- `corepack pnpm test`
- `corepack pnpm typecheck`
- `corepack pnpm build`

## GitHub Conventions

The repository follows the GitHub workflow convention documented in
[`docs/github-conventions.md`](./docs/github-conventions.md).

- Branches use `feat/<issue-number>-<short-feature>` and the matching `fix/`,
  `refactor/`, `release/`, and `hotfix/` variants
- Commit messages use `<type>: <description>`
- Issue titles and PR titles must match
- `dev` is the default integration branch and `main` remains the release-ready branch

Spec Kit feature docs now live in [`specs/002-production-scan-architecture/`](./specs/002-production-scan-architecture/),
so GitHub-style working branches may need `SPECIFY_FEATURE=002-production-scan-architecture`
when running Spec Kit helpers.

## CI

GitHub Actions runs the same baseline verification path used locally:

- `corepack pnpm lint`
- `corepack pnpm test`
- `corepack pnpm typecheck`
- `corepack pnpm build`

## CD

The current Oracle Cloud VPS CD path is retained for dev/demo deployments. It is not the
production topology for the production scan architecture, which is defined around separated
Control, Scan, AI, and Data/Security planes with stronger-than-pod scan isolation.

- Registry: `ghcr.io`
- Trigger: `main` push or manual `workflow_dispatch`
- Runtime: Docker Compose on the VPS
- Deploy path files: `deploy/oracle/docker-compose.infra.yml`, `deploy/oracle/docker-compose.app.yml`, `deploy/oracle/deploy.sh`, `deploy/oracle/bootstrap-infra.sh`, `deploy/oracle/install-alloy.sh`, `deploy/oracle/alloy/config.alloy`, and a server-managed `.env`
- Automated rollout scope: app stack only (`api`, `ai`, `web`)
- Manual bootstrap scope: infra stack (`postgres`, `redis`)
- Observability collection: Grafana Alloy on the Oracle VPS
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

The deploy job currently targets the `production` GitHub environment for compatibility with
existing workflow settings, but architecturally this path is dev/demo. Set the required secrets
before running CD. If any are blank or missing, the workflow fails early with a clear validation
error instead of reaching the SSH steps.

When configured, CD posts a high-signal success/failure notification to Microsoft Teams without blocking the deploy if the webhook itself fails.

Grafana Cloud replaces the previous idea of a VPS-hosted Grafana or Loki stack. Operators
install the Docker integration in Grafana Cloud, install Grafana Alloy on the Oracle VPS, and
use Grafana Cloud for logs, metrics, dashboards, and alert routing.

For first-time Oracle Cloud setup, follow the runbook in [`deploy/oracle/BOOTSTRAP.md`](./deploy/oracle/BOOTSTRAP.md) rather than reproducing the steps manually from memory.
