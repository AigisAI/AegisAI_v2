# AegisAI_v2

## Start Here

This repository is organized around an agent-first MVP baseline for AegisAI.

- Agents should start with [`AGENTS.md`](./AGENTS.md).
- The canonical execution path lives in [`specs/002-production-scan-architecture/quickstart.md`](./specs/002-production-scan-architecture/quickstart.md).
- The production product baseline is `C:\Users\권태욱\Desktop\Security Scan SaaS Final Specification.docx`.
- The active implementation package lives in [`specs/002-production-scan-architecture/`](./specs/002-production-scan-architecture/).
- The legacy MVP baseline remains available in [`specs/001-aegisai-mvp-foundation/`](./specs/001-aegisai-mvp-foundation/) and [`spec 2.2.md`](./spec%202.2.md).

If you are starting development work, follow the agent path `AGENTS.md -> quickstart.md ->
feature package` instead of jumping directly to `tasks.md`.

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
- Deploy path files: `deploy/oracle/docker-compose.prod.yml`, `deploy/oracle/deploy.sh`, `deploy/oracle/install-alloy.sh`, `deploy/oracle/alloy/config.alloy`, and a server-managed `.env`
- Application rollout: `api` and `web` containers on the Oracle VPS
- Observability collection: Grafana Alloy on the Oracle VPS
- Observability surface: Grafana Cloud dashboards, Explore, and alerting

Required GitHub secrets for dev/demo CD:

- `ORACLE_VPS_HOST`
- `ORACLE_VPS_USER`
- `ORACLE_VPS_SSH_PRIVATE_KEY`
- `ORACLE_VPS_KNOWN_HOSTS`
- `ORACLE_DEPLOY_PATH`
- `GHCR_USERNAME`
- `GHCR_READ_TOKEN`
- `TEAMS_WEBHOOK_URL`

The deploy job currently targets the `production` GitHub environment for compatibility with
existing workflow settings, but architecturally this path is dev/demo. Set these secrets
before running CD. If any are blank or missing, the workflow fails early with a clear
validation error instead of reaching the SSH steps.

Grafana Cloud replaces the previous idea of a VPS-hosted Grafana or Loki stack. Operators
install the Docker integration in Grafana Cloud, install Grafana Alloy on the Oracle VPS, and
use Grafana Cloud for logs, metrics, dashboards, and alert routing.

GitHub Actions still sends deploy-result notifications to Teams separately from Grafana Cloud
runtime alerts.

One-time VPS setup:

1. Install Docker Engine and Docker Compose plugin.
2. Create the deploy directory (for example `/opt/aegisai`).
3. Copy `deploy/oracle/.env.example` to `.env` on the VPS and fill in production values.
4. Create the Grafana Cloud stack and Docker integration.
5. Run `deploy/oracle/install-alloy.sh` from the deploy directory.
6. Open port `80` for the web container.

For the full Cloud-first operator flow, follow [`deploy/oracle/BOOTSTRAP.md`](./deploy/oracle/BOOTSTRAP.md).
