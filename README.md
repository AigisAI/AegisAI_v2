# AegisAI_v2

## Start Here

This repository is organized around an agent-first MVP baseline for AegisAI.

- Agents should start with [`AGENTS.md`](./AGENTS.md).
- The canonical execution path lives in [`specs/001-aegisai-mvp-foundation/quickstart.md`](./specs/001-aegisai-mvp-foundation/quickstart.md).
- The background product baseline lives in [`spec 2.2.md`](./spec%202.2.md).
- The active implementation package lives in [`specs/001-aegisai-mvp-foundation/`](./specs/001-aegisai-mvp-foundation/).

If you are starting development work, follow the agent path `AGENTS.md -> quickstart.md ->
feature package` instead of jumping directly to `tasks.md`.

## MVP Completion

When validating the shipped MVP baseline, use the completion flow in
[`specs/001-aegisai-mvp-foundation/quickstart.md`](./specs/001-aegisai-mvp-foundation/quickstart.md)
and the hardening checkpoints in
[`specs/001-aegisai-mvp-foundation/hardening-review.md`](./specs/001-aegisai-mvp-foundation/hardening-review.md).

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

Spec Kit feature docs still live in [`specs/001-aegisai-mvp-foundation/`](./specs/001-aegisai-mvp-foundation/),
so GitHub-style working branches may still need `SPECIFY_FEATURE` when running Spec Kit
helpers.

## CI

GitHub Actions runs the same baseline verification path used locally:

- `corepack pnpm lint`
- `corepack pnpm test`
- `corepack pnpm typecheck`
- `corepack pnpm build`

## CD

Production CD targets a single Oracle Cloud VPS.

- Registry: `ghcr.io`
- Trigger: `main` push or manual `workflow_dispatch`
- Runtime: Docker Compose on the VPS
- Deploy path files: `deploy/oracle/docker-compose.infra.yml`, `deploy/oracle/docker-compose.app.yml`, `deploy/oracle/deploy.sh`, `deploy/oracle/bootstrap-infra.sh`, `deploy/oracle/install-alloy.sh`, `deploy/oracle/alloy/config.alloy`, and a server-managed `.env`
- Automated rollout scope: app stack only (`api`, `web`)
- Manual bootstrap scope: infra stack (`postgres`, `redis`)
- Observability collection: Grafana Alloy on the Oracle VPS
- Observability surface: Grafana Cloud dashboards, Explore, and alerting
- Detailed runbook: [`deploy/oracle/BOOTSTRAP.md`](./deploy/oracle/BOOTSTRAP.md)

Required GitHub secrets for CD:

- `ORACLE_VPS_HOST`
- `ORACLE_VPS_USER`
- `ORACLE_VPS_SSH_PRIVATE_KEY`
- `ORACLE_VPS_KNOWN_HOSTS`
- `ORACLE_DEPLOY_PATH`
- `GHCR_USERNAME`
- `GHCR_READ_TOKEN`

The deploy job targets the `production` GitHub environment, so set these as available secrets before running CD. If any are blank or missing, the workflow now fails early with a clear validation error instead of reaching the SSH steps.

Optional production secret:

- `TEAMS_WEBHOOK_URL`

When configured, CD posts a high-signal success/failure notification to Microsoft Teams without blocking the deploy if the webhook itself fails.

Grafana Cloud replaces the previous idea of a VPS-hosted Grafana or Loki stack. Operators
install the Docker integration in Grafana Cloud, install Grafana Alloy on the Oracle VPS, and
use Grafana Cloud for logs, metrics, dashboards, and alert routing.

For first-time Oracle Cloud setup, follow the runbook in [`deploy/oracle/BOOTSTRAP.md`](./deploy/oracle/BOOTSTRAP.md) rather than reproducing the steps manually from memory.
