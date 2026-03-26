# Observability Stack With Teams, Loki, and Grafana Design

## Goal

Add a production-friendly observability baseline to the existing Oracle VPS deployment by
introducing a separate observability Docker Compose stack, Teams deployment/runtime alerts,
and the minimum operator documentation needed to bootstrap and use it safely.

## Scope

In scope:
- A dedicated Oracle observability compose stack
- Loki for centralized log storage
- Promtail for Docker log shipping
- Grafana with pre-provisioned Loki datasource
- GitHub Actions CD notifications to Teams
- Backend runtime error notifications to Teams
- Oracle bootstrap and README updates for the new stack
- Focused regression coverage for workflow and runtime wiring

Out of scope:
- Metrics/Prometheus collection
- Grafana dashboards beyond datasource provisioning
- TLS, domain routing, or public Grafana hardening
- Pager duty / incident escalation workflows
- Full structured application logging refactor

## Recommended Approach

Use a third Compose stack dedicated to observability, parallel to the existing split
`infra` and `app` stacks.

Why this approach:
- It fits the current Oracle single-VPS deployment without disturbing the app stack rollout.
- Observability can be bootstrapped once like infra, while normal CD remains focused on
  `api` and `web`.
- Grafana and Loki remain operational tools rather than release blockers.
- Teams notifications can be layered into deployment and runtime error handling with
  relatively small code changes.

## Deployment Shape

The production VPS will have three stack roles:

- `docker-compose.infra.yml`
  - `postgres`
  - `redis`
- `docker-compose.app.yml`
  - `api`
  - `web`
- `docker-compose.observability.yml`
  - `loki`
  - `promtail`
  - `grafana`

The observability stack is bootstrapped manually, similar to infra:
- `bootstrap-observability.sh` or
- `docker compose -f docker-compose.observability.yml up -d`

The regular CD workflow keeps deploying only the app stack, but it uploads the observability
files so the VPS always has the latest configuration.

## Loki / Promtail / Grafana Responsibilities

### Loki

- Stores container logs locally on the VPS
- Listens only inside the observability stack
- Does not expose a public port

### Promtail

- Reads Docker container logs from the host
- Discovers containers through the Docker socket
- Pushes parsed logs into Loki
- Adds useful labels such as container name and compose service

### Grafana

- Exposes a single operator-facing web UI on port `3001`
- Uses environment-provided admin credentials
- Auto-provisions Loki as the default datasource

This keeps the stack useful immediately without forcing dashboard authoring in the same issue.

## Teams Notifications

Teams will be used for high-signal alerts only.

### CD Alerts

The GitHub Actions CD workflow should send one Teams notification after each run when
`TEAMS_WEBHOOK_URL` is configured:
- green message for successful build/deploy
- red message for failed build/deploy

The Teams notification path must not fail the workflow if the webhook itself errors.

### Runtime Error Alerts

The backend should send Teams notifications only for 5xx/unhandled runtime errors captured by
`GlobalExceptionFilter`.

Payload should include:
- environment
- HTTP method
- request path
- status code
- error code
- message
- timestamp

It should avoid secrets, tokens, or raw request bodies.

If `TEAMS_WEBHOOK_URL` is not configured, notifications should become a no-op.

## Backend Wiring

Add a small observability module in the API:
- `ObservabilityModule`
- `TeamsNotifierService`

`GlobalExceptionFilter` should inject the notifier and fire a best-effort async alert for
5xx responses after logging locally.

No controller or route changes are needed.

## Configuration Changes

Add optional environment/config support for:
- `TEAMS_WEBHOOK_URL`
- `GRAFANA_ADMIN_USER`
- `GRAFANA_ADMIN_PASSWORD`

Runtime environment examples should document them for:
- workspace root `.env.example`
- `apps/api/.env.example`
- `deploy/oracle/.env.example`

GitHub Actions documentation should also mention `TEAMS_WEBHOOK_URL` as an optional production
secret for deploy notifications.

## Testing Strategy

Add or update tests for:
- CD workflow structure and observability file upload / Teams notify steps
- Presence and content of observability compose/config files
- `TeamsNotifierService` webhook/no-op behavior
- `GlobalExceptionFilter` integration with runtime alerts for 5xx only
- Config typing for new optional observability keys

The full repository validation path remains:
- `corepack pnpm lint`
- `corepack pnpm test`
- `corepack pnpm typecheck`
- `corepack pnpm build`

## Risks and Guardrails

- Do not make Teams webhook configuration mandatory for local development or production deploy.
- Do not expose Loki publicly.
- Do not let Grafana provisioning become a large dashboard-design project.
- Do not block successful deploys because Teams notification delivery failed.
- Keep the observability stack isolated from the main app rollout path.
