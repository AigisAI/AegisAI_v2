# Oracle Cloud Bootstrap Runbook

This runbook prepares a single Oracle Cloud VPS for the AegisAI production deploy while
using Grafana Cloud for dashboards, logs, metrics, and runtime alerting.

The deployment is intentionally split into two Compose projects:
- `aegisai-infra` for `postgres` and `redis`
- `aegisai-app` for `api` and `web`

Both projects share the external Docker network `aegisai-platform`.

## 1. Provision The Oracle VPS

Prepare one Ubuntu-based Oracle Cloud Compute instance with:
- SSH access enabled
- inbound port `22` open for deployment SSH
- inbound port `80` open for the web container

No Grafana UI port needs to be exposed publicly because dashboards and Explore live in
Grafana Cloud.

## 2. Install Docker Runtime On The VPS

Install Docker Engine and the Docker Compose plugin on the server, then verify:

```sh
docker --version
docker compose version
```

## 3. Create The Deploy Directory

Choose a deployment directory, for example `/opt/aegisai`:

```sh
mkdir -p /opt/aegisai
cd /opt/aegisai
```

The GitHub secret `ORACLE_DEPLOY_PATH` must match this directory.

## 4. Create The Grafana Cloud Stack

In Grafana Cloud:

1. Create or choose the production stack.
2. Open the Docker integration from Connections.
3. Copy the Loki logs endpoint and credentials.
4. Copy the Prometheus remote write endpoint and credentials.
5. Keep the stack name handy for `GRAFANA_CLOUD_INSTANCE_NAME`.

Grafana Alloy is Grafana's recommended collector for sending logs to Grafana Cloud, and the
Docker integration provides the collection model used by this repo.

## 5. Configure Microsoft Teams In Grafana Cloud

Create a Microsoft Teams workflow URL for the runtime alerts channel.

Then in Grafana Cloud:

1. Navigate to `Alerts & IRM -> Alerting -> Contact points`.
2. Add a `Microsoft Teams` contact point.
3. Paste the Teams workflow URL.
4. Use `Test` to confirm Grafana Cloud can deliver to Teams.

This Teams integration is for runtime and infrastructure alerts. GitHub Actions deploy-result
notifications remain a separate workflow-level path.

## 6. Copy Deploy Files To The VPS

Copy these files into the deploy directory:
- `docker-compose.infra.yml`
- `docker-compose.app.yml`
- `deploy.sh`
- `bootstrap-infra.sh`
- `install-alloy.sh`
- `alloy/config.alloy`
- `deploy/oracle/.env.example`

Create `.env` from `deploy/oracle/.env.example` and fill in production values.

Required runtime values include:
- `DATABASE_URL`
- `REDIS_URL`
- `APP_URL`
- `FRONTEND_URL`
- `SESSION_SECRET`
- `CSRF_SECRET`
- `TOKEN_ENCRYPTION_KEY`
- OAuth client ids and secrets
- `GRAFANA_CLOUD_LOGS_URL`
- `GRAFANA_CLOUD_LOGS_USERNAME`
- `GRAFANA_CLOUD_LOGS_PASSWORD`
- `GRAFANA_CLOUD_METRICS_URL`
- `GRAFANA_CLOUD_METRICS_USERNAME`
- `GRAFANA_CLOUD_METRICS_PASSWORD`
- `GRAFANA_CLOUD_INSTANCE_NAME`

## 7. Bootstrap Infra Once

Run the one-time infra bootstrap from the deploy directory:

```sh
sh ./bootstrap-infra.sh
```

Equivalent manual command:

```sh
docker compose -f docker-compose.infra.yml up -d
```

This creates the shared `postgres` and `redis` stack used by the app deployment.

Do not tear down the app stack with `--remove-orphans` against the same project directory unless
you intentionally want Compose to clean unrelated services. The repo-managed deploy script keeps
the app refresh to `docker compose -f docker-compose.app.yml up -d` so the `aegisai-infra` stack
stays intact.

## 8. Install And Start Grafana Alloy

Run the helper from the deploy directory:

```sh
sh ./install-alloy.sh
```

The helper installs Grafana Alloy as a systemd service, copies the repo-managed config to
`/etc/alloy/config.alloy`, and points the Alloy service at the deploy directory `.env` for
Grafana Cloud credentials.

The Docker integration metrics path requires Alloy to access Docker host resources, so the
helper also adds the `alloy` user to the `docker` group before restarting the service.

Useful verification commands:

```sh
sudo systemctl status alloy
sudo journalctl -u alloy -n 100 --no-pager
```

## 9. Configure GitHub Secrets

Set these repository secrets before triggering CD:
- `ORACLE_VPS_HOST`
- `ORACLE_VPS_USER`
- `ORACLE_VPS_SSH_PRIVATE_KEY`
- `ORACLE_VPS_KNOWN_HOSTS`
- `ORACLE_DEPLOY_PATH`
- `GHCR_USERNAME`
- `GHCR_READ_TOKEN`
- `TEAMS_WEBHOOK_URL`

`TEAMS_WEBHOOK_URL` is used by GitHub Actions to post deploy success or failure notifications.
It can be the same Teams channel as Grafana Cloud alerting, but the integration is configured
separately.

## 10. Trigger Deployment

The current workflow deploys on:
- `main` push
- manual `workflow_dispatch`

After bootstrap, trigger one deployment and confirm:
- `docker compose -f docker-compose.app.yml ps`
- `docker compose -f docker-compose.infra.yml ps`
- `docker compose -f docker-compose.app.yml config | grep '^name:'`
- `docker compose -f docker-compose.infra.yml config | grep '^name:'`
- the web container is reachable on port `80`
- Grafana Cloud Explore shows new Docker logs for `api` and `web`
- the Docker integration dashboards begin to populate
- Teams receives the deploy result if `TEAMS_WEBHOOK_URL` is configured

## 11. Validate In Grafana Cloud

Verify in Grafana Cloud:
- Docker logs arrive in Explore
- container metrics appear in the Docker integration dashboards
- a test alert reaches the Teams contact point

Recommended first alerts:
- log ingestion gap
- repeated API 5xx runtime errors
- container restart spikes

## 12. Ongoing Operation

Normal GitHub Actions deploys continue to update only the application stack. Grafana Alloy runs
independently on the VPS and keeps shipping data to Grafana Cloud between deploys.
