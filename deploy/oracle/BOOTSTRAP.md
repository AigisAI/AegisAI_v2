# Oracle Cloud CD Bootstrap

This runbook prepares a single Oracle Cloud VPS so the existing GitHub Actions CD workflow can deploy the `api` and `web` app stack safely, while keeping Loki/Grafana-based observability on the same host.

## What Is Manual vs Automated

Manual one-time work:
- Oracle Cloud VPS creation
- network/security rule setup
- Docker Engine and Docker Compose plugin installation
- runtime `.env` creation on the server
- first infra bootstrap for `postgres` and `redis`
- first observability bootstrap for `loki`, `promtail`, and `grafana`
- GitHub repository secret entry

Automated after bootstrap:
- image build and push to GHCR
- upload of deployment files from GitHub Actions
- app rollout for `api` and `web`

## 1. Oracle Cloud VPS Prerequisites

Prepare one Ubuntu-based Oracle Cloud Compute instance with:
- SSH access enabled
- inbound port `22` open for deployment SSH
- inbound port `80` open for the web container
- inbound port `3001` open only if operators will access Grafana directly over the public IP
- inbound port `443` open only if you add TLS later

This issue does not cover domain, HTTPS, or reverse proxy certificate setup.

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

## 4. Prepare Runtime Files On The VPS

Copy these files into the deploy directory:
- `docker-compose.infra.yml`
- `docker-compose.app.yml`
- `docker-compose.observability.yml`
- `deploy.sh`
- `bootstrap-infra.sh`
- `bootstrap-observability.sh`
- `loki-config.yml`
- `promtail-config.yml`
- `grafana/provisioning/datasources/loki.yml`

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
- `GRAFANA_ADMIN_USER`
- `GRAFANA_ADMIN_PASSWORD`

Optional runtime value:
- `TEAMS_WEBHOOK_URL`

## 5. Bootstrap Infra Once

Run the one-time infra bootstrap from the deploy directory:

```sh
sh ./bootstrap-infra.sh
```

Equivalent manual command:

```sh
docker compose -f docker-compose.infra.yml up -d
```

This creates the shared `postgres` and `redis` stack used by the app deployment.

## 6. Bootstrap Observability Once

Run the one-time observability bootstrap from the deploy directory:

```sh
sh ./bootstrap-observability.sh
```

Equivalent manual command:

```sh
docker compose -f docker-compose.observability.yml up -d
```

This brings up:
- `loki` for container log storage
- `promtail` for Docker log shipping
- `grafana` on port `3001`

## 7. Configure GitHub Secrets

Set these repository secrets before triggering CD:
- `ORACLE_VPS_HOST`
- `ORACLE_VPS_USER`
- `ORACLE_VPS_SSH_PRIVATE_KEY`
- `ORACLE_VPS_KNOWN_HOSTS`
- `ORACLE_DEPLOY_PATH`
- `GHCR_USERNAME`
- `GHCR_READ_TOKEN`

Optional production secret:
- `TEAMS_WEBHOOK_URL`

The CD workflow uses `ORACLE_VPS_HOST` and `ORACLE_VPS_USER` for SSH, and `GHCR_READ_TOKEN` to pull private GHCR images on the VPS.

## 8. Trigger Deployment

The current workflow deploys on:
- `main` push
- manual `workflow_dispatch`

After bootstrap, trigger one deployment and confirm:
- `docker compose -f docker-compose.app.yml ps`
- `docker compose -f docker-compose.infra.yml ps`
- `docker compose -f docker-compose.observability.yml ps`
- the web container is reachable on port `80`
- Grafana is reachable on `http://<server-ip>:3001` when that port is opened
- Teams receives the deploy result if `TEAMS_WEBHOOK_URL` is configured

## 9. Smoke Checks

Verify on the VPS:

```sh
docker compose -f docker-compose.infra.yml ps
docker compose -f docker-compose.app.yml ps
docker compose -f docker-compose.observability.yml ps
docker logs $(docker ps --filter name=api --format '{{.ID}}' | head -n 1)
```

Verify externally:
- the web root responds on `http://<server-ip>`
- the API container is running and attached to the shared network
- Grafana responds on `http://<server-ip>:3001` if public access is enabled

## 10. Known Follow-Up Work

Future issues should cover:
- domain and HTTPS/TLS
- backup, metrics, and alerting beyond log collection
- production hardening for firewall, fail2ban, and log shipping
- managed Postgres/Redis migration if single-VPS limits become a problem
