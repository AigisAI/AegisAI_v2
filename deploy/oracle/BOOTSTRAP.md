# Oracle Cloud CD Bootstrap

This runbook prepares a single Oracle Cloud VPS so the existing GitHub Actions CD workflow can deploy the `api` and `web` app stack safely.

## What Is Manual vs Automated

Manual one-time work:
- Oracle Cloud VPS creation
- network/security rule setup
- Docker Engine and Docker Compose plugin installation
- runtime `.env` creation on the server
- first infra bootstrap for `postgres` and `redis`
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
- `deploy.sh`

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

## 6. Configure GitHub Secrets

Set these repository secrets before triggering CD:
- `ORACLE_VPS_HOST`
- `ORACLE_VPS_USER`
- `ORACLE_VPS_SSH_PRIVATE_KEY`
- `ORACLE_DEPLOY_PATH`
- `GHCR_USERNAME`
- `GHCR_READ_TOKEN`

The CD workflow uses `ORACLE_VPS_HOST` and `ORACLE_VPS_USER` for SSH, and `GHCR_READ_TOKEN` to pull private GHCR images on the VPS.

## 7. Trigger Deployment

The current workflow deploys on:
- `main` push
- manual `workflow_dispatch`

After bootstrap, trigger one deployment and confirm:
- `docker compose -f docker-compose.app.yml ps`
- `docker compose -f docker-compose.infra.yml ps`
- the web container is reachable on port `80`

## 8. Smoke Checks

Verify on the VPS:

```sh
docker compose -f docker-compose.infra.yml ps
docker compose -f docker-compose.app.yml ps
docker logs $(docker ps --filter name=api --format '{{.ID}}' | head -n 1)
```

Verify externally:
- the web root responds on `http://<server-ip>`
- the API container is running and attached to the shared network

## 9. Known Follow-Up Work

Future issues should cover:
- domain and HTTPS/TLS
- backup and monitoring setup
- production hardening for firewall, fail2ban, and log shipping
- managed Postgres/Redis migration if single-VPS limits become a problem
