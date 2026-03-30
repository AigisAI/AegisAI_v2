# Oracle Deploy DNS And Orphan Stabilization Design

## Problem

Production recovery exposed two deployment-time risks in the Oracle split-stack setup.

1. Docker service names such as `redis` and `postgres` were being resolved through the Oracle
   VCN search domain first, causing lookups like `redis.vcn...` to fail with `NXDOMAIN`.
2. `deploy.sh` refreshed the app stack with `--remove-orphans` while the app and infra stacks
   shared the same implicit Compose project name. That allowed app-stack operations to remove
   `postgres` and `redis`.

## Scope

This hotfix only stabilizes the Oracle deployment path.

In scope:
- app/infra Compose project separation
- app service DNS lookup hardening
- deploy script safety improvement
- deployment regression coverage
- bootstrap documentation updates

Out of scope:
- application feature changes
- non-Oracle deployment targets
- broader Compose refactoring beyond the production deploy path

## Solution

### 1. Split Compose projects explicitly

Add top-level names:
- `aegisai-app` to `docker-compose.app.yml`
- `aegisai-infra` to `docker-compose.infra.yml`

Both files continue to share the same external network `aegisai-platform`.

This isolates orphan detection and prevents app-stack actions from targeting infra containers.

### 2. Force Docker service-name resolution to win

Add:

```yml
dns_opt:
  - ndots:0
```

to the `api` and `web` services in `docker-compose.app.yml`.

This prevents single-label Docker service names from being expanded through the Oracle search
domain before Docker DNS can resolve them.

### 3. Remove risky orphan cleanup from deploy.sh

Change app refresh from:

```sh
docker compose -f docker-compose.app.yml up -d --remove-orphans
```

to:

```sh
docker compose -f docker-compose.app.yml up -d
```

The split project names already keep app/infra separate, so aggressive orphan cleanup is not
needed in the normal deploy path.

## Verification

Regression coverage should assert:
- `aegisai-app` and `aegisai-infra` Compose project names exist
- `dns_opt: [ndots:0]` is present on app services
- `deploy.sh` no longer uses `--remove-orphans`
- bootstrap docs mention the two-project layout
