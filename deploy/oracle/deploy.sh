#!/bin/sh
set -eu

required_vars="GHCR_USERNAME GHCR_READ_TOKEN GHCR_OWNER IMAGE_TAG"
for var in $required_vars; do
  eval "value=\${$var:-}"
  if [ -z "$value" ]; then
    echo "Missing required environment variable: $var" >&2
    exit 1
  fi
done

for required_file in .env docker-compose.infra.yml docker-compose.app.yml; do
  if [ ! -f "$required_file" ]; then
    echo "Missing required deployment file: $required_file in $(pwd)" >&2
    exit 1
  fi
done

export GHCR_OWNER
export IMAGE_TAG

echo "$GHCR_READ_TOKEN" | docker login ghcr.io -u "$GHCR_USERNAME" --password-stdin
docker compose -f docker-compose.app.yml pull
docker compose -f docker-compose.app.yml up -d --remove-orphans
docker image prune -f
