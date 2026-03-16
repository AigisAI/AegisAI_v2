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

if [ ! -f .env ]; then
  echo "Missing runtime .env file in $(pwd)" >&2
  exit 1
fi

export GHCR_OWNER
export IMAGE_TAG

echo "$GHCR_READ_TOKEN" | docker login ghcr.io -u "$GHCR_USERNAME" --password-stdin
docker compose -f docker-compose.prod.yml pull
docker compose -f docker-compose.prod.yml up -d --remove-orphans
docker image prune -f
