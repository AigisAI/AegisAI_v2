#!/bin/sh
set -eu

required_file='.env'
infra_file='docker-compose.infra.yml'

if [ ! -f "$required_file" ]; then
  echo "Missing required runtime file: $required_file in $(pwd)" >&2
  exit 1
fi

if [ ! -f "$infra_file" ]; then
  echo "Missing required compose file: $infra_file in $(pwd)" >&2
  exit 1
fi

docker compose -f docker-compose.infra.yml up -d

echo "Infra bootstrap complete."
docker compose -f docker-compose.infra.yml ps
