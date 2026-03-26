#!/bin/sh
set -eu

required_file='.env'
observability_file='docker-compose.observability.yml'

if [ ! -f "$required_file" ]; then
  echo "Missing required runtime file: $required_file in $(pwd)" >&2
  exit 1
fi

if [ ! -f "$observability_file" ]; then
  echo "Missing required compose file: $observability_file in $(pwd)" >&2
  exit 1
fi

docker compose -f docker-compose.observability.yml up -d

echo "Observability bootstrap complete."
docker compose -f docker-compose.observability.yml ps
