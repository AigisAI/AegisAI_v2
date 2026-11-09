#!/bin/sh
set -eu
root=/opt/aegisai
test -f "$root/shared/root-encryption.resume"
release=$(cat "$root/shared/candidate-release")
case "$release" in ec2-runtime-[0-9]*) ;; *) exit 2 ;; esac
case "$release" in *[!a-zA-Z0-9-]*) exit 2 ;; esac
export RELEASE_ID="$release" RUNTIME_ENV_FILE="$root/shared/runtime-public.env"
set -a
. "$RUNTIME_ENV_FILE"
set +a
cd "$root/releases/$release"
if [ -f "$root/shared/web-release.override.yaml" ]; then
  docker compose -f deploy/aws-ec2/compose.yaml -f "$root/shared/web-release.override.yaml" up -d --wait --wait-timeout 180
else
  docker compose -f deploy/aws-ec2/compose.yaml up -d --wait --wait-timeout 180
fi
docker start aegisai-ingress
curl --fail --silent --show-error http://127.0.0.1:8080/api/health
# Remove only this workflow's resume marker after successful recovery.
python3 -c 'from pathlib import Path; Path("/opt/aegisai/shared/root-encryption.resume").unlink()'
