#!/bin/sh
set -eu
umask 077
release=${1:?release ID required}
expected_hash=${2:?source archive SHA256 required}
validation=${3:-full}
# Integrated profiles consume hosted-CI images; direct server builds are retired.
case "$validation" in prebuilt) ;; *) echo "Use the verified prepared candidate in prebuilt mode" >&2; exit 2 ;; esac
case "$release" in ec2-runtime-[0-9]*|ec2-demo-[0-9]*) ;; *) exit 2 ;; esac
case "$release" in *[!a-zA-Z0-9-]*) exit 2 ;; esac
case "$expected_hash" in *[!a-f0-9]*) exit 2 ;; esac
[ "${#expected_hash}" -eq 64 ]
root=/opt/aegisai
archive="/home/ubuntu/$release.tar.gz"
printf '%s  %s\n' "$expected_hash" "$archive" | sha256sum -c -
test -s "$root/shared/runtime-public.env"
test -s "$root/shared/private-broker-public.env"
test -s "$root/operator/data-plane-state.json"
test -s /run/aegisai-runtime-secrets/postgres-password
install -d -m 0755 "$root/scanner/catalog"
test ! -e "$root/releases/$release"
install -d -m 0750 "$root/releases/$release"
tar -xzf "$archive" -C "$root/releases/$release"
cd "$root/releases/$release"
export RELEASE_ID="$release" RUNTIME_ENV_FILE="$root/shared/runtime-public.env"
set -a
. "$RUNTIME_ENV_FILE"
set +a
# Observability is opt-in; validate the external bridge before disrupting services.
compose() {
  if [ -f "$root/shared/observability.override.yaml" ]; then
    docker network inspect aegisai-observability >/dev/null
    docker compose -f deploy/aws-ec2/compose.yaml -f "$root/shared/observability.override.yaml" "$@"
  else
    docker compose -f deploy/aws-ec2/compose.yaml "$@"
  fi
}
compose config --quiet
if [ "$validation" = prebuilt ]; then
  python3 - "${4:?verified candidate manifest required}" "$release" <<'PYVERIFY'
import json,subprocess,sys
manifest=json.load(open(sys.argv[1]))
assert manifest['releaseId']==sys.argv[2] and manifest['profile']=='private-single-host-v1'
for key in ('api','web'):
    expected=manifest['images'][key]
    actual=json.loads(subprocess.check_output(['docker','image','inspect',expected['tag']]))[0]
    assert actual['Id']==expected['id']
    assert actual['Config']['Labels']['org.opencontainers.image.revision']==manifest['sourceCommit']
PYVERIFY
else
compose build api web

if [ "$validation" = runtime-app ]; then
  docker run --rm -e NODE_ENV=test "aegisai-api:$release" \
    corepack pnpm --filter @aegisai/private-api test --runInBand runtime-api.e2e-spec.ts
fi

# Exercise provider/HTTP security boundaries in the actual runtime image.
if [ "$validation" = full ]; then
docker run --rm -e NODE_ENV=test "aegisai-api:$release" \
  corepack pnpm --filter @aegisai/private-api test --runInBand github-app.e2e-spec.ts github-read-session.e2e-spec.ts

if [ -f "$root/operator/github-live-installation.json" ]; then
  docker run --rm --network aegisai-ec2-demo_default --env-file "$root/shared/private-broker-public.env" \
    -v "$root/operator/github-live-installation.json:/run/preflight/install.json:ro" \
    -v "$root/releases/$release/deploy/aws-ec2/verify-github-installation.mjs:/app/test/github-live-preflight.mjs:ro" \
    "aegisai-api:$release" node /app/test/github-live-preflight.mjs
fi
fi

# Real DB tests use a separate loopback-only verification database, never the app DB.
docker run --rm --network host \
  -e DATABASE_URL=postgresql://verify:verify-only-local@127.0.0.1:15432/aegisai_verify \
  "aegisai-api:$release" corepack pnpm --filter @aegisai/private-api prisma:migrate:deploy
if [ "$validation" = full ]; then
  set -- /app/test/private-persistence/control-plane.test.mjs /app/test/private-persistence/dispatch-migration.test.mjs \
    /app/test/private-persistence/dispatch-queue.test.mjs /app/test/private-persistence/fetch-capabilities.test.mjs \
    /app/test/private-persistence/runtime-results.test.mjs /app/test/private-persistence/runtime-api.test.mjs
else
  # Only for the result/lifecycle continuation: provider authentication and
  # installation logic are unchanged. Keep affected queue and result coverage.
  set -- /app/test/private-persistence/dispatch-queue.test.mjs /app/test/private-persistence/runtime-results.test.mjs
  if [ "$validation" = runtime-app ]; then set -- "$@" /app/test/private-persistence/runtime-api.test.mjs; fi
fi
docker run --rm --network host \
  -e PERSISTENCE_TEST_DATABASE_URL=postgresql://verify:verify-only-local@127.0.0.1:15432/aegisai_verify \
  -v "$root/releases/$release/test/private-persistence:/app/test/private-persistence:ro" \
  "aegisai-api:$release" node --test --test-concurrency=1 "$@"

# Native Unix permissions need Linux/container UID 0. This trusted-code fixture
# receives only the disposable verification DB, never runtime.env or SCM keys.
docker run --rm --user 0 --network host --memory 768m --cpus 1 --pids-limit 128 \
  -e PERSISTENCE_TEST_DATABASE_URL=postgresql://verify:verify-only-local@127.0.0.1:15432/aegisai_verify \
  -v "$root/releases/$release/test/private-worker-native:/app/test/private-worker-native:ro" \
  "aegisai-api:$release" node --test --test-concurrency=1 /app/test/private-worker-native/*.test.mjs

fi

restart_supervisor=0
if systemctl is-active --quiet aegisai-scan-supervisor.service; then
  systemctl stop aegisai-scan-supervisor.service
  restart_supervisor=1
fi
systemctl stop aegisai-private-broker.service

install -d -m 0700 "$root/backups"
backup="$root/backups/pre-$release.sql"
docker exec aegisai-ec2-demo-postgres-1 pg_dump -U aegisai -d aegisai > "$backup"
test -s "$backup"
gzip "$backup"
docker exec aegisai-ec2-demo-postgres-1 psql -U aegisai -d aegisai -Atc \
  'SELECT count(*) FROM "_prisma_migrations" WHERE finished_at IS NOT NULL' \
  > "$root/backups/pre-$release.migrations"
compose run --rm api node apps/api/dist/data-security/migrate-main.js
compose up -d --no-deps --wait --wait-timeout 180 api web
curl --fail --silent --show-error http://127.0.0.1:8080/healthz
curl --fail --silent --show-error http://127.0.0.1:8080/api/health
compose ps
# A successful full replacement supersedes any separately released frontend.
rm -f "$root/shared/web-release.override.yaml" "$root/operator/web-release.json"
printf '%s\n' "$release" > "$root/shared/candidate-release"
install -m 0700 deploy/aws-ec2/run-private-broker.sh "$root/operator/run-private-broker.sh"
install -m 0644 deploy/aws-ec2/aegisai-private-broker.service /etc/systemd/system/
systemctl daemon-reload
systemctl start aegisai-private-broker.service
install -m 0700 deploy/aws-ec2/run-evidence-retention.sh "$root/operator/run-evidence-retention.sh"
install -m 0644 deploy/aws-ec2/aegisai-evidence-retention.service deploy/aws-ec2/aegisai-evidence-retention.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now aegisai-evidence-retention.timer
systemctl start aegisai-evidence-retention.service
# A changed host bundle is installed separately while the supervisor is stopped.
# Do not resume an older host worker implicitly across the data-plane transition.
if [ "$restart_supervisor" -eq 1 ] && [ "$validation" = prebuilt ]; then
  systemctl start aegisai-scan-supervisor.service
elif [ "$restart_supervisor" -eq 1 ]; then
  printf '%s\n' 'SUPERVISOR_STOPPED_FOR_COORDINATED_HOST_BUNDLE_UPDATE'
fi
# Ingress is deliberately not switched by this script.
