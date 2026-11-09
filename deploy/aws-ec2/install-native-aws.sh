#!/bin/sh
set -eu
umask 077
target=/usr/local/lib/aegisai-aws-cli
image=public.ecr.aws/aws-cli/aws-cli@sha256:0cea63506f28774b70b1a3dd1934f49bc202d9784dee23370acc81438e8d0292
if [ ! -x "$target/aws" ]; then
  install -d -m 0755 "$target"
  temporary_container=$(docker create --entrypoint /bin/true "$image")
  trap 'docker rm "$temporary_container" >/dev/null 2>&1 || true' EXIT
  docker cp "$temporary_container:/usr/local/aws-cli/v2/current/dist/." "$target/"
fi
"$target/aws" --version
