#!/bin/sh
set -eu
umask 077
root=/opt/aegisai
release=$(cat "$root/shared/candidate-release")
case "$release" in ec2-runtime-[0-9]*) ;; *) exit 2 ;; esac
case "$release" in *[!a-zA-Z0-9-]*) exit 2 ;; esac
install -d -m 0700 /run/aegisai-retention
exec flock --no-fork /run/aegisai-evidence-retention.lock \
  docker run --rm --name aegisai-evidence-retention --user 0 --no-healthcheck \
    --network aegisai-ec2-demo_default --read-only --cap-drop ALL --security-opt no-new-privileges \
    --ulimit core=0 --memory 256m --cpus 0.25 --pids-limit 64 \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16777216,mode=1777 \
    --log-driver none --env-file "$root/shared/runtime-public.env" \
    --mount type=bind,source=/run/aegisai-retention,target=/run/retention \
    "aegisai-api:$release" node apps/api/dist/data-security/maintenance-main.js
