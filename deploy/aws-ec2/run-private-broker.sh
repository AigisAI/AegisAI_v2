#!/bin/sh
set -eu
umask 077
root=/opt/aegisai
release=$(cat "$root/shared/candidate-release")
case "$release" in ec2-runtime-[0-9]*) ;; *) exit 2 ;; esac
case "$release" in *[!a-zA-Z0-9-]*) exit 2 ;; esac
exec /usr/bin/docker run --rm --name aegisai-private-broker --user 0 \
  --network aegisai-ec2-demo_default --read-only --cap-drop ALL \
  --security-opt no-new-privileges --ulimit core=0 --memory 512m --cpus 0.5 --pids-limit 128 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=67108864,mode=1777 \
  --log-driver json-file --log-opt max-size=1m --log-opt max-file=2 \
  --health-cmd 'node -e "const h=require(\"node:http\");const r=h.get({socketPath:\"/run/broker/control.sock\",path:\"/health\"},s=>{s.resume();s.on(\"end\",()=>process.exit(s.statusCode===200?0:1))});r.setTimeout(3000,()=>{r.destroy();process.exit(1)});r.on(\"error\",()=>process.exit(1));"' \
  --health-interval 15s --health-timeout 5s --health-retries 3 --health-start-period 15s \
  --env-file "$root/shared/private-broker-public.env" \
  --mount type=bind,source=/run/aegisai-source-broker,target=/run/broker \
  "aegisai-api:$release" node apps/api/dist/worker/private-worker-main.js
