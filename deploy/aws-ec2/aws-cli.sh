#!/bin/sh
set -eu
# Operator-only temporary login cache. Never mount this directory into the app.
install -d -m 0700 /dev/shm/aegisai-aws-input
exec docker run --rm -i --log-driver none --ulimit core=0 --memory=256m --cpus=0.5 --pids-limit=128 \
  -v /opt/aegisai/operator/aws:/root/.aws \
  -v /dev/shm/aegisai-aws-input:/run/aws-input:ro \
  -e AWS_PAGER= \
  public.ecr.aws/aws-cli/aws-cli@sha256:0cea63506f28774b70b1a3dd1934f49bc202d9784dee23370acc81438e8d0292 \
  --profile aegisai-deploy --region ap-northeast-2 "$@"
