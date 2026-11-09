#!/bin/sh
set -eu
# Root-owned temporary login cache; no long-lived access keys in source or argv.
exec docker run --rm -i \
  -v /opt/aegisai/operator/aws:/root/.aws \
  -e AWS_PAGER= \
  public.ecr.aws/aws-cli/aws-cli@sha256:0cea63506f28774b70b1a3dd1934f49bc202d9784dee23370acc81438e8d0292 \
  --profile aegisai-deploy --region ap-northeast-2 "$@"
