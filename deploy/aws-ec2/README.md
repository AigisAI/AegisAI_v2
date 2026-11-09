# Existing-EC2 private production runtime

Read [PRODUCTION-ACCESS.md](./PRODUCTION-ACCESS.md) for current access,
[OPERATIONS.md](./OPERATIONS.md) for recovery, and the
[checkpoint](../../docs/reports/2026-11-08-runtime-supervisor-checkpoint.md)
for artifacts and acceptance. Enter through the 002 and 003 quickstarts.

Real private Java scanning and durable results are deployed; AI is off. Historical
aegisai-ec2-demo resource names preserve existing volumes, not a mock runtime.
Original Oracle deployment is separate. Ports bind only to loopback behind Tailscale.

Full releases use deploy-candidate.sh with the archive hash and full validation.
The script builds, verifies against disposable PostgreSQL/native Unix roles, backs
up production, migrates and replaces workloads. It does not promote ingress or
resume an older host worker. Follow its coordinated bundle/readiness instruction.
Never use the production DB for verification suites or mount operator credentials.

Frontend-only releases use deploy-web.py. It refuses changed API/shared/dependency
inputs, builds web only, preserves backend/scanner processes and reverts a failed
web health check. A compose override records the component; root recovery includes
it. Successful full replacement supersedes it. Use affected web validation only.
Current runtime images originate from dirty snapshots. A separate source-capture
commit feb7628 passed hosted CI; dev integration and commit-based redeployment remain
pending. See [source capture](../../docs/production/source-capture.md).

The production UI preserves the existing cream/brass design and workspace layout
through real runtime APIs. Do not restore fixture endpoints or demo sessions to
restore a visual design. Private promotion checks actual scan acceptance, managed
boot, encrypted restore, validation and readiness. Legacy upload/token/ops APIs stay
closed. See runtime-execution.md for fenced queue completion, isolated tools,
bounded source, token revocation, limited coverage and shared-host residual risks.
