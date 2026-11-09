# Private platform expansion execution

Enter through AGENTS and canonical 006, retain its read order and gates, then
read this spec, plan, tasks and the G/H sections of the existing execution plan.
User rollout instruction on 2026-11-09 authorizes progress on the actual private
single-host expansion, beyond the prior documentation-only boundary.

Phase 1 is inventory, protected Terraform state, import and non-destructive plan.
Keep the currently deployed app/DB/scanner unchanged during this phase. Never
execute an apply containing creates, updates, replacements or deletes without
first reconciling the reviewed resource intent. Import only known existing assets.
No new EC2/EKS/Fargate/NAT, public ingress or runtime IAM expansion is authorized.

Use the separate operator login credential process for infrastructure operations;
never mount it in the app or expose AWS export output. Reject wrong AWS accounts.
State/config must not contain secret values, SCM keys or access credentials.
Keep evidence outside Git and in root-only storage on the encrypted existing disk.
Never fetch Secrets Manager secret versions into Terraform.

Validate formatting, initialization, resource schema, inventory correspondence,
no-op plan, concurrency lock behavior and a bounded read-only drift check. Preserve
plan/state evidence privately. Phase-1 success is not full rebuild evidence.
Do not rerun application suites or scans for isolated Terraform/operator changes.

H2/G3 Kubernetes rollout remains gated by its applicable external qualification,
threat model, capacity and recovery prerequisites; this package cannot forge or
bypass T053-T056. Later phases require a concrete scoped design before code/live
changes. All eight G/H acceptance criteria remain mandatory and independently tracked.

For issue #342 H4 implementation, read [observability.md](./observability.md) before code or installation. The current user authorizes this bounded diagnostic phase; private Kubernetes rollout and full G/H completion retain their independent gates.

For issue #344, the owner selected Slack for actual operational alerts. Follow
[the bounded operator-only handoff and notifier](../../deploy/aws-ec2/alerts/README.md).
No secret may enter chat/Git/logs; the receiver is selected by the owner and
notification delivery must be observed rather than inferred from configuration.
