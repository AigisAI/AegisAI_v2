# Platform expansion tasks

- [x] P0 Capture actual deployed source and read-only host resource inventory.
- [x] P0 Reconnect the existing operator login separately from runtime instance IAM.
- [x] P1 Capture exact approved AWS resources and exclusions without secret values.
- [x] P2 Generate protected Terraform definitions and exact pinned tools.
- [x] P3 Import existing resources; reconcile to zero cloud changes.
- [x] P4 Verify state protection, concurrency locking and read-only drift detection.
- [ ] H1 Complete scoped code-based recovery/reproduction evidence; record exclusions.
- [ ] H4 Implement actual Grafana/Loki/Prometheus and correlated OpenTelemetry traces/alerts.
- [ ] H3 Enforce deployment image scans, SBOM, provenance and trusted signatures.
- [ ] H2 Implement gated GitOps/CD with field ownership, drift and Git/app recovery.
- [ ] G3 Implement/verify actual Kubernetes RollingUpdate and bad-candidate recovery.
- [ ] G1 Implement/verify actual Blue/Green switch and previous-version recovery.
- [ ] G2 Implement/verify measured Canary routing and automatic abort/recovery.
- [ ] G4 Implement/verify actual bounded HPA up/down and data/session correctness.
- [ ] F Complete targeted failure, performance, recovery/cost and actual user path proof.

Do not mark any H/G item complete from configuration, a lab-only result or an
unrelated earlier CI pass. No additional compute or gate bypass is authorized.

## H1 live adoption checkpoint, 2026-11-09

12 existing addresses imported; actual plan NO_CHANGES. Account, role/policy,
network ingress, S3 encryption/lifecycle and root-volume ownership are preserved.
Root-only encrypted-disk state, operator locking, state-drift simulation against
live metadata, destruction-plan rejection, SSE-KMS state snapshot/download and
isolated restored-state no-op plan passed. Runtime IAM state-object read is denied.
No app deployment, new compute or cloud configuration mutation occurred.
H1 remains partial: full reconstruction, remaining resources and snapshot
retention automation are not verified/complete. G/H requirements remain open.
