# Production runtime tasks

Current private operating scope and evidence:
[`deployment checkpoint`](../../docs/reports/2026-11-08-runtime-supervisor-checkpoint.md).
The current architecture, operations, evidence and remaining-work index is
[production documentation](../../docs/production/README.md).
These completed gates apply only to the explicitly authorized one-owner, one-EC2,
selected AigisAI organization Java profile. They do not certify general multi-tenancy.

- [x] Durable OAuth identity and active personal tenant provisioning; real phone login.
- [x] Tenant-scoped integrations, selected repository bindings and idempotent requests.
- [x] Revocation preserves history and denies new/in-flight work; tenant tests use a disposable DB.
- [x] Block mock integration/scan/token APIs and direct source uploads in production.
- [x] Actual organization GitHub App ownership/admin checks and immutable ref resolution.
- [x] Separate identity/SCM managed secrets and instance-role startup loading.
- [x] One-use, hash-only ten-minute capability with fenced broker epoch and private UDS roles.
  GitHub's upstream token retains its provider expiry on total host failure; see
  runtime-execution.md. It is gateway-only and revoked before parsing, never a worker token.
- [x] Durable outbox/queue, bounded retries, tenant capacity, current-fence results and reconciliation.
- [x] Review and record the same-host private scope and residual shared-host risks.
- [x] Separate containerd/gVisor, pinned approved tools, no network/builds/packages/code execution.
- [x] Positive/negative native scanner fixtures; timeout/output-limit cleanup, ten fault repetitions.
- [x] Bounded immutable Git object fetch, per-job no-exec tmpfs, dedicated gateway UID and egress.
- [x] Boot lifecycle, singleton worker, maintenance locking, DB/egress freshness and bounded snapshots.
- [x] Durable normalized findings, nullable dependency locations, limited coverage and deterministic policy.
- [x] SSE-KMS reduced evidence, seven-day TTL, tenant/expiry checks and audited reads.
- [x] Scheduled expiry/orphan deletion, retries, status/lag alerts and fail-closed scan admission.
- [x] Real runtime frontend API contracts; no stored demo auth or fixture-data fallback.
- [x] AI disabled without blocking scans/results. Local model/API adapters remain future work.
- [x] Existing-root encryption and managed-secret reboot recovery; completed scan not replayed.
- [x] Instance-role offsite backup, transfer hash and disposable-DB restore with six migrations.
- [x] Scheduled nightly backup; keep user-retained original unencrypted recovery copies documented.
- [x] Operational journal/status, readiness, retention gates and bounded CPU/memory/disk/queue settings.
- [x] Private ingress pause/restore rollback acceptance. Older schema-incompatible image downgrades
  are not certified; initial release recovery uses closed ingress and verified data restoration.
- [x] All six canonical validation checks; target PostgreSQL/native permission checks.
- [x] Actual private Java scan completed three tools, encrypted evidence and physical source cleanup.
- [x] Open only private whitelisted application ingress; owner confirmed repositories/completed scan.
- [x] Restore existing cream/brass theme and workspace layout after owner feedback; frontend-only
  input equality, tests/types/lint/build/live route checks passed. No later visual sign-off claimed.

## Follow-up outside this initial private release

Documentation consolidation covers the recorded release's current/historical
status, artifact provenance, operating procedures, evidence limitations and
uncompleted baseline requirements. This does not complete the follow-up items below.

- [ ] Optional local/API advisory provider over reduced evidence (not authoritative findings).
- [ ] Hosted GitHub CI and clean reviewed release commit/PR; current artifacts are dirty snapshots.
- [ ] Browser-initiated new scan acceptance; operator service-to-worker scan and owner result view passed.
- [ ] General multi-tenant/separate-node baseline, HA, webhook intake, GitLab and broader coverage.
- [ ] Historical recovery-copy cleanup only if the user later authorizes it.
