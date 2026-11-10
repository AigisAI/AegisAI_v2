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

2026-11-09 operational fix: removed deployment/checker dependence on legacy local
credentials. Three managed-equivalent copies were retired with live RAM recovery
verification; app containers and DB were unchanged. Historical env/OAuth copies and
user-retained EBS artifacts remain outside that cleanup. Operator safety checks run
with fake secrets/temp files, not production identities or scans.

Documentation consolidation covers the recorded release's current/historical
status, artifact provenance, operating procedures, evidence limitations and
uncompleted baseline requirements. This does not complete the follow-up items below.

- [ ] Optional local/API advisory provider over reduced evidence (not authoritative findings).
- [x] Capture deployed sources in independent commit feb7628 and draft PR #337; verify 188 files and hosted CI run 42556229213.
- [x] Integrate the private profile on current dev, pass both CI jobs and deploy the immutable candidate ab65d878 (release ec2-runtime-20261109-054314). PR #339 remains unmerged; the deployed merge commit is retained by its release tag.
- [ ] Browser-initiated new scan acceptance; operator service-to-worker scan and owner result view passed.
- [ ] General multi-tenant/separate-node baseline, HA, webhook intake, GitLab and broader coverage.
- [ ] Historical recovery-copy cleanup only if the user later authorizes it.

## Mandatory rollout/scaling expansion — 2026-11-09

User instruction makes Blue/Green, Canary, actual Kubernetes RollingUpdate and
HPA implementation plus measured verification mandatory, all currently incomplete.
Follow [existing execution plan](../../docs/reports/2026-11-07-production-deployment-plan.md)
4/G and 9 and [remaining work](../../docs/production/remaining-work.md).
The existing commit-based private release is deployed; new requirements do not
retroactively certify new strategies. Keep one existing EC2, no extra compute,
scanner boundaries and applicable 005/006 gates. Capacity and architecture review
precede changes; lab-only proof cannot substitute for actual-service completion.

- [ ] G0 Confirm capacity, runtime boundaries, metrics and applicable Kubernetes admission gates.
- [ ] G1 Implement and verify Blue/Green traffic switch and previous-version recovery.
- [ ] G2 Implement and verify measured Canary traffic and automatic abort/recovery.
- [ ] G3 Implement and verify actual Kubernetes RollingUpdate and bad-candidate recovery.
- [ ] G4 Implement and verify real HPA scale-up/down, bounded resources and data/session correctness.

## Restored mandatory platform requirements — 2026-11-09

See [execution plan](../../docs/reports/2026-11-07-production-deployment-plan.md)
4/H for acceptance. These are additions to G1-G4, not replacements.

- [ ] H1 Terraform: approved-resource import/plan, protected state, drift and code-based recovery/reproducibility evidence.
- [ ] H2 GitOps/CD: verified digest deployment, limited OIDC, ownership, synchronization, drift handling, failure blocking and Git/app recovery evidence.
- [ ] H3 Supply chain: deployment image scans/SBOM/provenance/signatures and actual rejection of missing, tampered or policy-violating artifacts.
- [ ] H4 Observability: actually collect/query Prometheus metrics and Loki logs, connect both to Grafana dashboards/alerts, correlate AWS request/queue/worker/result OpenTelemetry traces, and verify data/retention/resource/cost controls.

Existing CI, artifact hashes and host status are partial evidence only. Keep all
new tasks open until their actual acceptance passes. No extra compute or live
operating change is authorized by this documentation task.
