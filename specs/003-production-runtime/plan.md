# Production runtime implementation plan

Enter through the 002 quickstart, then the 003 quickstart. This document describes
the implemented private runtime and the next delivery boundary; acceptance evidence
is in [release-evidence](../../docs/production/release-evidence.md), not inferred
from the presence of code. The DOCX product baseline and guardrails remain controlling.

## Current implementation

OAuth provisions a durable verified identity and personal tenant, with numeric
account admission. A separate organization GitHub App verifies administrator and
selected repository authority. Resolve immutable commit metadata before inserting
a canonical scan and one dispatch job in the same serializable transaction.

Use PostgreSQL for durable data and dispatch, with bounded transaction retries,
60-second fenced leases and revocation. The root singleton supervisor obtains work
through the separate broker and reconciles per-job sandboxes before delivery.
Only the dedicated source gateway receives upstream Contents-read authority.
Capabilities are one-use, hash-only and at most ten minutes; upstream GitHub token
expiry remains separately documented.

The host has an independent root-only containerd/gVisor runtime. Fixed approved
Opengrep/Trivy/Syft commands inspect bounded immutable source on per-job tmpfs.
No repository command, build or package installation runs. Confirm upstream
revocation before parsing; confirm source/runtime cleanup before final publication.
Keep the lease through execution and reject stale or duplicate completion.

Stage create-only SSE-KMS reduced evidence, then commit normalized runs/findings,
coverage, policy, evidence metadata and terminal scan/dispatch state atomically.
Read access requires active tenant, unexpired metadata and an audit write.
Scheduled expiry/orphan cleanup and stale-status admission gates supplement S3
lifecycle. AI is disabled and cannot block deterministic results.

The API and broker load selected Secrets Manager values into memory using the
existing instance role. The DB password is materialized into protected boot RAM.
A private allowlisted Nginx ingress exposes real runtime contracts. Legacy fixture
and management endpoints remain closed. The UI preserves existing workspace design;
visual restoration never authorizes reintroducing demo sessions or data.

## Release and recovery

The full candidate validates against disposable PostgreSQL and native Linux/UID
checks before production migration. Keep actual source hashes and dirty-snapshot
provenance. A frontend-only path byte-compares API/shared/dependency inputs and
retains a component override for recovery. Full replacement supersedes it.

Actual scan, physical cleanup, encrypted evidence, managed boot, existing-result
read, offsite backup restore and access pause/restore have passed for the current
private release. Their scope is explicit: prior arbitrary API-image downgrades,
full-host reconstruction and quantitative RTO/RPO are not certified.

## Next implementation boundary

Follow [remaining-work](../../docs/production/remaining-work.md): reviewed reproducible
source release/hosted CI, inactive local-secret dependency cleanup, operational
notification/retention gaps, bounded actual browser submission acceptance, then
optional local/API advisory integration. No additional compute is authorized.
Do not promote same-host operation as separate-node/general-service compliance.

Run affected checks for intermediate slices; full code releases retain the canonical
six checks plus applicable SQL/native gates. Documentation-only changes validate
links, factual evidence and changed-file scope without rerunning operational scans.

## Mandatory rollout/scaling expansion — 2026-11-09

User instruction makes Blue/Green, Canary, actual Kubernetes RollingUpdate and
HPA implementation plus measured verification mandatory, all currently incomplete.
Follow [existing execution plan](../../docs/reports/2026-11-07-production-deployment-plan.md)
4/G and 9 and [remaining work](../../docs/production/remaining-work.md).
The existing commit-based private release is deployed; new requirements do not
retroactively certify new strategies. Keep one existing EC2, no extra compute,
scanner boundaries and applicable 005/006 gates. Capacity and architecture review
precede changes; lab-only proof cannot substitute for actual-service completion.
