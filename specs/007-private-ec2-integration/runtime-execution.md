# Private single-host runtime execution design

Continue the 003 quickstart and single-host security review. This document defines
runtime invariants; it does not itself certify acceptance. The integrated private
runtime is deployed, with actual evidence and remaining limits recorded in
docs/production/release-evidence.md and remaining-work.md.

## Authority and source flow

The authenticated API selects a durable repository binding for the active tenant.
The App client rechecks installation/administrator authority and resolves the branch
through Git ref metadata. The canonical scan stores that exact commit SHA. Callers
cannot submit a different repository owner, installation, SHA, scanner set or policy.

Control Plane handles identity, repository metadata, dispatch and credential scope;
it never downloads repository contents. The App signing key remains in the integration
service. A separate trusted Scan Plane fetch gateway receives only a single-repository
Contents-read upstream token from the broker over a private, authenticated local
channel. Neither the general worker nor the parser sandbox receives that token.

The broker runs as an explicit separate process, never as an API controller.
Its root-owned SGID directory admits only the dedicated fetch group (GID 50001).
The supervisor uses a root-only Unix socket; the dedicated gateway uses a separate
group-accessible Unix socket. Listener identity determines the role, never a caller
header. The gateway stream remains connected for the full fetch. The broker also
retains its own upstream revocation resource, revokes on disconnect/deadline, and
confirms revocation independently before allowing a handoff. A database finalization
failure makes the process unhealthy until restart/reconciliation; a recovered DB
alone must not restore readiness. Duplicate listeners cannot rotate the active epoch.

The worker receives a one-use opaque fetch capability bound to tenant, repository,
scan, immutable SHA and current dispatch fencing token. Its default/maximum lifetime
is ten minutes; it is unusable after expiry, consumption, revocation or broker restart.
Durable records store scope, expiry, status and a capability fingerprint, never raw
capability or provider token values. The gateway checks authority before delivery.

Persist capability states ISSUED, CONSUMING, CONSUMED, REVOKED and EXPIRED with a
tenant/dispatch-job/scan composite foreign key, current dispatch-lease fingerprint,
issuer epoch, capability fingerprint, optional gateway-claim fingerprint and
database-time issue/expiry (at most 600 seconds). Issuance derives all repository
scope from the canonical scan; only explicitly admitted durable tenants qualify.
Consumption is atomic and one-use. Every operation checks the current broker epoch,
active tenant/integration, nonterminal scan and unexpired current dispatch fence.
Reject HARDENED/RESTRICTED isolation profiles at issuance and every gateway check;
the same-host runtime supports STANDARD only and cannot downgrade a stored profile.
Rotate unconsumed capabilities safely on retries; never rotate an active gateway
claim. Broker restart invalidates old capabilities. If a gateway claim's upstream
revocation is unknown, suspend its integration and cancel/fail its job before any
new issuance. No raw token value is persisted in these records or audit metadata.

GitHub installation tokens have a provider-controlled one-hour expiry. Do not claim
that an API parameter reduces it to ten minutes. They are upstream integration
credentials, never issued as the worker's scan capability. The gateway/broker retain
them only in memory and revoke immediately after a bounded fetch, before parsing.
An unconfirmed revocation fails the job and prevents parser handoff; freeze new
issuance for that integration until reconciliation or the upstream expiry horizon.
On control-channel loss the gateway fails closed and attempts revocation. Full host
failure loses all in-memory credentials; platform capabilities are invalidated on
restart. Audit this residual upstream lifetime honestly; no ordinary one-hour token
delivery to a worker may substitute for the ten-minute capability boundary.

## Bounded immutable fetch

Use Git object metadata and blob APIs at fixed GitHub endpoints. Resolve the stored
commit's tree, reject truncated/oversized trees and require all downloaded blobs to
belong to that immutable tree. Verify each blob's Git object hash. No Git checkout,
archive extraction, hooks, package manager, build or repository command runs.

Initial bounds: 1,000 files, 512-character safe relative paths, one MiB per blob and
20 MiB total source. Reject traversal, control characters, symlinks, hard links,
submodules and unsupported file modes. Do not silently skip oversized/unavailable
inputs and report complete coverage. Fetch duration is at most 90 seconds. Write
only into a fresh scan-owned tmpfs using exclusive/no-follow file creation. Mark
source files non-executable and read-only before handoff. Revoke credentials first.

Keep the privileged runtime socket under root-only `/run/aegisai-scan`; do not
relax that directory for a fetch process. Use a distinct `/run/aegisai-scan-jobs`
base owned root:GID 50001 with mode 0710. Root creates each bounded tmpfs and grants
the gateway UID 50001 temporary ownership only for that job. After the gateway's
entire process group is confirmed stopped, root seals every source/control file
as root-owned 0444 and directories 0555, restoring the job root to root-only 0700.
Reject links and special files. A failed seal prevents parser startup and requires
verified cleanup. Production boot provisioning and process lifecycle wiring must
be accepted before enabling this handoff; the standalone storage test is not a
background consumer.

## Runtime and lifecycle

A root supervisor alone owns the independent scanner containerd socket. Application
containers receive neither that socket nor the Docker socket. The supervisor is a
singleton and runs only one actual scan at a time. It heartbeats the PostgreSQL
dispatch lease; every result write requires current tenant and fencing token.

Derive container/storage names from a hash of tenant plus scan ID. On redelivery,
reconcile and remove an old sandbox for that exact scan before provisioning again.
Use per-scan bounded no-exec tmpfs; never retain full source or raw output on EBS.
The approved scanner image is pinned by digest. Run gVisor only, UID 65532, no network,
read-only root and input, no capabilities, no-new-privileges, one CPU, one GiB memory,
256 PIDs and bounded temporary/cache storage. There is no runc fallback.

Run fixed trusted Opengrep-core, Trivy and Syft commands. Generate core target metadata
outside repository control using the pinned core protocol. Ignore repository scanner
configuration. Tool stdout/stderr, execution time and normalized record counts have
hard bounds; timeout/output-limit/lease loss triggers sandbox destruction. Refuse
new work if destruction or tmpfs cleanup cannot be verified.

Disable scanner container logging explicitly. On output/timeout limits, kill the
actual sandbox while continuing to drain/discard its attachment stream before
removing the CLI; abandoning that stream first can stall runtime FIFO cleanup.
After a removal timeout, only a successful daemon absence check can prove cleanup.

The vulnerability DB is an immutable, digest-verified read-only vendor snapshot.
Check freshness on every scan, separately from update success. Scheduled refresh,
bounded version retention and disk-headroom checks remain release gates. Missing,
stale or incompatible DBs must not become successful clean coverage.

## Results and acceptance

The data plane uses a private S3 bucket with SSE-KMS envelope encryption and an
AWS-managed key. Disable S3 Bucket Keys so the default encryption context retains
the tenant/scan/evidence object ARN; additionally supply opaque tenant/scan/evidence
IDs as KMS context. Enforce TLS, KMS writes, owner-only ACLs, public-access blocks,
and create-only conditional writes. Store reduced rule metadata only, not raw tool
output or source. Two distinct Secrets Manager entries separate user-auth and SCM
credentials. Production processes retrieve them at startup into memory using the
existing instance's restricted role, never the operator login cache. The database
password may be materialized into root-only boot RAM for the database entrypoint.
No additional compute is authorized or provisioned for these managed services.

Evidence expiry is seven days. Persist its bounded size, classification, redaction
and expiration with the canonical result; stage an immutable encrypted object before
the final fenced transaction. On rollback, remove an unreferenced object only after
confirming the DB did not commit. Unknown commit state is reconciled by scheduled
orphan cleanup. Tenant/active-state/DB-time expiry checks and read audit writes must
pass before an authenticated evidence response. Every fifteen minutes delete expired
objects, mark deletion/audit, retry failures and reconcile old unreferenced objects.
S3 lifecycle is defense in depth, not the scheduled-enforcement mechanism. Stale or
failed retention status blocks new source processing; deletion lag over 24 hours is
an operational security alert. Keep all product guardrails and the documented private
same-host/historical-copy deviations visible.

Hold the original dispatch lease through fetch and scanner execution, heartbeating
every 15 seconds. After independently confirmed fetch revocation, the root-only
broker may move the scan to RUNNING. QUEUED, PLANNING and RUNNING remain lease-owned
states for heartbeat, cancellation and retry. There is no early dispatch ACK in the
production worker. Publish bounded normalized runs/findings and a dashboard-only
policy in the same serializable transaction that completes the canonical scan and
marks dispatch SUCCEEDED. Require the current fence, tenant/integration, broker
epoch and a CONSUMED fetch capability bound to that attempt. A stale or duplicate
publication cannot replace or duplicate results. Generic legacy dispatch ACK remains
distinct from scan completion and is never exposed through the worker socket.

Dependency findings without a source location use a null line number; never invent
line 1. Persist coverage limits explicitly: initial Java rules and declared Maven
dependencies are limited coverage, not proof of a complete dependency graph or a
clean repository. The initial result records AI as DISABLED, without requiring an
API key or local model. Later optional AI failure cannot roll back a valid scan.

Only bounded normalized metadata leaves Scan Plane. Strip code snippets, raw tool
messages and credentials; use trusted rule IDs/titles and validated paths/locations.
Persist scanner runs/findings/coverage and deterministic policy atomically, fenced
against stale attempts. Acknowledging dispatch is distinct from scan completion.
Repeated delivery cannot duplicate findings or replay completed work.

Evidence contains reduced redacted metadata, encrypted with enforced expiry and
scheduled deletion/retries. Never persist full source as evidence. Missing coverage,
unsupported language/build metadata, tool failures and partial dependency graphs
remain visible and cannot produce a clean/pass claim. AI is unavailable in this slice.

Before customer input: native positive/negative scanner fixtures, output/timeout
cleanup, source boundary tests, broker expiry/revocation, real-DB fencing/restart,
tenant/revocation tests and private operating-scope checks. Before ingress: real UI
contracts, evidence/policy, observability, backup/rollback and end-to-end acceptance.
