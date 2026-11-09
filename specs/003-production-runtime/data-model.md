# Private runtime persistence extension

The 002 models remain the baseline. The additive migration
`20261108050000_scan_fetch_capabilities` introduces the private fetch authority
library. Its original slice did not activate a consumer. The integrated private
runtime now uses it through a separate Unix broker; it contains no provider
credential column. Current activation/evidence is in tasks.md and the release record.

## ScanBrokerRuntime

One row, ID `private-single-host`, records the current random broker epoch.
Every capability operation checks it. Explicit broker bootstrap changes the epoch
and revokes outstanding capabilities. Old processes cannot issue against an older
epoch even if they still have in-memory state.

## ScanFetchCapability

The tenant, dispatch job and canonical scan are bound by composite foreign keys.
Scope is derived from the active job and durable repository binding. Account
admission derives the personal tenant using the same verified GitHub identity hash
as login; no caller-supplied tenant membership or provider user ID is authoritative.

Persist only the SHA-256 fingerprints of opaque capability, current dispatch fence
and optional gateway-claim secret. All secret values are returned only over the
authenticated private worker/gateway channel and must not be logged.
The private upstream resource is separate and never persisted.

States:

| State | Meaning | Claim fingerprint | Finish time |
| --- | --- | --- | --- |
| ISSUED | One-use worker capability, not yet delivered to source gateway | absent | absent |
| CONSUMING | Exactly one gateway owns the fetch | present | absent |
| CONSUMED | Source fetch and revocation confirmed with current authority | present | present |
| REVOKED | Rotation, failed/stale handoff, restart or authority loss | optional | present |
| EXPIRED | Expiry recorded by lifecycle maintenance | optional | present |

SQL enforces fingerprint formats, state consistency, one open capability per job,
and expiry strictly after issue and at most 600 seconds later. Database time governs
issuance and validation. Status does not override expiry: an expired ISSUED row
cannot be consumed even before maintenance records EXPIRED.

Concurrent consumption has one winner. Reissue rotates undelivered authority but
rejects an active gateway claim. Every source request rechecks claim, epoch, active
tenant/integration, immutable scope and current unexpired dispatch fence. A stale
completion may record revocation but cannot authorize parser handoff.

If an upstream token cannot be confirmed unusable, or broker restart discovers an
interrupted gateway claim, suspend the integration, fail/cancel the associated job
and audit `token.revocation_unconfirmed`. Reconciliation must establish revocation
or wait beyond the provider expiry before trusted reauthorization. Never let a
retry implicitly reactivate a suspended integration. Keep history and token-free
audit records. This conservative recovery path requires operator reconciliation.

## Upstream resource

`GithubReadSession` holds a single-repository Contents/Metadata-read provider token
in private memory fields. It cannot be JSON-serialized. It transfers only once to
the private gateway writer, revokes on broken delivery and at the scan-capability
deadline, and reports unconfirmed revocation. Already-unusable provider responses
are accepted only for self-revocation. Its existence is not permission to return
the provider token through a general API, environment, command argument or file.

The authenticated local transport, live provider delivery, lifecycle maintenance,
queue/worker integration and final result persistence have private-profile evidence
in the release record. Their broader multi-tenant baseline is not certified.

## Dispatch and durable publication

ScanDispatchJob is unique per canonical scan, with a tenant/scan composite foreign
key. Lease state and a random fence are checked against DB time. Final publication
requires active tenant/integration, current lease/epoch and CONSUMED capability.
ScannerRun, NormalizedFinding, PolicyDecision, EvidencePack and scan/dispatch
terminal state are persisted in one serializable transaction. S3 staging occurs
before commit; ambiguous commit state is reconciled rather than deleting blindly.

Dependency findings may have null lineStart/lineEnd, added by
20261108060000_runtime_result_locations. Never invent line 1.
20261108120000_evidence_expiry_enforcement adds EvidencePack.deletedAt and a pending
expiry index. Evidence metadata has expiresAt, object key, bounded byte size and
classification/redaction fields. Read checks use the active tenant and DB expiry;
scheduled deletion updates deletedAt and audits completion. Deleting evidence
does not delete normalized findings or scan history.

Six migrations are present in the current deployed schema; exact verification
counts and scope are in docs/production/release-evidence.md. The 365-day metadata
lifecycle and independent long-term audit storage remain follow-up work.
