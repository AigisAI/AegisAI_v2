# SAST AI Authority Proof Exceptional Hard Purge

## Purpose and boundary

This runbook is the only supported path for a legal or tenant-mandated hard purge of
`SastAiAdvisoryAuthorityProof` records and their T043 advisory/handoff chain. Normal tenant or
repository offboarding must soft-revoke access and retain these immutable, content-free audit
records. The application API, application database role, background workers, and ordinary
operators must not be able to invoke this procedure.

The proof ledger contains scope identifiers and digests, not source, evidence, secret, prompt,
or advisory content. A request to remove only source or model content therefore does not by
itself authorize removal of this ledger.

## Required authorization

Do not begin unless all of the following exist:

- an approved legal/privacy ticket identifying one tenant and the exact purge basis
- Security and Data Protection approval, with two named operators
- a maintenance window that prevents new scans, policy changes, waivers, suppressions, and AI
  advisory work for the tenant
- a dedicated, time-limited database maintenance role that can alter only the two named
  immutable delete triggers and delete the approved tenant rows
- a tested backup and rollback point
- an external, append-only audit destination that is outside the database being purged

Never reuse the application role, share credentials, place credentials in the ticket or audit
export, or broaden the target from an explicit tenant ID.

## Preflight and audit export

1. Soft-revoke the tenant and stop/deny all tenant jobs and internal AI proof requests.
2. Wait for active tenant transactions to finish. Confirm that the scan, policy, lifecycle,
   waiver, suppression, and advisory queues contain no running work for the tenant.
3. In a read-only session, inventory the exact `AiAdvisoryMetadata`,
   `SastAiAdvisoryHandoff`, and `SastAiAdvisoryAuthorityProof` IDs and counts. Confirm every
   proof belongs to the requested tenant through both its direct tenant scope and immutable
   handoff binding.
4. Export only the minimum required audit fields: change ticket, approvals, tenant ID, row IDs,
   scope/proof digests, counts, timestamps, and the planned deletion order. Do not export model
   output or other content as part of this procedure.
5. Hash the export, write it to the approved append-only destination, and have the second
   operator verify the hash and row counts before any mutation.

Any scope mismatch, unexplained row, active transaction, missing approval, failed export, or
count difference stops the procedure.

## Controlled maintenance transaction

Execute one reviewed transaction from a pinned migration/maintenance artifact. The artifact
must take the approved tenant ID as a bound parameter and must abort unless its preflight counts
equal the signed audit export.

Within that transaction, perform this exact order:

1. Acquire the tenant maintenance lock used by the purge artifact and recheck tenant revocation.
2. Materialize the approved proof, advisory, handoff, and authority-fence targets in temporary
   tables. Every destructive statement must join those exact targets; unbounded deletes are
   prohibited.
3. Disable only `SastAiAdvisoryAuthorityProof_immutable_delete`, delete the approved proof rows,
   and immediately re-enable that trigger.
4. Delete the matching `AiAdvisoryMetadata` rows.
5. Disable only `SastAiAdvisoryHandoff_immutable_delete`, delete the now-unreferenced approved
   handoff rows, and immediately re-enable that trigger.
6. After all tenant authoritative rows have been removed or tombstoned according to the parent
   offboarding plan, delete the tenant's `SastAiAdvisoryAuthorityFence` coordination rows. A
   fence key is canonical JSON; its tenant element must exactly equal the approved tenant ID.
7. Verify the targeted rows are absent, both immutable delete triggers are enabled, no
   non-target tenant count changed, and every statement count equals the approved inventory.
8. Commit only after the second operator confirms the verification output. Otherwise roll back
   the entire transaction.

Do not disable foreign-key enforcement, update proof rows, drop constraints or functions,
disable all user triggers, or delete parent rows before their approved proof/advisory children.
The restrictive foreign keys are a safety control and must remain active.

## Post-purge evidence and recovery

1. Re-run the read-only inventory and record zero remaining targeted rows plus unchanged control
   tenant counts.
2. Record trigger-enabled state, transaction ID, database audit event IDs, operator identities,
   timestamps, deployed artifact digest, and before/after counts in the external audit record.
3. Run tenant-isolation and health checks before re-enabling shared workers. Keep the purged
   tenant revoked unless the approved offboarding plan explicitly says otherwise.
4. Revoke the maintenance role/credential immediately.

Before commit, recovery is transaction rollback. After commit, recovery requires the approved
backup and a new incident/change record; never reconstruct or reinsert a proof from the external
audit export because it is evidence, not an application restore source.
