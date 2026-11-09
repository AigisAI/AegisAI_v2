# Private production access

Origin: https://aegisai-aws.tailaca7d2.ts.net/ with Tailscale enabled.
The owner confirmed actual login, repositories and the completed scan on a phone.
Only GitHub account 161540124 and selected AigisAI organization 241095585 repositories
are admitted. One existing EC2 runs one actual Java scan at a time; AI is off.
This private profile does not certify general multi-tenancy, separate nodes or HA.

API release: ec2-runtime-20261108-122119. Frontend: ec2-runtime-20261108-124735.
Both are dirty snapshots. See the [checkpoint](../../docs/reports/2026-11-08-runtime-supervisor-checkpoint.md)
for hashes, tests and the later design correction. The UI uses real data and the
original cream/brass workspace classes; no demo-auth or fixture fallback is active.

## Routes and identity

Only GitHub login/callback, session/logout, health and real runtime routes are
exposed. Legacy fixture/upload/token/management APIs and ops routes return 404.
Healthz identifies private ingress, not scanner availability. Scan admission also
requires fresh scanner, vulnerability DB, egress and retention readiness.

Identity-only GitHub App (Email read) is separate from the organization SCM App
(Contents/Metadata/Members read, no writes). The callback remains
https://aegisai-aws.tailaca7d2.ts.net/api/auth/github/callback.
Managed Auth configuration returns login to the root workspace. PKCE/state,
secure HttpOnly SameSite cookies, Redis sessions and CSRF remain required.

## Credentials and host

The API loads separate Auth/SCM Secrets Manager bundles into memory; the broker
loads only SCM. Current container configuration contains secret references and
no signing-key mount. The existing instance role has selected secret reads,
bucket-scoped evidence/backup operations and KMS only via S3; no EC2/IAM management.
Native AWS CLI loads only the DB password into root-only RAM before Docker starts.
The actual managed-secret reboot passed without operator credentials.

Inactive root-only legacy recovery files remain; do not describe all historical
copies as managed-secret-only. The active root and offsite backups are encrypted.
The user declined deletion of the original unencrypted root volume/snapshot.
Original Oracle service is unchanged.

SSH uses ubuntu@100.64.144.15 and the existing key. Public inbound security-group
rules are empty. Tailscale Serve is enabled; Funnel is disabled. Operator profile
aegisai-deploy is temporary and separate from application credentials. Recheck
STS before operator mutations; never mount its cache in apps or sandboxes.

Read [OPERATIONS.md](./OPERATIONS.md) before maintenance or recovery.
