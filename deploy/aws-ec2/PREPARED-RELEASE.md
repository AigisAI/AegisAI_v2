# Prepared private EC2 release

This profile replaces neither the general API nor its schema. Follow
[007 quickstart](../../specs/007-private-ec2-integration/quickstart.md).
The current request ends before deployment. Nothing below authorizes `--apply`.

Hosted CI checks both profiles and emits `private-ec2-candidate-<CI source SHA>`.
The artifact contains the Git source archive, API/web Docker save archives,
profile, validator, future deployment script and hashed `candidate.json`.
The CI source SHA is the tested PR merge commit, not necessarily the branch tip.
Record the run URL, artifact digest and manifest SHA from that successful run.
Download before the three-day artifact expiry; do not rebuild on the EC2.

Preparation performs an offline artifact check, then a read-only SSH snapshot
using `tools/private-runtime/read-target.py`. Validate with:

```text
python check-candidate.py <candidate-directory> --manifest-sha256 <trusted SHA> --target-snapshot <snapshot.json>
```

The snapshot expires after 15 minutes. It requires the existing instance, exact
six-migration family, all seven byte-identical installed host modules, idle ready
scanner and room for image replacement plus 3 GiB reserve. No Docker load, service
restart, SQL write, secret change or ingress change occurs in this preflight.

Only after a later user deployment instruction, transfer the verified artifact
via the existing Tailscale connection to a private operator directory. Recheck
all hashes using the trusted CI manifest SHA. On the server, the default command
only checks readiness:

```text
sudo sh <candidate-directory>/deploy-prepared.sh <candidate-directory> <trusted SHA> --check
```

A later explicit `--apply` pauses ingress, records the previous app release and
web override, loads the prebuilt images, backs up the existing database, checks
its private migration history and replaces API/web/broker. It preserves current
Postgres/Redis volumes and host workers. Public ingress is never added. Direct
legacy server-build deployment modes are retired for this integrated profile.

Ingress stays closed after replacement until affected real acceptance succeeds:
managed-secret startup, health, existing login/session, selected repository and
prior scan retrieval, evidence authorization/expiry and idle scanner readiness.
Do not rerun scans or restore backups unless that release changes those paths.
This prepared candidate has not passed these post-deployment checks yet.

On failure keep ingress paused. The root-only `operator/before-<release>.json`
records the previous release and exact web override. Restore those previous
image/Compose references and restart their broker and API/web before reopening
private ingress. No schema changes are introduced by this candidate; do not
restore/delete the production DB automatically. Keep existing images and backups.
A historical root restore proof does not certify rollback of this new candidate.

This is single-host replacement with a maintenance window. Blue/green, canary,
rolling zero-downtime and HPA are not implemented or claimed. General 006
external qualification and Kubernetes rollout remain independently blocked.
