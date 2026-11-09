# Root encryption and recovery procedure

This is maintenance on the existing EC2, not a second compute deployment. Use an
independently verified temporary AWS operator session outside the target machine.
Do not rely exclusively on credentials or SSH inside the machine being rebooted.

1. Verify account, instance ID, current root volume, AZ, size and encryption. Check
   permission to snapshot, create an encrypted same-AZ gp3 volume and replace root.
   Dry-run authorization is not a guarantee of KMS/volume completion.
2. Install `restore-after-root-replacement.sh` root-only and enable
   `aegisai-root-restore.service`. Confirm Docker and Tailscale boot enablement.
   Record the active candidate and create `/opt/aegisai/shared/root-encryption.resume`.
3. Gracefully stop only the known app/verification containers and scan daemon;
   refuse unknown running containers. Flush writes and snapshot the original root.
   Keep workloads stopped: writes after this point would not appear in the copy.
4. Wait for snapshot completion. Create an encrypted 30-GiB gp3 volume from it in
   the instance AZ. Verify available/encrypted, then create the root replacement
   task with that volume and `DeleteReplacedRootVolume=false`.
5. Poll the task from the independent operator session. AWS reboots the instance;
   do not issue an additional reboot. The marker-gated unit restores the candidate
   and ingress and removes the marker only after health succeeds.
6. Independently verify root attachment/encryption, old-volume retention, EC2 status,
   Tailscale, all app health checks, recorded private ingress state,
   persisted identity, instance-role managed secret retrieval and gVisor isolation.
   Run `verify-data-recovery.py` against a unique disposable verification DB to
   prove the fresh backup's migration and entity counts match the live database.

Keep task/snapshot/volume identifiers in operator state. If a task fails, inspect
actual attachment and task failure before any retry. Restore original workloads
from the marker script if the original root remains attached. If replacement
succeeded but the guest is unhealthy, use the retained original volume through a
new root replacement task, then investigate before attempting encryption again.
Never delete or detach a volume by a guessed identifier.

The original root and source snapshot are unencrypted rollback artifacts and incur
storage charges. Retention is temporary; take and verify an encrypted rollback
snapshot before their separately reviewed cleanup. Do not claim all historical
copies are encrypted while these artifacts remain. No full recovery, RTO or
multi-tenant availability claim follows from a successful small-database restore.

AWS reference: [Replace the root volume](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/replace-root.html).

Current managed runtime requires aegisai-runtime-secrets.service before Docker,
the native AWS CLI and the instance profile. The root restore helper includes any
frontend-only web-release.override.yaml. See OPERATIONS.md for current backup and
managed boot evidence. Earlier root replacement steps remain historical maintenance
guidance, not instructions to perform another root replacement now.
