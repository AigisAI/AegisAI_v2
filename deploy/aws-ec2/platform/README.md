# Private platform adoption

Follow the canonical 006 entrypoint and [008 quickstart](../../../specs/008-private-platform-expansion/quickstart.md).
This phase manages existing resources; it does not deploy Kubernetes or replace
the current app. The deployed app source remains ab65d878.

The committed Terraform configuration adopts 12 existing resource addresses:
EC2 with its existing encrypted root block, the private security group, IAM role,
instance profile and inline policy, and seven S3 bucket/configuration resources.
The active root volume has one owner: the instance root block. Retained old
volumes/snapshots, pre-existing VPC/subnet, AWS-managed KMS keys and secret values
are outside this management boundary. Secrets Manager containers/rotation are
also not yet managed here. No cloud resources were created/replaced/changed.

Terraform CLI and AWS provider versions/checksums are pinned. CLI vendor archive
SHA-256 is verified before installation; provider signatures/checksums are checked
by Terraform and its committed lockfile. These controls do not complete H3's
separate deployment-image signing requirement.

Existing EC2 user-data was checked empty before adoption. A nonempty value blocks
adoption rather than placing bootstrap secrets in state. State and plans stay in
root-only `/opt/aegisai/platform` on the existing encrypted disk. Provider cache
uses protected tmpfs. The app gets neither state nor operator credentials.

The existing short-lived operator login is exported through `credential_process`
only to the provider/native operator CLI in memory. No long-lived AWS keys are
added to code, state, image, CI or application settings. The runtime instance
role is unchanged; it is not broadened for Terraform.

Protected operator commands after source verification/installation:

```text
sudo python3 -E -s -B /opt/aegisai/operator/platform-340/code/manage_terraform.py import
sudo python3 -E -s -B /opt/aegisai/operator/platform-340/code/manage_terraform.py plan
sudo python3 -E -s -B /opt/aegisai/operator/platform-340/code/state_proofs.py
sudo python3 -E -s -B /opt/aegisai/operator/platform-340/code/backup_state.py
```

There is no apply action in this wrapper. Import updates local bookkeeping only.
All resource mutations, replacements, incomplete plans and destruction are
rejected; `prevent_destroy` additionally protects each managed resource.
Use the exclusive operator lock for all operations. Never bypass it with a
concurrent raw Terraform command.

Live adoption produced zero additions, changes and deletions. The safety proof
compares intentionally stale **isolated test state** against real AWS metadata;
it does not alter cloud tags or production state. A destruction-only plan is
rejected without executing deletion. These are targeted new-path checks, not a
repeat of application/scanner suites.

State snapshots use create-only SSE-KMS objects in `infrastructure-state/340/` in
the existing private bucket. Runtime IAM cannot read that prefix. Download hash,
decompression and isolated restored-state no-op plan were verified. The live
state is never restored by this proof. Snapshot cleanup/retention automation is
pending; the existing evidence/backups lifecycle does not cover this prefix.

The local backend has one root-only operator host and protected off-host snapshots;
it is not a multi-operator remote backend. Full machine/application reconstruction,
remaining resource coverage and production recovery under host loss are still
unverified, so H1 remains partially complete. Do not infer completion of any G/H
requirement from import/no-op alone.
