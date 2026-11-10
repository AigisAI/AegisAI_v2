# Single-instance deployment constraint — 2026-11-07

Status update: the investigation below resulted in the private gVisor/containerd
deployment on 2026-11-08. Current evidence and remaining baseline deviations are in
[production documentation](../../docs/production/README.md). Preserve the original
constraint and rationale below; it is not an instruction to repeat provisioning.

The user explicitly requires the existing EC2 instance only and rejected additional
compute, including Fargate. Do not create another VM, cluster node, Fargate task or
NAT Gateway. No extra-compute monthly budget was granted. The existing 2-vCPU,
8-GB m7i-flex.large host is the sole compute target.

This constraint conflicts with the DOCX baseline's control-node/scan-workload
separation. Preserve that baseline as the multi-tenant product target; do not
silently describe same-host containers as compliant. Investigate gVisor systrap,
which does not require /dev/kvm, using a dedicated containerd daemon/socket/state
directory and no app Docker socket access. Same-host management and availability
remain shared risks even if sandbox isolation tests pass.

The actual repository owner is the AigisAI organization (ID 241095585), and goodtu02
(ID 161540124) is a verified active organization administrator. Do not restrict the
implementation to personal repositories. Use the separate organization-owned App
and read-only organization membership verification. Initial same-host operation
must be restricted to the explicitly admitted operator account and organization;
public multi-tenant onboarding is outside this constrained operating profile.

Before repository execution: define the permitted private operator/organization scope,
enforce account/tenant admission, review the deviation, and prove no network,
read-only inputs/root, ephemeral per-scan storage, resource/time/process limits,
credential removal before parsing and sandbox destruction. Ordinary runc isolation
is not an acceptable fallback. Deny unsupported hardened/restricted profiles.

Runtime installation and trusted fixture tests may proceed while application ingress
stays closed. They do not grant approval for general multi-tenant launch, prove
scanner correctness or meet availability objectives. Continue the real GitHub App,
OAuth, queue/worker, evidence, policy/UI and recovery gates independently.

See `single-host-security-review.md` for the implementation threat review, permitted
private scope, residual risks and checks required before repository processing.
