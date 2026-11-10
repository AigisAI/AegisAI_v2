# Signed local image admission phase, issue352

Keep existing application traffic on Compose. Reuse the exact H3 API/web candidate
only after current root-approved source, cryptographic provenance/SBOM, fresh
vulnerability scan and target compatibility verification. Import into K3s' distinct
k8s.io containerd namespace, not the independent scanner runtime. Bind imported
target digest to the already verified image archive and tag it by exact repository
digest. No registry or GitHub credentials are introduced.

Root writes the operator-only digest ledger and cluster-scoped fail-closed
ValidatingAdmissionPolicy. The empty aegisai-private namespace selects its binding.
Every main/init image must equal an approved digest; mutable tags and ephemeral
debug containers are rejected. Pod credentials are not automounted. Keep the
namespace's restricted PodSecurity and default-deny ingress/egress; permit DNS
only. Do not yet allow AWS metadata, SCM, DB, Redis, telemetry or catalog hostPath.
These are later explicit migration exceptions, not silently required for this probe.

Use actual rejected Pod CREATEs for unknown digest, mutable tag, privileged mode
and host Docker socket. A bounded trusted Node probe from the approved API image
then checks real DNS, blocked metadata/control API and absent service-account
token, without app startup, SCM/DB credentials or customer input. Remove only
this exact probe Pod/UID. Preserve original running container IDs and release.
This verifies initial admission/network boundaries, not API migration, GitOps,
workload-specific egress, rollout/scaling or general qualification completion.
