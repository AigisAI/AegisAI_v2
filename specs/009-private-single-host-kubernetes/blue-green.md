# Actual private API Blue/Green, issue367

Enter canonical002/private003 and integrated006/008/009 first. Preserve the
approved one-existing-EC2 private scope and unpassed general qualification.
Read current production checkpoint and rolling/scaling.md before execution.

Keep the existing API Deployment, web, Git and data as a ready fallback. Install
Argo Rollouts1.10.2 with vendor-hashed CRDs and amd64 digest. Its single controller
runs in its own bounded aegisai-rollouts namespace, watches only aegisai-private, and has no cluster-admin,
AWS/metadata, operator credentials, app Secrets, node or RBAC access. Notification
informers see only controller-namespace configuration/Secrets, not application data.
Restricted PodSecurity,96MiB/250m ceiling, read-only filesystem and bounded tmp
apply. Root installs CRDs; the controller never receives CRD privileges.

The separate API Rollout api-blue-green uses the same restricted Pod template,
catalog projection, signed images, managed credentials and backend policies.
Use a distinct delivery label in its selector so its ReplicaSets cannot be
adopted by the fallback Deployment. Existing component labels retain source-aware
metrics and policy. Blue/Green Services api-bg-active/preview belong to Rollouts;
Argo's existing Deployment chart cannot reconcile them. Root controls the desired
Rollout template; controller may update only status/operational fields and the
two named selectors. HPA continues to own only the original Deployment during
this bounded verification. Temporarily cap it at1 while the Rollout retains up
to2 API replicas, keeping the absolute API total3. It is restored afterward.

Use one additional restricted web-bg Pod with the unchanged original signed web
image and a root-reviewed Nginx config targeting api-bg-active. This preserves
the app's existing API prefix/headers/private outer allowlist. Existing web stays
ready, so the total web maximum2 and application namespace quota6 still hold.
Private ingress may select web-bg only after active/preview endpoints are Ready,
exact source/digest verification passes freshly, session/data checks pass and a
root fail-safe restoration timer is armed. No public ingress or AWS change.

Initial Rollout uses the current signed3ed API. Change its template to the freshly
verified previous f340 API with autoPromotionEnabled=false. Verify both Ready
version endpoints and existing owner session, then actually promote the preview
and observe Service selector/EndpointSlice/version and real private responses.
Switch back to3ed and restore original ingress/HPA. The previous f340 API has
per-process throttling, so it must remain exactly1 replica; this bounded rollback
exercise does not certify its multi-replica security. No scan/schema/DB restore.
All switches record health, bounded response latency, endpoint Pod/image and
transition seconds. A readiness-only result or controller installation is not G1.

Failure recovery: restore the original ingress content/inode and root traffic
state first, then scale api-blue-green/web-bg to0 and restore original HPA1..2.
An independent root timer runs the same recovery if the verifier is interrupted.
Do not delete retained images, data, original Deployment/web or control state.
Keep source archive/freshness and isolated scanner budgets intact. Reject mutation
if capacity, role boundaries, Git ownership or pinned image availability diverge.

G2 weighted Canary and Argo declarative adoption of this separate profile follow
separately. G1 acceptance does not close G2/fullH2 or general005/006 gates.

Primary references reviewed2026-11-10:
- https://argoproj.github.io/argo-rollouts/features/bluegreen/
- https://raw.githubusercontent.com/argoproj/argo-rollouts/v1.10.2/cmd/rollouts-controller/main.go
- https://raw.githubusercontent.com/argoproj/argo-rollouts/v1.10.2/utils/defaults/defaults.go
- https://github.com/argoproj/argo-rollouts/tree/v1.10.2/manifests
