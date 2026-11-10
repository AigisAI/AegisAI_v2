# Signed API/web standby, issue356

Use the signed projected-catalog API image from354, without exposing hostPath,
Docker/scanner sockets or Kubernetes credentials. Restricted PodSecurity and
read-only root filesystems remain. API runs UID/GID1000, web101, all capabilities
dropped, no privilege escalation, RuntimeDefault seccomp, bounded RAM/CPU/tmpfs.
Only API gets the same existing instance-profile access already used by Compose
for Secrets Manager/S3; no AWS permission change or per-pod IAM claim. Other Pods
remain blocked from metadata. Secrets stay startup-memory only; Git has no values.

Helm4.3.1 renders only digest-bound images and fixed private ClusterIP services.
Keep the original frontend bytes and authentication/callback/session configuration.
Use existing Redis and private PostgreSQL six-migration database through named
selectorless services. No migrations, scan, new session fabrication or restoration
in standby. API gets the root-published status ConfigMap as a read-only projected
volume. Keep one API/web initially; rollout surge1 and later API-only HPA1-2.

Ownership: Helm/Argo owns Deployments, ordinary Services, web configuration and
static Pod network rules. Root catalog publisher owns runtime-catalog ConfigMap.
Root endpoint bridge owns EndpointSlices, exact Docker-data/telemetry network
addresses and future Prometheus file-discovery targets. Existing protected
non-secret runtime references populate an operator-owned api-public ConfigMap;
application/SCM secrets are never copied into it. Do not let GitOps overwrite these
operator fields. Later Rollouts/HPA take only their explicitly assigned fields.

The bridge validates named existing containers/networks and health before
advertising endpoints. Permit API DNS, selected data5432/6379, Alloy4318,
existing metadata80 and publicHTTPS443 excluding private/link-local networks.
Web may call API3000, not metadata/SCM/data. Metrics9465 admits only actual
Prometheus; frontend8080 admits only the known ingress/router. No NodePort,
LoadBalancer, public listener, extra compute/registry or new IAM.

Keep Tailscale ingress on the original Compose endpoint. First verify standby
startup, catalog propagation, data/evidence reads, authorization, unchanged UI
assets and bounded telemetry. A failed standby cannot interrupt current traffic.
Rollback is removal/scale-down of only this new Helm release; do not restore SQL,
delete data volumes or disturb the independent gVisor supervisor. Actual cutover,
RollingUpdate/GitOps/scaling and final owner flow need their own evidence.

Pinned-tool references checked2026-11-10:
- https://github.com/helm/helm/releases/tag/v4.3.1
- https://get.helm.sh/helm-v4.3.1-linux-amd64.tar.gz.sha256sum
- https://argo-cd.readthedocs.io/en/stable/user-guide/helm/
