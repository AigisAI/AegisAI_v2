# Constrained private GitOps, issue359

Continue the actual signed f340 API/web deployment and retained Docker fallback.
Install Argo CD3.6.1 core controller/repo-server/Redis only, maximum608MiB total,
restricted non-root read-only Pods with bounded temporary storage. No UI, Dex,
ApplicationSet, public service, host socket or AWS permission change. Pin vendor
manifest SHA256 and image digests. This is existing-host software, not new compute.

The root operator alone chooses an immutable Git chart revision and verified
application image digests. Argo pulls the public repository without a GitHub token;
CI does not receive kubeconfig/SSH/AWS secrets. CI GitHub OIDC provenance remains
verified by the independent root H3 importer before promotion. Do not invent AWS
AssumeRole/OIDC permissions: AWS resources remain separately managed by Terraform.

Controller service account has only namespaced app-object rights. It may manage
the ordinary API/web Deployments/Services/ServiceAccounts, web-nginx ConfigMap and
static network rules. No namespace, CRD, RBAC, secret, EndpointSlice or root-owned
runtime-catalog/api-public write in the app namespace. No node/scanner/host access.
Only the controller can access the private Kubernetes API; only repo-server can
reach publicHTTPS. Both may access their isolated Redis, and DNS remains bounded.
Repo-server and Redis mount no Kubernetes token and cannot reach metadata.

Keep root publisher/endpoint/metrics field ownership. HPA replicas and future
Rollouts service selectors/traffic fields require explicit ignore/respect ownership
before those controllers start. Adopt the current Helm resources without changing
Pod specs/serving digests, then verify actual harmless drift correction. Record
Git revision recovery separately from image/app recovery; no destructive restore,
scan replay or qualification claim. H2 is not complete merely on installation.

References checked2026-11-10:
- https://argo-cd.readthedocs.io/en/stable/operator-manual/core/
- https://argo-cd.readthedocs.io/en/stable/operator-manual/cluster-management/
- https://argo-cd.readthedocs.io/en/stable/operator-manual/declarative-setup/
- https://argo-cd.readthedocs.io/en/stable/user-guide/diffing/
