# Private one-host production scope

The owner explicitly authorizes this narrower same-host private production
scope, not a demo and not general-service qualification. Admit only existing
owner161540124 and selected organization241095585 repositories. Keep independent
containerd/gVisor, no customer code/build/package execution, immutable source,
one heavy scan, advisory-only optional AI, separate login/SCM authority, sessions,
CSRF/throttling and bounded encrypted evidence. No direct upload or public signup.

Kubernetes may run management and API/web on the same existing host. DB, Redis,
broker and scan supervisor remain outside it and are not replicated by HPA.
No separate-node isolation, node autoscaling or HA claim. General T053-T056 and
005 signed qualification remain unchanged and NOT_QUALIFIED; this package does
not issue their GO or authorize their provider execution.

Budget: existing2CPU/7776MiB/50GiB only. Before bootstrap require4GiB available
memory and6GiB free disk. Reserve existing scanner1GiB and >3GiB disk throughout
later operation. K3s service maximum1536MiB/1CPU, intended idle below1GiB.
Kubelet reserves4096MiB for host/Docker workloads and1024MiB for Kubernetes,
evicts at512MiB available. API later1-2 replicas, maximum3 including surge,
320MiB each; web64MiB, router96MiB, Argo core608MiB, Rollouts96MiB,
metrics64MiB and DNS64MiB ceilings. These are budgets, not measured capacity or
performance claims. Re-measure and refuse stages when coexistence is insufficient.

Only private node172.31.55.151 binds Kubernetes API/kubelet. Host firewall admits
loopback, self and pod10.44/16 only; no SG or Tailscale Serve change. Service
CIDR10.45/16 and pod10.44/16 must not overlap live routes. Use host-gw on the
single node, no VXLAN listener, ServiceLB, NodePort ingress or default Traefik.
Use a separate K3s data/runtime socket, never Docker or scanner containerd.
Root-only kubeconfig, local encrypted control data, Secret encryption, metadata-
only bounded audit, no anonymous API/kubelet access. No cluster admin in CI/app.

Application migration must first enforce digest allowlists bound to actual H3
signature receipts, least-privilege RBAC and default-deny network rules. Existing
API-only instance-role access, if retained for existing Secrets Manager/S3 calls,
must be explicitly bounded to that workload; management/router/other pods cannot
reach metadata. It is shared host IAM, not per-pod IAM. No secret in Git/env
metadata or durable signing-key fallback. Any catalog hostPath exception must
be exact/read-only and admitted separately before changing PodSecurity policy.

Terraform owns cloud resources; Helm/Argo own declarative workloads; Rollouts
owns selected Services/traffic; HPA owns replicas. Demonstrate actual normal
Deployment RollingUpdate separately from Rollouts, actual Blue/Green switch/back,
measured weighted Canary abort/recovery, and real HPA1->2->1. Management installation
and local fixtures cannot satisfy these. Keep all eight G/H requirements tracked.
