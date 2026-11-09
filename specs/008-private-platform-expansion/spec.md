# Private platform expansion scope

The user requires G1 Blue/Green, G2 Canary, G3 actual Kubernetes RollingUpdate,
G4 HPA, H1 Terraform IaC, H2 GitOps/CD, H3 deployment supply-chain enforcement,
H4 actual Grafana/Loki/Prometheus plus OpenTelemetry tracing. See the existing
execution plan sections 4/G, 4/H, 8 and 9 for binding acceptance.

The target is the existing account 024139495514, region ap-northeast-2 and instance
i-0d24d0502cfc5a9c5. Preserve current owner/org scope, data, independent gVisor
scanner, one heavy scan, readonly bounded source and revoked fetch credentials.
No customer code/build/package execution. No upload or AI finding authority.
AI may remain disabled. Maintain existing theme and private Tailscale ingress.

Cloud resources belong to Terraform; app manifests to Helm/Argo CD; Rollouts owns
traffic strategies and HPA owns API replicas. Do not give multiple controllers
ownership of one field. DB/Redis/broker/supervisor do not scale with API HPA.
No claim of node autoscaling, separate-node isolation or HA on one host.

Phase-1 import must retain all existing resources, access rules, retention,
encryption and policy. User-retained legacy disks/snapshots are out of management.
Default local state uses the existing encrypted root disk, root-only mode and
exclusive operator locking, with no Git/CI artifact upload. A remote backend is
not silently created. Terraform state omits secret versions and nonempty EC2
user-data; management cannot claim full reconstruction while an exclusion remains.

Cloud mutation, operational installs, resource use and costs are recorded per
phase. New paid topology or expanded runtime privilege is not implied by the
user's request. Preserve the general 005/006 external qualification chain.
