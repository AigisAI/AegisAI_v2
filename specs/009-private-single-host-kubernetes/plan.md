# Installation and migration sequence

1. Pin K3s v1.37.2+k3s1, the official stable channel on2026-11-09, and vendor
   SHA256 binary/airgap images. Never pipe a mutable remote install script.
2. Validate exact host, ready/idle scanner, root free space, available memory,
   route/subnet separation and continuing app health. Capture protected before
   state without credentials. Leave the app release and ingress unchanged.
3. Install dedicated root-owned data/config/unit and private-port firewall.
   SQLite is single-host control data, not the app database. Disable unused
   Traefik/ServiceLB/storage/metrics addons and Helm controller. Keep DNS and
   network-policy controller. Install no workload until boundaries are verified.
4. Wait bounded readiness; constrain DNS, create empty restricted app namespace
   with quota/default-deny, check anonymous access rejection, exact sockets,
   metadata deny for system pods and unchanged app IDs/data path. Record actual
   bootstrap evidence; do not mark any G/H requirement newly complete.
5. Pin/render/test later Helm/Argo/Rollouts/router manifests and signed-image
   admission. Import only verified current images, bridge fixed DB/Redis names,
   review exact readonly catalog access and observability/SCM egress. Keep original
   ingress until standby health/auth/data/session acceptance passes.
6. Move traffic with a concrete preserved prior endpoint. Exercise each required
   success/failure strategy and bounded API-only HPA once. Add deep real worker
   tracing separately; only changed worker acceptance needs one actual scan.

Recovery for bootstrap: stop only aegisai-k3s.service. Preserve its data, vendor
artifacts, firewall and previous app. Never run a stock uninstall/killall script
or flush iptables, Docker/scan state or retained disks/snapshots. The original app
has not moved, so no app rollback/SQL restore is needed. Later migration needs
its own tested routing/image rollback and control-state backup before cutover.

Primary sources reviewed2026-11-09:
- https://update.k3s.io/v1-release/channels
- https://github.com/k3s-io/k3s/releases/tag/v1.37.2%2Bk3s1
- https://docs.k3s.io/cli/server
- https://docs.k3s.io/security/hardening-guide
- https://docs.k3s.io/installation/requirements
- https://argoproj.github.io/argo-rollouts/features/traffic-management/traefik/
