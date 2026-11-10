# Actual private platform continuation

- [x] Record owner approval and preserve general qualification truth.
- [x] Review exact host/capacity/network/scanner boundaries and bootstrap recovery.
- [x] Test fail-closed native preflight and pin/check vendor bytes.
- [x] Install bounded private K3s alongside unchanged app; capture actual readiness.
- [ ] Enforce signed-image admission and least-privilege app/control networking.
- [ ] Migrate API/web with existing auth/session/SCM/data/telemetry preserved.
- [ ] H2 actual GitOps/CD, field ownership, drift and Git/app recovery.
- [ ] G3 actual Deployment RollingUpdate and bad-candidate recovery.
- [ ] G1 actual Blue/Green switch/back with data/session preservation.
- [ ] G2 actual measured Canary and automatic abort/recovery.
- [ ] G4 actual bounded API HPA1->2->1 and metric-failure behavior.
- [ ] H4 actual scan/queue/broker/worker trace correlation.
- [ ] H1 remaining resource/reconstruction and bounded final recovery/cost proof.

H3 private API/web signature enforcement and actual collector failure/recovery
Slack acceptance are already recorded in the previous deployment checkpoint.
No bootstrap or configuration-only proof completes the above acceptance items.

Bootstrap evidence: source e395386187e9f6ec2b360f73f6e4e466b5d7e871,
CI42731876689 passed; one actual Ready node v1.37.2+k3s1, root-only kubeconfig,
private control listeners, encrypted control Secrets, restricted empty application
namespaces/default-deny and ready DNS. Docker application IDs/images/release
remain unchanged. No real scan, restore, traffic migration, GitOps or G1-G4 proof.
