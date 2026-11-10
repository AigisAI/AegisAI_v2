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

2026-11-10 migration update: exact signed f340a441f366 source now serves private
traffic through one Ready API and web. Native catalog rotation, managed secret
loading/data/authorization/original HTML and actual per-Pod metrics passed.
Activate->original Docker rollback->reactivate passed. Legacy Compose mutation
entrypoints now reject while Kubernetes owns traffic. General qualification and
all G1-G4/H2/deep-H4 requirements remain open. Current owner session acceptance
was not available (no unexpired session); no synthetic session or OAuth repetition.

Issue359: bounded Argo core is live and actually Synced/Healthy. Native RBAC and
repo metadata/token boundaries passed, harmless drift restored in3.631s, and
immutable Git forward/back/forward passed without further Pod replacement. Image
promotion/CD integration and future HPA/Rollouts field ownership remain; H2 is
partial. See gitops.md. All four G requirements and deep-H4/H1 recovery remain.

Issue361: actual API1->2->1, missing metrics retention and collector recovery passed. Existing real owner session/data/evidence also passed afterward. Complete shared atomic request throttling across replicas before closing full G4 security acceptance; see scaling.md.
