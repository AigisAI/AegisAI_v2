# Requirements Checklist: Production Runtime Infrastructure

- [x] 004 feature package has a canonical quickstart.
- [x] 004 references the completed 003 production AI inference baseline.
- [x] 004 references the completed 002 production scan architecture baseline.
- [x] 004 keeps 001 as the legacy MVP baseline.
- [x] Kubernetes AI Plane deployment preserves advisory-only AI.
- [x] AI does not create authoritative findings.
- [x] AI does not override policy decisions.
- [x] AI does not receive SCM credentials.
- [x] AI does not receive full repositories, source archives, or raw scanner payloads.
- [x] Scanner sandbox provisioning uses stronger-than-pod isolation.
- [x] Scanner sandbox provisioning forbids package install/build, dynamic testing, direct source upload, and auto-fix PR/MR flows.
- [x] Runtime infrastructure work is split into issue-sized package, manifest, autoscaling, and sandbox slices.
- [x] Completion validation points to quickstart and CI rather than duplicating command checklists in README.
