# Requirements Checklist: Production Deployment Operations

- [x] 005 feature package has a canonical quickstart.
- [x] 005 references the completed 004 runtime infrastructure baseline.
- [x] 005 references the completed 003 production AI inference baseline.
- [x] 005 references the completed 002 production scan architecture baseline.
- [x] 005 keeps 001 as the legacy MVP baseline.
- [x] live production Kubernetes cluster provisioning is scoped as explicit operations work.
- [x] provider-specific microVM platform rollout is scoped as explicit operations work.
- [x] provider credentials are not introduced as local development defaults.
- [x] Oracle VPS and Docker Compose remain dev/demo paths only.
- [x] Completion validation points to quickstart and CI rather than duplicating command checklists in README.
- [x] The detailed SAST runtime and rule-governance follow-up is handed to `006-production-sast-runtime-design` before live scanner rollout.
- [x] 005 preflight has no evidence-free path and accepts only a fresh Qualification Authority-signed T056 `GO` bound to the exact current 005 contract.
- [x] The qualification binding preserves the T056 record, manifest, plan, repository commit, provider/adapter, rollback target, kill-switch evidence, contract revision, and expiry.
- [x] Preflight requires all three credential scopes and approval kinds, exact provider/adapter matching, trusted-time audit, and digest-bound reference-only resources.
- [x] Handoff starts before qualification expiry, lasts no more than eight hours, and uses the exact T056 rollback target.
- [x] Passing repository validation grants only `deploymentOperationsEntryAuthorized`; live deployment, Kubernetes execution, provider/production mutation, and production-readiness authority remain forbidden.
- [x] T056 revisioned assets pin the exact normalized 005 deployment-operations contract digest.
