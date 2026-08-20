# Plan: Production Deployment Operations

## Approach

Keep deployment operations in two deliberately separate stages. Repository code
first validates a signed, fresh T056 `GO` decision and builds a reference-only
preflight/handoff envelope. A later, explicitly authorized operations run may
consume that envelope with provider credentials. The repository stage never
calls Kubernetes or a provider and never manufactures external qualification
evidence.

## Target Boundaries

- `specs/005-production-deployment-operations`: normative deployment-entry,
  preflight, handoff, and live-operation boundary
- `specs/006-production-sast-runtime-design`: T053-T056 qualification producer
  and evidence rules
- `packages/shared`: public immutable qualification-entry, cluster, microVM,
  credential, approval, audit, preflight, and handoff contracts
- `qualification/t056-v1`: revisioned T056 manifest/policy that pins the exact
  005 contract digest
- `deploy/kubernetes`: future provider-neutral production cluster overlays
- `deploy/scanner-sandbox`: future provider-specific microVM rollout inputs
- `docs`: future provider runbooks and environment-specific support documents

## Runtime Shape

1. T053-T055 execute externally on one production-equivalent provider and emit
   their complete signed evidence; T056 independently verifies the chain.
2. T056 recomputes all 54 gates and emits `GO` only when every mandatory gate and
   final approval passes. Every execution/readiness authority remains false.
3. A Qualification Authority signs a deployment-entry attestation within one
   hour of the T056 decision. The attestation expires no more than one hour later.
4. The 005 verifier uses trusted UTC, an injected Ed25519 verifier, and canonical
   digester to reconstruct one immutable qualification binding.
5. Preflight verifies the exact provider, adapter, repository commit, contract,
   rollback target, kill-switch evidence, three credential boundaries, three
   operator approvals, plane separation, resource references, and audit signal.
6. Handoff repeats preflight verification and adds a bounded future execution
   window, the exact qualified rollback plan, incident channel, dry-run evidence,
   change ticket, and reference-only credential handoff mode.
7. Only a separate authorized live operation may use provider credentials to
   provision Kubernetes or roll out microVMs. Passing repository validation is
   not that authorization.

## Key Interfaces

- `DeploymentSastQualificationEntryAttestation`: short-lived Qualification
  Authority Ed25519 signature over exact T056 and current 005 contract bindings
- `DeploymentSastQualificationBinding`: digest-bound preflight subject rebuilt
  only from the signed record and attestation
- `ProductionClusterProvisioning`: provider, region, four plane namespaces,
  network boundaries, and audit sink references
- `MicroVmPlatformRollout`: exact qualified provider/adapter, region, hardened
  sandbox, token broker, evidence storage, egress policy, TTL, and denied capabilities
- `DeploymentCredentialBoundary`: one fail-closed record per required admin scope
- `DeploymentOperatorApprovalReference`: digest-bound approval over the exact
  qualification binding with bounded validity
- `DeploymentOperationAuditSignal`: trusted-time preflight attribution over the
  qualification binding without free-form payloads
- `DeploymentOperationPreflight`: exact closed object combining all verified inputs
- `DeploymentOperationHandoffManifest`: reference-only operator envelope with an
  at-most-eight-hour execution window and exact rollback target

## Completion Strategy

Use contract and runtime tests for both the passing path and every authority-
widening/replay path. Regenerate T056 assets whenever the normalized 005 contract
changes, pin the new manifest digest in tests, then run the active 006 validation
path. Stop before any step that needs provider credentials, Kubernetes access, or
real production-equivalent qualification execution.
