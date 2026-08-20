# Specification: Production Deployment Operations

## Scope

This milestone defines the final repository-owned boundary before live production
Kubernetes cluster provisioning and provider-specific microVM rollout. It does
not provision a real cluster, call a provider, or require provider credentials.
It validates that live-operation inputs are reference-only and cryptographically
bound to a fresh, immutable T056 `GO` decision for the same repository commit,
provider, adapter, rollback target, kill-switch evidence, and 005 contract
revision.

## In Scope

- Provider-neutral production cluster provisioning and plane-separation contract
- Provider-specific microVM rollout and scanner-sandbox boundary contract
- Explicit credential-scope and operator-approval reference model
- Qualification Authority Ed25519 deployment-entry attestation over T056 `GO`
- Digest-bound `DeploymentSastQualificationBinding` consumed by preflight
- Trusted-time, expiry, provider/adapter, audit, rollback, and execution-window checks
- Dev/demo Oracle VPS path preservation as a non-production deploy path
- Documentation and active 006 qualification handoff synchronization

## Out of Scope

- Creating or mutating a live production Kubernetes cluster in this slice
- Executing provider CLIs or provider-specific microVM APIs
- Storing provider credentials, kubeconfigs, or secret values in repository files
- Adding provider credentials as local-development defaults
- Treating repository tests or synthetic signatures as external T053-T056 evidence
- Customer code execution outside hardened scan isolation
- Package install/build, dynamic testing, auto-fix PR/MR, or direct source upload
- AI finding authority, policy override, SCM mutation, or deployment authority
- AI access to SCM credentials, full repositories, source archives, or raw scanner payloads

## Requirements

- Production cluster provisioning MUST preserve separated Control, Scan, AI, and
  Data/Security planes.
- Provider-specific microVM rollout MUST preserve stronger-than-pod scanner
  isolation and explicitly deny package install, repository build, dynamic test,
  direct source upload, and auto-fix PR/MR capabilities.
- Preflight MUST have no evidence-free validation path. It MUST receive the exact
  T056 record, its Qualification Authority Ed25519 deployment-entry attestation,
  a canonical digester, an injected signature verifier, and trusted UTC time.
- The T056 record MUST be valid `GO` with all 54 gates passed, zero failed or
  not-applicable gates, and a contract reference/digest for the exact current 005
  deployment-operations contract.
- The signed qualification binding MUST preserve the T056 record, manifest,
  plan, repository commit, provider, adapter, rollback, kill-switch, contract,
  authorization-time, and expiry identities without caller substitution.
- The entry attestation MUST be created within one hour of the T056 decision,
  MUST be valid for at most one hour, and MUST be fresh at trusted evaluation time.
- Cluster, microVM, audit, and qualification provider identities MUST match;
  microVM and qualification adapter references MUST match; cluster and microVM
  regions MUST match.
- Preflight MUST contain exactly the three credential scopes and exactly the
  production-change, security-boundary, and credential-handoff approval kinds.
  Each approval MUST bind the qualification digest and remain valid at trusted time.
- External resource and approval inputs MUST be digest-bound, reference-only,
  bounded values. Unknown fields and forbidden payload values MUST fail closed.
- Handoff MUST repeat the full preflight evidence validation, start before the
  qualification expiry, last no more than eight hours, and use the exact T056
  rollback target.
- Every qualification and handoff authority bit except
  `deploymentOperationsEntryAuthorized` MUST remain false. Passing validation
  MUST NOT execute Kubernetes, mutate a provider or production, or establish
  production readiness.
- Oracle VPS and Docker Compose MUST remain documented as dev/demo paths only.

## Acceptance

- `DeploymentSastQualificationEntryAttestation` binds a valid current-contract
  T056 `GO` record and verifies a real Ed25519 Qualification Authority signature.
- `DeploymentSastQualificationBinding` is reconstructed from verified evidence
  and rejected on record, signature, time, commit, provider, adapter, rollback,
  kill-switch, contract, digest, or authority drift.
- `DeploymentOperationPreflight` rejects non-GO, missing evidence, expired or
  future evidence, wrong-role/invalid signatures, provider drift, approval drift,
  unknown fields, and forbidden payload fields.
- `DeploymentOperationHandoffManifest` rejects expired qualification entry,
  overlong windows, and rollback-target drift while remaining reference-only.
- T056 revisioned assets pin the exact current 005 contract digest.
- Repository validation proves the contract behavior but does not claim external
  T053-T056 execution or live deployment readiness.
- The completion gate stays synchronized with CI and the active 006 quickstart.
