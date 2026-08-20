# Data Model: Production Deployment Operations

## Entities

### DeploymentSastQualificationEntryAttestation

- exact T056 record, manifest, and plan IDs/digests
- exact repository commit, provider ID, and provider-adapter reference
- exact rollback target and kill-switch evidence IDs/digests
- exact current 005 contract reference/digest
- `recordDecidedAt`, `attestedAt`, and `expiresAt`
- exactly 54 expected and passed gates
- Qualification Authority Ed25519 signature over the canonical attestation digest
- only `deploymentOperationsEntryAuthorized=true`; all execution/readiness and
  finding/policy/publication/SCM/AI authority flags false

### DeploymentSastQualificationBinding

- immutable projection of the verified record and entry attestation
- authorization and expiry instants
- deterministic `bindingId` and `bindingDigest`
- no secret values and no live-operation authority

### ProductionClusterProvisioning

- `environment=PRODUCTION`
- exact T056-qualified provider identity
- region and cluster name
- four distinct Control, Scan, AI, and Data/Security plane namespaces
- no plane may use a Kubernetes reserved namespace
- distinct digest-bound network-boundary references and audit-sink reference

### MicroVmPlatformRollout

- exact T056-qualified provider and provider-adapter reference
- region and platform name
- `HARDENED | RESTRICTED` isolation class
- scanner sandbox, token broker, evidence storage, and egress-policy references
- positive TTL no greater than 7,200 seconds
- exact ordered denial of package install, customer repository build, dynamic
  test execution, direct source upload, and auto-fix pull request capabilities

### DeploymentCredentialBoundary

- digest-bound credential-provider reference
- exactly one of `CLUSTER_ADMIN`, `MICROVM_PLATFORM_ADMIN`, or
  `SECRET_MANAGER_ADMIN`
- `allowedUse=EXPLICIT_DEPLOYMENT_OPERATION`
- `localDevelopmentDefault=false`
- `repositoryPersisted=false`
- `rotationRequired=true`
- `auditRequired=true`

### DeploymentOperatorApprovalReference

- exactly one production-change, security-boundary, or credential-handoff approval
- digest-bound approval reference
- `subjectDigest` equal to the qualification binding digest
- approval and validity instants; maximum validity is 24 hours

### DeploymentOperationAuditSignal

- production environment and exact qualified provider
- digest-bound operation ID
- deployment operator, Control Plane, or Data/Security Plane actor
- exact `SAST_QUALIFICATION_BINDING` target and binding ID
- exact `DEPLOYMENT_PREFLIGHT_VERIFIED` event
- occurrence time equal to verifier-owned trusted UTC

### DeploymentOperationPreflight

- one valid cluster-provisioning boundary
- one valid microVM-rollout boundary
- exactly three ordered credential boundaries
- one verified SAST qualification binding
- one exact audit signal
- exactly three ordered operator approvals
- digest-bound KMS, secret-manager, object-storage, and DNS references

### DeploymentOperationHandoffManifest

- one fully revalidated preflight
- external secret-manager reference or ephemeral OIDC federation handoff mode
- future execution window beginning before qualification expiry and lasting at
  most eight hours
- exact T056-qualified rollback reference
- digest-bound incident, dry-run-evidence, and change-ticket references

## State

- `qualification_blocked`: T053-T055 or required T056 evidence is not complete
- `qualification_no_go`: T056 evidence is invalid, stale, drifted, or breached
- `qualification_go`: all T056 gates pass, but only 005 entry is authorized
- `entry_attested`: a fresh Qualification Authority signature binds the exact GO
- `preflight_verified`: repository-owned reference and boundary checks pass
- `handoff_ready`: a bounded reference-only operator envelope passes validation
- `provisioning`: a separately authorized external operation is changing resources
- `validating`: live plane/runtime health is being checked externally
- `ready`: live production readiness has been established outside this contract
- `rolled_back`: an authorized operation followed the qualified rollback target
- `failed`: an external operation failed and requires audit-visible follow-up

Repository code in this milestone can reach only `handoff_ready`. It cannot set
`provisioning`, `validating`, `ready`, `rolled_back`, or live-operation success.

## Boundary Rules

- Unknown fields fail closed on attestations, bindings, preflight, and handoff.
- Non-GO, incomplete, wrong-contract, stale, future, invalid-signature, or
  authority-widened qualification evidence cannot produce a binding.
- The provider, adapter, repository commit, rollback target, kill-switch evidence,
  and 005 contract revision cannot change after T056.
- Provider identity integrity comes from the signed T056 chain; all external
  resource, adapter, approval, credential, audit, and handoff references are
  digest-bound and reference-only.
- Credential values, kubeconfigs, SCM tokens, full repository content, source
  archives, and raw scanner payloads are never model fields.
- AI remains advisory-only and receives no repository or deployment credentials.
- Passing preflight or handoff grants no deployment, Kubernetes execution,
  provider mutation, production mutation, or production-readiness authority.
