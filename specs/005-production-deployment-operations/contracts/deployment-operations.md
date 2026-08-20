# Contracts: Production Deployment Operations

This contract is the repository-owned boundary between a successful SAST
production qualification and a separately authorized live deployment operation.
Every validator in this contract is fail closed. A passing value authorizes only
entry into the deployment-operations workflow; it does not authorize Kubernetes
execution, provider mutation, production readiness, finding publication, policy
changes, SCM mutation, or AI actions.

All timestamps are canonical RFC 3339 UTC instants in JavaScript ISO form, for
example `2026-08-20T20:32:00.000Z`. The T056-bound provider identity is a safe
URI without a query or fragment. Every other external reference is a safe URI,
is reference-only, ends in `/sha256:<64 lowercase hexadecimal characters>`, and
is limited to 2,048 UTF-8 bytes. Secret values, kubeconfigs, SCM tokens, full
repositories, source archives, and raw scanner payloads are forbidden
throughout this contract.

## ProductionClusterProvisioning

```ts
interface ProductionClusterProvisioning {
  environment: "PRODUCTION";
  provider: string;
  region: string;
  clusterName: string;
  controlPlaneNamespace: string;
  scanPlaneNamespace: string;
  aiPlaneNamespace: string;
  dataSecurityNamespace: string;
  networkBoundaryRefs: string[];
  auditSinkRef: string;
}
```

The provider must be the exact provider identity bound by the signed T056
record. Its integrity comes from the qualification record, entry attestation,
and binding digests rather than a second provider-identity digest suffix. The
four plane namespaces must be distinct DNS labels. `networkBoundaryRefs` must
contain at least four and no more than 64 distinct digest-bound references.
Production cluster provisioning must preserve separate Control, Scan, AI, and
Data/Security plane namespaces or equivalent trust boundaries. Region, cluster,
and platform names cannot contain path separators. Plane namespaces cannot use
`default`, `kube-system`, `kube-public`, or `kube-node-lease`.

## MicroVmPlatformRollout

```ts
interface MicroVmPlatformRollout {
  provider: string;
  providerAdapterRef: string;
  region: string;
  platformName: string;
  isolationClass: "HARDENED" | "RESTRICTED";
  scannerSandboxProfileRef: string;
  tokenBrokerRef: string;
  evidenceStorageRef: string;
  egressPolicyRef: string;
  ttlSeconds: number;
  forbiddenScannerCapabilities: [
    "PACKAGE_INSTALL",
    "CUSTOMER_REPOSITORY_BUILD",
    "DYNAMIC_TEST_EXECUTION",
    "DIRECT_SOURCE_UPLOAD",
    "AUTO_FIX_PULL_REQUEST"
  ];
}
```

Provider-specific microVM rollout must isolate repository fetch and scanner
execution from the Control Plane and AI Plane. The provider and adapter must be
identical to those qualified by T056. The sandbox profile must explicitly deny
all five forbidden capabilities in the canonical order. A positive TTL of at
most 7,200 seconds is mandatory; this contract does not turn the rollout
description into a live microVM operation.

## DeploymentCredentialBoundary

```ts
interface DeploymentCredentialBoundary {
  credentialProvider: string;
  credentialScope:
    | "CLUSTER_ADMIN"
    | "MICROVM_PLATFORM_ADMIN"
    | "SECRET_MANAGER_ADMIN";
  allowedUse: "EXPLICIT_DEPLOYMENT_OPERATION";
  localDevelopmentDefault: false;
  repositoryPersisted: false;
  rotationRequired: true;
  auditRequired: true;
}
```

Preflight requires exactly one boundary for each credential scope in the order
shown above. Deployment credentials are explicit operation inputs. They must
not be committed, mirrored into examples, or treated as local-development
defaults.

## DeploymentSastQualificationEntryAttestation

The qualification authority converts a fresh, immutable T056 `GO` record into
a short-lived deployment-entry attestation. Its canonical core binds all of the
following fields:

```ts
interface DeploymentSastQualificationEntryAttestationCore {
  version: "deployment-sast-qualification-entry-attestation-v1";
  goNoGoRecordId: string;
  goNoGoRecordDigest: string;
  goNoGoManifestId: string;
  goNoGoManifestDigest: string;
  goNoGoPlanId: string;
  goNoGoPlanDigest: string;
  repositoryCommitSha: string;
  providerId: string;
  providerAdapterRef: string;
  rollbackTargetRef: string;
  rollbackTargetDigest: string;
  killSwitchEvidenceAttestationId: string;
  killSwitchEvidenceAttestationDigest: string;
  deploymentOperationsContractRef: string;
  deploymentOperationsContractDigest: string;
  expectedGateCount: 54;
  passedGateCount: 54;
  recordDecidedAt: string;
  attestedAt: string;
  expiresAt: string;
  deploymentOperationsEntryAuthorized: true;
  findingAuthority: false;
  policyAuthority: false;
  publicationAuthority: false;
  scmMutationAuthority: false;
  aiAuthority: false;
  deploymentAuthority: false;
  kubernetesExecutionAuthority: false;
  productionMutationAuthority: false;
  productionReadinessAuthority: false;
}

interface DeploymentSastQualificationEntryAttestation
  extends DeploymentSastQualificationEntryAttestationCore {
  attestationId: string;
  attestationDigest: string;
  signature: SastEndToEndQualificationSignature;
}
```

The source record must be a structurally and cryptographically valid T056
record with status `GO`, all 54 gates passed, zero failed gates, zero
not-applicable gates, and non-null plan, provider, repository commit, rollback,
and kill-switch bindings. Its deployment-operations contract reference and
digest must identify this exact contract revision.

`attestedAt` must be no earlier than `recordDecidedAt` and no more than one hour
later. `expiresAt` must be after `attestedAt` and at most one hour later. The
signature must use Ed25519, have role `QUALIFICATION_AUTHORITY`, bind the
attestation digest, and use `attestedAt` as `signedAt`. Validation requires an
injected signature verifier, canonical digester, and trusted UTC instant. The
trusted instant must be within `[attestedAt, expiresAt)`.

## DeploymentSastQualificationBinding

```ts
interface DeploymentSastQualificationBinding {
  version: "deployment-sast-qualification-binding-v1";
  goNoGoRecordId: string;
  goNoGoRecordDigest: string;
  entryAttestationId: string;
  entryAttestationDigest: string;
  goNoGoManifestId: string;
  goNoGoManifestDigest: string;
  goNoGoPlanId: string;
  goNoGoPlanDigest: string;
  repositoryCommitSha: string;
  providerId: string;
  providerAdapterRef: string;
  rollbackTargetRef: string;
  rollbackTargetDigest: string;
  killSwitchEvidenceAttestationId: string;
  killSwitchEvidenceAttestationDigest: string;
  deploymentOperationsContractRef: string;
  deploymentOperationsContractDigest: string;
  authorizedAt: string;
  expiresAt: string;
  deploymentOperationsEntryAuthorized: true;
  findingAuthority: false;
  policyAuthority: false;
  publicationAuthority: false;
  scmMutationAuthority: false;
  aiAuthority: false;
  deploymentAuthority: false;
  kubernetesExecutionAuthority: false;
  productionMutationAuthority: false;
  productionReadinessAuthority: false;
  bindingId: string;
  bindingDigest: string;
}
```

The binding is reconstructed only from the exact T056 record and its verified
entry attestation. Its identifier and digest cover the full canonical core, so
the record, plan, commit, provider, adapter, rollback target, kill-switch
evidence, contract revision, authorization time, expiry, or authority flags
cannot drift independently.

## DeploymentOperatorApprovalReference

```ts
interface DeploymentOperatorApprovalReference {
  approval:
    | "PRODUCTION_CHANGE_APPROVAL"
    | "SECURITY_BOUNDARY_APPROVAL"
    | "CREDENTIAL_HANDOFF_APPROVAL";
  approvalRef: string;
  subjectDigest: string;
  approvedAt: string;
  validUntil: string;
}
```

Preflight requires exactly one approval of each kind in the canonical order.
Every approval reference is digest-bound and its `subjectDigest` equals the
qualification binding digest. Approval cannot predate qualification, cannot be
created in the future relative to trusted UTC, must still be valid, and may be
valid for at most 24 hours from approval.

## DeploymentOperationAuditSignal

```ts
interface DeploymentOperationAuditSignal {
  environment: "PRODUCTION";
  provider: string;
  operationId: string;
  actor: "DEPLOYMENT_OPERATOR" | "CONTROL_PLANE" | "DATA_SECURITY_PLANE";
  targetType: "SAST_QUALIFICATION_BINDING";
  targetId: string;
  eventType: "DEPLOYMENT_PREFLIGHT_VERIFIED";
  occurredAt: string;
}
```

The provider and target must equal the qualification binding. `occurredAt`
must equal the injected trusted UTC instant, and the operation identifier must
be digest-bound. Audit records may not contain free-form metadata or forbidden
payloads.

## DeploymentOperationPreflight

```ts
interface DeploymentOperationPreflight {
  clusterProvisioning: ProductionClusterProvisioning;
  microVmRollout: MicroVmPlatformRollout;
  credentialBoundaries: DeploymentCredentialBoundary[];
  sastQualification: DeploymentSastQualificationBinding;
  auditSignal: DeploymentOperationAuditSignal;
  operatorApprovals: DeploymentOperatorApprovalReference[];
  kmsKeyRef: string;
  secretManagerRef: string;
  objectStorageRef: string;
  dnsZoneRef: string;
}
```

Preflight validation has no evidence-free overload. It requires the exact T056
record, the signed deployment-entry attestation, a trusted UTC instant, an
Ed25519 signature verifier, and a canonical digester. Unknown fields fail
validation. The cluster, microVM, audit signal, and qualification binding must
use one provider; microVM and qualification must use one adapter; cluster and
microVM must use one region. KMS, secret manager, object storage, DNS, network,
audit, sandbox, broker, evidence, egress, adapter, credential, and approval
inputs must all be digest-bound references. Provider identity is instead bound
by exact equality to the signed T056 qualification.

Passing preflight confirms repository-owned contract integrity only. It does
not execute cluster provisioning, provider-specific microVM rollout, secret
handoff, Kubernetes actions, or production mutations.

## DeploymentOperationHandoffManifest

```ts
interface DeploymentOperationHandoffManifest {
  preflight: DeploymentOperationPreflight;
  credentialHandoffMode:
    | "EXTERNAL_SECRET_MANAGER_REFERENCE"
    | "EPHEMERAL_OIDC_FEDERATION";
  executionWindow: {
    startsAt: string;
    endsAt: string;
  };
  rollbackPlanRef: string;
  incidentChannelRef: string;
  dryRunEvidenceRef: string;
  changeTicketRef: string;
}
```

Handoff validation repeats the full preflight evidence validation. The
execution window must start at or after trusted UTC but strictly before the
qualification binding expires; it must end after it starts and last no more
than eight hours. `rollbackPlanRef` must be the exact rollback target qualified
by T056. Rollback, incident, dry-run, and change-ticket references must be
digest-bound.

Credential handoff remains reference-only and supports only external secret
manager references or ephemeral OIDC federation. Passing handoff validation is
the final repository-owned readiness envelope before a separately approved live
operation. It still grants no deployment, Kubernetes execution, provider
mutation, production mutation, or production-readiness authority.
