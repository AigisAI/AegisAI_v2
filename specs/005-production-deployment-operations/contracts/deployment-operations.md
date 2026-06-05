# Contracts: Production Deployment Operations

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

Production cluster provisioning must preserve separate Control, Scan, AI, and
Data/Security plane namespaces or equivalent trust boundaries.

## MicroVmPlatformRollout

```ts
interface MicroVmPlatformRollout {
  provider: string;
  region: string;
  platformName: string;
  isolationClass: "HARDENED" | "RESTRICTED";
  scannerSandboxProfileRef: string;
  tokenBrokerRef: string;
  evidenceStorageRef: string;
  egressPolicyRef: string;
  ttlSeconds: number;
}
```

Provider-specific microVM platform rollout must isolate repository fetch and
scanner execution from the Control Plane and AI Plane.

## DeploymentCredentialBoundary

```ts
interface DeploymentCredentialBoundary {
  credentialProvider: string;
  credentialScope: "CLUSTER_ADMIN" | "MICROVM_PLATFORM_ADMIN" | "SECRET_MANAGER_ADMIN";
  allowedUse: "EXPLICIT_DEPLOYMENT_OPERATION";
  localDevelopmentDefault: false;
  repositoryPersisted: false;
  rotationRequired: true;
  auditRequired: true;
}
```

Deployment credentials must be explicit operations inputs. They must not be
committed, mirrored into examples, or treated as local development defaults.

## DeploymentOperationAuditSignal

```ts
interface DeploymentOperationAuditSignal {
  environment: "PRODUCTION";
  provider: string;
  operationId: string;
  actor: "DEPLOYMENT_OPERATOR" | "CONTROL_PLANE" | "DATA_SECURITY_PLANE";
  targetType: string;
  targetId: string;
  eventType: string;
  metadata?: Record<string, unknown>;
  occurredAt: string;
}
```

`occurredAt` must be an RFC 3339/ISO-8601 UTC timestamp, for example
`2026-06-05T01:17:08Z`.

Audit metadata must not contain provider secret values, SCM tokens, full
repository content, source archives, or raw scanner payloads.

## DeploymentOperationPreflight

```ts
interface DeploymentOperationPreflight {
  clusterProvisioning: ProductionClusterProvisioning;
  microVmRollout: MicroVmPlatformRollout;
  credentialBoundary: DeploymentCredentialBoundary;
  auditSignal: DeploymentOperationAuditSignal;
  operatorApprovalRefs: Array<
    | "PRODUCTION_CHANGE_APPROVAL"
    | "SECURITY_BOUNDARY_APPROVAL"
    | "CREDENTIAL_HANDOFF_APPROVAL"
  >;
  kmsKeyRef: string;
  secretManagerRef: string;
  objectStorageRef: string;
  dnsZoneRef: string;
}
```

Preflight readiness is the final repository-owned contract before live
production execution. It confirms that cluster provisioning, microVM rollout,
deployment credential boundary, audit sink, KMS, secret manager, object storage,
DNS, and operator approval references are present.

Preflight inputs must remain references only. They must not contain provider
secret values, kubeconfigs, SCM tokens, full repositories, source archives, or
raw scanner payloads. Passing preflight does not execute live Kubernetes
provisioning or provider-specific microVM rollout.

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

The handoff manifest is the operator-facing readiness envelope for live
execution. It binds a passing preflight contract to an execution window,
rollback reference, incident channel, dry-run evidence reference, change ticket,
and credential handoff mode.

Credential handoff must be reference-only. Supported modes are external secret
manager reference and ephemeral OIDC federation. The manifest must not contain
provider secret values, kubeconfigs, SCM tokens, full repositories, source
archives, or raw scanner payloads. Passing handoff validation still does not
execute live Kubernetes provisioning or provider-specific microVM rollout.
