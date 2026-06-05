# Data Model: Production Deployment Operations

## Entities

### ProductionClusterProvisioning

- `environment`
- `provider`
- `region`
- `clusterName`
- `controlPlaneNamespace`
- `scanPlaneNamespace`
- `aiPlaneNamespace`
- `dataSecurityNamespace`
- `networkBoundaryRefs`
- `auditSinkRef`

### MicroVmPlatformRollout

- `provider`
- `region`
- `platformName`
- `isolationClass`
- `scannerSandboxProfileRef`
- `tokenBrokerRef`
- `evidenceStorageRef`
- `egressPolicyRef`
- `ttlSeconds`

### DeploymentCredentialBoundary

- `credentialProvider`
- `credentialScope`
- `allowedUse`
- `localDevelopmentDefault`
- `repositoryPersisted`
- `rotationRequired`
- `auditRequired`

### DeploymentOperationAuditSignal

- `environment`
- `provider`
- `operationId`
- `actor`
- `targetType`
- `targetId`
- `eventType`
- `metadata`
- `occurredAt`

## State

- `planned`: operation has documented inputs and guardrails
- `approved`: operator has approved a provider-specific rollout
- `provisioning`: provider resources are being created or updated
- `validating`: plane boundaries and runtime health gates are being checked
- `ready`: production deployment operation passed validation
- `rolled_back`: operation was reverted through an approved rollback path
- `failed`: operation failed and requires audit-visible follow-up

## Boundary Rules

- `DeploymentCredentialBoundary.localDevelopmentDefault` must be `false` for
  provider production credentials.
- `DeploymentCredentialBoundary.repositoryPersisted` must be `false`.
- Cluster provisioning data can reference secret managers, but must not store
  credential values.
- microVM rollout data can reference scanner sandbox and token broker resources,
  but must not grant AI access to repositories or SCM credentials.
- Audit metadata must not contain secret values, SCM tokens, full repository
  content, source archives, or raw scanner payloads.
