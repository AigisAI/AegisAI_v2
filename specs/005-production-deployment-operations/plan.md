# Plan: Production Deployment Operations

## Approach

Implement deployment operations in thin, testable slices. The first slice is
documentation and active feature re-baselining. Later slices add provider-neutral
cluster provisioning inputs, provider-neutral microVM rollout inputs, operation
audit contracts, and provider-specific runbooks.

## Target Boundaries

- `specs/005-production-deployment-operations`: active deployment operations
  package
- `deploy/kubernetes`: future provider-neutral production cluster overlays
- `deploy/scanner-sandbox`: future provider-specific microVM platform rollout
  inputs
- `packages/shared`: public deployment operations contracts when code contracts
  are introduced
- `docs`: operational runbooks and environment-specific support documents

## Runtime Shape

1. Operators prepare production cluster provisioning inputs outside local
   development defaults.
2. Control, Scan, AI, and Data/Security plane boundaries are validated before
   rollout is considered ready.
3. Provider-specific microVM platform rollout configures scanner isolation before
   production scanner traffic is enabled.
4. Credential use is explicit, short-lived where possible, audited, and never
   committed to repository files.
5. Rollback and audit signals are defined before provider-specific automation is
   introduced as an operational rollout.

## Key Interfaces

- ProductionClusterProvisioning: provider, region, namespaces, network
  boundaries, and audit sink references.
- MicroVmPlatformRollout: provider, region, scanner sandbox profile, token
  broker, evidence storage, egress policy, and TTL.
- DeploymentCredentialBoundary: allowed credential scope and proof that provider
  credentials are not local defaults or repository-persisted. This is the
  provider credential boundary for deployment operations.
- DeploymentOperationAuditSignal: production operation attribution without
  secret values.

## Completion Strategy

Use TDD for each implementation slice. Keep the completed scan architecture,
AI inference, and runtime infrastructure guardrails intact. Add tests whenever
cluster provisioning inputs, microVM rollout inputs, credential boundaries, or
operation audit surfaces are introduced.
