# Specification: Production Deployment Operations

## Scope

This milestone turns the deferred live production Kubernetes cluster
provisioning and provider-specific microVM platform rollout work from 004 into
an implementation-ready operations package. It does not provision a real cluster
or require provider credentials in this slice. It defines the operational
contracts and guardrails needed before provider-specific rollout work begins.

## In Scope

- Production cluster provisioning contract skeleton
- Provider-specific microVM platform rollout contract skeleton
- Deployment credential boundary model
- Plane separation checks for live deployment operations
- Dev/demo Oracle VPS path preservation as a non-production deploy path
- Documentation and active feature re-baselining

## Out of Scope

- Creating a live production Kubernetes cluster in this slice
- Storing provider credentials in repository files
- Adding provider credentials as local development defaults
- Running provider CLIs against production accounts
- Customer code execution outside hardened scan isolation
- Package install/build, dynamic testing, auto-fix PR/MR, or direct source upload
- AI finding authority or policy override
- AI access to SCM credentials, full repositories, source archives, or raw scanner payloads

## Requirements

- Production cluster provisioning MUST preserve separated Control, Scan, AI, and
  Data/Security planes.
- Provider-specific microVM platform rollout MUST preserve stronger-than-pod
  scanner isolation.
- Deployment credential boundaries MUST distinguish explicit operations input
  from local development defaults.
- The package MUST NOT introduce provider credentials as local development defaults.
- AI Plane runtime deployment MUST remain advisory-only.
- Scanner sandbox rollout MUST keep package install/build, dynamic testing,
  direct source upload, and auto-fix PR/MR flows forbidden.
- Oracle VPS and Docker Compose MUST remain documented as dev/demo paths only.

## Acceptance

- Entry-point docs identify `005-production-deployment-operations` as the active
  feature package.
- `004-production-runtime-infrastructure` remains linked and preserved as the
  completed runtime infrastructure baseline.
- `003-production-ai-inference-runtime` remains linked and preserved as the
  completed AI inference baseline.
- `002-production-scan-architecture` remains linked and preserved as the
  completed production scan architecture baseline.
- Contracts describe `ProductionClusterProvisioning`,
  `MicroVmPlatformRollout`, and `DeploymentCredentialBoundary`.
- The completion gate stays synchronized with CI.
