# Plan: Production Runtime Infrastructure

## Approach

Implement runtime infrastructure in thin, testable slices. The first slice is
documentation and active feature re-baselining. Later slices add deployment
manifests, runtime autoscaling, scanner sandbox provisioning, and operational
guardrails.

## Target Boundaries

- `specs/004-production-runtime-infrastructure`: active feature package
- `packages/shared`: public runtime infrastructure contracts when code contracts
  are introduced
- `deploy/kubernetes`: Kubernetes deployment manifests for Control, Scan, AI,
  and Data/Security plane integration points
- `deploy/scanner-sandbox`: scanner sandbox provisioning configuration and
  microVM lifecycle contracts
- `apps/ai`: AI Plane runtime image and health contract consumed by manifests
- `apps/api`: Control Plane integration points for planner, token broker, and audit

## Runtime Shape

1. Control Plane accepts integration, webhook, scan planner, token broker, policy,
   and comment dispatcher traffic.
2. Scan Plane provisions ephemeral scanner sandboxes with stronger-than-pod
   isolation before repository fetch or scanner execution.
3. AI Plane runs behind Kubernetes service boundaries and only receives reduced
   evidence through the model gateway.
4. Data/Security Plane provides tenant-aware database, object storage retention,
   audit, KMS, and secrets boundaries.
5. Observability tracks queue pressure, latency, provider health, fallback use,
   sandbox lifecycle, and policy-safe audit events.

## Key Interfaces

- AiPlaneDeployment: deployment manifests, service, health, configuration, and
  secret references for the AI Plane.
- RuntimeAutoscalingPolicy: request latency, queue pressure, provider health,
  fallback, and resource thresholds.
- ScannerSandboxProvisioning: microVM sandbox request, lifecycle, repository
  fetch boundary, scanner adapter boundary, and evidence handoff.
- InfrastructureAuditSignal: tenant, scan, runtime, sandbox, and deployment
  attribution without secret values.

## Completion Strategy

Use TDD for each implementation slice. Keep the production scan architecture and
AI inference guardrails intact. Add tests whenever a deployment manifest,
autoscaling policy, sandbox lifecycle, or secret boundary is introduced.
