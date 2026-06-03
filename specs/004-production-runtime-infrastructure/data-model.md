# Data Model: Production Runtime Infrastructure

## Entities

### AiPlaneDeployment

- `name`
- `namespace`
- `image`
- `serviceName`
- `healthPath`
- `configRefs`
- `secretRefs`
- `networkPolicyRefs`
- `advisoryOnly`

### RuntimeAutoscalingPolicy

- `targetName`
- `minReplicas`
- `maxReplicas`
- `latencyP95Ms`
- `queueDepth`
- `providerErrorRate`
- `fallbackRate`
- `cpuUtilization`
- `memoryUtilization`

### ScannerSandboxProvisioning

- `sandboxProvider`
- `isolationClass`
- `tenantId`
- `scanRequestId`
- `repositoryBindingId`
- `scannerSetVersion`
- `ttlSeconds`
- `networkEgressPolicy`
- `evidenceOutputRef`

### InfrastructureAuditSignal

- `tenantId`
- `scanRequestId`
- `runtimeId`
- `sandboxId`
- `eventType`
- `actor`
- `targetType`
- `targetId`
- `metadata`
- `occurredAt`

## State

- `planned`: deployment or sandbox request is accepted for planning
- `provisioning`: runtime or sandbox resources are being prepared
- `ready`: runtime or sandbox health gate passed
- `running`: runtime or scanner workload is active
- `draining`: runtime or sandbox is stopping new work
- `terminated`: runtime or sandbox lifecycle ended
- `failed`: runtime or sandbox lifecycle failed

## Boundary Rules

- AI Plane deployment data cannot include SCM credentials, repository archives,
  full source trees, raw scanner payloads, or policy override fields.
- Scanner sandbox provisioning can reference repository binding and scan request
  identifiers, but must not persist issued token values.
- Sandbox output is evidence metadata only; raw artifacts stay under object
  storage retention and redaction rules.
- Autoscaling policies do not override policy decisions or finding authority.
