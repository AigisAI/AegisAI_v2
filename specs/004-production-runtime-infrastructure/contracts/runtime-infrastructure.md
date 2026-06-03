# Contracts: Production Runtime Infrastructure

## AiPlaneDeployment

```ts
interface AiPlaneDeployment {
  name: string;
  namespace: string;
  image: string;
  serviceName: string;
  healthPath: "/health";
  configRefs: string[];
  secretRefs: string[];
  networkPolicyRefs: string[];
  advisoryOnly: true;
}
```

The AI Plane deployment must not include SCM credential, repository archive,
full repository, raw scanner payload, policy override, waiver, suppression, or
finding authority fields.

## RuntimeAutoscalingPolicy

```ts
interface RuntimeAutoscalingPolicy {
  targetName: string;
  minReplicas: number;
  maxReplicas: number;
  latencyP95Ms: number;
  queueDepth: number;
  providerErrorRate: number;
  fallbackRate: number;
  cpuUtilization: number;
  memoryUtilization: number;
}
```

Autoscaling policy is advisory to infrastructure controllers. It must not create
findings, override policy, or alter waiver/suppression state.

## ScannerSandboxProvisioning

```ts
interface ScannerSandboxProvisioning {
  sandboxProvider: "MICROVM";
  isolationClass: "HARDENED" | "RESTRICTED";
  tenantId: string;
  scanRequestId: string;
  repositoryBindingId: string;
  scannerSetVersion: string;
  ttlSeconds: number;
  networkEgressPolicy: "SCM_AND_SCANNER_UPDATES_ONLY" | "SCM_ONLY";
  evidenceOutputRef: string;
}
```

Scanner sandbox provisioning may request scan-scoped repository access through
the token broker, but token values are short-lived, non-persisted, and never
exposed to the AI Plane.

## InfrastructureAuditSignal

```ts
interface InfrastructureAuditSignal {
  tenantId: string;
  scanRequestId?: string;
  runtimeId?: string;
  sandboxId?: string;
  eventType: string;
  actor: "CONTROL_PLANE" | "SCAN_PLANE" | "AI_PLANE" | "DATA_SECURITY_PLANE";
  targetType: string;
  targetId: string;
  metadata?: Record<string, unknown>;
  occurredAt: string;
}
```

Audit metadata must not contain secret values, SCM tokens, full repository
content, source archives, or raw scanner payloads.
