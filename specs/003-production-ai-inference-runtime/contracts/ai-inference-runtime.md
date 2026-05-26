# Contract: AI Inference Runtime

## ReducedEvidence

```ts
export interface ReducedEvidence {
  findingIds: string[];
  scannerNames: string[];
  evidencePackId: string;
  summary: string;
  snippets: Array<{
    label: string;
    language?: string;
    redactedText: string;
  }>;
  metadata: Record<string, string | number | boolean>;
  redactionState: 'redacted' | 'reduced';
}
```

## AiInferenceRequest

```ts
export interface AiInferenceRequest {
  tenantId: string;
  scanRequestId: string;
  canonicalScanKey: string;
  requestId: string;
  reducedEvidence: ReducedEvidence;
  requestedCapabilities: Array<'detector' | 'planner'>;
  runtimePolicy: {
    allowFallback: boolean;
    maxLatencyMs: number;
  };
  createdAt: string;
}
```

## AiInferenceResponse

```ts
export interface AiInferenceResponse {
  requestId: string;
  tenantId: string;
  scanRequestId: string;
  detectorAdvisories: Array<{
    findingId: string;
    confidence: number;
    rationale: string;
  }>;
  plannerAdvisories: Array<{
    action: string;
    rationale: string;
    priority: 'low' | 'medium' | 'high';
  }>;
  modelMetadata: {
    provider: string;
    model: string;
    version: string;
  };
  fallback: {
    used: boolean;
    reason?: string;
  };
  latencyMs: number;
  createdAt: string;
}
```

## Boundary Rules

- `AiInferenceRequest` accepts reduced evidence only.
- The contract has no fields for SCM credentials, repository archives, full source
  trees, or raw scanner payloads.
- `AiInferenceResponse` is advisory-only and does not contain authoritative
  finding creation, policy override, waiver approval, or suppression authority.
