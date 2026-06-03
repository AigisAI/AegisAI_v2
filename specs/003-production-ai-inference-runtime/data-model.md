# Data Model: Production AI Inference Runtime

## Entities

### AiInferenceRequest

- `tenantId`
- `scanRequestId`
- `canonicalScanKey`
- `requestId`
- `reducedEvidence`
- `requestedCapabilities`
- `runtimePolicy`
- `createdAt`

### ReducedEvidence

- `findingIds`
- `scannerNames`
- `evidencePackId`
- `summary`
- `snippets`
- `metadata`
- `redactionState`

### AiInferenceResponse

- `requestId`
- `tenantId`
- `scanRequestId`
- `detectorAdvisories`
- `plannerAdvisories`
- `modelMetadata`
- `fallback`
- `latencyMs`
- `createdAt`

### AiInferenceAuditEvent

- `tenantId`
- `scanRequestId`
- `requestId`
- `eventType`
- `provider`
- `model`
- `fallbackUsed`
- `rejectionReason`
- `createdAt`

### AiAdvisoryMetadata

- `id`
- `tenantId`
- `scanRequestId`
- `findingId`
- `modelVersion`
- `advisoryOnly`
- `redactedEvidenceOnly`
- `detectorSignals`
- `plannerSteps`
- `confidence`
- `detectorAdvisories`
- `plannerAdvisories`
- `modelMetadata`
- `fallback`
- `createdAt`

## State

- `requested`: request accepted by the model gateway
- `rejected`: request rejected before provider execution
- `completed`: advisory response returned
- `fallback_completed`: deterministic fallback returned
- `failed`: provider and fallback paths failed

## Attribution Rules

- Every request and response carries tenant and scan attribution.
- Rejections are audited with a specific reason.
- Provider credentials are never persisted in these entities.
- Raw source, repository archives, and SCM tokens are not valid fields.
- Advisory metadata is persisted for tenant/scan/finding attribution only and
  does not grant finding creation, policy override, waiver, or suppression
  authority.
