export const AI_INFERENCE_RUNTIME_FEATURE_ID = '003-production-ai-inference-runtime';

export const AI_INFERENCE_CAPABILITIES = ['detector', 'planner'] as const;
export type AiInferenceCapability = (typeof AI_INFERENCE_CAPABILITIES)[number];

export const AI_INFERENCE_REJECTION_REASONS = [
  'UNREDACTED_EVIDENCE',
  'FORBIDDEN_INPUT_CLASS',
  'MISSING_TENANT_ATTRIBUTION',
  'MISSING_SCAN_ATTRIBUTION',
  'MODEL_GATEWAY_UNAVAILABLE'
] as const;
export type AiInferenceRejectionReason = (typeof AI_INFERENCE_REJECTION_REASONS)[number];

export const AI_INFERENCE_EVENT_TYPES = [
  'ai_inference.requested',
  'ai_inference.rejected',
  'ai_inference.completed',
  'ai_inference.fallback_completed',
  'ai_inference.failed'
] as const;
export type AiInferenceEventType = (typeof AI_INFERENCE_EVENT_TYPES)[number];

export interface ReducedEvidenceSnippet {
  label: string;
  language?: string;
  redactedText: string;
}

export interface ReducedEvidence {
  findingIds: string[];
  scannerNames: string[];
  evidencePackId: string;
  summary: string;
  snippets: ReducedEvidenceSnippet[];
  metadata: Record<string, string | number | boolean>;
  redactionState: 'redacted' | 'reduced';
}

export interface AiRuntimePolicy {
  allowFallback: boolean;
  maxLatencyMs: number;
}

export interface AiInferenceRequest {
  tenantId: string;
  scanRequestId: string;
  canonicalScanKey: string;
  requestId: string;
  modelVersion: string;
  reducedEvidence: ReducedEvidence;
  requestedCapabilities: AiInferenceCapability[];
  runtimePolicy: AiRuntimePolicy;
  createdAt: string;
}

export interface AiDetectorAdvisory {
  findingId: string;
  confidence: number;
  rationale: string;
  signals: string[];
}

export interface AiPlannerAdvisory {
  findingId?: string;
  action: string;
  rationale: string;
  priority: 'low' | 'medium' | 'high';
}

export interface AiModelMetadata {
  provider: string;
  model: string;
  version: string;
}

export interface AiInferenceFallback {
  used: boolean;
  reason?: string;
}

export interface AiInferenceResponse {
  requestId: string;
  tenantId: string;
  scanRequestId: string;
  advisoryOnly: true;
  detectorAdvisories: AiDetectorAdvisory[];
  plannerAdvisories: AiPlannerAdvisory[];
  modelMetadata: AiModelMetadata;
  fallback: AiInferenceFallback;
  latencyMs: number;
  createdAt: string;
}

export interface AiInferenceAuditEvent {
  tenantId: string;
  scanRequestId: string;
  requestId: string;
  eventType: AiInferenceEventType;
  provider?: string;
  model?: string;
  fallbackUsed: boolean;
  rejectionReason?: AiInferenceRejectionReason;
  latencyMs?: number;
  createdAt: string;
}
