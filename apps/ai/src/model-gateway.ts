import type {
  AiInferenceAuditEvent,
  AiInferenceRejectionReason,
  AiInferenceRequest,
  AiInferenceResponse
} from "@aegisai/shared";

export interface ModelGatewayConfig {
  providerId: string;
  model: string;
  version: string;
  allowFallback: boolean;
}

export interface ModelProviderContext {
  config: ModelGatewayConfig;
  fallbackReason?: string;
}

export interface AiModelProvider {
  infer(request: AiInferenceRequest, context?: ModelProviderContext): Promise<AiInferenceResponse>;
}

export interface ModelGatewayOptions {
  config: ModelGatewayConfig;
  provider?: AiModelProvider;
  fallbackProvider: AiModelProvider;
  auditSink?: (event: AiInferenceAuditEvent) => void;
}

export interface ModelGateway {
  infer(request: AiInferenceRequest): Promise<AiInferenceResponse>;
}

export function validateModelGatewayConfig(config: ModelGatewayConfig): ModelGatewayConfig {
  if (config.providerId.trim().length === 0) {
    throw new Error("Model gateway provider id is required.");
  }

  if (config.model.trim().length === 0) {
    throw new Error("Model gateway model is required.");
  }

  if (config.version.trim().length === 0) {
    throw new Error("Model gateway version is required.");
  }

  return config;
}

export function createModelGateway(options: ModelGatewayOptions): ModelGateway {
  const config = validateModelGatewayConfig(options.config);

  return {
    async infer(request) {
      const startedAt = Date.now();

      try {
        validateAiInferenceRequest(request);
      } catch (error) {
        emitAuditEvent(options, request, "ai_inference.rejected", {
          rejectionReason: rejectionReasonFor(error)
        });
        throw error;
      }

      emitAuditEvent(options, request, "ai_inference.requested");

      if (options.provider) {
        try {
          const response = await options.provider.infer(request, { config });
          emitAuditEvent(options, request, "ai_inference.completed", {
            latencyMs: elapsedMs(startedAt),
            provider: response.modelMetadata.provider,
            model: response.modelMetadata.model,
            fallbackUsed: response.fallback.used
          });
          return response;
        } catch (error) {
          if (!config.allowFallback || !request.runtimePolicy.allowFallback) {
            emitAuditEvent(options, request, "ai_inference.failed", {
              latencyMs: elapsedMs(startedAt),
              fallbackUsed: false
            });
            throw error;
          }

          const response = await options.fallbackProvider.infer(request, {
            config,
            fallbackReason: error instanceof Error ? error.message : "provider failed"
          });
          emitAuditEvent(options, request, "ai_inference.fallback_completed", {
            latencyMs: elapsedMs(startedAt),
            provider: response.modelMetadata.provider,
            model: response.modelMetadata.model,
            fallbackUsed: true
          });
          return response;
        }
      }

      if (!config.allowFallback || !request.runtimePolicy.allowFallback) {
        emitAuditEvent(options, request, "ai_inference.failed", {
          latencyMs: elapsedMs(startedAt),
          fallbackUsed: false
        });
        throw new Error("Model gateway provider is not configured and fallback is disabled.");
      }

      const response = await options.fallbackProvider.infer(request, {
        config,
        fallbackReason: "provider not configured"
      });
      emitAuditEvent(options, request, "ai_inference.fallback_completed", {
        latencyMs: elapsedMs(startedAt),
        provider: response.modelMetadata.provider,
        model: response.modelMetadata.model,
        fallbackUsed: true
      });
      return response;
    }
  };
}

export function validateAiInferenceRequest(request: AiInferenceRequest): AiInferenceRequest {
  if (request.tenantId.trim().length === 0) {
    throw new AiInferenceValidationError("AI inference request requires tenant attribution.", "MISSING_TENANT_ATTRIBUTION");
  }

  if (request.scanRequestId.trim().length === 0) {
    throw new AiInferenceValidationError("AI inference request requires scan attribution.", "MISSING_SCAN_ATTRIBUTION");
  }

  if (request.reducedEvidence.redactionState !== "redacted" && request.reducedEvidence.redactionState !== "reduced") {
    throw new AiInferenceValidationError(
      "AI inference request must remain inside the reduced evidence boundary.",
      "UNREDACTED_EVIDENCE"
    );
  }

  const serializedEvidence = JSON.stringify(request.reducedEvidence);

  for (const forbiddenKey of FORBIDDEN_INPUT_KEYS) {
    if (new RegExp(forbiddenKey, "i").test(serializedEvidence)) {
      throw new AiInferenceValidationError(
        "AI inference request must remain inside the reduced evidence boundary.",
        "FORBIDDEN_INPUT_CLASS"
      );
    }
  }

  return request;
}

export function createDeterministicFallbackProvider(): AiModelProvider {
  return {
    async infer(request, context) {
      const startedAt = Date.now();
      const findingId = request.reducedEvidence.findingIds[0] ?? "finding";
      const severity = String(request.reducedEvidence.metadata.severity ?? "MEDIUM").toUpperCase();
      const priority = severity === "CRITICAL" || severity === "HIGH" ? "high" : "medium";

      return {
        requestId: request.requestId,
        tenantId: request.tenantId,
        scanRequestId: request.scanRequestId,
        advisoryOnly: true,
        detectorAdvisories: [
          {
            findingId,
            confidence: severity === "CRITICAL" || severity === "HIGH" ? 0.68 : 0.55,
            rationale: "Deterministic fallback advisory generated from reduced scanner evidence.",
            signals: [
              "FALLBACK_DETERMINISTIC",
              `EVIDENCE_${request.reducedEvidence.redactionState.toUpperCase()}`,
              `SCANNERS_${request.reducedEvidence.scannerNames.join("_")}`
            ]
          }
        ],
        plannerAdvisories: [
          {
            findingId,
            action: "Review normalized scanner evidence with the owning team.",
            rationale: "Fallback planning keeps remediation and policy decisions outside the AI Plane.",
            priority
          }
        ],
        modelMetadata: {
          provider: "deterministic",
          model: context?.config.model ?? "detector-planner-fallback",
          version: context?.config.version ?? "v1"
        },
        fallback: {
          used: true,
          reason: context?.fallbackReason
        },
        latencyMs: Math.max(0, Date.now() - startedAt),
        createdAt: new Date().toISOString()
      };
    }
  };
}

class AiInferenceValidationError extends Error {
  constructor(
    message: string,
    readonly rejectionReason: AiInferenceRejectionReason
  ) {
    super(message);
  }
}

const FORBIDDEN_INPUT_KEYS = [
  "accessToken",
  "refreshToken",
  "tokenValue",
  "secretValue",
  "scmCredential",
  "scmToken",
  "sourceArchive",
  "repositoryArchive",
  "fullRepository",
  "rawScannerPayload"
];

type AuditEventOverrides = Partial<
  Pick<AiInferenceAuditEvent, "fallbackUsed" | "latencyMs" | "model" | "provider" | "rejectionReason">
>;

function emitAuditEvent(
  options: ModelGatewayOptions,
  request: AiInferenceRequest,
  eventType: AiInferenceAuditEvent["eventType"],
  overrides: AuditEventOverrides = {}
): void {
  options.auditSink?.({
    tenantId: request.tenantId,
    scanRequestId: request.scanRequestId,
    requestId: request.requestId,
    eventType,
    provider: overrides.provider ?? options.config.providerId,
    model: overrides.model ?? options.config.model,
    fallbackUsed: overrides.fallbackUsed ?? false,
    rejectionReason: overrides.rejectionReason,
    latencyMs: overrides.latencyMs,
    createdAt: new Date().toISOString()
  });
}

function rejectionReasonFor(error: unknown): AiInferenceRejectionReason {
  if (error instanceof AiInferenceValidationError) {
    return error.rejectionReason;
  }

  return "MODEL_GATEWAY_UNAVAILABLE";
}

function elapsedMs(startedAt: number): number {
  return Math.max(0, Date.now() - startedAt);
}
