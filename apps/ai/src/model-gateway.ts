import type { AiInferenceRequest, AiInferenceResponse } from "@aegisai/shared";

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
      if (options.provider) {
        try {
          return await options.provider.infer(request, { config });
        } catch (error) {
          if (!config.allowFallback || !request.runtimePolicy.allowFallback) {
            throw error;
          }

          return options.fallbackProvider.infer(request, {
            config,
            fallbackReason: error instanceof Error ? error.message : "provider failed"
          });
        }
      }

      if (!config.allowFallback || !request.runtimePolicy.allowFallback) {
        throw new Error("Model gateway provider is not configured and fallback is disabled.");
      }

      return options.fallbackProvider.infer(request, {
        config,
        fallbackReason: "provider not configured"
      });
    }
  };
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
