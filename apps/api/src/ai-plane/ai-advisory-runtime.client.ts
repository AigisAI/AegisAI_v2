import { BadGatewayException, Injectable } from "@nestjs/common";
import axios from "axios";

import { ConfigService } from "../config/config.service";

import type { AiAdvisoryRequest, AiInferenceRequest, AiInferenceResponse } from "../../../../packages/shared/src";

const FORBIDDEN_RUNTIME_RESPONSE_KEYS = [
  "accessToken",
  "refreshToken",
  "tokenValue",
  "secretValue",
  "sourceArchive",
  "fullRepository",
  "rawScannerPayload",
  "policyOverride",
  "findingOverride",
  "enforcementAction",
  "blockRequested",
  "waiverApplied",
  "staleSuppressed"
];

@Injectable()
export class AiAdvisoryRuntimeClient {
  constructor(private readonly config: ConfigService) {}

  async createAdvisory(input: AiAdvisoryRequest): Promise<AiInferenceResponse> {
    try {
      const response = await axios.post(this.runtimeUrl(), this.toInferenceRequest(input), {
        timeout: this.config.get("AI_ADVISORY_TIMEOUT_MS")
      });

      return this.parseRuntimeOutput(response.data);
    } catch (error) {
      if (error instanceof BadGatewayException) {
        throw error;
      }

      throw new BadGatewayException("AI advisory runtime request failed.");
    }
  }

  private toInferenceRequest(input: AiAdvisoryRequest): AiInferenceRequest {
    const maxLatencyMs = Number(this.config.get("AI_ADVISORY_TIMEOUT_MS"));
    const location =
      input.normalizedFinding.lineEnd && input.normalizedFinding.lineEnd !== input.normalizedFinding.lineStart
        ? `${input.normalizedFinding.filePath}:${input.normalizedFinding.lineStart}-${input.normalizedFinding.lineEnd}`
        : `${input.normalizedFinding.filePath}:${input.normalizedFinding.lineStart}`;

    return {
      tenantId: input.tenantId,
      scanRequestId: input.scanRequestId,
      canonicalScanKey: [
        input.tenantId,
        input.scanRequestId,
        input.findingId,
        "AI_ADVISORY",
        input.modelVersion
      ].join(":"),
      requestId: `ai_inference_${input.scanRequestId}_${input.findingId}`,
      reducedEvidence: {
        findingIds: [input.findingId],
        scannerNames: [input.normalizedFinding.scannerProvenance],
        evidencePackId: input.evidence.id,
        summary: `${input.normalizedFinding.title} (${input.normalizedFinding.severity})`,
        snippets: [
          {
            label: "finding-location",
            redactedText: location
          }
        ],
        metadata: {
          severity: input.normalizedFinding.severity,
          scannerProvenance: input.normalizedFinding.scannerProvenance,
          findingStatus: input.normalizedFinding.status,
          evidenceByteSize: input.evidence.byteSize,
          evidenceExpiresAt: input.evidence.expiresAt
        },
        redactionState: input.evidence.redacted ? "redacted" : "reduced"
      },
      requestedCapabilities: ["detector", "planner"],
      runtimePolicy: {
        allowFallback: true,
        maxLatencyMs: Number.isFinite(maxLatencyMs) ? maxLatencyMs : 2500
      },
      createdAt: new Date().toISOString()
    };
  }

  private parseRuntimeOutput(input: unknown): AiInferenceResponse {
    if (!input || typeof input !== "object" || Array.isArray(input)) {
      throw new BadGatewayException("AI advisory runtime response must be an object.");
    }

    if (hasForbiddenRuntimeResponseKey(input)) {
      throw new BadGatewayException("AI advisory runtime response contains forbidden authority or sensitive content.");
    }

    const candidate = input as Partial<AiInferenceResponse>;

    if (
      typeof candidate.requestId !== "string" ||
      typeof candidate.tenantId !== "string" ||
      typeof candidate.scanRequestId !== "string" ||
      candidate.advisoryOnly !== true ||
      !Array.isArray(candidate.detectorAdvisories) ||
      !candidate.detectorAdvisories.every(isDetectorAdvisory) ||
      !Array.isArray(candidate.plannerAdvisories) ||
      !candidate.plannerAdvisories.every(isPlannerAdvisory) ||
      !candidate.modelMetadata ||
      typeof candidate.modelMetadata.provider !== "string" ||
      typeof candidate.modelMetadata.model !== "string" ||
      typeof candidate.modelMetadata.version !== "string" ||
      !candidate.fallback ||
      typeof candidate.fallback.used !== "boolean" ||
      (candidate.fallback.reason !== undefined && typeof candidate.fallback.reason !== "string") ||
      typeof candidate.latencyMs !== "number" ||
      typeof candidate.createdAt !== "string"
    ) {
      throw new BadGatewayException("AI advisory runtime response is malformed.");
    }

    return candidate as AiInferenceResponse;
  }

  private runtimeUrl(): string {
    return `${this.config.get("AI_SERVER_URL").replace(/\/$/, "")}/ai/advisories`;
  }
}

function isDetectorAdvisory(input: unknown): boolean {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return false;
  }

  const candidate = input as Record<string, unknown>;

  return (
    typeof candidate.findingId === "string" &&
    typeof candidate.confidence === "number" &&
    candidate.confidence >= 0 &&
    candidate.confidence <= 1 &&
    typeof candidate.rationale === "string" &&
    Array.isArray(candidate.signals) &&
    candidate.signals.every((signal) => typeof signal === "string")
  );
}

function isPlannerAdvisory(input: unknown): boolean {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return false;
  }

  const candidate = input as Record<string, unknown>;

  return (
    (candidate.findingId === undefined || typeof candidate.findingId === "string") &&
    typeof candidate.action === "string" &&
    typeof candidate.rationale === "string" &&
    (candidate.priority === "low" || candidate.priority === "medium" || candidate.priority === "high")
  );
}

function hasForbiddenRuntimeResponseKey(input: unknown): boolean {
  if (input === null || typeof input !== "object") {
    return false;
  }

  if (Array.isArray(input)) {
    return input.some((item) => hasForbiddenRuntimeResponseKey(item));
  }

  return Object.entries(input as Record<string, unknown>).some(
    ([key, value]) => isForbiddenRuntimeResponseKey(key) || hasForbiddenRuntimeResponseKey(value)
  );
}

function isForbiddenRuntimeResponseKey(key: string): boolean {
  return FORBIDDEN_RUNTIME_RESPONSE_KEYS.some(
    (forbiddenKey) => forbiddenKey.toLowerCase() === key.toLowerCase()
  );
}
