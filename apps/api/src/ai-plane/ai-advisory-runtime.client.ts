import { BadGatewayException, Injectable } from "@nestjs/common";
import axios from "axios";

import { ConfigService } from "../config/config.service";

import type { AiAdvisoryRequest } from "../../../../packages/shared/src";

export interface AiAdvisoryRuntimeOutput {
  detectorSignals: string[];
  plannerSteps: string[];
  confidence: number;
  modelVersion: string;
}

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

  async createAdvisory(input: AiAdvisoryRequest): Promise<AiAdvisoryRuntimeOutput> {
    try {
      const response = await axios.post(this.runtimeUrl(), input, {
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

  private parseRuntimeOutput(input: unknown): AiAdvisoryRuntimeOutput {
    if (!input || typeof input !== "object" || Array.isArray(input)) {
      throw new BadGatewayException("AI advisory runtime response must be an object.");
    }

    const serialized = JSON.stringify(input);

    for (const forbiddenKey of FORBIDDEN_RUNTIME_RESPONSE_KEYS) {
      if (new RegExp(forbiddenKey, "i").test(serialized)) {
        throw new BadGatewayException(
          "AI advisory runtime response contains forbidden authority or sensitive content."
        );
      }
    }

    const candidate = input as Partial<AiAdvisoryRuntimeOutput>;

    if (
      !Array.isArray(candidate.detectorSignals) ||
      !candidate.detectorSignals.every((signal) => typeof signal === "string") ||
      !Array.isArray(candidate.plannerSteps) ||
      !candidate.plannerSteps.every((step) => typeof step === "string") ||
      typeof candidate.confidence !== "number" ||
      candidate.confidence < 0 ||
      candidate.confidence > 1 ||
      typeof candidate.modelVersion !== "string"
    ) {
      throw new BadGatewayException("AI advisory runtime response is malformed.");
    }

    return {
      detectorSignals: candidate.detectorSignals,
      plannerSteps: candidate.plannerSteps,
      confidence: candidate.confidence,
      modelVersion: candidate.modelVersion
    };
  }

  private runtimeUrl(): string {
    return `${this.config.get("AI_SERVER_URL").replace(/\/$/, "")}/ai/advisories`;
  }
}
