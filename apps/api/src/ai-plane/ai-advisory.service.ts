import { BadRequestException, Injectable, NotFoundException } from "@nestjs/common";

import type {
  AiAdvisoryRequest,
  AiAdvisoryResult,
  AiDetectorAdvisory,
  AiInferenceFallback,
  AiInferenceResponse,
  AiModelMetadata,
  AiPlannerAdvisory
} from "../../../../packages/shared/src";
import { ConfigService } from "../config/config.service";
import { AiAdvisoryRuntimeClient } from "./ai-advisory-runtime.client";

interface AiAdvisoryRuntimeProjection {
  detectorSignals: string[];
  plannerSteps: string[];
  confidence: number;
  modelVersion: string;
  detectorAdvisories?: AiDetectorAdvisory[];
  plannerAdvisories?: AiPlannerAdvisory[];
  modelMetadata?: AiModelMetadata;
  fallback?: AiInferenceFallback;
}

const FORBIDDEN_AI_INPUT_KEYS = [
  "accessToken",
  "refreshToken",
  "tokenValue",
  "secretValue",
  "sourceArchive",
  "fullRepository",
  "rawScannerPayload",
  "policyOverride",
  "findingOverride"
];

@Injectable()
export class AiAdvisoryService {
  private readonly advisories: AiAdvisoryResult[] = [];
  private advisorySequence = 0;

  constructor(
    private readonly config?: ConfigService,
    private readonly runtimeClient?: AiAdvisoryRuntimeClient
  ) {}

  async createAdvisory(input: AiAdvisoryRequest): Promise<AiAdvisoryResult> {
    this.assertReducedInput(input);
    const runtimeOutput = await this.resolveRuntimeOutput(input);

    const advisory: AiAdvisoryResult = {
      id: `ai_advisory_${++this.advisorySequence}`,
      tenantId: input.tenantId,
      scanRequestId: input.scanRequestId,
      findingId: input.findingId,
      modelVersion: runtimeOutput.modelVersion,
      advisoryOnly: true,
      redactedEvidenceOnly: true,
      detectorSignals: runtimeOutput.detectorSignals,
      plannerSteps: runtimeOutput.plannerSteps,
      confidence: runtimeOutput.confidence,
      detectorAdvisories: runtimeOutput.detectorAdvisories,
      plannerAdvisories: runtimeOutput.plannerAdvisories,
      modelMetadata: runtimeOutput.modelMetadata,
      fallback: runtimeOutput.fallback,
      createdAt: new Date().toISOString()
    };

    this.advisories.push(advisory);

    return advisory;
  }

  getAdvisory(tenantId: string, advisoryId: string): AiAdvisoryResult {
    const advisory = this.advisories.find(
      (candidate) => candidate.id === advisoryId && candidate.tenantId === tenantId
    );

    if (!advisory) {
      throw new NotFoundException("AI advisory was not found for tenant.");
    }

    return advisory;
  }

  private assertReducedInput(input: AiAdvisoryRequest): void {
    if (!input.evidence.redacted) {
      throw new BadRequestException("AI advisory input must use redacted evidence.");
    }

    const serialized = JSON.stringify(input);

    for (const forbiddenKey of FORBIDDEN_AI_INPUT_KEYS) {
      if (new RegExp(forbiddenKey, "i").test(serialized)) {
        throw new BadRequestException("AI advisory input contains forbidden sensitive content.");
      }
    }
  }

  private async resolveRuntimeOutput(input: AiAdvisoryRequest): Promise<AiAdvisoryRuntimeProjection> {
    if (this.config?.get("USE_INTERNAL_AI") === "true") {
      if (!this.runtimeClient) {
        throw new BadRequestException("AI advisory runtime client is not configured.");
      }

      return this.projectInferenceResponse(await this.runtimeClient.createAdvisory(input));
    }

    return {
      detectorSignals: this.detectorSignalsFor(input),
      plannerSteps: this.plannerStepsFor(input),
      confidence: this.confidenceFor(input),
      modelVersion: input.modelVersion
    };
  }

  private projectInferenceResponse(response: AiInferenceResponse): AiAdvisoryRuntimeProjection {
    return {
      detectorSignals: Array.from(new Set(response.detectorAdvisories.flatMap((advisory) => advisory.signals))),
      plannerSteps: response.plannerAdvisories.map((advisory) => advisory.action),
      confidence: response.detectorAdvisories.reduce(
        (highestConfidence, advisory) => Math.max(highestConfidence, advisory.confidence),
        0
      ),
      modelVersion: response.modelMetadata.version,
      detectorAdvisories: response.detectorAdvisories,
      plannerAdvisories: response.plannerAdvisories,
      modelMetadata: response.modelMetadata,
      fallback: response.fallback
    };
  }

  private detectorSignalsFor(input: AiAdvisoryRequest): string[] {
    return [
      "SCANNER_CONFIRMED",
      `SEVERITY_${input.normalizedFinding.severity}`,
      `PROVENANCE_${input.normalizedFinding.scannerProvenance}`
    ];
  }

  private plannerStepsFor(input: AiAdvisoryRequest): string[] {
    const steps = ["Review scanner evidence before remediation."];

    if (input.normalizedFinding.severity === "CRITICAL" || input.normalizedFinding.severity === "HIGH") {
      steps.push("Prioritize owner review before merging affected changes.");
    }

    steps.push("Apply remediation outside the AI advisory boundary.");

    return steps;
  }

  private confidenceFor(input: AiAdvisoryRequest): number {
    if (input.normalizedFinding.severity === "CRITICAL") {
      return 0.82;
    }

    if (input.normalizedFinding.severity === "HIGH") {
      return 0.74;
    }

    return 0.61;
  }
}
