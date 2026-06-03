import { BadRequestException, Injectable, NotFoundException, Optional } from "@nestjs/common";

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
import { PrismaService } from "../prisma/prisma.service";
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

interface AiAdvisoryMetadataRecord {
  id: string;
  tenantId: string;
  scanRequestId: string;
  findingId: string;
  modelVersion: string;
  advisoryOnly: boolean;
  redactedEvidenceOnly: boolean;
  detectorSignals: unknown;
  plannerSteps: unknown;
  confidence: number;
  detectorAdvisories?: unknown;
  plannerAdvisories?: unknown;
  modelMetadata?: unknown;
  fallback?: unknown;
  createdAt: Date | string;
}

interface AiAdvisoryMetadataDelegate {
  create(input: { data: Record<string, unknown> }): Promise<AiAdvisoryMetadataRecord>;
  findFirst(input: { where: { id: string; tenantId: string } }): Promise<AiAdvisoryMetadataRecord | null>;
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
    private readonly runtimeClient?: AiAdvisoryRuntimeClient,
    @Optional() private readonly prisma?: PrismaService
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

    const persistentStore = this.persistentStore();
    if (persistentStore) {
      return this.toAdvisoryResult(
        await persistentStore.create({
          data: {
            id: advisory.id,
            tenantId: advisory.tenantId,
            scanRequestId: advisory.scanRequestId,
            findingId: advisory.findingId,
            modelVersion: advisory.modelVersion,
            advisoryOnly: advisory.advisoryOnly,
            redactedEvidenceOnly: advisory.redactedEvidenceOnly,
            detectorSignals: advisory.detectorSignals,
            plannerSteps: advisory.plannerSteps,
            confidence: advisory.confidence,
            detectorAdvisories: advisory.detectorAdvisories,
            plannerAdvisories: advisory.plannerAdvisories,
            modelMetadata: advisory.modelMetadata,
            fallback: advisory.fallback
          }
        })
      );
    }

    this.advisories.push(advisory);

    return advisory;
  }

  async getAdvisory(tenantId: string, advisoryId: string): Promise<AiAdvisoryResult> {
    const persistentStore = this.persistentStore();
    if (persistentStore) {
      const advisory = await persistentStore.findFirst({
        where: {
          id: advisoryId,
          tenantId
        }
      });

      if (advisory) {
        return this.toAdvisoryResult(advisory);
      }
    }

    const advisory = this.advisories.find(
      (candidate) => candidate.id === advisoryId && candidate.tenantId === tenantId
    );

    if (!advisory) {
      throw new NotFoundException("AI advisory was not found for tenant.");
    }

    return advisory;
  }

  private persistentStore(): AiAdvisoryMetadataDelegate | undefined {
    const candidate = this.prisma as unknown as { aiAdvisoryMetadata?: AiAdvisoryMetadataDelegate } | undefined;

    if (
      candidate?.aiAdvisoryMetadata &&
      typeof candidate.aiAdvisoryMetadata.create === "function" &&
      typeof candidate.aiAdvisoryMetadata.findFirst === "function"
    ) {
      return candidate.aiAdvisoryMetadata;
    }

    return undefined;
  }

  private toAdvisoryResult(record: AiAdvisoryMetadataRecord): AiAdvisoryResult {
    return {
      id: record.id,
      tenantId: record.tenantId,
      scanRequestId: record.scanRequestId,
      findingId: record.findingId,
      modelVersion: record.modelVersion,
      advisoryOnly: true,
      redactedEvidenceOnly: true,
      detectorSignals: toStringArray(record.detectorSignals),
      plannerSteps: toStringArray(record.plannerSteps),
      confidence: record.confidence,
      detectorAdvisories: toDetectorAdvisories(record.detectorAdvisories),
      plannerAdvisories: toPlannerAdvisories(record.plannerAdvisories),
      modelMetadata: toModelMetadata(record.modelMetadata),
      fallback: toFallback(record.fallback),
      createdAt: record.createdAt instanceof Date ? record.createdAt.toISOString() : record.createdAt
    };
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

function toStringArray(input: unknown): string[] {
  return Array.isArray(input) ? input.filter((item): item is string => typeof item === "string") : [];
}

function toDetectorAdvisories(input: unknown): AiDetectorAdvisory[] | undefined {
  if (!Array.isArray(input)) {
    return undefined;
  }

  return input.filter(isDetectorAdvisory);
}

function toPlannerAdvisories(input: unknown): AiPlannerAdvisory[] | undefined {
  if (!Array.isArray(input)) {
    return undefined;
  }

  return input.filter(isPlannerAdvisory);
}

function toModelMetadata(input: unknown): AiModelMetadata | undefined {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return undefined;
  }

  const candidate = input as Record<string, unknown>;

  if (
    typeof candidate.provider === "string" &&
    typeof candidate.model === "string" &&
    typeof candidate.version === "string"
  ) {
    return {
      provider: candidate.provider,
      model: candidate.model,
      version: candidate.version
    };
  }

  return undefined;
}

function toFallback(input: unknown): AiInferenceFallback | undefined {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return undefined;
  }

  const candidate = input as Record<string, unknown>;

  if (typeof candidate.used !== "boolean") {
    return undefined;
  }

  return {
    used: candidate.used,
    reason: typeof candidate.reason === "string" ? candidate.reason : undefined
  };
}

function isDetectorAdvisory(input: unknown): input is AiDetectorAdvisory {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return false;
  }

  const candidate = input as Record<string, unknown>;

  return (
    typeof candidate.findingId === "string" &&
    typeof candidate.confidence === "number" &&
    typeof candidate.rationale === "string" &&
    Array.isArray(candidate.signals) &&
    candidate.signals.every((signal) => typeof signal === "string")
  );
}

function isPlannerAdvisory(input: unknown): input is AiPlannerAdvisory {
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
