import { BadRequestException, Injectable, NotFoundException } from "@nestjs/common";

import type { AiAdvisoryRequest, AiAdvisoryResult } from "../../../../packages/shared/src";

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

  createAdvisory(input: AiAdvisoryRequest): AiAdvisoryResult {
    this.assertReducedInput(input);

    const advisory: AiAdvisoryResult = {
      id: `ai_advisory_${++this.advisorySequence}`,
      tenantId: input.tenantId,
      scanRequestId: input.scanRequestId,
      findingId: input.findingId,
      modelVersion: input.modelVersion,
      advisoryOnly: true,
      redactedEvidenceOnly: true,
      detectorSignals: this.detectorSignalsFor(input),
      plannerSteps: this.plannerStepsFor(input),
      confidence: this.confidenceFor(input),
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
