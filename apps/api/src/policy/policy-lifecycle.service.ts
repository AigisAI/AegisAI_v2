import { BadRequestException, Injectable, NotFoundException } from "@nestjs/common";

import type {
  Suppression,
  SuppressionCreateInput,
  Waiver,
  WaiverCreateInput,
  WaiverUpdateInput
} from "../../../../packages/shared/src";

const FORBIDDEN_LIFECYCLE_KEYS = [
  "accessToken",
  "refreshToken",
  "tokenValue",
  "secretValue",
  "sourceArchive",
  "fullRepository",
  "rawScannerPayload",
  "aiOverride",
  "policyOverride",
  "findingOverride",
  "enforcementAction",
  "blockRequested"
];

@Injectable()
export class PolicyLifecycleService {
  private readonly waivers: Waiver[] = [];
  private readonly suppressions: Suppression[] = [];
  private waiverSequence = 0;
  private suppressionSequence = 0;

  createWaiver(input: WaiverCreateInput): Waiver {
    this.assertSafeLifecyclePayload(input);
    this.assertRequiredString(input.tenantId, "tenantId");
    this.assertRequiredString(input.owner, "owner");
    this.assertRequiredString(input.reason, "reason");
    this.assertRequiredString(input.scope, "scope");
    this.assertRequiredString(input.expiresAt, "expiresAt");

    const waiver: Waiver = {
      id: `waiver_${++this.waiverSequence}`,
      tenantId: input.tenantId,
      owner: input.owner,
      reason: input.reason,
      scope: input.scope,
      expiresAt: input.expiresAt
    };

    this.waivers.push(waiver);

    return waiver;
  }

  updateWaiver(waiverId: string, input: WaiverUpdateInput): Waiver {
    this.assertSafeLifecyclePayload(input);
    this.assertRequiredString(input.tenantId, "tenantId");

    const waiver = this.waivers.find(
      (candidate) => candidate.id === waiverId && candidate.tenantId === input.tenantId
    );

    if (!waiver) {
      throw new NotFoundException("Waiver was not found for tenant.");
    }

    if (input.owner !== undefined) {
      this.assertRequiredString(input.owner, "owner");
      waiver.owner = input.owner;
    }

    if (input.reason !== undefined) {
      this.assertRequiredString(input.reason, "reason");
      waiver.reason = input.reason;
    }

    if (input.scope !== undefined) {
      this.assertRequiredString(input.scope, "scope");
      waiver.scope = input.scope;
    }

    if (input.expiresAt !== undefined) {
      this.assertRequiredString(input.expiresAt, "expiresAt");
      waiver.expiresAt = input.expiresAt;
    }

    if (input.lastReviewedAt !== undefined) {
      this.assertRequiredString(input.lastReviewedAt, "lastReviewedAt");
      waiver.lastReviewedAt = input.lastReviewedAt;
    }

    return waiver;
  }

  createSuppression(input: SuppressionCreateInput): Suppression {
    this.assertSafeLifecyclePayload(input);
    this.assertRequiredString(input.tenantId, "tenantId");
    this.assertRequiredString(input.scanRequestId, "scanRequestId");

    if (!["STALE_RESULT", "DUPLICATE", "POLICY"].includes(input.reason)) {
      throw new BadRequestException("Suppression reason is invalid.");
    }

    const suppression: Suppression = {
      id: `suppression_${++this.suppressionSequence}`,
      tenantId: input.tenantId,
      scanRequestId: input.scanRequestId,
      findingId: input.findingId,
      reason: input.reason
    };

    this.suppressions.push(suppression);

    return suppression;
  }

  private assertSafeLifecyclePayload(input: unknown): void {
    const serialized = JSON.stringify(input);

    for (const forbiddenKey of FORBIDDEN_LIFECYCLE_KEYS) {
      if (new RegExp(forbiddenKey, "i").test(serialized)) {
        throw new BadRequestException("Lifecycle payload contains forbidden sensitive or authority content.");
      }
    }
  }

  private assertRequiredString(value: unknown, fieldName: string): asserts value is string {
    if (typeof value !== "string" || value.trim().length === 0) {
      throw new BadRequestException(`Lifecycle payload is missing required field: ${fieldName}.`);
    }
  }
}
