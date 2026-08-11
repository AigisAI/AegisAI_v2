import { BadRequestException, Injectable, NotFoundException } from "@nestjs/common";

import type {
  Suppression,
  SuppressionCreateInput,
  Waiver,
  WaiverCreateInput,
  WaiverUpdateInput
} from '@aegisai/shared';

const WAIVER_CREATE_KEYS = [
  'tenantId',
  'owner',
  'reason',
  'scope',
  'expiresAt'
] as const;
const WAIVER_UPDATE_KEYS = [
  'tenantId',
  'owner',
  'reason',
  'scope',
  'expiresAt',
  'lastReviewedAt'
] as const;
const SUPPRESSION_CREATE_KEYS = [
  'tenantId',
  'scanRequestId',
  'findingId',
  'reason'
] as const;

@Injectable()
export class PolicyLifecycleService {
  private readonly waivers: Waiver[] = [];
  private readonly suppressions: Suppression[] = [];
  private waiverSequence = 0;
  private suppressionSequence = 0;

  createWaiver(input: WaiverCreateInput): Waiver {
    this.assertExactLifecyclePayload(
      input,
      WAIVER_CREATE_KEYS,
      WAIVER_CREATE_KEYS
    );
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
    this.assertExactLifecyclePayload(
      input,
      WAIVER_UPDATE_KEYS,
      ['tenantId']
    );
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
    this.assertExactLifecyclePayload(
      input,
      SUPPRESSION_CREATE_KEYS,
      ['tenantId', 'scanRequestId', 'reason']
    );
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

  private assertExactLifecyclePayload(
    input: unknown,
    allowedKeys: readonly string[],
    requiredKeys: readonly string[]
  ): asserts input is Record<string, unknown> {
    if (
      input === null ||
      typeof input !== 'object' ||
      Array.isArray(input)
    ) {
      throw new BadRequestException(
        'Lifecycle payload must be an exact object.'
      );
    }
    const record = input as Record<string, unknown>;
    if (
      Object.keys(record).some((key) => !allowedKeys.includes(key)) ||
      requiredKeys.some(
        (key) => !Object.prototype.hasOwnProperty.call(record, key)
      )
    ) {
      throw new BadRequestException(
        'Lifecycle payload contains unknown or missing fields.'
      );
    }
  }

  private assertRequiredString(value: unknown, fieldName: string): asserts value is string {
    if (typeof value !== "string" || value.trim().length === 0) {
      throw new BadRequestException(`Lifecycle payload is missing required field: ${fieldName}.`);
    }
  }
}
