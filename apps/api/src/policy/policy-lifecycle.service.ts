import { BadRequestException, Injectable, NotFoundException } from "@nestjs/common";

import type {
  Suppression,
  SuppressionCreateInput,
  Waiver,
  WaiverCreateInput,
  WaiverUpdateInput
} from '@aegisai/shared';
import { PolicyLifecycleStore } from './policy-lifecycle.store';

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
  constructor(private readonly store: PolicyLifecycleStore) {}

  async createWaiver(input: WaiverCreateInput): Promise<Waiver> {
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
    this.assertIsoInstant(input.expiresAt, 'expiresAt');
    return this.store.createWaiver(input);
  }

  async updateWaiver(
    waiverId: string,
    input: WaiverUpdateInput
  ): Promise<Waiver> {
    this.assertExactLifecyclePayload(
      input,
      WAIVER_UPDATE_KEYS,
      ['tenantId']
    );
    this.assertRequiredString(input.tenantId, "tenantId");

    if (input.owner !== undefined) {
      this.assertRequiredString(input.owner, "owner");
    }

    if (input.reason !== undefined) {
      this.assertRequiredString(input.reason, "reason");
    }

    if (input.scope !== undefined) {
      this.assertRequiredString(input.scope, "scope");
    }

    if (input.expiresAt !== undefined) {
      this.assertRequiredString(input.expiresAt, "expiresAt");
      this.assertIsoInstant(input.expiresAt, 'expiresAt');
    }

    if (input.lastReviewedAt !== undefined) {
      this.assertRequiredString(input.lastReviewedAt, "lastReviewedAt");
      this.assertIsoInstant(input.lastReviewedAt, 'lastReviewedAt');
    }
    const waiver = await this.store.updateWaiver(waiverId, input);
    if (!waiver) {
      throw new NotFoundException("Waiver was not found for tenant.");
    }
    return waiver;
  }

  async createSuppression(
    input: SuppressionCreateInput
  ): Promise<Suppression> {
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

    if (input.findingId !== undefined) {
      this.assertRequiredString(input.findingId, 'findingId');
    }
    return this.store.createSuppression(input);
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

  private assertIsoInstant(value: string, fieldName: string): void {
    if (
      !Number.isFinite(Date.parse(value)) ||
      new Date(value).toISOString() !== value
    ) {
      throw new BadRequestException(
        `Lifecycle payload field must be an ISO instant: ${fieldName}.`
      );
    }
  }
}
