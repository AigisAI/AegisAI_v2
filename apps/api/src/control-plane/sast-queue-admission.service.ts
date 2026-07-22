import { BadRequestException, ConflictException, Injectable } from '@nestjs/common';
import {
  evaluateSastQueueAdmission,
  type SastQueueAdmissionDecision,
  type SastQueuePolicySet,
  type SastScanLane
} from '@aegisai/shared';

import {
  SastQueueAdmissionStore,
  type SastQueueDispatchAcknowledgementInput,
  type SastQueueDispatchClaim,
  type SastQueueDispatchClaimInput,
  type SastQueueReservationInput,
  type SastQueueReservationRecord
} from './sast-queue-admission.store';

const MAX_DISPATCH_LEASE_SECONDS = 300;

export interface SastQueueAdmissionResult {
  decision: SastQueueAdmissionDecision;
  admittedAt?: string;
}

@Injectable()
export class SastQueueAdmissionService {
  constructor(private readonly store: SastQueueAdmissionStore) {}

  async reserve(input: SastQueueReservationInput): Promise<SastQueueAdmissionDecision> {
    return (await this.reserveWithContext(input)).decision;
  }

  async reserveWithContext(
    input: SastQueueReservationInput
  ): Promise<SastQueueAdmissionResult> {
    const existingReservation = await this.store.findReservation(input.scanRequestId);
    if (existingReservation) {
      this.assertReservationIdentity(existingReservation, input);
      return {
        decision: this.cloneDecision(existingReservation.decision),
        admittedAt: existingReservation.enqueuedAt
      };
    }

    if (input.usage.snapshotVersion === Number.MAX_SAFE_INTEGER) {
      return { decision: this.invalidUsageDecision(input.policySet) };
    }

    const evaluated = evaluateSastQueueAdmission({
      lane: input.lane,
      tenantId: input.tenantId,
      repositoryBindingId: input.repositoryBindingId,
      requestedAt: input.requestedAt,
      policySet: input.policySet,
      usage: input.usage
    });
    if (evaluated.state !== 'ADMITTED') {
      return { decision: evaluated };
    }

    const result = await this.store.reserveAdmitted(input, evaluated);
    if (result.state === 'STALE') {
      return { decision: this.staleUsageDecision(input.policySet, input.lane) };
    }

    this.assertReservationIdentity(result.reservation, input);
    return {
      decision: this.cloneDecision(result.reservation.decision),
      admittedAt: result.reservation.enqueuedAt
    };
  }

  async claimNextForDispatch(
    input: SastQueueDispatchClaimInput
  ): Promise<SastQueueDispatchClaim | null> {
    if (
      (input.lane !== 'FAST' && input.lane !== 'DEEP') ||
      !this.isUtcDayStart(input.dailyWindowStartedAt) ||
      !this.isNonBlankBounded(input.workerId, 200) ||
      !this.isIsoTimestamp(input.claimedAt) ||
      !Number.isSafeInteger(input.leaseSeconds) ||
      input.leaseSeconds < 1 ||
      input.leaseSeconds > MAX_DISPATCH_LEASE_SECONDS
    ) {
      throw new BadRequestException('SAST dispatch claim input is invalid.');
    }

    return this.store.claimNextForDispatch({
      ...input,
      dailyWindowStartedAt: this.normalizeTimestamp(input.dailyWindowStartedAt),
      claimedAt: this.normalizeTimestamp(input.claimedAt)
    });
  }

  async acknowledgeDispatch(input: SastQueueDispatchAcknowledgementInput): Promise<boolean> {
    if (
      !this.isNonBlankBounded(input.scanRequestId, 200) ||
      !this.isNonBlankBounded(input.workerId, 200) ||
      !this.isIsoTimestamp(input.acknowledgedAt)
    ) {
      throw new BadRequestException('SAST dispatch acknowledgement input is invalid.');
    }

    return this.store.acknowledgeDispatch({
      ...input,
      acknowledgedAt: this.normalizeTimestamp(input.acknowledgedAt)
    });
  }

  private assertReservationIdentity(
    reservation: SastQueueReservationRecord,
    input: SastQueueReservationInput
  ): void {
    if (
      reservation.canonicalScanKey !== input.canonicalScanKey ||
      reservation.lane !== input.lane ||
      reservation.tenantId !== input.tenantId ||
      reservation.repositoryBindingId !== input.repositoryBindingId ||
      reservation.queuePolicyVersion !== input.policySet.policyVersion ||
      reservation.queuePolicyDigest !== input.policySet.digest
    ) {
      throw new ConflictException('An admitted SAST queue reservation is immutable.');
    }
  }

  private staleUsageDecision(
    policySet: SastQueuePolicySet,
    lane: SastScanLane
  ): SastQueueAdmissionDecision {
    const policy = policySet.lanes[lane];
    return {
      state: 'DEFERRED',
      queueName: policy.queueName,
      queuePolicyVersion: policySet.policyVersion,
      queuePolicyDigest: policySet.digest,
      reasonCodes: ['QUEUE_USAGE_STALE'],
      retryAfterSeconds: policy.capacityRetrySeconds
    };
  }

  private invalidUsageDecision(policySet: SastQueuePolicySet): SastQueueAdmissionDecision {
    return {
      state: 'REJECTED',
      queuePolicyVersion: policySet.policyVersion,
      queuePolicyDigest: policySet.digest,
      reasonCodes: ['QUEUE_USAGE_INVALID']
    };
  }

  private cloneDecision(decision: SastQueueAdmissionDecision): SastQueueAdmissionDecision {
    return { ...decision, reasonCodes: [...decision.reasonCodes] };
  }

  private isUtcDayStart(value: string): boolean {
    if (!this.isIsoTimestamp(value)) {
      return false;
    }

    const timestamp = new Date(value);
    return (
      timestamp.getTime() ===
      Date.UTC(timestamp.getUTCFullYear(), timestamp.getUTCMonth(), timestamp.getUTCDate())
    );
  }

  private isIsoTimestamp(value: string): boolean {
    return (
      typeof value === 'string' &&
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u.test(value) &&
      Number.isFinite(Date.parse(value))
    );
  }

  private isNonBlankBounded(value: string, maxLength: number): boolean {
    return (
      typeof value === 'string' &&
      value === value.trim() &&
      value.length > 0 &&
      value.length <= maxLength
    );
  }

  private normalizeTimestamp(value: string): string {
    return new Date(value).toISOString();
  }
}
