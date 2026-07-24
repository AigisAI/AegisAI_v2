import { BadRequestException, ConflictException, Injectable } from '@nestjs/common';
import {
  evaluateSastQueueAdmission,
  isSastScanPlanValid,
  type SastQueueAdmissionDecision,
  type SastQueuePolicySet,
  type SastScanLane,
  type SastScanPlan,
  type SastUserVisiblePlanningState
} from '@aegisai/shared';

import {
  SastQueueAdmissionStore,
  type SastQueueDispatchAcknowledgementInput,
  type SastQueueDispatchClaim,
  type SastQueueDispatchClaimInput,
  type SastQueueDispatchCompletionInput,
  type SastQueueReservationInput,
  type SastQueueReservationRecord
} from './sast-queue-admission.store';

const MAX_DISPATCH_LEASE_SECONDS = 300;

export interface SastQueueAdmissionResult {
  decision: SastQueueAdmissionDecision;
  admittedAt?: string;
  planning?: SastUserVisiblePlanningState;
  plan?: SastScanPlan;
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
    this.assertPlanIdentity(input);
    const existingReservation = await this.store.findReservation(input.scanRequestId);
    if (existingReservation) {
      this.assertReservationIdentity(existingReservation, input);
      return {
        decision: this.cloneDecision(existingReservation.decision),
        admittedAt: existingReservation.enqueuedAt,
        planning: this.clonePlanning(existingReservation.planning),
        plan: this.clonePlan(existingReservation.plan)
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

    const planning: SastUserVisiblePlanningState = {
      state: 'ADMITTED',
      profileId: input.planningContext.profileId,
      coverageClaim: input.planningContext.coverageClaim,
      queueName: evaluated.queueName,
      queuePolicyVersion: evaluated.queuePolicyVersion,
      queuePolicyDigest: evaluated.queuePolicyDigest,
      canonicalScanKey: input.canonicalScanKey,
      reasonCodes: [
        ...input.planningContext.reasonCodes,
        ...evaluated.reasonCodes
      ],
      updatedAt: this.normalizeTimestamp(input.requestedAt)
    };
    const result = await this.store.reserveAdmitted(input, evaluated, planning);
    if (result.state === 'STALE') {
      return { decision: this.staleUsageDecision(input.policySet, input.lane) };
    }

    this.assertReservationIdentity(result.reservation, input);
    return {
      decision: this.cloneDecision(result.reservation.decision),
      admittedAt: result.reservation.enqueuedAt,
      planning: this.clonePlanning(result.reservation.planning),
      plan: this.clonePlan(result.reservation.plan)
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

    const claim = await this.store.claimNextForDispatch({
      ...input,
      dailyWindowStartedAt: this.normalizeTimestamp(input.dailyWindowStartedAt),
      claimedAt: this.normalizeTimestamp(input.claimedAt)
    });
    return claim ? { ...claim, plan: this.clonePlan(claim.plan) } : null;
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

  async completeDispatch(input: SastQueueDispatchCompletionInput): Promise<boolean> {
    if (
      !this.isNonBlankBounded(input.scanRequestId, 200) ||
      !this.isNonBlankBounded(input.workerId, 200) ||
      !this.isIsoTimestamp(input.completedAt) ||
      !['COMPLETED', 'FAILED', 'CANCELED'].includes(input.terminalStatus)
    ) {
      throw new BadRequestException('SAST dispatch completion input is invalid.');
    }

    return this.store.completeDispatch({
      ...input,
      completedAt: this.normalizeTimestamp(input.completedAt)
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
      reservation.queuePolicyDigest !== input.policySet.digest ||
      reservation.plan.canonicalScanKey !== input.plan.canonicalScanKey ||
      reservation.planning.canonicalScanKey !== input.canonicalScanKey
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

  private clonePlanning(
    planning: SastUserVisiblePlanningState
  ): SastUserVisiblePlanningState {
    return { ...planning, reasonCodes: [...planning.reasonCodes] };
  }

  private clonePlan(plan: SastScanPlan): SastScanPlan {
    return this.deepFreeze(structuredClone(plan));
  }

  private assertPlanIdentity(input: SastQueueReservationInput): void {
    let validPlan = false;
    try {
      validPlan = isSastScanPlanValid(input.plan);
    } catch {
      validPlan = false;
    }
    if (
      !validPlan ||
      input.plan.scanRequestId !== input.scanRequestId ||
      input.plan.canonicalScanKey !== input.canonicalScanKey ||
      input.plan.tenantId !== input.tenantId ||
      input.plan.repositoryState.repositoryBindingId !== input.repositoryBindingId ||
      input.plan.profile.lane !== input.lane ||
      input.plan.profile.id !== input.planningContext.profileId
    ) {
      throw new BadRequestException('SAST queue plan identity is invalid.');
    }
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

  private deepFreeze<T>(value: T): T {
    if (value && typeof value === 'object' && !Object.isFrozen(value)) {
      for (const nested of Object.values(value)) {
        this.deepFreeze(nested);
      }
      Object.freeze(value);
    }

    return value;
  }
}
