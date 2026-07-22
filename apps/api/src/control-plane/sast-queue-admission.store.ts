import type {
  SastQueueAdmissionDecision,
  SastQueuePolicySet,
  SastQueueUsageSnapshot,
  SastScanLane,
  SastScanPlan,
  SastUserVisiblePlanningState
} from '@aegisai/shared';

export const SAST_QUEUE_MAX_DISPATCH_ATTEMPTS = 2;

export interface SastQueueReservationInput {
  scanRequestId: string;
  canonicalScanKey: `sha256:${string}`;
  lane: SastScanLane;
  tenantId: string;
  repositoryBindingId: string;
  requestedAt: string;
  policySet: SastQueuePolicySet;
  usage: SastQueueUsageSnapshot;
  plan: SastScanPlan;
  planningContext: Pick<
    SastUserVisiblePlanningState,
    'profileId' | 'coverageClaim' | 'reasonCodes'
  >;
}

export interface SastQueueReservationRecord {
  scanRequestId: string;
  canonicalScanKey: `sha256:${string}`;
  lane: SastScanLane;
  tenantId: string;
  repositoryBindingId: string;
  queuePolicyVersion: string;
  queuePolicyDigest: `sha256:${string}`;
  dailyWindowStartedAt: string;
  enqueuedAt: string;
  decision: SastQueueAdmissionDecision;
  planning: SastUserVisiblePlanningState;
  plan: SastScanPlan;
}

export type SastQueueReservationWriteResult =
  | { state: 'RESERVED'; reservation: SastQueueReservationRecord }
  | { state: 'EXISTING'; reservation: SastQueueReservationRecord }
  | { state: 'STALE' };

export interface SastQueueDispatchClaimInput {
  lane: SastScanLane;
  dailyWindowStartedAt: string;
  workerId: string;
  claimedAt: string;
  leaseSeconds: number;
}

export interface SastQueueDispatchClaim {
  scanRequestId: string;
  canonicalScanKey: `sha256:${string}`;
  lane: SastScanLane;
  tenantId: string;
  repositoryBindingId: string;
  queueName: 'scan.fast.v1' | 'scan.deep.v1';
  queuePolicyVersion: string;
  queuePolicyDigest: `sha256:${string}`;
  enqueuedAt: string;
  leaseOwner: string;
  leaseExpiresAt: string;
  plan: SastScanPlan;
}

export interface SastQueueDispatchAcknowledgementInput {
  scanRequestId: string;
  workerId: string;
  acknowledgedAt: string;
}

export interface SastQueueDispatchCompletionInput {
  scanRequestId: string;
  workerId: string;
  completedAt: string;
  terminalStatus: 'COMPLETED' | 'FAILED' | 'CANCELED';
}

export abstract class SastQueueAdmissionStore {
  abstract findReservation(scanRequestId: string): Promise<SastQueueReservationRecord | null>;

  abstract reserveAdmitted(
    input: SastQueueReservationInput,
    decision: SastQueueAdmissionDecision,
    planning: SastUserVisiblePlanningState
  ): Promise<SastQueueReservationWriteResult>;

  abstract claimNextForDispatch(
    input: SastQueueDispatchClaimInput
  ): Promise<SastQueueDispatchClaim | null>;

  abstract acknowledgeDispatch(
    input: SastQueueDispatchAcknowledgementInput
  ): Promise<boolean>;

  abstract completeDispatch(
    input: SastQueueDispatchCompletionInput
  ): Promise<boolean>;
}
