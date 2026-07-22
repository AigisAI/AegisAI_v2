import type {
  SastQueueAdmissionDecision,
  SastQueuePolicySet,
  SastQueueUsageSnapshot,
  SastScanLane
} from '@aegisai/shared';

export interface SastQueueReservationInput {
  scanRequestId: string;
  canonicalScanKey: `sha256:${string}`;
  lane: SastScanLane;
  tenantId: string;
  repositoryBindingId: string;
  requestedAt: string;
  policySet: SastQueuePolicySet;
  usage: SastQueueUsageSnapshot;
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
}

export interface SastQueueDispatchAcknowledgementInput {
  scanRequestId: string;
  workerId: string;
  acknowledgedAt: string;
}

export abstract class SastQueueAdmissionStore {
  abstract findReservation(scanRequestId: string): Promise<SastQueueReservationRecord | null>;

  abstract reserveAdmitted(
    input: SastQueueReservationInput,
    decision: SastQueueAdmissionDecision
  ): Promise<SastQueueReservationWriteResult>;

  abstract claimNextForDispatch(
    input: SastQueueDispatchClaimInput
  ): Promise<SastQueueDispatchClaim | null>;

  abstract acknowledgeDispatch(
    input: SastQueueDispatchAcknowledgementInput
  ): Promise<boolean>;
}
