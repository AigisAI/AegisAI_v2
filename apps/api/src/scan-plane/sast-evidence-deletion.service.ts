import { createHash, randomUUID } from 'node:crypto';

import {
  buildSastEvidenceDeletionProof,
  isSastEvidenceDeletionProofShapeValid,
  isSastEvidenceDeletionScheduleShapeValid,
  type SastEvidenceDeletionReceipt
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';

import {
  SastEvidenceAccessPersistenceError,
  SastEvidenceAccessStore,
  type SastEvidenceDeletionCandidate
} from './sast-evidence-access.store';
import {
  SastEvidenceDeletionAuthority,
  SastEvidenceDeletionAuthorityUnavailableError
} from './sast-evidence-deletion.authority';

const DELETION_LEASE_MILLISECONDS = 60_000;
const DELETION_RETRY_MILLISECONDS = 60_000;

export type SastEvidenceDeletionProcessingResult =
  | 'IDLE'
  | 'DELETED'
  | 'REPLAYED'
  | 'RETRY_SCHEDULED'
  | 'LEASE_LOST';

@Injectable()
export class SastEvidenceDeletionService {
  constructor(
    private readonly store: SastEvidenceAccessStore,
    private readonly authority: SastEvidenceDeletionAuthority
  ) {}

  backfill(referenceTime = new Date(), limit = 32): Promise<number> {
    return this.store.backfillDeletionSchedules({
      referenceTime: referenceTime.toISOString(),
      limit
    });
  }

  async nextDueAt(): Promise<Date | null> {
    const value = await this.store.nextDeletionDueAt();
    if (value === null) return null;
    if (!isCanonicalTimestamp(value)) {
      throw new SastEvidenceAccessPersistenceError(
        'CONTEXT_DRIFT'
      );
    }
    return new Date(value);
  }

  async processNext(
    referenceTime: Date,
    workerId: string,
    clock: () => string = () => new Date().toISOString()
  ): Promise<SastEvidenceDeletionProcessingResult> {
    if (
      !Number.isFinite(referenceTime.getTime()) ||
      !isBoundedIdentifier(workerId)
    ) {
      return 'IDLE';
    }
    const reference = referenceTime.toISOString();
    const candidate = await this.store.claimDeletion({
      referenceTime: reference,
      leaseOwner: workerId,
      leaseExpiresAt: new Date(
        referenceTime.getTime() + DELETION_LEASE_MILLISECONDS
      ).toISOString()
    });
    if (!candidate) return 'IDLE';
    if (!isCandidateValid(candidate, reference)) {
      await this.safeRelease(candidate, referenceTime);
      return 'RETRY_SCHEDULED';
    }

    let receipt: SastEvidenceDeletionReceipt;
    try {
      receipt = await this.authority.delete({
        operationId: candidate.schedule.operationId,
        deletionScheduleId:
          candidate.schedule.deletionScheduleId,
        deletionScheduleDigest:
          candidate.schedule.scheduleDigest,
        scope: candidate.schedule.scope
      });
    } catch (error) {
      await this.safeRelease(candidate, referenceTime);
      if (
        error instanceof
        SastEvidenceDeletionAuthorityUnavailableError
      ) {
        return 'RETRY_SCHEDULED';
      }
      return 'RETRY_SCHEDULED';
    }

    const observedAt = readClock(clock);
    if (
      !observedAt ||
      !isReceiptValid(receipt, candidate, observedAt)
    ) {
      await this.safeRelease(candidate, referenceTime);
      return 'RETRY_SCHEDULED';
    }
    const proof = buildSastEvidenceDeletionProof({
      schedule: candidate.schedule,
      receipt,
      digestCanonical: digest
    });
    if (!isSastEvidenceDeletionProofShapeValid(proof, digest)) {
      await this.safeRelease(candidate, referenceTime);
      return 'RETRY_SCHEDULED';
    }
    try {
      const finalized = await this.store.finalizeDeletion({
        candidate,
        receipt,
        proof
      });
      if (
        !isSastEvidenceDeletionProofShapeValid(
          finalized.proof,
          digest
        ) ||
        finalized.proof.deletionProofId !==
          proof.deletionProofId ||
        finalized.proof.providerReceiptDigest !==
          proof.providerReceiptDigest
      ) {
        return 'RETRY_SCHEDULED';
      }
      return finalized.replayed ? 'REPLAYED' : 'DELETED';
    } catch (error) {
      if (
        error instanceof SastEvidenceAccessPersistenceError &&
        error.reason === 'LEASE_LOST'
      ) {
        return 'LEASE_LOST';
      }
      await this.safeRelease(candidate, referenceTime);
      return 'RETRY_SCHEDULED';
    }
  }

  private async safeRelease(
    candidate: SastEvidenceDeletionCandidate,
    referenceTime: Date
  ): Promise<void> {
    try {
      await this.store.releaseDeletion({
        candidate,
        retryAt: new Date(
          referenceTime.getTime() + DELETION_RETRY_MILLISECONDS
        ).toISOString()
      });
    } catch {
      // A lost lease is already fenced by the durable claim token.
    }
  }
}

export function createSastEvidenceDeletionWorkerId(): string {
  return `evidence-deletion:${randomUUID()}`;
}

function isCandidateValid(
  candidate: Readonly<SastEvidenceDeletionCandidate>,
  referenceTime: string
): boolean {
  return (
    isSastEvidenceDeletionScheduleShapeValid(
      candidate.schedule,
      digest
    ) &&
    isBoundedIdentifier(candidate.leaseOwner) &&
    /^[a-f0-9-]{36}$/u.test(candidate.leaseToken) &&
    isCanonicalTimestamp(candidate.leaseExpiresAt) &&
    Date.parse(candidate.schedule.deleteAfter) <=
      Date.parse(referenceTime) &&
    Date.parse(candidate.leaseExpiresAt) >
      Date.parse(referenceTime)
  );
}

function isReceiptValid(
  receipt: unknown,
  candidate: Readonly<SastEvidenceDeletionCandidate>,
  observedAt: string
): receipt is SastEvidenceDeletionReceipt {
  if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) {
    return false;
  }
  const value = receipt as Record<string, unknown>;
  const keys = [
    'operationId',
    'providerReceiptRef',
    'providerReceiptDigest',
    'completedAt'
  ];
  return (
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key)) &&
    value.operationId === candidate.schedule.operationId &&
    typeof value.providerReceiptRef === 'string' &&
    /^sast-evidence-delete-receipt:\/\/[a-f0-9]{64}$/u.test(
      value.providerReceiptRef
    ) &&
    typeof value.providerReceiptDigest === 'string' &&
    /^sha256:[a-f0-9]{64}$/u.test(value.providerReceiptDigest) &&
    isCanonicalTimestamp(value.completedAt) &&
    Date.parse(value.completedAt) >=
      Date.parse(candidate.schedule.deleteAfter) &&
    Date.parse(value.completedAt) <= Date.parse(observedAt) &&
    Date.parse(value.completedAt) <=
      Date.parse(candidate.leaseExpiresAt)
  );
}

function isBoundedIdentifier(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= 2048 &&
    value === value.normalize('NFC') &&
    value === value.trim() &&
    !/\p{Cc}/u.test(value)
  );
}

function isCanonicalTimestamp(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const milliseconds = Date.parse(value);
  return (
    Number.isFinite(milliseconds) &&
    new Date(milliseconds).toISOString() === value
  );
}

function readClock(clock: () => string): string | null {
  try {
    const value = clock();
    return isCanonicalTimestamp(value) ? value : null;
  } catch {
    return null;
  }
}

function digest(value: string): `sha256:${string}` {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}
