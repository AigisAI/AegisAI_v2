import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import {
  SAST_PLANNING_REASON_CODES,
  orderSastQueueCandidatesFairly,
  type SastPlanningReasonCode,
  type SastQueueAdmissionDecision
} from '@aegisai/shared';

import { PrismaService } from '../prisma/prisma.service';
import {
  SastQueueAdmissionStore,
  type SastQueueDispatchAcknowledgementInput,
  type SastQueueDispatchClaim,
  type SastQueueDispatchClaimInput,
  type SastQueueReservationInput,
  type SastQueueReservationRecord,
  type SastQueueReservationWriteResult
} from './sast-queue-admission.store';

interface PersistedReservationRow {
  scanRequestId: string;
  canonicalScanKey: string;
  lane: 'FAST' | 'DEEP';
  tenantId: string;
  repositoryBindingId: string;
  queuePolicyVersion: string;
  queuePolicyDigest: string;
  enqueuedAt: Date;
  decision: Prisma.JsonValue;
  dispatchLeaseOwner: string | null;
  dispatchLeaseExpiresAt: Date | null;
}

class RetryableDispatchClaimConflict extends Error {}

@Injectable()
export class PrismaSastQueueAdmissionStore extends SastQueueAdmissionStore {
  private static readonly MAX_TRANSACTION_ATTEMPTS = 5;

  constructor(private readonly prisma: PrismaService) {
    super();
  }

  async findReservation(scanRequestId: string): Promise<SastQueueReservationRecord | null> {
    const reservation = await this.prisma.sastQueueReservation.findUnique({
      where: { scanRequestId },
      include: { ledger: true }
    });

    return reservation ? this.toReservationRecord(reservation) : null;
  }

  async reserveAdmitted(
    input: SastQueueReservationInput,
    decision: SastQueueAdmissionDecision
  ): Promise<SastQueueReservationWriteResult> {
    return this.runSerializable(async (transaction) => {
      const existing = await transaction.sastQueueReservation.findUnique({
        where: { scanRequestId: input.scanRequestId },
        include: { ledger: true }
      });
      if (existing) {
        return { state: 'EXISTING', reservation: this.toReservationRecord(existing) };
      }

      const dailyWindowStartedAt = this.normalizeDate(input.usage.dailyWindowStartedAt);
      const requestedAt = this.normalizeDate(input.requestedAt);
      const ledgerId = this.ledgerId(input.lane, dailyWindowStartedAt);
      let ledger = await transaction.sastQueueLedger.findUnique({ where: { id: ledgerId } });

      if (!ledger) {
        ledger = await transaction.sastQueueLedger.create({
          data: {
            id: ledgerId,
            lane: input.lane,
            dailyWindowStartedAt,
            snapshotVersion: BigInt(input.usage.snapshotVersion),
            queuedInLane: input.usage.queuedInLane
          }
        });
      }

      const [tenantUsage, repositoryUsage] = await Promise.all([
        transaction.sastQueueTenantUsage.findUnique({
          where: {
            ledgerId_tenantId: {
              ledgerId,
              tenantId: input.tenantId
            }
          }
        }),
        transaction.sastQueueRepositoryUsage.findUnique({
          where: {
            ledgerId_tenantId_repositoryBindingId: {
              ledgerId,
              tenantId: input.tenantId,
              repositoryBindingId: input.repositoryBindingId
            }
          }
        })
      ]);

      if (
        ledger.snapshotVersion !== BigInt(input.usage.snapshotVersion) ||
        ledger.queuedInLane !== input.usage.queuedInLane ||
        (tenantUsage !== null && !this.matchesTenantUsage(tenantUsage, input)) ||
        (repositoryUsage !== null && !this.matchesRepositoryUsage(repositoryUsage, input))
      ) {
        return { state: 'STALE' };
      }

      await transaction.sastQueueTenantUsage.upsert({
        where: {
          ledgerId_tenantId: {
            ledgerId,
            tenantId: input.tenantId
          }
        },
        create: {
          ledgerId,
          tenantId: input.tenantId,
          activeForTenant: input.usage.activeForTenant,
          queuedForTenant: input.usage.queuedForTenant + 1,
          admittedTodayForTenant: input.usage.admittedTodayForTenant + 1
        },
        update: {
          queuedForTenant: { increment: 1 },
          admittedTodayForTenant: { increment: 1 }
        }
      });
      await transaction.sastQueueRepositoryUsage.upsert({
        where: {
          ledgerId_tenantId_repositoryBindingId: {
            ledgerId,
            tenantId: input.tenantId,
            repositoryBindingId: input.repositoryBindingId
          }
        },
        create: {
          ledgerId,
          tenantId: input.tenantId,
          repositoryBindingId: input.repositoryBindingId,
          activeForRepository: input.usage.activeForRepository,
          lastRepositoryAdmissionAt: requestedAt
        },
        update: { lastRepositoryAdmissionAt: requestedAt }
      });
      await transaction.sastQueueLedger.update({
        where: { id: ledgerId },
        data: {
          queuedInLane: { increment: 1 },
          snapshotVersion: { increment: 1 }
        }
      });
      await transaction.sastQueueReservation.create({
        data: {
          scanRequestId: input.scanRequestId,
          ledgerId,
          canonicalScanKey: input.canonicalScanKey,
          lane: input.lane,
          tenantId: input.tenantId,
          repositoryBindingId: input.repositoryBindingId,
          queuePolicyVersion: input.policySet.policyVersion,
          queuePolicyDigest: input.policySet.digest,
          enqueuedAt: requestedAt,
          decision: this.toJson(decision)
        }
      });

      return {
        state: 'RESERVED',
        reservation: {
          scanRequestId: input.scanRequestId,
          canonicalScanKey: input.canonicalScanKey,
          lane: input.lane,
          tenantId: input.tenantId,
          repositoryBindingId: input.repositoryBindingId,
          queuePolicyVersion: input.policySet.policyVersion,
          queuePolicyDigest: input.policySet.digest,
          dailyWindowStartedAt: dailyWindowStartedAt.toISOString(),
          enqueuedAt: requestedAt.toISOString(),
          decision: this.cloneDecision(decision)
        }
      };
    });
  }

  async claimNextForDispatch(
    input: SastQueueDispatchClaimInput
  ): Promise<SastQueueDispatchClaim | null> {
    return this.runSerializable(async (transaction) => {
      const claimedAt = this.normalizeDate(input.claimedAt);
      const ledgerId = this.ledgerId(input.lane, this.normalizeDate(input.dailyWindowStartedAt));
      const ledger = await transaction.sastQueueLedger.findUnique({ where: { id: ledgerId } });
      if (!ledger) {
        return null;
      }

      const existingClaim = await transaction.sastQueueReservation.findFirst({
        where: {
          ledgerId,
          publishedAt: null,
          dispatchLeaseOwner: input.workerId,
          dispatchLeaseExpiresAt: { gt: claimedAt }
        },
        orderBy: [{ enqueuedAt: 'asc' }, { scanRequestId: 'asc' }]
      });
      if (existingClaim) {
        return this.toDispatchClaim(existingClaim);
      }

      const candidates = await transaction.sastQueueReservation.findMany({
        where: {
          ledgerId,
          publishedAt: null,
          OR: [
            { dispatchLeaseExpiresAt: null },
            { dispatchLeaseExpiresAt: { lte: claimedAt } }
          ]
        },
        orderBy: [{ enqueuedAt: 'asc' }, { scanRequestId: 'asc' }]
      });
      const ordered = orderSastQueueCandidatesFairly(
        input.lane,
        candidates.map((candidate) => ({
          lane: candidate.lane,
          tenantId: candidate.tenantId,
          scanRequestId: candidate.scanRequestId,
          enqueuedAt: candidate.enqueuedAt.toISOString()
        })),
        ledger.lastServedTenantId ?? undefined
      );
      const next = ordered[0];
      if (!next) {
        return null;
      }

      const leaseExpiresAt = new Date(claimedAt.getTime() + input.leaseSeconds * 1000);
      const claimed = await transaction.sastQueueReservation.updateMany({
        where: {
          scanRequestId: next.scanRequestId,
          publishedAt: null,
          OR: [
            { dispatchLeaseExpiresAt: null },
            { dispatchLeaseExpiresAt: { lte: claimedAt } }
          ]
        },
        data: {
          dispatchLeaseOwner: input.workerId,
          dispatchLeaseExpiresAt: leaseExpiresAt,
          dispatchAttempt: { increment: 1 }
        }
      });
      if (claimed.count !== 1) {
        throw new RetryableDispatchClaimConflict();
      }

      await transaction.sastQueueLedger.update({
        where: { id: ledgerId },
        data: { lastServedTenantId: next.tenantId }
      });
      const reservation = await transaction.sastQueueReservation.findUniqueOrThrow({
        where: { scanRequestId: next.scanRequestId }
      });

      return this.toDispatchClaim(reservation);
    });
  }

  async acknowledgeDispatch(
    input: SastQueueDispatchAcknowledgementInput
  ): Promise<boolean> {
    return this.runSerializable(async (transaction) => {
      const acknowledgedAt = this.normalizeDate(input.acknowledgedAt);
      const reservation = await transaction.sastQueueReservation.findUnique({
        where: { scanRequestId: input.scanRequestId }
      });
      if (!reservation || reservation.dispatchLeaseOwner !== input.workerId) {
        return false;
      }
      if (reservation.publishedAt) {
        return true;
      }
      if (
        !reservation.dispatchLeaseExpiresAt ||
        reservation.dispatchLeaseExpiresAt.getTime() < acknowledgedAt.getTime()
      ) {
        return false;
      }

      const acknowledged = await transaction.sastQueueReservation.updateMany({
        where: {
          scanRequestId: input.scanRequestId,
          dispatchLeaseOwner: input.workerId,
          publishedAt: null,
          dispatchLeaseExpiresAt: { gte: acknowledgedAt }
        },
        data: { publishedAt: acknowledgedAt }
      });

      return acknowledged.count === 1;
    });
  }

  private async runSerializable<T>(
    operation: (transaction: Prisma.TransactionClient) => Promise<T>
  ): Promise<T> {
    let lastError: unknown;

    for (let attempt = 1; attempt <= PrismaSastQueueAdmissionStore.MAX_TRANSACTION_ATTEMPTS; attempt += 1) {
      try {
        return await this.prisma.$transaction(operation, {
          isolationLevel: Prisma.TransactionIsolationLevel.Serializable,
          maxWait: 5_000,
          timeout: 10_000
        });
      } catch (error) {
        lastError = error;
        if (!this.isRetryableTransactionError(error) || attempt === PrismaSastQueueAdmissionStore.MAX_TRANSACTION_ATTEMPTS) {
          throw error;
        }
      }
    }

    throw lastError;
  }

  private isRetryableTransactionError(error: unknown): boolean {
    return (
      error instanceof RetryableDispatchClaimConflict ||
      (error instanceof Prisma.PrismaClientKnownRequestError &&
        (error.code === 'P2002' || error.code === 'P2034'))
    );
  }

  private matchesTenantUsage(
    authoritative: {
      activeForTenant: number;
      queuedForTenant: number;
      admittedTodayForTenant: number;
    },
    input: SastQueueReservationInput
  ): boolean {
    return (
      authoritative.activeForTenant === input.usage.activeForTenant &&
      authoritative.queuedForTenant === input.usage.queuedForTenant &&
      authoritative.admittedTodayForTenant === input.usage.admittedTodayForTenant
    );
  }

  private matchesRepositoryUsage(
    authoritative: {
      activeForRepository: number;
      lastRepositoryAdmissionAt: Date | null;
    },
    input: SastQueueReservationInput
  ): boolean {
    return (
      authoritative.activeForRepository === input.usage.activeForRepository &&
      this.timestampsEqual(
        authoritative.lastRepositoryAdmissionAt,
        input.usage.lastRepositoryAdmissionAt
      )
    );
  }

  private timestampsEqual(left: Date | null, right?: string): boolean {
    if (left === null || right === undefined) {
      return left === null && right === undefined;
    }

    return left.getTime() === Date.parse(right);
  }

  private toReservationRecord(
    reservation: PersistedReservationRow & {
      ledger: { dailyWindowStartedAt: Date; lane: 'FAST' | 'DEEP' };
    }
  ): SastQueueReservationRecord {
    const decision = this.parseDecision(reservation.decision);
    this.assertPersistedAdmissionIdentity(reservation, decision);
    if (reservation.ledger.lane !== reservation.lane) {
      throw new Error('Persisted SAST queue ledger lane is invalid.');
    }

    return {
      scanRequestId: reservation.scanRequestId,
      canonicalScanKey: this.asDigest(reservation.canonicalScanKey),
      lane: reservation.lane,
      tenantId: reservation.tenantId,
      repositoryBindingId: reservation.repositoryBindingId,
      queuePolicyVersion: reservation.queuePolicyVersion,
      queuePolicyDigest: this.asDigest(reservation.queuePolicyDigest),
      dailyWindowStartedAt: reservation.ledger.dailyWindowStartedAt.toISOString(),
      enqueuedAt: reservation.enqueuedAt.toISOString(),
      decision
    };
  }

  private toDispatchClaim(reservation: PersistedReservationRow): SastQueueDispatchClaim {
    const decision = this.parseDecision(reservation.decision);
    this.assertPersistedAdmissionIdentity(reservation, decision);
    if (
      !decision.queueName ||
      !reservation.dispatchLeaseOwner ||
      !reservation.dispatchLeaseExpiresAt
    ) {
      throw new Error('Persisted SAST queue reservation is not dispatchable.');
    }

    return {
      scanRequestId: reservation.scanRequestId,
      canonicalScanKey: this.asDigest(reservation.canonicalScanKey),
      lane: reservation.lane,
      tenantId: reservation.tenantId,
      repositoryBindingId: reservation.repositoryBindingId,
      queueName: decision.queueName,
      queuePolicyVersion: reservation.queuePolicyVersion,
      queuePolicyDigest: this.asDigest(reservation.queuePolicyDigest),
      enqueuedAt: reservation.enqueuedAt.toISOString(),
      leaseOwner: reservation.dispatchLeaseOwner,
      leaseExpiresAt: reservation.dispatchLeaseExpiresAt.toISOString()
    };
  }

  private assertPersistedAdmissionIdentity(
    reservation: PersistedReservationRow,
    decision: SastQueueAdmissionDecision
  ): void {
    const expectedQueueName =
      reservation.lane === 'FAST' ? 'scan.fast.v1' : 'scan.deep.v1';
    if (
      decision.state !== 'ADMITTED' ||
      decision.queueName !== expectedQueueName ||
      decision.fairnessKey !== reservation.tenantId ||
      decision.queuePolicyVersion !== reservation.queuePolicyVersion ||
      decision.queuePolicyDigest !== reservation.queuePolicyDigest ||
      decision.reasonCodes.length !== 0 ||
      decision.retryAfterSeconds !== undefined
    ) {
      throw new Error('Persisted SAST queue admission identity is invalid.');
    }
  }

  private parseDecision(value: Prisma.JsonValue): SastQueueAdmissionDecision {
    if (!value || Array.isArray(value) || typeof value !== 'object') {
      throw new Error('Persisted SAST queue decision is invalid.');
    }

    const candidate = value as Record<string, Prisma.JsonValue>;
    const state = candidate.state;
    const reasonCodes = candidate.reasonCodes;
    if (
      (state !== 'ADMITTED' && state !== 'DEFERRED' && state !== 'REJECTED') ||
      !Array.isArray(reasonCodes) ||
      !reasonCodes.every(
        (reasonCode): reasonCode is SastPlanningReasonCode =>
          typeof reasonCode === 'string' &&
          (SAST_PLANNING_REASON_CODES as readonly string[]).includes(reasonCode)
      )
    ) {
      throw new Error('Persisted SAST queue decision is invalid.');
    }

    return {
      state,
      queueName:
        candidate.queueName === 'scan.fast.v1' || candidate.queueName === 'scan.deep.v1'
          ? candidate.queueName
          : undefined,
      fairnessKey:
        typeof candidate.fairnessKey === 'string' ? candidate.fairnessKey : undefined,
      queuePolicyVersion:
        typeof candidate.queuePolicyVersion === 'string'
          ? candidate.queuePolicyVersion
          : undefined,
      queuePolicyDigest:
        typeof candidate.queuePolicyDigest === 'string'
          ? this.asDigest(candidate.queuePolicyDigest)
          : undefined,
      reasonCodes: [...reasonCodes],
      retryAfterSeconds:
        typeof candidate.retryAfterSeconds === 'number'
          ? candidate.retryAfterSeconds
          : undefined
    };
  }

  private cloneDecision(decision: SastQueueAdmissionDecision): SastQueueAdmissionDecision {
    return { ...decision, reasonCodes: [...decision.reasonCodes] };
  }

  private toJson(decision: SastQueueAdmissionDecision): Prisma.InputJsonValue {
    return JSON.parse(JSON.stringify(decision)) as Prisma.InputJsonValue;
  }

  private asDigest(value: string): `sha256:${string}` {
    if (!/^sha256:[a-f0-9]{64}$/u.test(value)) {
      throw new Error('Persisted SAST digest is invalid.');
    }

    return value as `sha256:${string}`;
  }

  private normalizeDate(value: string): Date {
    return new Date(new Date(value).toISOString());
  }

  private ledgerId(lane: 'FAST' | 'DEEP', dailyWindowStartedAt: Date): string {
    return `${lane}:${dailyWindowStartedAt.toISOString()}`;
  }
}
