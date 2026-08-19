import { createHash } from 'node:crypto';

import { ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import {
  SAST_COVERAGE_CLAIMS,
  SAST_PLANNING_REASON_CODES,
  SAST_PLANNING_STATES,
  SAST_PROFILE_IDS,
  buildApplicableSastKillSwitchSelectors,
  buildSastKillSwitchContextFromPlanParts,
  isSastScanPlanValid,
  orderSastQueueCandidatesFairly,
  type SastPlanningReasonCode,
  type SastQueueAdmissionDecision,
  type SastScanPlan,
  type SastUserVisiblePlanningState
} from '@aegisai/shared';

import { PrismaService } from '../prisma/prisma.service';
import {
  SAST_QUEUE_MAX_DISPATCH_ATTEMPTS,
  SastQueueAdmissionStore,
  type SastQueueDispatchAcknowledgementInput,
  type SastQueueDispatchClaim,
  type SastQueueDispatchClaimInput,
  type SastQueueDispatchCompletionInput,
  type SastQueueReservationInput,
  type SastQueueReservationRecord,
  type SastQueueReservationWriteResult
} from './sast-queue-admission.store';

interface PersistedReservationRow {
  scanRequestId: string;
  ledgerId: string;
  canonicalScanKey: string;
  lane: 'FAST' | 'DEEP';
  tenantId: string;
  repositoryBindingId: string;
  queuePolicyVersion: string;
  queuePolicyDigest: string;
  dailyWindowStartedAt: Date;
  enqueuedAt: Date;
  decision: Prisma.JsonValue;
  planning: Prisma.JsonValue;
  immutablePlan: Prisma.JsonValue;
  dispatchLeaseOwner: string | null;
  dispatchLeaseExpiresAt: Date | null;
  dispatchAttempt: number;
  publishedAt: Date | null;
  startedAt: Date | null;
  completedAt: Date | null;
  terminalStatus: string | null;
}

interface LockedRuleBundleLifecycleHeadRow {
  manifestId: string;
  manifestDigest: string;
  bundleId: string;
  bundleDigest: string;
  transitionId: string;
  transitionDigest: string;
  sequence: number;
  lifecycleState: string;
  promotionEvidenceId: string;
  promotionEvidenceDigest: string;
  approvalSetDigest: string;
  selectionReceiptExists: boolean;
}

interface LockedRuleBundleCanaryHeadRow {
  rolloutId: string;
  rolloutDigest: string;
  currentStep: string;
  latestDecisionId: string | null;
  latestDecisionDigest: string | null;
  latestOutcome: string | null;
  assignmentReceiptExists: boolean;
}

interface LockedKillSwitchEvaluationRow {
  headCount: number;
  matchedDecisionCount: number;
  actualHeadCount: bigint;
}

interface LockedKillSwitchHeadRow {
  bindingSelectorKey: string;
  bindingSequence: number;
  bindingDecisionId: string | null;
  bindingDecisionDigest: string | null;
  bindingAction: string | null;
  bindingActive: boolean;
  bindingEffectiveAt: Date | null;
  bindingExpiresAt: Date | null;
  currentSequence: number;
  currentDecisionId: string | null;
  currentDecisionDigest: string | null;
  currentAction: string | null;
  currentActive: boolean;
  currentEffectiveAt: Date | null;
  currentExpiresAt: Date | null;
}

class RetryableDispatchClaimConflict extends Error {}

const digestCanonical = (value: string): `sha256:${string}` =>
  `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;

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
    decision: SastQueueAdmissionDecision,
    planning: SastUserVisiblePlanningState
  ): Promise<SastQueueReservationWriteResult> {
    this.assertAdmissionWriteIdentity(input, decision, planning);
    return this.runSerializable(async (transaction) => {
      const existing = await transaction.sastQueueReservation.findUnique({
        where: { scanRequestId: input.scanRequestId },
        include: { ledger: true }
      });
      if (existing) {
        return { state: 'EXISTING', reservation: this.toReservationRecord(existing) };
      }

      await this.assertCurrentRuleBundleLifecycleHeads(transaction, input.plan);
      await this.assertCurrentRuleBundleCanaryAssignments(
        transaction,
        input.plan
      );
      await this.assertCurrentSastKillSwitchEvaluation(
        transaction,
        input.plan
      );

      const scanRequest = await transaction.scanRequest.findUnique({
        where: { id: input.scanRequestId }
      });
      if (!scanRequest || scanRequest.tenantId !== input.tenantId) {
        throw new NotFoundException('Durable scan request not found for queue admission.');
      }
      if (
        scanRequest.repositoryBindingId !== input.repositoryBindingId ||
        scanRequest.lane !== input.lane ||
        (scanRequest.status !== 'QUEUED' && scanRequest.status !== 'PLANNING')
      ) {
        throw new ConflictException('Durable scan request is not eligible for queue admission.');
      }
      if (scanRequest.sastPlanning !== null) {
        const existingPlanning = this.parsePlanning(scanRequest.sastPlanning);
        if (
          existingPlanning.canonicalScanKey &&
          existingPlanning.canonicalScanKey !== input.canonicalScanKey
        ) {
          throw new ConflictException('SAST canonical planning identity is immutable.');
        }
        if (
          existingPlanning.state === 'ADMITTED' &&
          !this.isEquivalentPlanning(existingPlanning, planning)
        ) {
          throw new ConflictException('An admitted SAST planning decision is immutable.');
        }
      }

      const dailyWindowStartedAt = this.normalizeDate(input.usage.dailyWindowStartedAt);
      const requestedAt = this.normalizeDate(input.requestedAt);
      const ledgerId = this.ledgerId(input.lane);
      let ledger = await transaction.sastQueueLedger.findUnique({ where: { id: ledgerId } });

      if (!ledger) {
        ledger = await transaction.sastQueueLedger.create({
          data: {
            id: ledgerId,
            lane: input.lane,
            snapshotVersion: BigInt(input.usage.snapshotVersion),
            queuedInLane: input.usage.queuedInLane
          }
        });
      }

      const [tenantUsage, dailyTenantUsage, repositoryUsage] = await Promise.all([
        transaction.sastQueueTenantUsage.findUnique({
          where: {
            ledgerId_tenantId: {
              ledgerId,
              tenantId: input.tenantId
            }
          }
        }),
        transaction.sastQueueDailyTenantUsage.findUnique({
          where: {
            ledgerId_tenantId_dailyWindowStartedAt: {
              ledgerId,
              tenantId: input.tenantId,
              dailyWindowStartedAt
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
        (dailyTenantUsage !== null &&
          dailyTenantUsage.admittedTodayForTenant !==
            input.usage.admittedTodayForTenant) ||
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
          queuedForTenant: input.usage.queuedForTenant + 1
        },
        update: {
          queuedForTenant: { increment: 1 }
        }
      });
      await transaction.sastQueueDailyTenantUsage.upsert({
        where: {
          ledgerId_tenantId_dailyWindowStartedAt: {
            ledgerId,
            tenantId: input.tenantId,
            dailyWindowStartedAt
          }
        },
        create: {
          ledgerId,
          tenantId: input.tenantId,
          dailyWindowStartedAt,
          admittedTodayForTenant: input.usage.admittedTodayForTenant + 1
        },
        update: { admittedTodayForTenant: { increment: 1 } }
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
          dailyWindowStartedAt,
          enqueuedAt: requestedAt,
          decision: this.toJson(decision),
          planning: this.toJson(planning),
          immutablePlan: this.toJson(input.plan)
        }
      });
      await transaction.scanRequest.update({
        where: { id: input.scanRequestId },
        data: {
          sastPlanning: this.toJson(planning),
          status: 'QUEUED'
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
          decision: this.cloneDecision(decision),
          planning: this.clonePlanning(planning),
          plan: this.clonePlan(input.plan)
        }
      };
    });
  }

  async claimNextForDispatch(
    input: SastQueueDispatchClaimInput
  ): Promise<SastQueueDispatchClaim | null> {
    return this.runSerializable(async (transaction) => {
      const claimedAt = this.normalizeDate(input.claimedAt);

      const existingClaim = await transaction.sastQueueReservation.findFirst({
        where: {
          lane: input.lane,
          publishedAt: null,
          completedAt: null,
          dispatchLeaseOwner: input.workerId,
          dispatchLeaseExpiresAt: { gt: claimedAt }
        },
        orderBy: [{ enqueuedAt: 'asc' }, { scanRequestId: 'asc' }]
      });
      if (existingClaim) {
        return this.toDispatchClaim(existingClaim);
      }

      await this.expireExhaustedDispatches(transaction, input.lane, claimedAt);

      const oldestPending = await transaction.sastQueueReservation.findFirst({
        where: {
          lane: input.lane,
          publishedAt: null,
          completedAt: null,
          dispatchAttempt: { lt: SAST_QUEUE_MAX_DISPATCH_ATTEMPTS },
          OR: [
            { dispatchLeaseExpiresAt: null },
            { dispatchLeaseExpiresAt: { lte: claimedAt } }
          ]
        },
        orderBy: [{ enqueuedAt: 'asc' }, { scanRequestId: 'asc' }]
      });
      if (!oldestPending) {
        return null;
      }

      const ledgerId = oldestPending.ledgerId;
      const ledger = await transaction.sastQueueLedger.findUnique({ where: { id: ledgerId } });
      if (!ledger || ledger.lane !== input.lane) {
        throw new Error('Persisted SAST queue ledger is unavailable for dispatch.');
      }

      const candidates = await transaction.sastQueueReservation.findMany({
        where: {
          ledgerId,
          publishedAt: null,
          completedAt: null,
          dispatchAttempt: { lt: SAST_QUEUE_MAX_DISPATCH_ATTEMPTS },
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
          completedAt: null,
          dispatchAttempt: { lt: SAST_QUEUE_MAX_DISPATCH_ATTEMPTS },
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
      if (reservation.completedAt) {
        return false;
      }
      if (reservation.publishedAt) {
        return true;
      }
      if (
        !reservation.dispatchLeaseExpiresAt ||
        reservation.dispatchLeaseExpiresAt.getTime() <= acknowledgedAt.getTime()
      ) {
        return false;
      }

      const [ledger, tenantUsage, repositoryUsage] = await Promise.all([
        transaction.sastQueueLedger.findUnique({
          where: { id: reservation.ledgerId }
        }),
        transaction.sastQueueTenantUsage.findUnique({
          where: {
            ledgerId_tenantId: {
              ledgerId: reservation.ledgerId,
              tenantId: reservation.tenantId
            }
          }
        }),
        transaction.sastQueueRepositoryUsage.findUnique({
          where: {
            ledgerId_tenantId_repositoryBindingId: {
              ledgerId: reservation.ledgerId,
              tenantId: reservation.tenantId,
              repositoryBindingId: reservation.repositoryBindingId
            }
          }
        })
      ]);
      if (
        !ledger ||
        ledger.queuedInLane < 1 ||
        !tenantUsage ||
        tenantUsage.queuedForTenant < 1 ||
        !repositoryUsage
      ) {
        throw new Error('Persisted SAST queue usage cannot transition to active.');
      }

      const acknowledged = await transaction.sastQueueReservation.updateMany({
        where: {
          scanRequestId: input.scanRequestId,
          dispatchLeaseOwner: input.workerId,
          publishedAt: null,
          completedAt: null,
          dispatchLeaseExpiresAt: { gt: acknowledgedAt }
        },
        data: { publishedAt: acknowledgedAt, startedAt: acknowledgedAt }
      });

      if (acknowledged.count !== 1) {
        throw new RetryableDispatchClaimConflict();
      }

      await Promise.all([
        transaction.sastQueueLedger.update({
          where: { id: reservation.ledgerId },
          data: {
            queuedInLane: { decrement: 1 },
            snapshotVersion: { increment: 1 }
          }
        }),
        transaction.sastQueueTenantUsage.update({
          where: {
            ledgerId_tenantId: {
              ledgerId: reservation.ledgerId,
              tenantId: reservation.tenantId
            }
          },
          data: {
            queuedForTenant: { decrement: 1 },
            activeForTenant: { increment: 1 }
          }
        }),
        transaction.sastQueueRepositoryUsage.update({
          where: {
            ledgerId_tenantId_repositoryBindingId: {
              ledgerId: reservation.ledgerId,
              tenantId: reservation.tenantId,
              repositoryBindingId: reservation.repositoryBindingId
            }
          },
          data: { activeForRepository: { increment: 1 } }
        }),
        transaction.scanRequest.update({
          where: { id: reservation.scanRequestId },
          data: { status: 'RUNNING', startedAt: acknowledgedAt }
        })
      ]);

      return true;
    });
  }

  private async expireExhaustedDispatches(
    transaction: Prisma.TransactionClient,
    lane: 'FAST' | 'DEEP',
    claimedAt: Date
  ): Promise<void> {
    const exhausted = await transaction.sastQueueReservation.findMany({
      where: {
        lane,
        publishedAt: null,
        completedAt: null,
        dispatchAttempt: { gte: SAST_QUEUE_MAX_DISPATCH_ATTEMPTS },
        dispatchLeaseExpiresAt: { lte: claimedAt }
      },
      orderBy: [{ enqueuedAt: 'asc' }, { scanRequestId: 'asc' }]
    });

    for (const reservation of exhausted) {
      const [ledger, tenantUsage] = await Promise.all([
        transaction.sastQueueLedger.findUnique({
          where: { id: reservation.ledgerId }
        }),
        transaction.sastQueueTenantUsage.findUnique({
          where: {
            ledgerId_tenantId: {
              ledgerId: reservation.ledgerId,
              tenantId: reservation.tenantId
            }
          }
        })
      ]);
      if (
        !ledger ||
        ledger.queuedInLane < 1 ||
        !tenantUsage ||
        tenantUsage.queuedForTenant < 1
      ) {
        throw new Error('Persisted exhausted dispatch cannot release queued capacity.');
      }

      const expired = await transaction.sastQueueReservation.updateMany({
        where: {
          scanRequestId: reservation.scanRequestId,
          publishedAt: null,
          completedAt: null,
          dispatchAttempt: { gte: SAST_QUEUE_MAX_DISPATCH_ATTEMPTS },
          dispatchLeaseExpiresAt: { lte: claimedAt }
        },
        data: {
          completedAt: claimedAt,
          terminalStatus: 'FAILED'
        }
      });
      if (expired.count !== 1) {
        throw new RetryableDispatchClaimConflict();
      }

      await Promise.all([
        transaction.sastQueueLedger.update({
          where: { id: reservation.ledgerId },
          data: {
            queuedInLane: { decrement: 1 },
            snapshotVersion: { increment: 1 }
          }
        }),
        transaction.sastQueueTenantUsage.update({
          where: {
            ledgerId_tenantId: {
              ledgerId: reservation.ledgerId,
              tenantId: reservation.tenantId
            }
          },
          data: { queuedForTenant: { decrement: 1 } }
        }),
        transaction.scanRequest.update({
          where: { id: reservation.scanRequestId },
          data: { status: 'FAILED', completedAt: claimedAt }
        })
      ]);
    }
  }

  async completeDispatch(input: SastQueueDispatchCompletionInput): Promise<boolean> {
    return this.runSerializable(async (transaction) => {
      const completedAt = this.normalizeDate(input.completedAt);
      const reservation = await transaction.sastQueueReservation.findUnique({
        where: { scanRequestId: input.scanRequestId }
      });
      if (!reservation || reservation.dispatchLeaseOwner !== input.workerId) {
        return false;
      }
      if (reservation.completedAt) {
        return reservation.terminalStatus === input.terminalStatus;
      }
      if (!reservation.publishedAt || !reservation.startedAt) {
        return false;
      }

      const [tenantUsage, repositoryUsage] = await Promise.all([
        transaction.sastQueueTenantUsage.findUnique({
          where: {
            ledgerId_tenantId: {
              ledgerId: reservation.ledgerId,
              tenantId: reservation.tenantId
            }
          }
        }),
        transaction.sastQueueRepositoryUsage.findUnique({
          where: {
            ledgerId_tenantId_repositoryBindingId: {
              ledgerId: reservation.ledgerId,
              tenantId: reservation.tenantId,
              repositoryBindingId: reservation.repositoryBindingId
            }
          }
        })
      ]);
      if (
        !tenantUsage ||
        tenantUsage.activeForTenant < 1 ||
        !repositoryUsage ||
        repositoryUsage.activeForRepository < 1
      ) {
        throw new Error('Persisted SAST queue usage cannot transition to terminal.');
      }

      const completed = await transaction.sastQueueReservation.updateMany({
        where: {
          scanRequestId: input.scanRequestId,
          dispatchLeaseOwner: input.workerId,
          publishedAt: { not: null },
          completedAt: null
        },
        data: {
          completedAt,
          terminalStatus: input.terminalStatus
        }
      });
      if (completed.count !== 1) {
        throw new RetryableDispatchClaimConflict();
      }

      await Promise.all([
        transaction.sastQueueLedger.update({
          where: { id: reservation.ledgerId },
          data: { snapshotVersion: { increment: 1 } }
        }),
        transaction.sastQueueTenantUsage.update({
          where: {
            ledgerId_tenantId: {
              ledgerId: reservation.ledgerId,
              tenantId: reservation.tenantId
            }
          },
          data: { activeForTenant: { decrement: 1 } }
        }),
        transaction.sastQueueRepositoryUsage.update({
          where: {
            ledgerId_tenantId_repositoryBindingId: {
              ledgerId: reservation.ledgerId,
              tenantId: reservation.tenantId,
              repositoryBindingId: reservation.repositoryBindingId
            }
          },
          data: { activeForRepository: { decrement: 1 } }
        }),
        transaction.scanRequest.update({
          where: { id: reservation.scanRequestId },
          data: { status: input.terminalStatus, completedAt }
        })
      ]);

      return true;
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
    },
    input: SastQueueReservationInput
  ): boolean {
    return (
      authoritative.activeForTenant === input.usage.activeForTenant &&
      authoritative.queuedForTenant === input.usage.queuedForTenant
    );
  }

  private async assertCurrentRuleBundleLifecycleHeads(
    transaction: Prisma.TransactionClient,
    plan: Readonly<SastScanPlan>
  ): Promise<void> {
    const bundles = [...plan.scannerSet.ruleBundles].sort((left, right) =>
      left.manifestId.localeCompare(right.manifestId)
    );

    for (const bundle of bundles) {
      const lifecycle = bundle.lifecycle;
      const rows = await transaction.$queryRaw<
        LockedRuleBundleLifecycleHeadRow[]
      >`
        SELECT
          head."manifestId",
          head."manifestDigest",
          head."bundleId",
          head."bundleDigest",
          head."transitionId",
          head."transitionDigest",
          head."sequence",
          head."lifecycleState",
          head."promotionEvidenceId",
          head."promotionEvidenceDigest",
          head."approvalSetDigest",
          EXISTS (
            SELECT 1
            FROM "SastRuleBundleLifecycleSelectionReceipt" receipt
            WHERE receipt."id" = ${lifecycle.selectionReceiptId}
              AND receipt."receiptDigest" = ${lifecycle.selectionReceiptDigest}
              AND receipt."manifestId" = head."manifestId"
              AND receipt."manifestDigest" = head."manifestDigest"
              AND receipt."bundleId" = head."bundleId"
              AND receipt."bundleDigest" = head."bundleDigest"
              AND receipt."lifecycleState" = head."lifecycleState"
              AND receipt."lifecycleSequence" = head."sequence"
              AND receipt."transitionId" = head."transitionId"
              AND receipt."transitionDigest" = head."transitionDigest"
              AND receipt."promotionEvidenceId" = head."promotionEvidenceId"
              AND receipt."promotionEvidenceDigest" = head."promotionEvidenceDigest"
              AND receipt."approvalSetDigest" = head."approvalSetDigest"
          ) AS "selectionReceiptExists"
        FROM "SastRuleBundleLifecycleHead" head
        WHERE head."manifestId" = ${bundle.manifestId}
        FOR UPDATE OF head
      `;
      const head = rows[0];
      if (
        rows.length !== 1 ||
        !head ||
        head.manifestId !== bundle.manifestId ||
        head.manifestDigest !== bundle.manifestDigest ||
        head.bundleId !== bundle.bundleId ||
        head.bundleDigest !== bundle.digest ||
        (head.lifecycleState !== 'CANARY' &&
          head.lifecycleState !== 'ACTIVE') ||
        head.lifecycleState !== lifecycle.lifecycleState ||
        head.sequence !== lifecycle.lifecycleSequence ||
        head.transitionId !== lifecycle.lifecycleTransitionId ||
        head.transitionDigest !== lifecycle.lifecycleTransitionDigest ||
        head.promotionEvidenceId !== lifecycle.promotionEvidenceId ||
        head.promotionEvidenceDigest !== lifecycle.promotionEvidenceDigest ||
        head.approvalSetDigest !== lifecycle.approvalSetDigest ||
        head.selectionReceiptExists !== true
      ) {
        throw new ConflictException(
          'SAST rule-bundle lifecycle changed before queue admission.'
        );
      }
    }
  }

  private async assertCurrentSastKillSwitchEvaluation(
    transaction: Prisma.TransactionClient,
    plan: Readonly<SastScanPlan>
  ): Promise<void> {
    const projection = plan.killSwitchEvaluation;
    if (!projection) {
      throw new ConflictException(
        'SAST queue admission requires a clear kill-switch evaluation.'
      );
    }
    const context = buildSastKillSwitchContextFromPlanParts(
      {
        tenantId: plan.tenantId,
        repositoryBindingId: plan.repositoryState.repositoryBindingId,
        scanRequestId: plan.scanRequestId,
        profile: plan.profile,
        profileDigest: plan.profileDigest,
        scannerSet: plan.scannerSet
      },
      digestCanonical
    );
    if (!context || context.contextDigest !== projection.contextDigest) {
      throw new ConflictException(
        'SAST kill-switch evaluation context does not match the immutable plan.'
      );
    }
    const expectedSelectorKeys = buildApplicableSastKillSwitchSelectors(
      context,
      'PLANNING',
      digestCanonical
    ).map((entry) => entry.selectorKey);
    const evaluatedAt = new Date(projection.evaluatedAt);
    const evaluations = await transaction.$queryRaw<
      LockedKillSwitchEvaluationRow[]
    >`
      SELECT
        evaluation."headCount",
        evaluation."matchedDecisionCount",
        (SELECT count(*) FROM "SastKillSwitchEvaluationHead" binding
          WHERE binding."evaluationId" = evaluation."id") AS "actualHeadCount"
      FROM "SastKillSwitchEvaluation" evaluation
      WHERE evaluation."id" = ${projection.evaluationId}
        AND evaluation."receiptDigest" = ${projection.evaluationReceiptDigest}
        AND evaluation."contextDigest" = ${projection.contextDigest}
        AND evaluation."snapshotDigest" = ${projection.snapshotDigest}
        AND evaluation."headSetDigest" = ${projection.headSetDigest}
        AND evaluation."evaluatedAt" = ${evaluatedAt}
        AND evaluation."gate" = 'PLANNING'
        AND evaluation."outcome" = 'CLEAR'
        AND evaluation."tenantId" = ${plan.tenantId}
        AND evaluation."repositoryBindingId" = ${plan.repositoryState.repositoryBindingId}
        AND evaluation."scanRequestId" = ${plan.scanRequestId}
        AND evaluation."profileId" = ${plan.profile.id}
        AND evaluation."profileDigest" = ${plan.profileDigest}
        AND evaluation."scannerSetDigest" = ${plan.scannerSet.scannerSetDigest}
    `;
    const evaluation = evaluations[0];
    if (
      evaluations.length !== 1 ||
      !evaluation ||
      evaluation.matchedDecisionCount !== 0 ||
      BigInt(evaluation.headCount) !== evaluation.actualHeadCount
    ) {
      throw new ConflictException(
        'SAST kill-switch evaluation is unavailable or incomplete.'
      );
    }

    const heads = await transaction.$queryRaw<LockedKillSwitchHeadRow[]>`
      SELECT
        binding."selectorKey" AS "bindingSelectorKey",
        binding."sequence" AS "bindingSequence",
        binding."decisionId" AS "bindingDecisionId",
        binding."decisionDigest" AS "bindingDecisionDigest",
        binding."action" AS "bindingAction",
        binding."active" AS "bindingActive",
        binding."effectiveAt" AS "bindingEffectiveAt",
        binding."expiresAt" AS "bindingExpiresAt",
        head."sequence" AS "currentSequence",
        head."currentDecisionId" AS "currentDecisionId",
        head."currentDecisionDigest" AS "currentDecisionDigest",
        head."currentAction" AS "currentAction",
        head."active" AS "currentActive",
        head."effectiveAt" AS "currentEffectiveAt",
        head."expiresAt" AS "currentExpiresAt"
      FROM "SastKillSwitchEvaluationHead" binding
      JOIN "SastKillSwitchHead" head
        ON head."selectorKey" = binding."selectorKey"
      WHERE binding."evaluationId" = ${projection.evaluationId}
      ORDER BY binding."selectorKey" COLLATE "C"
      FOR UPDATE OF head
    `;
    if (
      heads.length !== evaluation.headCount ||
      heads.length !== expectedSelectorKeys.length ||
      heads.some(
        (head, index) =>
          head.bindingSelectorKey !== expectedSelectorKeys[index] ||
          head.bindingSequence !== head.currentSequence ||
          head.bindingDecisionId !== head.currentDecisionId ||
          head.bindingDecisionDigest !== head.currentDecisionDigest ||
          head.bindingAction !== head.currentAction ||
          head.bindingActive !== head.currentActive ||
          !this.timestampsEqual(
            head.bindingEffectiveAt,
            head.currentEffectiveAt?.toISOString()
          ) ||
          !this.timestampsEqual(
            head.bindingExpiresAt,
            head.currentExpiresAt?.toISOString()
          ) ||
          head.currentActive
      )
    ) {
      throw new ConflictException(
        'SAST kill-switch state changed before queue admission.'
      );
    }
  }

  private async assertCurrentRuleBundleCanaryAssignments(
    transaction: Prisma.TransactionClient,
    plan: Readonly<SastScanPlan>
  ): Promise<void> {
    const bundles = [...plan.scannerSet.ruleBundles].sort((left, right) =>
      left.manifestId.localeCompare(right.manifestId)
    );

    for (const bundle of bundles) {
      const assignment = bundle.canaryAssignment;
      if (bundle.lifecycle.lifecycleState === 'ACTIVE') {
        if (assignment !== null) {
          throw new ConflictException(
            'An active SAST rule bundle cannot carry a canary assignment.'
          );
        }
        continue;
      }
      if (!assignment) {
        throw new ConflictException(
          'A canary SAST rule bundle requires an assignment receipt.'
        );
      }

      const rows = await transaction.$queryRaw<
        LockedRuleBundleCanaryHeadRow[]
      >`
        SELECT
          head."rolloutId",
          head."rolloutDigest",
          head."currentStep",
          head."latestDecisionId",
          head."latestDecisionDigest",
          head."latestOutcome",
          EXISTS (
            SELECT 1
            FROM "SastRuleBundleCanaryAssignmentReceipt" receipt
            JOIN "SastRuleBundleCanaryMembership" membership
              ON membership."id" = receipt."membershipId"
             AND membership."membershipDigest" = receipt."membershipDigest"
            JOIN "SastRuleBundleCanaryRollout" rollout
              ON rollout."id" = receipt."rolloutId"
             AND rollout."rolloutDigest" = receipt."rolloutDigest"
            WHERE receipt."id" = ${assignment.assignmentReceiptId}
              AND receipt."assignmentReceiptDigest" = ${assignment.assignmentReceiptDigest}
              AND receipt."rolloutId" = head."rolloutId"
              AND receipt."rolloutDigest" = head."rolloutDigest"
              AND receipt."membershipId" = ${assignment.membershipId}
              AND receipt."membershipDigest" = ${assignment.membershipDigest}
              AND receipt."tenantId" = ${plan.tenantId}
              AND receipt."repositoryBindingId" = ${plan.repositoryState.repositoryBindingId}
              AND receipt."profileId" = ${plan.profile.id}
              AND receipt."profileDigest" = ${plan.profileDigest}
              AND receipt."bucketBasisPoints" = ${assignment.bucketBasisPoints}
              AND receipt."step" = head."currentStep"
              AND receipt."stepHeadDecisionId" IS NOT DISTINCT FROM head."latestDecisionId"
              AND receipt."stepHeadDecisionDigest" IS NOT DISTINCT FROM head."latestDecisionDigest"
              AND receipt."selection" = 'CANDIDATE'
              AND receipt."selectedManifestId" = ${bundle.manifestId}
              AND receipt."selectedManifestDigest" = ${bundle.manifestDigest}
              AND receipt."selectedBundleDigest" = ${bundle.digest}
              AND membership."tenantId" = receipt."tenantId"
              AND membership."repositoryBindingId" = receipt."repositoryBindingId"
              AND membership."profileId" = receipt."profileId"
              AND membership."profileDigest" = receipt."profileDigest"
              AND membership."bucketBasisPoints" = receipt."bucketBasisPoints"
              AND membership."excluded" IS FALSE
              AND rollout."candidateManifestId" = ${bundle.manifestId}
              AND rollout."candidateManifestDigest" = ${bundle.manifestDigest}
              AND rollout."candidateBundleDigest" = ${bundle.digest}
          ) AS "assignmentReceiptExists"
        FROM "SastRuleBundleCanaryRolloutHead" head
        WHERE head."rolloutId" = ${assignment.rolloutId}
        FOR UPDATE OF head
      `;
      const head = rows[0];
      if (
        rows.length !== 1 ||
        !head ||
        head.rolloutId !== assignment.rolloutId ||
        head.rolloutDigest !== assignment.rolloutDigest ||
        head.currentStep !== assignment.step ||
        head.latestDecisionId !== assignment.stepHeadDecisionId ||
        head.latestDecisionDigest !== assignment.stepHeadDecisionDigest ||
        head.latestOutcome === 'PAUSED' ||
        head.assignmentReceiptExists !== true
      ) {
        throw new ConflictException(
          'SAST rule-bundle canary assignment changed before queue admission.'
        );
      }
    }
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
      ledger: { lane: 'FAST' | 'DEEP' };
    }
  ): SastQueueReservationRecord {
    const decision = this.parseDecision(reservation.decision);
    const planning = this.parsePlanning(reservation.planning);
    const plan = this.parsePlan(reservation.immutablePlan);
    this.assertPersistedAdmissionIdentity(reservation, decision, planning, plan);
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
      dailyWindowStartedAt: reservation.dailyWindowStartedAt.toISOString(),
      enqueuedAt: reservation.enqueuedAt.toISOString(),
      decision,
      planning,
      plan
    };
  }

  private toDispatchClaim(reservation: PersistedReservationRow): SastQueueDispatchClaim {
    const decision = this.parseDecision(reservation.decision);
    const planning = this.parsePlanning(reservation.planning);
    const plan = this.parsePlan(reservation.immutablePlan);
    this.assertPersistedAdmissionIdentity(reservation, decision, planning, plan);
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
      leaseExpiresAt: reservation.dispatchLeaseExpiresAt.toISOString(),
      plan
    };
  }

  private assertPersistedAdmissionIdentity(
    reservation: PersistedReservationRow,
    decision: SastQueueAdmissionDecision,
    planning: SastUserVisiblePlanningState,
    plan: SastScanPlan
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
      decision.retryAfterSeconds !== undefined ||
      planning.state !== 'ADMITTED' ||
      planning.profileId !== plan.profile.id ||
      planning.canonicalScanKey !== reservation.canonicalScanKey ||
      planning.queueName !== expectedQueueName ||
      planning.queuePolicyVersion !== reservation.queuePolicyVersion ||
      planning.queuePolicyDigest !== reservation.queuePolicyDigest ||
      plan.scanRequestId !== reservation.scanRequestId ||
      plan.canonicalScanKey !== reservation.canonicalScanKey ||
      plan.tenantId !== reservation.tenantId ||
      plan.repositoryState.repositoryBindingId !== reservation.repositoryBindingId ||
      plan.profile.lane !== reservation.lane
    ) {
      throw new Error('Persisted SAST queue admission identity is invalid.');
    }
  }

  private assertAdmissionWriteIdentity(
    input: SastQueueReservationInput,
    decision: SastQueueAdmissionDecision,
    planning: SastUserVisiblePlanningState
  ): void {
    let validPlan = false;
    try {
      validPlan = isSastScanPlanValid(input.plan);
    } catch {
      validPlan = false;
    }
    const expectedQueueName = input.lane === 'FAST' ? 'scan.fast.v1' : 'scan.deep.v1';
    if (
      !validPlan ||
      input.plan.scanRequestId !== input.scanRequestId ||
      input.plan.canonicalScanKey !== input.canonicalScanKey ||
      input.plan.tenantId !== input.tenantId ||
      input.plan.repositoryState.repositoryBindingId !== input.repositoryBindingId ||
      input.plan.profile.lane !== input.lane ||
      decision.state !== 'ADMITTED' ||
      decision.queueName !== expectedQueueName ||
      decision.fairnessKey !== input.tenantId ||
      decision.queuePolicyVersion !== input.policySet.policyVersion ||
      decision.queuePolicyDigest !== input.policySet.digest ||
      decision.reasonCodes.length !== 0 ||
      decision.retryAfterSeconds !== undefined ||
      planning.state !== 'ADMITTED' ||
      planning.profileId !== input.plan.profile.id ||
      !(SAST_COVERAGE_CLAIMS as readonly string[]).includes(planning.coverageClaim) ||
      !planning.reasonCodes.every((reasonCode) =>
        (SAST_PLANNING_REASON_CODES as readonly string[]).includes(reasonCode)
      ) ||
      !Number.isFinite(Date.parse(planning.updatedAt)) ||
      planning.canonicalScanKey !== input.canonicalScanKey ||
      planning.queueName !== expectedQueueName ||
      planning.queuePolicyVersion !== input.policySet.policyVersion ||
      planning.queuePolicyDigest !== input.policySet.digest
    ) {
      throw new ConflictException('SAST admitted reservation payload is invalid.');
    }
  }

  private isEquivalentPlanning(
    left: SastUserVisiblePlanningState,
    right: SastUserVisiblePlanningState
  ): boolean {
    return (
      left.state === right.state &&
      left.profileId === right.profileId &&
      left.coverageClaim === right.coverageClaim &&
      left.queueName === right.queueName &&
      left.queuePolicyVersion === right.queuePolicyVersion &&
      left.queuePolicyDigest === right.queuePolicyDigest &&
      left.canonicalScanKey === right.canonicalScanKey &&
      left.retryAfterSeconds === right.retryAfterSeconds &&
      left.reasonCodes.length === right.reasonCodes.length &&
      left.reasonCodes.every((reasonCode, index) => reasonCode === right.reasonCodes[index])
    );
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

  private parsePlanning(value: Prisma.JsonValue): SastUserVisiblePlanningState {
    if (!value || Array.isArray(value) || typeof value !== 'object') {
      throw new Error('Persisted SAST planning state is invalid.');
    }
    const candidate = value as Record<string, Prisma.JsonValue>;
    const reasonCodes = candidate.reasonCodes;
    if (
      typeof candidate.state !== 'string' ||
      !(SAST_PLANNING_STATES as readonly string[]).includes(candidate.state) ||
      typeof candidate.coverageClaim !== 'string' ||
      !(SAST_COVERAGE_CLAIMS as readonly string[]).includes(candidate.coverageClaim) ||
      !Array.isArray(reasonCodes) ||
      !reasonCodes.every(
        (reasonCode): reasonCode is SastPlanningReasonCode =>
          typeof reasonCode === 'string' &&
          (SAST_PLANNING_REASON_CODES as readonly string[]).includes(reasonCode)
      ) ||
      typeof candidate.updatedAt !== 'string' ||
      !Number.isFinite(Date.parse(candidate.updatedAt))
    ) {
      throw new Error('Persisted SAST planning state is invalid.');
    }

    return {
      state: candidate.state as SastUserVisiblePlanningState['state'],
      profileId:
        typeof candidate.profileId === 'string' &&
        (SAST_PROFILE_IDS as readonly string[]).includes(candidate.profileId)
          ? (candidate.profileId as SastUserVisiblePlanningState['profileId'])
          : undefined,
      coverageClaim: candidate.coverageClaim as SastUserVisiblePlanningState['coverageClaim'],
      queueName:
        candidate.queueName === 'scan.fast.v1' || candidate.queueName === 'scan.deep.v1'
          ? candidate.queueName
          : undefined,
      queuePolicyVersion:
        typeof candidate.queuePolicyVersion === 'string'
          ? candidate.queuePolicyVersion
          : undefined,
      queuePolicyDigest:
        typeof candidate.queuePolicyDigest === 'string'
          ? this.asDigest(candidate.queuePolicyDigest)
          : undefined,
      canonicalScanKey:
        typeof candidate.canonicalScanKey === 'string'
          ? this.asDigest(candidate.canonicalScanKey)
          : undefined,
      reasonCodes: [...reasonCodes],
      retryAfterSeconds:
        typeof candidate.retryAfterSeconds === 'number'
          ? candidate.retryAfterSeconds
          : undefined,
      updatedAt: new Date(candidate.updatedAt).toISOString()
    };
  }

  private parsePlan(value: Prisma.JsonValue): SastScanPlan {
    const plan = structuredClone(value) as unknown as SastScanPlan;
    let valid = false;
    try {
      valid = isSastScanPlanValid(plan);
    } catch {
      valid = false;
    }
    if (!valid) {
      throw new Error('Persisted immutable SAST scan plan is invalid.');
    }
    return plan;
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
    return structuredClone(plan);
  }

  private toJson(value: unknown): Prisma.InputJsonValue {
    return JSON.parse(JSON.stringify(value)) as Prisma.InputJsonValue;
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

  private ledgerId(lane: 'FAST' | 'DEEP'): string {
    return `lane:${lane}`;
  }
}
