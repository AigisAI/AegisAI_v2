import { createHash, randomInt, randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';

import {
  SAST_ACCEPTED_EVIDENCE_POLICY,
  buildSastEvidenceDeletionSchedule,
  isSastAcceptedEvidenceBuildResultShapeValid,
  isSastEvidenceAccessDecisionShapeValid,
  isSastEvidenceDeletionProofShapeValid,
  isSastEvidenceDeletionScheduleShapeValid,
  isSastScanCoverageDecisionShapeValid,
  isSastScanFreshnessDecisionShapeValid,
  type SastAcceptedEvidenceBuildResult,
  type SastEvidenceAccessDecision,
  type SastEvidenceDeletionProof,
  type SastEvidenceDeletionSchedule,
  type SastScanCoverageDecision,
  type SastScanFreshnessDecision
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';

import { PrismaService } from '../prisma/prisma.service';
import {
  SastEvidenceAccessPersistenceError,
  SastEvidenceAccessStore,
  sastEvidenceAccessScopeFromResult,
  type PersistedSastEvidenceAccessDecision,
  type SastEvidenceAccessContext,
  type SastEvidenceDeletionCandidate
} from './sast-evidence-access.store';

const SERIALIZABLE_ATTEMPTS = 3;
const SERIALIZABLE_RETRY_BASE_DELAY_MILLISECONDS = 10;
const SERIALIZABLE_MAX_WAIT_MILLISECONDS = 5_000;
const SERIALIZABLE_INTERACTIVE_TIMEOUT_MILLISECONDS = 10_000;
const SERIALIZABLE_BACKGROUND_TIMEOUT_MILLISECONDS = 120_000;
const MAXIMUM_CONTEXT_DRIFT_ATTEMPTS = 3;
const CONTEXT_DRIFT_RETRY_MILLISECONDS = 60_000;

const scheduleInclude = Prisma.validator<Prisma.SastEvidenceDeletionScheduleInclude>()({
  claim: true,
  proof: true,
  tenant: { select: { sastAiAdvisoryOptIn: true } },
  repositoryBinding: {
    select: { sastAiAdvisoryOptIn: true }
  },
  buildDecision: {
    include: {
      evidencePack: {
        include: {
          fragments: { orderBy: { ordinal: 'asc' } }
        }
      },
      freshnessDecision: {
        include: { coverageDecision: true }
      }
    }
  }
});

const packInclude = Prisma.validator<Prisma.SastAcceptedEvidencePackInclude>()({
  fragments: { orderBy: { ordinal: 'asc' } },
  buildDecision: {
    include: {
      freshnessDecision: {
        include: { coverageDecision: true }
      }
    }
  }
});

type ScheduleRow = Prisma.SastEvidenceDeletionScheduleGetPayload<{
  include: typeof scheduleInclude;
}>;
type PackRow = Prisma.SastAcceptedEvidencePackGetPayload<{
  include: typeof packInclude;
}>;
type EvidenceTransaction = Prisma.TransactionClient;

interface DriftedDeletionClaim {
  driftedScheduleId: string;
}

@Injectable()
export class PrismaSastEvidenceAccessStore
  extends SastEvidenceAccessStore {
  constructor(private readonly prisma: PrismaService) {
    super();
  }

  async load(input: {
    tenantId: string;
    repositoryBindingId: string;
    evidencePackId: string;
    referenceTime: string;
  }): Promise<SastEvidenceAccessContext | null> {
    return this.runSerializable(async (transaction) => {
      let row = await this.readSchedule(transaction, input);
      if (!row) {
        const pack = await transaction.sastAcceptedEvidencePack.findFirst({
          where: {
            id: input.evidencePackId,
            tenantId: input.tenantId,
            repositoryBindingId: input.repositoryBindingId
          },
          include: packInclude
        });
        if (!pack) return null;
        await this.createSchedule(transaction, pack);
        row = await this.readSchedule(transaction, input);
      }
      return row ? contextFromRow(row) : null;
    }, SERIALIZABLE_INTERACTIVE_TIMEOUT_MILLISECONDS);
  }

  async persistDecision(input: {
    context: Readonly<SastEvidenceAccessContext>;
    decision: Readonly<SastEvidenceAccessDecision>;
  }): Promise<PersistedSastEvidenceAccessDecision> {
    if (
      !isSastEvidenceAccessDecisionShapeValid(
        input.decision,
        digest
      ) ||
      stableJson(input.decision.scope) !==
        stableJson(input.context.schedule.scope) ||
      input.decision.deletionScheduleId !==
        input.context.schedule.deletionScheduleId ||
      input.decision.deletionScheduleDigest !==
        input.context.schedule.scheduleDigest
    ) {
      throw new SastEvidenceAccessPersistenceError(
        'OUTPUT_INVALID'
      );
    }
    return this.runSerializable(async (transaction) => {
      const scope = input.decision.scope;
      const currentRow = await this.readSchedule(transaction, {
        tenantId: scope.tenantId,
        repositoryBindingId: scope.repositoryBindingId,
        evidencePackId: scope.evidencePackId
      });
      if (!currentRow) {
        throw new SastEvidenceAccessPersistenceError(
          'CONTEXT_DRIFT'
        );
      }
      const current = contextFromRow(currentRow);
      if (stableJson(current) !== stableJson(input.context)) {
        throw new SastEvidenceAccessPersistenceError(
          'CONTEXT_DRIFT'
        );
      }
      const existing =
        await transaction.sastEvidenceAccessDecision.findUnique({
          where: { id: input.decision.accessDecisionId }
        });
      if (existing) {
        return replayDecision(existing.decision, input.decision);
      }
      const decision = input.decision;
      await transaction.sastEvidenceAccessDecision.create({
        data: {
          id: decision.accessDecisionId,
          buildDecisionId: scope.buildDecisionId,
          deletionScheduleId: decision.deletionScheduleId,
          evidencePackId: scope.evidencePackId,
          tenantId: scope.tenantId,
          repositoryBindingId: scope.repositoryBindingId,
          scanRequestId: scope.scanRequestId,
          attemptId: scope.attemptId,
          occurrenceId: scope.occurrenceId,
          findingFingerprint: scope.findingFingerprint,
          purpose: decision.purpose,
          accessPolicyVersion: decision.accessPolicyVersion,
          secretRegistryVersion: decision.secretRegistryVersion,
          outcome: decision.outcome,
          classification: decision.classification,
          reasonCodes: json(decision.reasonCodes),
          sourcePackDigest: scope.sourcePackDigest,
          redactedProjectionDigest:
            decision.redactedProjectionDigest,
          redactedFragmentCount:
            decision.redactedFragmentCount,
          redactedTotalBytes: decision.redactedTotalBytes,
          redactionCount: decision.redactionCount,
          secondPassRedactionDecisionRef:
            decision.secondPassRedactionDecisionRef,
          reducedEvidenceRef: decision.reducedEvidenceRef,
          aiPayloadExpiresAt: decision.aiPayloadExpiresAt
            ? new Date(decision.aiPayloadExpiresAt)
            : null,
          evidenceExpiresAt: new Date(
            decision.evidenceExpiresAt
          ),
          decision: json(decision),
          decisionDigest: decision.decisionDigest,
          decidedAt: new Date(decision.decidedAt),
          createdAt: new Date(decision.decidedAt)
        }
      });
      return {
        decision: decision as SastEvidenceAccessDecision,
        replayed: false
      };
    }, SERIALIZABLE_INTERACTIVE_TIMEOUT_MILLISECONDS);
  }

  async confirmAccess(input: {
    tenantId: string;
    repositoryBindingId: string;
    evidencePackId: string;
    accessDecisionId: string;
    purpose: 'DASHBOARD' | 'AI_ADVISORY';
    secretRegistryVersion: string;
    redactedProjectionDigest: `sha256:${string}`;
    referenceTime: string;
  }): Promise<SastEvidenceAccessContext | null> {
    return this.runSerializable(async (transaction) => {
      const [row, accessRow] = await Promise.all([
        this.readSchedule(transaction, input),
        transaction.sastEvidenceAccessDecision.findFirst({
          where: {
            id: input.accessDecisionId,
            tenantId: input.tenantId,
            repositoryBindingId: input.repositoryBindingId,
            evidencePackId: input.evidencePackId,
            purpose: input.purpose,
            secretRegistryVersion:
              input.secretRegistryVersion,
            outcome: 'ALLOWED',
            redactedProjectionDigest:
              input.redactedProjectionDigest,
            evidenceExpiresAt: {
              gt: new Date(input.referenceTime)
            }
          }
        })
      ]);
      if (!row || !accessRow) return null;
      const decision =
        accessRow.decision as unknown as SastEvidenceAccessDecision;
      if (
        !isSastEvidenceAccessDecisionShapeValid(decision, digest) ||
        decision.accessDecisionId !== accessRow.id ||
        decision.decisionDigest !== accessRow.decisionDigest ||
        decision.outcome !== 'ALLOWED' ||
        decision.purpose !== input.purpose ||
        decision.secretRegistryVersion !==
          input.secretRegistryVersion ||
        decision.redactedProjectionDigest !==
          input.redactedProjectionDigest ||
        decision.evidenceExpiresAt !==
          accessRow.evidenceExpiresAt.toISOString()
      ) {
        throw new SastEvidenceAccessPersistenceError(
          'CONTEXT_DRIFT'
        );
      }
      const context = contextFromRow(row);
      if (
        stableJson(decision.scope) !==
          stableJson(context.schedule.scope) ||
        decision.deletionScheduleId !==
          context.schedule.deletionScheduleId ||
        decision.deletionScheduleDigest !==
          context.schedule.scheduleDigest
      ) {
        throw new SastEvidenceAccessPersistenceError(
          'CONTEXT_DRIFT'
        );
      }
      return context.deletionState === 'ACTIVE' ? context : null;
    }, SERIALIZABLE_INTERACTIVE_TIMEOUT_MILLISECONDS);
  }

  async backfillDeletionSchedules(input: {
    referenceTime: string;
    limit: number;
  }): Promise<number> {
    const limit = Math.max(1, Math.min(128, input.limit));
    return this.runSerializable(async (transaction) => {
      const rows = await transaction.$queryRaw<Array<{ id: string }>>(
        Prisma.sql`
          SELECT p."id"
          FROM "SastAcceptedEvidencePack" p
          WHERE NOT EXISTS (
            SELECT 1
            FROM "SastEvidenceDeletionSchedule" s
            WHERE s."evidencePackId" = p."id"
          )
          ORDER BY p."expiresAt" ASC, p."id" ASC
          FOR UPDATE OF p SKIP LOCKED
          LIMIT ${limit}
        `
      );
      let scheduled = 0;
      for (const row of rows) {
        const pack =
          await transaction.sastAcceptedEvidencePack.findUnique({
            where: { id: row.id },
            include: packInclude
          });
        if (!pack) continue;
        await this.createSchedule(transaction, pack);
        scheduled += 1;
      }
      return scheduled;
    });
  }

  async nextDeletionDueAt(): Promise<string | null> {
    const rows = await this.prisma.$queryRaw<
      Array<{ dueAt: Date | null }>
    >(Prisma.sql`
      SELECT MIN(
        GREATEST(
          s."deleteAfter",
          CASE
            WHEN c."status" = 'CLAIMED'
              THEN COALESCE(c."leaseExpiresAt", c."nextAttemptAt")
            ELSE c."nextAttemptAt"
          END
        )
      ) AS "dueAt"
      FROM "SastEvidenceDeletionClaim" c
      INNER JOIN "SastEvidenceDeletionSchedule" s
        ON s."id" = c."scheduleId"
      LEFT JOIN "SastEvidenceDeletionProof" p
        ON p."scheduleId" = s."id"
      WHERE c."status" IN ('PENDING', 'CLAIMED')
        AND p."id" IS NULL
    `);
    return rows[0]?.dueAt?.toISOString() ?? null;
  }

  async claimDeletion(input: {
    referenceTime: string;
    leaseOwner: string;
    leaseExpiresAt: string;
  }): Promise<SastEvidenceDeletionCandidate | null> {
    const claimed = await this.runSerializable<
      SastEvidenceDeletionCandidate | DriftedDeletionClaim | null
    >(async (transaction) => {
      const referenceTime = new Date(input.referenceTime);
      const claim =
        await transaction.sastEvidenceDeletionClaim.findFirst({
          where: {
            nextAttemptAt: { lte: referenceTime },
            OR: [
              { status: 'PENDING' },
              {
                status: 'CLAIMED',
                leaseExpiresAt: { lte: referenceTime }
              }
            ],
            schedule: {
              deleteAfter: { lte: referenceTime },
              proof: { is: null }
            }
          },
          orderBy: [
            { nextAttemptAt: 'asc' },
            { scheduleId: 'asc' }
          ],
          include: {
            schedule: { include: scheduleInclude }
          }
        });
      if (!claim) return null;
      let context: SastEvidenceAccessContext;
      try {
        context = contextFromRow(claim.schedule);
      } catch (error) {
        if (
          error instanceof SastEvidenceAccessPersistenceError &&
          error.reason === 'CONTEXT_DRIFT'
        ) {
          return { driftedScheduleId: claim.scheduleId };
        }
        throw error;
      }
      if (
        context.deletionState === 'DELETED' ||
        !context.result?.pack ||
        context.result.pack.packDigest !==
          claim.schedule.sourcePackDigest ||
        Date.parse(context.result.pack.expiresAt) >
          referenceTime.getTime()
      ) {
        return { driftedScheduleId: claim.scheduleId };
      }
      const leaseToken = randomUUID();
      const updated =
        await transaction.sastEvidenceDeletionClaim.updateMany({
          where: {
            scheduleId: claim.scheduleId,
            OR: [
              { status: 'PENDING' },
              {
                status: 'CLAIMED',
                leaseExpiresAt: { lte: referenceTime }
              }
            ]
          },
          data: {
            status: 'CLAIMED',
            leaseOwner: input.leaseOwner,
            leaseToken,
            leaseExpiresAt: new Date(input.leaseExpiresAt),
            attemptCount: { increment: 1 },
            lastErrorCode: null,
            quarantinedAt: null
          }
        });
      if (updated.count !== 1) return null;
      return {
        schedule: context.schedule,
        leaseOwner: input.leaseOwner,
        leaseToken,
        leaseExpiresAt: input.leaseExpiresAt
      };
    });
    if (claimed && 'driftedScheduleId' in claimed) {
      await this.fenceDriftedClaim(
        claimed.driftedScheduleId,
        input.referenceTime
      );
      throw new SastEvidenceAccessPersistenceError(
        'CONTEXT_DRIFT'
      );
    }
    return claimed;
  }

  async finalizeDeletion(input: {
    candidate: Readonly<SastEvidenceDeletionCandidate>;
    receipt: Readonly<{
      operationId: string;
      providerReceiptRef: string;
      providerReceiptDigest: `sha256:${string}`;
      completedAt: string;
    }>;
    proof: Readonly<SastEvidenceDeletionProof>;
  }): Promise<{ proof: SastEvidenceDeletionProof; replayed: boolean }> {
    if (
      !isSastEvidenceDeletionProofShapeValid(input.proof, digest) ||
      input.receipt.operationId !== input.candidate.schedule.operationId ||
      input.proof.operationId !== input.receipt.operationId ||
      input.proof.providerReceiptRef !==
        input.receipt.providerReceiptRef ||
      input.proof.providerReceiptDigest !==
        input.receipt.providerReceiptDigest ||
      input.proof.completedAt !== input.receipt.completedAt
    ) {
      throw new SastEvidenceAccessPersistenceError(
        'OUTPUT_INVALID'
      );
    }
    return this.runSerializable(async (transaction) => {
      const row = await transaction.sastEvidenceDeletionSchedule.findUnique({
        where: { id: input.candidate.schedule.deletionScheduleId },
        include: scheduleInclude
      });
      if (!row) {
        throw new SastEvidenceAccessPersistenceError(
          'CONTEXT_DRIFT'
        );
      }
      if (row.proof) {
        const existing =
          row.proof.proof as unknown as SastEvidenceDeletionProof;
        if (
          isSastEvidenceDeletionProofShapeValid(existing, digest) &&
          stableJson(existing) === stableJson(input.proof)
        ) {
          return { proof: existing, replayed: true };
        }
        throw new SastEvidenceAccessPersistenceError(
          'REPLAY_CONFLICT'
        );
      }
      if (
        stableJson(row.schedule) !==
          stableJson(input.candidate.schedule) ||
        !row.claim ||
        row.claim.status !== 'CLAIMED' ||
        row.claim.leaseOwner !== input.candidate.leaseOwner ||
        row.claim.leaseToken !== input.candidate.leaseToken ||
        row.claim.leaseExpiresAt?.toISOString() !==
          input.candidate.leaseExpiresAt ||
        Date.parse(input.receipt.completedAt) <
          row.deleteAfter.getTime() ||
        Date.parse(input.receipt.completedAt) >
          Date.parse(input.candidate.leaseExpiresAt) ||
        !row.buildDecision.evidencePack ||
        row.buildDecision.evidencePack.id !== row.evidencePackId ||
        row.buildDecision.evidencePack.packDigest !==
          row.sourcePackDigest
      ) {
        throw new SastEvidenceAccessPersistenceError('LEASE_LOST');
      }
      await transaction.sastEvidenceDeletionProof.create({
        data: {
          id: input.proof.deletionProofId,
          scheduleId: row.id,
          operationId: row.operationId,
          tenantId: row.tenantId,
          evidencePackId: row.evidencePackId,
          buildDecisionId: row.buildDecisionId,
          providerReceiptRef:
            input.proof.providerReceiptRef,
          providerReceiptDigest:
            input.proof.providerReceiptDigest,
          completedAt: new Date(input.proof.completedAt),
          proof: json(input.proof),
          proofDigest: input.proof.proofDigest,
          createdAt: new Date(input.proof.completedAt)
        }
      });
      await transaction.sastAcceptedEvidencePack.delete({
        where: { id: row.evidencePackId }
      });
      const completed =
        await transaction.sastEvidenceDeletionClaim.updateMany({
          where: {
            scheduleId: row.id,
            status: 'CLAIMED',
            leaseToken: input.candidate.leaseToken
          },
          data: {
            status: 'COMPLETED',
            leaseOwner: null,
            leaseToken: null,
            leaseExpiresAt: null,
            nextAttemptAt: new Date(input.proof.completedAt),
            lastErrorCode: null,
            quarantinedAt: null
          }
        });
      if (completed.count !== 1) {
        throw new SastEvidenceAccessPersistenceError('LEASE_LOST');
      }
      return {
        proof: input.proof as SastEvidenceDeletionProof,
        replayed: false
      };
    });
  }

  async releaseDeletion(input: {
    candidate: Readonly<SastEvidenceDeletionCandidate>;
    retryAt: string;
  }): Promise<void> {
    const updated =
      await this.prisma.sastEvidenceDeletionClaim.updateMany({
        where: {
          scheduleId:
            input.candidate.schedule.deletionScheduleId,
          status: 'CLAIMED',
          leaseOwner: input.candidate.leaseOwner,
          leaseToken: input.candidate.leaseToken
        },
        data: {
          status: 'PENDING',
          leaseOwner: null,
          leaseToken: null,
          leaseExpiresAt: null,
          nextAttemptAt: new Date(input.retryAt),
          lastErrorCode: null,
          quarantinedAt: null
        }
      });
    if (updated.count !== 1) {
      throw new SastEvidenceAccessPersistenceError('LEASE_LOST');
    }
  }

  private async fenceDriftedClaim(
    scheduleId: string,
    referenceTime: string
  ): Promise<void> {
    const observedAt = new Date(referenceTime);
    const retryAt = new Date(
      observedAt.getTime() + CONTEXT_DRIFT_RETRY_MILLISECONDS
    );
    await this.prisma.$executeRaw(Prisma.sql`
      UPDATE "SastEvidenceDeletionClaim"
      SET
        "status" = CASE
          WHEN "attemptCount" + 1 >= ${MAXIMUM_CONTEXT_DRIFT_ATTEMPTS}
            THEN 'QUARANTINED'
          ELSE 'PENDING'
        END,
        "leaseOwner" = NULL,
        "leaseToken" = NULL,
        "leaseExpiresAt" = NULL,
        "nextAttemptAt" = ${retryAt},
        "attemptCount" = "attemptCount" + 1,
        "lastErrorCode" = 'CONTEXT_DRIFT',
        "quarantinedAt" = CASE
          WHEN "attemptCount" + 1 >= ${MAXIMUM_CONTEXT_DRIFT_ATTEMPTS}
            THEN ${observedAt}
          ELSE NULL
        END,
        "updatedAt" = ${observedAt}
      WHERE "scheduleId" = ${scheduleId}
        AND (
          "status" = 'PENDING'
          OR (
            "status" = 'CLAIMED'
            AND "leaseExpiresAt" <= ${observedAt}
          )
        )
    `);
  }

  private readSchedule(
    reader: EvidenceTransaction,
    input: {
      tenantId: string;
      repositoryBindingId: string;
      evidencePackId: string;
    }
  ): Promise<ScheduleRow | null> {
    return reader.sastEvidenceDeletionSchedule.findFirst({
      where: {
        evidencePackId: input.evidencePackId,
        tenantId: input.tenantId,
        repositoryBindingId: input.repositoryBindingId
      },
      include: scheduleInclude
    });
  }

  private async createSchedule(
    transaction: EvidenceTransaction,
    packRow: PackRow
  ): Promise<void> {
    const result = resultFromPackRow(packRow);
    if (
      !isSastAcceptedEvidenceBuildResultShapeValid(
        result,
        digest,
        SAST_ACCEPTED_EVIDENCE_POLICY
      ) ||
      !result.pack
    ) {
      throw new SastEvidenceAccessPersistenceError(
        'CONTEXT_DRIFT'
      );
    }
    const schedule = buildSastEvidenceDeletionSchedule({
      scope: sastEvidenceAccessScopeFromResult(result),
      scheduledAt: result.pack.createdAt,
      deleteAfter: result.pack.expiresAt,
      digestCanonical: digest
    });
    await transaction.sastEvidenceDeletionSchedule.create({
      data: {
        id: schedule.deletionScheduleId,
        operationId: schedule.operationId,
        evidencePackId: result.pack.evidencePackId,
        buildDecisionId: result.decision.buildDecisionId,
        tenantId: schedule.scope.tenantId,
        repositoryBindingId:
          schedule.scope.repositoryBindingId,
        scanRequestId: schedule.scope.scanRequestId,
        attemptId: schedule.scope.attemptId,
        occurrenceId: schedule.scope.occurrenceId,
        sourcePackDigest: schedule.scope.sourcePackDigest,
        deleteAfter: new Date(schedule.deleteAfter),
        scheduledAt: new Date(schedule.scheduledAt),
        schedule: json(schedule),
        scheduleDigest: schedule.scheduleDigest,
        createdAt: new Date(schedule.scheduledAt),
        claim: {
          create: {
            status: 'PENDING',
            nextAttemptAt: new Date(schedule.deleteAfter),
            attemptCount: 0
          }
        }
      }
    });
  }

  private async runSerializable<T>(
    operation: (transaction: EvidenceTransaction) => Promise<T>,
    timeoutMilliseconds =
      SERIALIZABLE_BACKGROUND_TIMEOUT_MILLISECONDS
  ): Promise<T> {
    let lastError: unknown;
    for (
      let attempt = 1;
      attempt <= SERIALIZABLE_ATTEMPTS;
      attempt += 1
    ) {
      try {
        return await this.prisma.$transaction(operation, {
          isolationLevel:
            Prisma.TransactionIsolationLevel.Serializable,
          maxWait: SERIALIZABLE_MAX_WAIT_MILLISECONDS,
          timeout: timeoutMilliseconds
        });
      } catch (error) {
        lastError = error;
        if (
          !isRetryableTransactionError(error) ||
          attempt === SERIALIZABLE_ATTEMPTS
        ) {
          throw error;
        }
        await delay(
          SERIALIZABLE_RETRY_BASE_DELAY_MILLISECONDS * attempt +
            randomInt(
              SERIALIZABLE_RETRY_BASE_DELAY_MILLISECONDS + 1
            )
        );
      }
    }
    throw lastError;
  }
}

function contextFromRow(row: ScheduleRow): SastEvidenceAccessContext {
  const schedule = row.schedule as unknown as SastEvidenceDeletionSchedule;
  if (
    !isSastEvidenceDeletionScheduleShapeValid(schedule, digest) ||
    schedule.deletionScheduleId !== row.id ||
    schedule.operationId !== row.operationId ||
    schedule.scheduleDigest !== row.scheduleDigest ||
    schedule.scope.evidencePackId !== row.evidencePackId ||
    schedule.scope.buildDecisionId !== row.buildDecisionId ||
    schedule.scope.tenantId !== row.tenantId ||
    schedule.scope.repositoryBindingId !==
      row.repositoryBindingId ||
    schedule.scope.scanRequestId !== row.scanRequestId ||
    schedule.scope.attemptId !== row.attemptId ||
    schedule.scope.occurrenceId !== row.occurrenceId ||
    schedule.scope.sourcePackDigest !== row.sourcePackDigest ||
    schedule.scheduledAt !== row.scheduledAt.toISOString() ||
    schedule.deleteAfter !== row.deleteAfter.toISOString() ||
    !row.claim
  ) {
    throw new SastEvidenceAccessPersistenceError('CONTEXT_DRIFT');
  }
  const proof = row.proof?.proof as unknown;
  const canonicalProof = row.proof
    ? (proof as SastEvidenceDeletionProof)
    : null;
  if (
    canonicalProof &&
    (!isSastEvidenceDeletionProofShapeValid(
      canonicalProof,
      digest
    ) ||
      canonicalProof.deletionScheduleId !== row.id ||
      canonicalProof.operationId !== row.operationId ||
      canonicalProof.proofDigest !== row.proof?.proofDigest ||
      canonicalProof.providerReceiptDigest !==
        row.proof?.providerReceiptDigest)
  ) {
    throw new SastEvidenceAccessPersistenceError('CONTEXT_DRIFT');
  }
  const packRow = row.buildDecision.evidencePack;
  if ((canonicalProof && packRow) || (!canonicalProof && !packRow)) {
    throw new SastEvidenceAccessPersistenceError('CONTEXT_DRIFT');
  }
  let result: SastAcceptedEvidenceBuildResult | null = null;
  if (packRow) {
    result = resultFromScheduleRow(row);
    if (
      !isSastAcceptedEvidenceBuildResultShapeValid(
        result,
        digest,
        SAST_ACCEPTED_EVIDENCE_POLICY
      ) ||
      stableJson(sastEvidenceAccessScopeFromResult(result)) !==
        stableJson(schedule.scope)
    ) {
      throw new SastEvidenceAccessPersistenceError(
        'CONTEXT_DRIFT'
      );
    }
  }
  const freshness =
    row.buildDecision.freshnessDecision
      .decision as unknown as SastScanFreshnessDecision;
  const coverage =
    row.buildDecision.freshnessDecision.coverageDecision
      .decision as unknown as SastScanCoverageDecision;
  const decisionsValid =
    isSastScanFreshnessDecisionShapeValid(freshness, digest) &&
    isSastScanCoverageDecisionShapeValid(coverage, digest) &&
    freshness.freshnessDecisionId ===
      row.buildDecision.freshnessDecision.id &&
    freshness.decisionDigest ===
      row.buildDecision.freshnessDecision.decisionDigest &&
    coverage.coverageDecisionId ===
      row.buildDecision.freshnessDecision.coverageDecision.id &&
    coverage.decisionDigest ===
      row.buildDecision.freshnessDecision.coverageDecision
        .decisionDigest &&
    freshness.scope.coverageDecisionId ===
      coverage.coverageDecisionId &&
    freshness.scope.coverageDecisionDigest ===
      coverage.decisionDigest;
  if (!decisionsValid) {
    throw new SastEvidenceAccessPersistenceError('CONTEXT_DRIFT');
  }
  const deletionState = canonicalProof
    ? 'DELETED'
    : row.claim.status === 'CLAIMED' ||
        row.claim.status === 'QUARANTINED'
      ? 'DELETION_PENDING'
      : 'ACTIVE';
  if (
    (canonicalProof && row.claim.status !== 'COMPLETED') ||
    (!canonicalProof && row.claim.status === 'COMPLETED')
  ) {
    throw new SastEvidenceAccessPersistenceError('CONTEXT_DRIFT');
  }
  return {
    result,
    schedule,
    deletionState,
    deletionProof: canonicalProof,
    tenantAiAdvisoryOptIn:
      row.tenant.sastAiAdvisoryOptIn,
    repositoryAiAdvisoryOptIn:
      row.repositoryBinding.sastAiAdvisoryOptIn,
    freshnessEligible:
      freshness.latestTargetAuthority === 'VERIFIED' &&
      freshness.staleStatus === 'FRESH' &&
      freshness.comparabilityStatus === 'COMPARABLE' &&
      freshness.reasonCodes.length === 0 &&
      !freshness.aiAdvisoryAllowed &&
      !freshness.publicationAttempted,
    coverageComplete:
      coverage.state === 'COMPLETE' &&
      coverage.reasonCodes.length === 0 &&
      row.buildDecision.freshnessDecision.coverageDecision
        .state === 'COMPLETE'
  };
}

function resultFromScheduleRow(
  row: ScheduleRow
): SastAcceptedEvidenceBuildResult {
  const packRow = row.buildDecision.evidencePack;
  if (!packRow) {
    throw new SastEvidenceAccessPersistenceError('CONTEXT_DRIFT');
  }
  const result = {
    decision:
      row.buildDecision.decision as unknown as SastAcceptedEvidenceBuildResult['decision'],
    pack: packRow.pack as unknown as SastAcceptedEvidenceBuildResult['pack']
  };
  if (
    !result.pack ||
    packRow.fragments.length !== result.pack.fragments.length ||
    packRow.fragments.some(
      (fragment, index) =>
        stableJson(fragment.fragment) !==
        stableJson(result.pack?.fragments[index])
    ) ||
    !packScalarsMatch(packRow, result, row.buildDecision)
  ) {
    throw new SastEvidenceAccessPersistenceError('CONTEXT_DRIFT');
  }
  return result;
}

function resultFromPackRow(
  row: PackRow
): SastAcceptedEvidenceBuildResult {
  const result = {
    decision:
      row.buildDecision.decision as unknown as SastAcceptedEvidenceBuildResult['decision'],
    pack: row.pack as unknown as SastAcceptedEvidenceBuildResult['pack']
  };
  if (
    !result.pack ||
    row.fragments.length !== result.pack.fragments.length ||
    row.fragments.some(
      (fragment, index) =>
        stableJson(fragment.fragment) !==
        stableJson(result.pack?.fragments[index])
    ) ||
    !packScalarsMatch(row, result, row.buildDecision)
  ) {
    throw new SastEvidenceAccessPersistenceError('CONTEXT_DRIFT');
  }
  return result;
}

function packScalarsMatch(
  row: {
    id: string;
    buildDecisionId: string;
    tenantId: string;
    repositoryBindingId: string;
    scanRequestId: string;
    attemptId: string;
    occurrenceId: string;
    findingFingerprint: string;
    packDigest: string;
    dashboardSafe: boolean;
    aiSafe: boolean;
    classificationDecisionRef: string | null;
    deletionScheduleRef: string | null;
    createdAt: Date;
    expiresAt: Date;
  },
  result: Readonly<SastAcceptedEvidenceBuildResult>,
  buildDecision: {
    id: string;
    outcome: string;
    decisionDigest: string;
    evidencePackId: string | null;
    evidencePackDigest: string | null;
  }
): boolean {
  const pack = result.pack;
  const decision = result.decision;
  return (
    !!pack &&
    row.id === pack.evidencePackId &&
    row.buildDecisionId === decision.buildDecisionId &&
    buildDecision.id === decision.buildDecisionId &&
    buildDecision.outcome === decision.outcome &&
    buildDecision.decisionDigest === decision.decisionDigest &&
    buildDecision.evidencePackId === pack.evidencePackId &&
    buildDecision.evidencePackDigest === pack.packDigest &&
    row.tenantId === pack.scope.tenantId &&
    row.repositoryBindingId === pack.scope.repositoryBindingId &&
    row.scanRequestId === pack.scope.scanRequestId &&
    row.attemptId === pack.scope.attemptId &&
    row.occurrenceId === pack.scope.occurrenceId &&
    row.findingFingerprint === pack.scope.findingFingerprint &&
    row.packDigest === pack.packDigest &&
    row.dashboardSafe === false &&
    row.aiSafe === false &&
    row.classificationDecisionRef === null &&
    row.deletionScheduleRef === null &&
    row.createdAt.toISOString() === pack.createdAt &&
    row.expiresAt.toISOString() === pack.expiresAt
  );
}

function replayDecision(
  stored: Prisma.JsonValue,
  requested: Readonly<SastEvidenceAccessDecision>
): PersistedSastEvidenceAccessDecision {
  const decision = stored as unknown as SastEvidenceAccessDecision;
  if (
    !isSastEvidenceAccessDecisionShapeValid(decision, digest) ||
    stableJson(replayProjection(decision)) !==
      stableJson(replayProjection(requested))
  ) {
    throw new SastEvidenceAccessPersistenceError(
      'REPLAY_CONFLICT'
    );
  }
  return { decision, replayed: true };
}

function replayProjection(
  decision: Readonly<SastEvidenceAccessDecision>
): unknown {
  const {
    decidedAt: _decidedAt,
    decisionDigest: _decisionDigest,
    aiPayloadExpiresAt: _aiPayloadExpiresAt,
    ...stable
  } = decision;
  void _decidedAt;
  void _decisionDigest;
  void _aiPayloadExpiresAt;
  return stable;
}

function isRetryableTransactionError(error: unknown): boolean {
  if (!(error instanceof Prisma.PrismaClientKnownRequestError)) {
    return false;
  }
  if (error.code === 'P2034') return true;
  if (error.code !== 'P2002') return false;
  const modelName = error.meta?.modelName;
  return (
    modelName === 'SastEvidenceAccessDecision' ||
    modelName === 'SastEvidenceDeletionSchedule' ||
    modelName === 'SastEvidenceDeletionProof'
  );
}

function json(value: unknown): Prisma.InputJsonValue {
  return value as Prisma.InputJsonValue;
}

function digest(value: string): `sha256:${string}` {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) {
    return '[' + value.map(stableJson).join(',') + ']';
  }
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return (
      '{' +
      Object.keys(record)
        .sort()
        .map(
          (key) =>
            JSON.stringify(key) + ':' + stableJson(record[key])
        )
        .join(',') +
      '}'
    );
  }
  return JSON.stringify(value);
}
