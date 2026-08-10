import { createHash } from 'node:crypto';

import {
  SAST_CAPABILITIES,
  SAST_FINDING_FINGERPRINT_VERSION,
  SAST_SCAN_PROFILES,
  SAST_SCANNER_KINDS,
  buildSastScanCoverageRecordsPreimage,
  buildSastScanFreshnessDecision,
  buildSastScanPlanDigestPreimage,
  evaluateSastScanRetry,
  isSastExternalPublicationDecisionShapeValid,
  isSastLatestTargetObservationShapeValid,
  isSastScanCoverageDecisionShapeValid,
  isSastScanFreshnessDecisionShapeValid,
  isSastScanPlanValid,
  isSastScanRetryDecisionShapeValid,
  isSastScannerCoverageRecordShapeValid,
  sastProfileFamily,
  type SastCapability,
  type SastExternalPublicationDecision,
  type SastFindingLifecycleCoverageDecision,
  type SastLatestTargetObservation,
  type SastProfileId,
  type SastScanComparisonSource,
  type SastScanCoverageDecision,
  type SastScanFreshnessDecision,
  type SastScanFreshnessScope,
  type SastScanPlan,
  type SastScanRetryDecision,
  type SastScannerCoverageRecord,
  type SastScannerWrapperExecutionRequest
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';

import { PrismaService } from '../prisma/prisma.service';
import {
  SastScanFreshnessPersistenceError,
  SastScanFreshnessStore,
  type PersistedSastScanFreshness,
  type SastScanFreshnessContext,
  type SastScanRetryDurableContext
} from './sast-scan-freshness.store';

const SERIALIZABLE_ATTEMPTS = 3;
const SERIALIZABLE_MAX_WAIT_MILLISECONDS = 5_000;
const SERIALIZABLE_TIMEOUT_MILLISECONDS = 120_000;

type FreshnessReader = Pick<
  Prisma.TransactionClient,
  | 'sastScanCoverageDecision'
  | 'sastLatestTargetObservation'
  | 'sastScanFreshnessDecision'
>;

@Injectable()
export class PrismaSastScanFreshnessStore
  extends SastScanFreshnessStore {
  constructor(private readonly prisma: PrismaService) {
    super();
  }

  async loadContext(
    coverageDecisionId: string
  ): Promise<SastScanFreshnessContext | null> {
    return this.readContext(this.prisma, coverageDecisionId);
  }

  async persistFreshness(input: {
    context: Readonly<SastScanFreshnessContext>;
    observation: Readonly<SastLatestTargetObservation> | null;
    decision: Readonly<SastScanFreshnessDecision>;
  }): Promise<PersistedSastScanFreshness> {
    this.validateFreshnessInput(input);
    return this.runSerializable(async (transaction) => {
      const current = await this.readContext(
        transaction,
        input.context.scope.coverageDecisionId
      );
      if (!current || !sameFreshnessContext(current, input.context)) {
        throw new SastScanFreshnessPersistenceError('CONTEXT_DRIFT');
      }
      if (current.existingDecision) {
        return replayFreshness(current.existingDecision, input.decision);
      }
      if (input.observation) {
        await transaction.sastLatestTargetObservation.create({
          data: {
            id: input.observation.observationId,
            tenantId: input.observation.tenantId,
            repositoryBindingId:
              input.observation.repositoryBindingId,
            provider: input.observation.provider,
            targetRef: input.observation.targetRef,
            headCommitSha: input.observation.headCommitSha,
            sequence: BigInt(input.observation.sequence),
            observerRef: input.observation.observerRef,
            observation: json(input.observation),
            observationDigest:
              input.observation.observationDigest,
            observedAt: new Date(input.observation.observedAt),
            createdAt: new Date(input.decision.decidedAt)
          }
        });
      }
      const decision = input.decision;
      const scope = decision.scope;
      await transaction.sastScanFreshnessDecision.create({
        data: {
          id: decision.freshnessDecisionId,
          coverageDecisionId: scope.coverageDecisionId,
          previousCoverageDecisionId:
            decision.previousCoverageDecisionId,
          observationId: decision.observationId,
          tenantId: scope.tenantId,
          repositoryBindingId: scope.repositoryBindingId,
          provider: scope.provider,
          targetRef: scope.targetRef,
          commitSha: scope.commitSha,
          scanRequestId: scope.scanRequestId,
          attemptId: scope.attemptId,
          attemptNumber: scope.attemptNumber,
          coverageDecisionDigest: scope.coverageDecisionDigest,
          lifecycleContextKey: scope.lifecycleContextKey,
          canonicalScanKey: scope.canonicalScanKey,
          planDigest: scope.planDigest,
          profileId: scope.profileId,
          profileDigest: scope.profileDigest,
          profileFamily: scope.profileFamily,
          requiredCapabilities: json(scope.requiredCapabilities),
          fingerprintVersion: scope.fingerprintVersion,
          lifecycleEligibilityScope:
            scope.lifecycleEligibilityScope,
          observationDigest: decision.observationDigest,
          observedHeadCommitSha: decision.observedHeadCommitSha,
          observationSequence:
            decision.observationSequence === null
              ? null
              : BigInt(decision.observationSequence),
          previousCoverageDecisionDigest:
            decision.previousCoverageDecisionDigest,
          previousScanRequestId: decision.previousScanRequestId,
          previousCommitSha: decision.previousCommitSha,
          latestTargetAuthority: decision.latestTargetAuthority,
          staleStatus: decision.staleStatus,
          comparabilityStatus: decision.comparabilityStatus,
          externalCommentEligible:
            decision.externalCommentEligible,
          blockingStatusEligible: decision.blockingStatusEligible,
          lifecycleMutationAllowed:
            decision.lifecycleMutationAllowed,
          aiAdvisoryAllowed: false,
          publicationAttempted: false,
          reasonCodes: json(decision.reasonCodes),
          decision: json(decision),
          decisionDigest: decision.decisionDigest,
          decidedAt: new Date(decision.decidedAt),
          createdAt: new Date(decision.decidedAt)
        }
      });
      return {
        freshnessDecisionId: decision.freshnessDecisionId,
        decisionDigest: decision.decisionDigest,
        replayed: false
      };
    });
  }

  async verifyLifecycleSource(
    input: Readonly<SastFindingLifecycleCoverageDecision>
  ): Promise<'MATCHED' | 'REJECTED'> {
    const row = await this.prisma.sastScanFreshnessDecision.findFirst({
      where: {
        coverageDecisionId: input.sourceCoverageDecisionRef,
        tenantId: input.tenantId,
        repositoryBindingId: input.repositoryBindingId,
        scanRequestId: input.scanRequestId,
        attemptId: input.attemptId,
        coverageDecisionDigest:
          input.sourceCoverageDecisionDigest,
        latestTargetAuthority: 'VERIFIED',
        staleStatus: 'FRESH',
        comparabilityStatus: 'COMPARABLE',
        lifecycleMutationAllowed: true,
        aiAdvisoryAllowed: false,
        publicationAttempted: false
      },
      include: {
        scanRequest: { select: { completedAt: true } },
        coverageDecision: { select: { state: true } }
      }
    });
    if (!row || row.coverageDecision.state !== 'COMPLETE') {
      return 'REJECTED';
    }
    const decision = row.decision as unknown as SastScanFreshnessDecision;
    if (
      !isSastScanFreshnessDecisionShapeValid(decision, digest) ||
      decision.decisionDigest !== row.decisionDigest ||
      !decision.lifecycleMutationAllowed ||
      !row.scanRequest.completedAt ||
      input.canonicalScanKey !== decision.scope.canonicalScanKey ||
      input.planDigest !== decision.scope.planDigest ||
      input.commitSha !== decision.scope.commitSha ||
      input.lifecycleContextKey !==
        decision.scope.lifecycleContextKey ||
      input.profileId !== decision.scope.profileId ||
      input.profileDigest !== decision.scope.profileDigest ||
      input.previousScanRequestId !==
        decision.previousScanRequestId ||
      input.previousCommitSha !== decision.previousCommitSha ||
      input.completedAt !== row.scanRequest.completedAt.toISOString() ||
      input.decidedAt !== decision.decidedAt ||
      stableJson(input.completeCapabilities) !==
        stableJson(
          decision.scope.requiredCapabilities.filter(
            (capability) => capability !== 'SBOM'
          )
        )
    ) {
      return 'REJECTED';
    }
    return 'MATCHED';
  }

  async loadRetryContext(
    request: Readonly<SastScannerWrapperExecutionRequest>
  ): Promise<SastScanRetryDurableContext | null> {
    const scan = await this.prisma.scanRequest.findFirst({
      where: {
        id: request.plan.scanRequestId,
        tenantId: request.plan.tenantId,
        repositoryBindingId:
          request.plan.repositoryState.repositoryBindingId
      },
      include: {
        sastQueueReservation: {
          select: { canonicalScanKey: true, immutablePlan: true }
        },
        sastScanAttempts: {
          orderBy: { attemptNumber: 'desc' },
          take: 1,
          include: {
            finalAuditEvent: {
              select: {
                id: true,
                tenantId: true,
                scanRequestId: true,
                attemptId: true,
                eventType: true,
                occurredAt: true
              }
            }
          }
        },
        sastRetryDecisions: {
          where: { requestedAttemptId: request.attemptId },
          take: 1,
          select: { decision: true }
        }
      }
    });
    const previous = scan?.sastScanAttempts[0];
    const reservation = scan?.sastQueueReservation;
    if (!scan || !previous || !reservation) return null;
    const durablePlan = reservation.immutablePlan as unknown as SastScanPlan;
    if (!isSastScanPlanValid(durablePlan)) return null;
    const durablePlanDigest = digest(
      buildSastScanPlanDigestPreimage(durablePlan)
    );
    const finalAudit = previous.finalAuditEvent;
    const previousCompletedAt = previous.completedAt?.toISOString() ?? null;
    const previousFinalAuditValid = Boolean(
      finalAudit &&
        finalAudit.id === previous.finalAuditEventId &&
        finalAudit.tenantId === previous.tenantId &&
        finalAudit.scanRequestId === previous.scanRequestId &&
        finalAudit.attemptId === previous.id &&
        finalAudit.eventType === 'sandbox.terminated' &&
        previousCompletedAt !== null &&
        finalAudit.occurredAt.toISOString() === previousCompletedAt
    );
    const existing = scan.sastRetryDecisions[0]?.decision as unknown as
      | SastScanRetryDecision
      | undefined;
    return {
      evaluation: {
        scope: {
          tenantId: request.plan.tenantId,
          repositoryBindingId:
            request.plan.repositoryState.repositoryBindingId,
          scanRequestId: request.plan.scanRequestId,
          canonicalScanKey: request.plan.canonicalScanKey,
          planDigest: digest(
            buildSastScanPlanDigestPreimage(request.plan)
          ),
          originalScannerSetDigest:
            durablePlan.scannerSet.scannerSetDigest,
          previousAttemptId: previous.id,
          previousAttemptNumber: previous.attemptNumber,
          previousSandboxId: previous.sandboxId,
          previousWorkloadIdentityRef:
            previous.workloadIdentityRef,
          requestedAttemptId: request.attemptId,
          requestedAttemptNumber: request.attemptNumber,
          requestedSandboxId: request.sandboxId,
          requestedWorkloadIdentityRef:
            request.workloadIdentityRef
        },
        previousStage: previous.stage,
        previousFailureClass: previous.failureClass,
        previousRetryEligible: previous.retryEligible,
        previousCompletedAt,
        previousFinalAuditEventId: previous.finalAuditEventId,
        previousFinalAuditValid,
        durableCanonicalScanKey: reservation.canonicalScanKey as
          `sha256:${string}`,
        durablePlanDigest
      },
      existingDecision:
        existing && isSastScanRetryDecisionShapeValid(existing, digest)
          ? existing
          : null
    };
  }

  async persistRetryDecision(input: {
    context: Readonly<SastScanRetryDurableContext>;
    decision: Readonly<SastScanRetryDecision>;
  }): Promise<{
    retryDecisionId: string;
    decisionDigest: `sha256:${string}`;
    retryAllowed: boolean;
    replayed: boolean;
  }> {
    const retryEvaluation = {
      ...input.context.evaluation,
      currentScannerSetDigest:
        input.decision.currentScannerSetDigest,
      scannerSetAvailable: input.decision.scannerSetAvailable,
      killSwitchStatus: input.decision.killSwitchStatus,
      killSwitchSnapshotDigest:
        input.decision.killSwitchSnapshotDigest
    };
    if (
      !isSastScanRetryDecisionShapeValid(input.decision, digest) ||
      stableJson(input.decision.scope) !==
        stableJson(input.context.evaluation.scope) ||
      input.decision.previousFailureClass !==
        input.context.evaluation.previousFailureClass ||
      input.decision.previousCompletedAt !==
        input.context.evaluation.previousCompletedAt ||
      input.decision.previousFinalAuditEventId !==
        input.context.evaluation.previousFinalAuditEventId ||
      stableJson(input.decision.reasonCodes) !==
        stableJson(evaluateSastScanRetry(retryEvaluation))
    ) {
      throw new SastScanFreshnessPersistenceError('CONTEXT_DRIFT');
    }
    return this.runSerializable(async (transaction) => {
      const scope = input.decision.scope;
      const previous = await transaction.sastScanAttempt.findFirst({
        where: {
          id: scope.previousAttemptId,
          tenantId: scope.tenantId,
          repositoryBindingId: scope.repositoryBindingId,
          scanRequestId: scope.scanRequestId
        },
        include: {
          finalAuditEvent: {
            select: {
              id: true,
              tenantId: true,
              scanRequestId: true,
              attemptId: true,
              eventType: true,
              occurredAt: true
            }
          },
          scanRequest: {
            include: {
              sastQueueReservation: {
                select: {
                  canonicalScanKey: true,
                  immutablePlan: true
                }
              }
            }
          }
        }
      });
      if (!previous || !sameRetryPredecessor(previous, input.context)) {
        throw new SastScanFreshnessPersistenceError('CONTEXT_DRIFT');
      }
      const existing = await transaction.sastScanRetryDecision.findFirst({
        where: {
          OR: [
            { id: input.decision.retryDecisionId },
            { requestedAttemptId: scope.requestedAttemptId },
            {
              scanRequestId: scope.scanRequestId,
              requestedAttemptNumber: scope.requestedAttemptNumber
            }
          ]
        },
        select: { decision: true }
      });
      if (existing) {
        const stored = existing.decision as unknown as SastScanRetryDecision;
        if (
          !isSastScanRetryDecisionShapeValid(stored, digest) ||
          stableJson(stored) !== stableJson(input.decision)
        ) {
          throw new SastScanFreshnessPersistenceError('REPLAY_CONFLICT');
        }
        return {
          retryDecisionId: stored.retryDecisionId,
          decisionDigest: stored.decisionDigest,
          retryAllowed: stored.retryAllowed,
          replayed: true
        };
      }
      const decision = input.decision;
      await transaction.sastScanRetryDecision.create({
        data: {
          id: decision.retryDecisionId,
          tenantId: scope.tenantId,
          repositoryBindingId: scope.repositoryBindingId,
          scanRequestId: scope.scanRequestId,
          canonicalScanKey: scope.canonicalScanKey,
          planDigest: scope.planDigest,
          originalScannerSetDigest: scope.originalScannerSetDigest,
          previousAttemptId: scope.previousAttemptId,
          previousAttemptNumber: scope.previousAttemptNumber,
          previousSandboxId: scope.previousSandboxId,
          previousWorkloadIdentityRef:
            scope.previousWorkloadIdentityRef,
          requestedAttemptId: scope.requestedAttemptId,
          requestedAttemptNumber: scope.requestedAttemptNumber,
          requestedSandboxId: scope.requestedSandboxId,
          requestedWorkloadIdentityRef:
            scope.requestedWorkloadIdentityRef,
          retryAllowed: decision.retryAllowed,
          previousFailureClass: decision.previousFailureClass,
          previousCompletedAt: decision.previousCompletedAt
            ? new Date(decision.previousCompletedAt)
            : null,
          previousFinalAuditEventId:
            decision.previousFinalAuditEventId,
          currentScannerSetDigest: decision.currentScannerSetDigest,
          scannerSetAvailable: decision.scannerSetAvailable,
          killSwitchStatus: decision.killSwitchStatus,
          killSwitchSnapshotDigest:
            decision.killSwitchSnapshotDigest,
          reasonCodes: json(decision.reasonCodes),
          decision: json(decision),
          decisionDigest: decision.decisionDigest,
          decidedAt: new Date(decision.decidedAt),
          createdAt: new Date(decision.decidedAt)
        }
      });
      return {
        retryDecisionId: decision.retryDecisionId,
        decisionDigest: decision.decisionDigest,
        retryAllowed: decision.retryAllowed,
        replayed: false
      };
    });
  }

  private async readContext(
    reader: FreshnessReader,
    coverageDecisionId: string
  ): Promise<SastScanFreshnessContext | null> {
    const row = await reader.sastScanCoverageDecision.findUnique({
      where: { id: coverageDecisionId },
      include: {
        attempt: { select: { attemptNumber: true } },
        repositoryBinding: {
          include: { integration: { select: { provider: true } } }
        },
        scanRequest: {
          select: { status: true, completedAt: true }
        },
        freshnessDecision: { select: { decision: true } },
        scannerRecords: { orderBy: { scanner: 'asc' } },
        publicationDecision: true
      }
    });
    if (!row) return null;
    const coverage = row.decision as unknown as SastScanCoverageDecision;
    if (
      !isSastScanCoverageDecisionShapeValid(coverage, digest) ||
      !coverageRowMatchesDecision(row, coverage) ||
      !coverageLedgerMatchesDecision(row, coverage)
    ) {
      throw new SastScanFreshnessPersistenceError('CONTEXT_DRIFT');
    }
    const profile = SAST_SCAN_PROFILES[coverage.scope.profileId];
    const requiredCapabilities = SAST_CAPABILITIES.filter((capability) =>
      profile.requiredCapabilities.includes(capability)
    );
    const scope: SastScanFreshnessScope = {
      tenantId: row.tenantId,
      repositoryBindingId: row.repositoryBindingId,
      provider: row.repositoryBinding.integration.provider,
      targetRef: row.targetRef,
      commitSha: row.commitSha,
      scanRequestId: row.scanRequestId,
      attemptId: row.attemptId,
      attemptNumber: row.attempt.attemptNumber as 1 | 2,
      coverageDecisionId: row.id,
      coverageDecisionDigest:
        row.decisionDigest as `sha256:${string}`,
      lifecycleContextKey:
        row.lifecycleContextKey as `sha256:${string}`,
      canonicalScanKey: row.canonicalScanKey as `sha256:${string}`,
      planDigest: row.planDigest as `sha256:${string}`,
      profileId: row.profileId as SastProfileId,
      profileDigest: row.profileDigest as `sha256:${string}`,
      profileFamily: sastProfileFamily(row.profileId as SastProfileId),
      requiredCapabilities,
      fingerprintVersion: SAST_FINDING_FINGERPRINT_VERSION,
      lifecycleEligibilityScope: lifecycleEligibilityScope({
        tenantId: row.tenantId,
        repositoryBindingId: row.repositoryBindingId,
        targetRef: row.targetRef,
        profileFamily: sastProfileFamily(row.profileId as SastProfileId),
        requiredCapabilities
      })
    };
    const previousRow = await reader.sastScanCoverageDecision.findFirst({
      where: {
        tenantId: row.tenantId,
        repositoryBindingId: row.repositoryBindingId,
        targetRef: row.targetRef,
        state: 'COMPLETE',
        id: { not: row.id },
        decidedAt: { lt: row.decidedAt },
        scanRequest: {
          completedAt: { not: null, lt: row.decidedAt }
        }
      },
      orderBy: { decidedAt: 'desc' },
      include: {
        scanRequest: { select: { completedAt: true } },
        scannerRecords: { orderBy: { scanner: 'asc' } },
        publicationDecision: true
      }
    });
    const comparison = previousRow
      ? buildComparisonSource(previousRow)
      : null;
    const latestObservation =
      await reader.sastLatestTargetObservation.findFirst({
        where: {
          tenantId: scope.tenantId,
          repositoryBindingId: scope.repositoryBindingId,
          provider: scope.provider,
          targetRef: scope.targetRef
        },
        orderBy: { sequence: 'desc' },
        select: { id: true, sequence: true, observedAt: true }
      });
    const latestObservationSequence = latestObservation
      ? Number(latestObservation.sequence)
      : null;
    if (
      latestObservationSequence !== null &&
      (!Number.isSafeInteger(latestObservationSequence) ||
        latestObservationSequence <= 0)
    ) {
      throw new SastScanFreshnessPersistenceError('CONTEXT_DRIFT');
    }
    const existing = row.freshnessDecision?.decision as unknown as
      | SastScanFreshnessDecision
      | undefined;
    return {
      coverageComplete:
        row.state === 'COMPLETE' &&
        coverage.state === 'COMPLETE' &&
        row.scanRequest.status === 'COMPLETED' &&
        row.scanRequest.completedAt !== null,
      coverageCompletedAt:
        row.scanRequest.completedAt
          ? new Date(
              Math.max(
                row.scanRequest.completedAt.getTime(),
                row.decidedAt.getTime()
              )
            ).toISOString()
          : null,
      scope,
      comparison,
      latestObservation: latestObservation
        ? {
            observationId: latestObservation.id,
            sequence: latestObservationSequence as number,
            observedAt: latestObservation.observedAt.toISOString()
          }
        : null,
      existingDecision:
        existing && isSastScanFreshnessDecisionShapeValid(existing, digest)
          ? existing
          : null
    };
  }

  private validateFreshnessInput(input: {
    context: Readonly<SastScanFreshnessContext>;
    observation: Readonly<SastLatestTargetObservation> | null;
    decision: Readonly<SastScanFreshnessDecision>;
  }): void {
    const previous = input.context.latestObservation;
    const observationMonotonic = Boolean(
      input.observation &&
        (!previous ||
          (input.observation.sequence > previous.sequence &&
            Date.parse(input.observation.observedAt) >=
              Date.parse(previous.observedAt)))
    );
    const expected = buildSastScanFreshnessDecision({
      freshnessDecisionId: input.decision.freshnessDecisionId,
      coverageComplete: input.context.coverageComplete,
      scope: input.context.scope,
      observation: input.observation,
      observationAuthority: input.observation
        ? 'VERIFIED'
        : input.decision.latestTargetAuthority === 'UNAVAILABLE'
          ? 'UNAVAILABLE'
          : 'INVALID',
      observationMonotonic,
      comparison: input.context.comparison,
      decidedAt: input.decision.decidedAt,
      digestCanonical: digest
    });
    if (
      !isSastScanFreshnessDecisionShapeValid(input.decision, digest) ||
      (input.observation !== null &&
        !isSastLatestTargetObservationShapeValid(
          input.observation,
          digest
        )) ||
      stableJson(input.decision.scope) !==
        stableJson(input.context.scope) ||
      !input.context.coverageCompletedAt ||
      Date.parse(input.decision.decidedAt) <
        Date.parse(input.context.coverageCompletedAt) ||
      (input.observation !== null &&
        (input.observation.tenantId !== input.context.scope.tenantId ||
          input.observation.repositoryBindingId !==
            input.context.scope.repositoryBindingId ||
          input.observation.provider !== input.context.scope.provider ||
          input.observation.targetRef !==
            input.context.scope.targetRef ||
          Date.parse(input.observation.observedAt) <
            Date.parse(input.context.coverageCompletedAt) ||
          Date.parse(input.observation.observedAt) >
            Date.parse(input.decision.decidedAt) + 5_000)) ||
      (!input.context.coverageComplete &&
        (input.decision.externalCommentEligible ||
          input.decision.blockingStatusEligible ||
          input.decision.lifecycleMutationAllowed)) ||
      input.decision.observationId !==
        (input.observation?.observationId ?? null) ||
      stableJson(input.decision) !== stableJson(expected)
    ) {
      throw new SastScanFreshnessPersistenceError('CONTEXT_DRIFT');
    }
  }

  private async runSerializable<T>(
    operation: (transaction: Prisma.TransactionClient) => Promise<T>
  ): Promise<T> {
    let lastError: unknown;
    for (let attempt = 1; attempt <= SERIALIZABLE_ATTEMPTS; attempt += 1) {
      try {
        return await this.prisma.$transaction(operation, {
          isolationLevel: Prisma.TransactionIsolationLevel.Serializable,
          maxWait: SERIALIZABLE_MAX_WAIT_MILLISECONDS,
          timeout: SERIALIZABLE_TIMEOUT_MILLISECONDS
        });
      } catch (error) {
        lastError = error;
        if (!isRetryableTransactionError(error) ||
          attempt === SERIALIZABLE_ATTEMPTS) {
          throw error;
        }
      }
    }
    throw lastError;
  }
}

type CoverageLedgerProjection = {
  scannerRecords: Array<{
    id: string;
    scanner: string;
    scannerRunId: string | null;
    artifactIngestionId: string | null;
    dispositionDecisionId: string | null;
    correlationSourceId: string | null;
    record: Prisma.JsonValue;
    recordDigest: string;
  }>;
  publicationDecision: {
    id: string;
    coverageDecisionId: string;
    tenantId: string;
    repositoryBindingId: string;
    scanRequestId: string;
    attemptId: string;
    coverageState: string;
    externalCommentAllowed: boolean;
    blockingStatusAllowed: boolean;
    aiAdvisoryAllowed: boolean;
    lifecycleMutationAllowed: boolean;
    latestTargetAuthority: string;
    staleStatus: string;
    comparabilityStatus: string;
    reasonCodes: Prisma.JsonValue;
    decision: Prisma.JsonValue;
    decisionDigest: string;
    decidedAt: Date;
  } | null;
};

function buildComparisonSource(
  row: {
    id: string;
    tenantId: string;
    repositoryBindingId: string;
    scanRequestId: string;
    attemptId: string;
    correlationBatchId: string;
    lifecycleContextKey: string;
    targetRef: string;
    commitSha: string;
    lane: string;
    profileId: string;
    profileDigest: string;
    canonicalScanKey: string;
    planDigest: string;
    scannerSetDigest: string;
    correlationSourceSetDigest: string;
    state: string;
    requiredScanners: Prisma.JsonValue;
    optionalScanners: Prisma.JsonValue;
    missingRequiredScanners: Prisma.JsonValue;
    pendingRequiredScanners: Prisma.JsonValue;
    failedRequiredScanners: Prisma.JsonValue;
    achievedRequiredCapabilities: Prisma.JsonValue;
    missingRequiredCapabilities: Prisma.JsonValue;
    duplicateScanners: Prisma.JsonValue;
    optionalIncompleteScanners: Prisma.JsonValue;
    reasonCodes: Prisma.JsonValue;
    recordsDigest: string;
    authority: Prisma.JsonValue;
    decisionDigest: string;
    decision: Prisma.JsonValue;
    decidedAt: Date;
    scanRequest: { completedAt: Date | null };
  } & CoverageLedgerProjection
): SastScanComparisonSource | null {
  const coverage = row.decision as unknown as SastScanCoverageDecision;
  const profileId = row.profileId as SastProfileId;
  const profile = SAST_SCAN_PROFILES[profileId];
  if (
    !profile ||
    !row.scanRequest.completedAt ||
    !isSastScanCoverageDecisionShapeValid(coverage, digest) ||
    coverage.state !== 'COMPLETE' ||
    !coverageRowMatchesDecision(row, coverage) ||
    !coverageLedgerMatchesDecision(row, coverage)
  ) {
    return null;
  }
  const requiredCapabilities = SAST_CAPABILITIES.filter((capability) =>
    profile.requiredCapabilities.includes(capability)
  );
  const profileFamily = sastProfileFamily(profileId);
  return {
    coverageDecisionId: row.id,
    coverageDecisionDigest: row.decisionDigest as `sha256:${string}`,
    scanRequestId: row.scanRequestId,
    commitSha: row.commitSha,
    tenantId: row.tenantId,
    repositoryBindingId: row.repositoryBindingId,
    targetRef: row.targetRef,
    profileId,
    profileDigest: row.profileDigest as `sha256:${string}`,
    profileFamily,
    requiredCapabilities,
    fingerprintVersion: SAST_FINDING_FINGERPRINT_VERSION,
    lifecycleEligibilityScope: lifecycleEligibilityScope({
      tenantId: row.tenantId,
      repositoryBindingId: row.repositoryBindingId,
      targetRef: row.targetRef,
      profileFamily,
      requiredCapabilities
    }),
    completedAt: row.scanRequest.completedAt.toISOString()
  };
}

function coverageRowMatchesDecision(
  row: {
    id: string;
    tenantId: string;
    repositoryBindingId: string;
    scanRequestId: string;
    attemptId: string;
    correlationBatchId: string;
    lifecycleContextKey: string;
    targetRef: string;
    commitSha: string;
    lane: string;
    profileId: string;
    profileDigest: string;
    canonicalScanKey: string;
    planDigest: string;
    scannerSetDigest: string;
    correlationSourceSetDigest: string;
    state: string;
    requiredScanners: Prisma.JsonValue;
    optionalScanners: Prisma.JsonValue;
    missingRequiredScanners: Prisma.JsonValue;
    pendingRequiredScanners: Prisma.JsonValue;
    failedRequiredScanners: Prisma.JsonValue;
    achievedRequiredCapabilities: Prisma.JsonValue;
    missingRequiredCapabilities: Prisma.JsonValue;
    duplicateScanners: Prisma.JsonValue;
    optionalIncompleteScanners: Prisma.JsonValue;
    reasonCodes: Prisma.JsonValue;
    recordsDigest: string;
    authority: Prisma.JsonValue;
    decisionDigest: string;
    decidedAt: Date;
  } & CoverageLedgerProjection,
  decision: Readonly<SastScanCoverageDecision>
): boolean {
  const scope = decision.scope;
  return (
    decision.coverageDecisionId === row.id &&
    decision.decisionDigest === row.decisionDigest &&
    scope.tenantId === row.tenantId &&
    scope.repositoryBindingId === row.repositoryBindingId &&
    scope.scanRequestId === row.scanRequestId &&
    scope.attemptId === row.attemptId &&
    scope.correlationBatchId === row.correlationBatchId &&
    scope.lifecycleContextKey === row.lifecycleContextKey &&
    scope.targetRef === row.targetRef &&
    scope.commitSha === row.commitSha &&
    scope.lane === row.lane &&
    scope.profileId === row.profileId &&
    scope.profileDigest === row.profileDigest &&
    scope.canonicalScanKey === row.canonicalScanKey &&
    scope.planDigest === row.planDigest &&
    scope.scannerSetDigest === row.scannerSetDigest &&
    scope.correlationSourceSetDigest ===
      row.correlationSourceSetDigest &&
    decision.state === row.state &&
    stableJson(decision.requiredScanners) ===
      stableJson(row.requiredScanners) &&
    stableJson(decision.optionalScanners) ===
      stableJson(row.optionalScanners) &&
    stableJson(decision.missingRequiredScanners) ===
      stableJson(row.missingRequiredScanners) &&
    stableJson(decision.pendingRequiredScanners) ===
      stableJson(row.pendingRequiredScanners) &&
    stableJson(decision.failedRequiredScanners) ===
      stableJson(row.failedRequiredScanners) &&
    stableJson(decision.achievedRequiredCapabilities) ===
      stableJson(row.achievedRequiredCapabilities) &&
    stableJson(decision.missingRequiredCapabilities) ===
      stableJson(row.missingRequiredCapabilities) &&
    stableJson(decision.duplicateScanners) ===
      stableJson(row.duplicateScanners) &&
    stableJson(decision.optionalIncompleteScanners) ===
      stableJson(row.optionalIncompleteScanners) &&
    stableJson(decision.reasonCodes) === stableJson(row.reasonCodes) &&
    decision.recordsDigest === row.recordsDigest &&
    stableJson(decision.authority) === stableJson(row.authority) &&
    decision.decidedAt === row.decidedAt.toISOString()
  );
}

function coverageLedgerMatchesDecision(
  row: CoverageLedgerProjection,
  decision: Readonly<SastScanCoverageDecision>
): boolean {
  const records = row.scannerRecords
    .map((stored) => stored.record as unknown as SastScannerCoverageRecord)
    .sort(
      (left, right) =>
        SAST_SCANNER_KINDS.indexOf(left.scanner) -
        SAST_SCANNER_KINDS.indexOf(right.scanner)
    );
  if (
    records.length !== SAST_SCANNER_KINDS.length ||
    new Set(records.map((record) => record.scannerCoverageId)).size !==
      records.length ||
    records.some(
      (record, index) =>
        record.scanner !== SAST_SCANNER_KINDS[index] ||
        !isSastScannerCoverageRecordShapeValid(record, digest)
    ) ||
    digest(buildSastScanCoverageRecordsPreimage(records)) !==
      decision.recordsDigest
  ) {
    return false;
  }
  const rowsById = new Map(
    row.scannerRecords.map((stored) => [stored.id, stored])
  );
  if (rowsById.size !== records.length) return false;
  for (const record of records) {
    const stored = rowsById.get(record.scannerCoverageId);
    if (
      !stored ||
      stored.scanner !== record.scanner ||
      stored.scannerRunId !== record.scannerRunId ||
      stored.artifactIngestionId !== record.artifactIngestionId ||
      stored.dispositionDecisionId !== record.dispositionDecisionId ||
      stored.correlationSourceId !== record.correlationSourceId ||
      stored.recordDigest !== record.recordDigest ||
      stableJson(stored.record) !== stableJson(record)
    ) {
      return false;
    }
  }

  const publicationRow = row.publicationDecision;
  const publication = publicationRow?.decision as unknown as
    | SastExternalPublicationDecision
    | undefined;
  return Boolean(
    publicationRow &&
    publication &&
    isSastExternalPublicationDecisionShapeValid(publication, digest) &&
    publication.publicationDecisionId === publicationRow.id &&
    publication.coverageDecisionId === decision.coverageDecisionId &&
    publication.coverageDecisionId ===
      publicationRow.coverageDecisionId &&
    publication.coverageDecisionDigest === decision.decisionDigest &&
    publication.coverageState === decision.state &&
    publication.decidedAt === decision.decidedAt &&
    publication.decisionDigest === publicationRow.decisionDigest &&
    publicationRow.tenantId === decision.scope.tenantId &&
    publicationRow.repositoryBindingId ===
      decision.scope.repositoryBindingId &&
    publicationRow.scanRequestId === decision.scope.scanRequestId &&
    publicationRow.attemptId === decision.scope.attemptId &&
    publicationRow.coverageState === decision.state &&
    publicationRow.externalCommentAllowed === false &&
    publicationRow.blockingStatusAllowed === false &&
    publicationRow.aiAdvisoryAllowed === false &&
    publicationRow.lifecycleMutationAllowed === false &&
    publicationRow.latestTargetAuthority === 'UNAVAILABLE' &&
    publicationRow.staleStatus === 'UNKNOWN' &&
    publicationRow.comparabilityStatus === 'UNKNOWN' &&
    stableJson(publicationRow.reasonCodes) ===
      stableJson(publication.reasonCodes) &&
    publicationRow.decidedAt.toISOString() === publication.decidedAt &&
    stableJson(publicationRow.decision) === stableJson(publication)
  );
}

function lifecycleEligibilityScope(input: {
  tenantId: string;
  repositoryBindingId: string;
  targetRef: string;
  profileFamily: string;
  requiredCapabilities: readonly SastCapability[];
}): `sha256:${string}` {
  return digest(
    [
      'sast-lifecycle-eligibility-scope-v1',
      input.tenantId,
      input.repositoryBindingId,
      input.targetRef,
      input.profileFamily,
      SAST_FINDING_FINGERPRINT_VERSION,
      ...input.requiredCapabilities
    ].join('\0')
  );
}

function sameFreshnessContext(
  left: Readonly<SastScanFreshnessContext>,
  right: Readonly<SastScanFreshnessContext>
): boolean {
  return left.coverageComplete === right.coverageComplete &&
    left.coverageCompletedAt === right.coverageCompletedAt &&
    stableJson(left.scope) === stableJson(right.scope) &&
    stableJson(left.comparison) === stableJson(right.comparison) &&
    stableJson(left.latestObservation) ===
      stableJson(right.latestObservation);
}

function replayFreshness(
  stored: Readonly<SastScanFreshnessDecision>,
  requested: Readonly<SastScanFreshnessDecision>
): PersistedSastScanFreshness {
  if (
    !isSastScanFreshnessDecisionShapeValid(stored, digest) ||
    stableJson(stored) !== stableJson(requested)
  ) {
    throw new SastScanFreshnessPersistenceError('REPLAY_CONFLICT');
  }
  return {
    freshnessDecisionId: stored.freshnessDecisionId,
    decisionDigest: stored.decisionDigest,
    replayed: true
  };
}

function sameRetryPredecessor(
  previous: {
    id: string;
    tenantId: string;
    repositoryBindingId: string;
    scanRequestId: string;
    attemptNumber: number;
    sandboxId: string;
    workloadIdentityRef: string;
    stage: string;
    failureClass: string | null;
    retryEligible: boolean;
    completedAt: Date | null;
    finalAuditEventId: string | null;
    finalAuditEvent: {
      id: string;
      tenantId: string;
      scanRequestId: string | null;
      attemptId: string | null;
      eventType: string;
      occurredAt: Date;
    } | null;
    scanRequest: {
      sastQueueReservation: {
        canonicalScanKey: string;
        immutablePlan: Prisma.JsonValue;
      } | null;
    };
  },
  context: Readonly<SastScanRetryDurableContext>
): boolean {
  const expected = context.evaluation;
  const plan = previous.scanRequest.sastQueueReservation
    ?.immutablePlan as unknown as SastScanPlan | undefined;
  const completedAt = previous.completedAt?.toISOString() ?? null;
  const finalAuditValid = Boolean(
    previous.finalAuditEvent &&
      previous.finalAuditEvent.id === previous.finalAuditEventId &&
      previous.finalAuditEvent.tenantId === previous.tenantId &&
      previous.finalAuditEvent.scanRequestId === previous.scanRequestId &&
      previous.finalAuditEvent.attemptId === previous.id &&
      previous.finalAuditEvent.eventType === 'sandbox.terminated' &&
      completedAt !== null &&
      previous.finalAuditEvent.occurredAt.toISOString() === completedAt
  );
  return (
    previous.id === expected.scope.previousAttemptId &&
    previous.tenantId === expected.scope.tenantId &&
    previous.repositoryBindingId ===
      expected.scope.repositoryBindingId &&
    previous.scanRequestId === expected.scope.scanRequestId &&
    previous.attemptNumber === expected.scope.previousAttemptNumber &&
    previous.sandboxId === expected.scope.previousSandboxId &&
    previous.workloadIdentityRef ===
      expected.scope.previousWorkloadIdentityRef &&
    previous.stage === expected.previousStage &&
    previous.failureClass === expected.previousFailureClass &&
    previous.retryEligible === expected.previousRetryEligible &&
    completedAt === expected.previousCompletedAt &&
    previous.finalAuditEventId ===
      expected.previousFinalAuditEventId &&
    finalAuditValid === expected.previousFinalAuditValid &&
    plan !== undefined &&
    isSastScanPlanValid(plan) &&
    previous.scanRequest.sastQueueReservation?.canonicalScanKey ===
      expected.durableCanonicalScanKey &&
    digest(buildSastScanPlanDigestPreimage(plan)) ===
      expected.durablePlanDigest
  );
}

function isRetryableTransactionError(error: unknown): boolean {
  return error instanceof Prisma.PrismaClientKnownRequestError &&
    (error.code === 'P2034' || error.code === 'P2002');
}

function json(value: unknown): Prisma.InputJsonValue {
  return value as Prisma.InputJsonValue;
}

function digest(value: string): `sha256:${string}` {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}
