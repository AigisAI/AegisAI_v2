import {
  SAST_RULE_BUNDLE_CANARY_STEPS,
  isSastScanPlanValid,
  isSastRuleBundleCanaryAssignmentReceiptShapeValid,
  isSastRuleBundleCanaryEligibilityDecisionShapeValid,
  isSastRuleBundleCanaryMembershipShapeValid,
  isSastRuleBundleCanaryObservationReceiptShapeValid,
  isSastRuleBundleCanaryRolloutShapeValid,
  isSastRuleBundleCanaryScanObservationShapeValid,
  isSastRuleBundleCanaryStepDecisionShapeValid,
  nextSastRuleBundleCanaryStep,
  type SastRuleBundleCanaryAssignmentReceipt,
  type SastRuleBundleCanaryEligibilityDecision,
  type SastRuleBundleCanaryMembership,
  type SastRuleBundleCanaryObservationBinding,
  type SastRuleBundleCanaryObservationReceipt,
  type SastRuleBundleCanaryPassedStepBinding,
  type SastRuleBundleCanaryRollout,
  type SastRuleBundleCanaryScanObservation,
  type SastRuleBundleCanaryStepDecision,
  type SastScanPlan
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';

import { PrismaService } from '../prisma/prisma.service';
import { digestSastRuleBundleCanonical } from './sast-rule-bundle-canonical';
import {
  SastRuleBundleCanaryPersistenceError,
  SastRuleBundleCanaryStore,
  type PendingSastRuleBundleCanaryAssignment,
  type PersistedSastRuleBundleCanaryAssignment,
  type PersistedSastRuleBundleCanaryEligibilityDecision,
  type PersistedSastRuleBundleCanaryObservation,
  type PersistedSastRuleBundleCanaryRollout,
  type PersistedSastRuleBundleCanaryStepDecision,
  type SastRuleBundleCanaryRolloutSnapshot
} from './sast-rule-bundle-canary.store';

const SERIALIZABLE_RETRIES = 3;
const SERIALIZABLE_MAX_WAIT_MILLISECONDS = 5_000;
const SERIALIZABLE_TIMEOUT_MILLISECONDS = 120_000;

type RolloutRow = Prisma.SastRuleBundleCanaryRolloutGetPayload<Record<string, never>>;
type EligibilityRow = Prisma.SastRuleBundleCanaryEligibilityDecisionGetPayload<Record<string, never>>;
type MembershipRow = Prisma.SastRuleBundleCanaryMembershipGetPayload<Record<string, never>>;
type AssignmentRow = Prisma.SastRuleBundleCanaryAssignmentReceiptGetPayload<Record<string, never>>;
type ObservationRow = Prisma.SastRuleBundleCanaryScanObservationGetPayload<Record<string, never>>;
type DecisionRow = Prisma.SastRuleBundleCanaryStepDecisionGetPayload<Record<string, never>>;
type ReceiptRow = Prisma.SastRuleBundleCanaryObservationReceiptGetPayload<Record<string, never>>;

@Injectable()
export class PrismaSastRuleBundleCanaryStore extends SastRuleBundleCanaryStore {
  constructor(private readonly prisma: PrismaService) {
    super();
  }

  async registerRollout(
    rollout: Readonly<SastRuleBundleCanaryRollout>
  ): Promise<PersistedSastRuleBundleCanaryRollout> {
    assertRolloutValid(rollout);
    const persist = () =>
      this.runSerializable(async (tx) => {
        await lockManifest(tx, rollout.candidateManifestId);
        const existing = await tx.sastRuleBundleCanaryRollout.findUnique({
          where: { id: rollout.rolloutId }
        });
        if (existing) return replayRollout(existing, rollout);
        await assertRolloutReferences(tx, rollout);
        const created = await tx.sastRuleBundleCanaryRollout.create({
          data: rolloutData(rollout)
        });
        await tx.sastRuleBundleCanaryRolloutStep.createMany({
          data: rollout.progression.map((step, position) => ({
            rolloutId: rollout.rolloutId,
            position,
            step
          }))
        });
        return replayRollout(created, rollout, false);
      });
    try {
      return await persist();
    } catch (error) {
      if (isUniqueConflict(error)) return persistAfterUnique(persist);
      throw mapPrismaError(error);
    }
  }

  async findRolloutForCandidate(
    manifestId: string,
    profileId: string
  ): Promise<SastRuleBundleCanaryRolloutSnapshot | null> {
    return this.runSerializable(async (tx) => {
      const row = await tx.sastRuleBundleCanaryRollout.findUnique({
        where: {
          candidateManifestId_profileId: {
            candidateManifestId: manifestId,
            profileId
          }
        }
      });
      return row ? this.snapshot(tx, row) : null;
    });
  }

  async findRollout(
    rolloutId: string
  ): Promise<SastRuleBundleCanaryRolloutSnapshot | null> {
    return this.runSerializable(async (tx) => {
      const row = await tx.sastRuleBundleCanaryRollout.findUnique({
        where: { id: rolloutId }
      });
      return row ? this.snapshot(tx, row) : null;
    });
  }

  async registerEligibilityDecision(
    decision: Readonly<SastRuleBundleCanaryEligibilityDecision>
  ): Promise<PersistedSastRuleBundleCanaryEligibilityDecision> {
    assertEligibilityValid(decision);
    const persist = () =>
      this.runSerializable(async (tx) => {
        const head = await lockRolloutHead(tx, decision.rolloutId);
        if (head.latestOutcome === 'PAUSED') {
          throw new SastRuleBundleCanaryPersistenceError('ROLLOUT_PAUSED');
        }
        const completed =
          await tx.sastRuleBundleCanaryObservationReceipt.findUnique({
            where: { rolloutId: decision.rolloutId },
            select: { id: true }
          });
        if (completed) {
          throw new SastRuleBundleCanaryPersistenceError('STEP_STALE');
        }
        const rolloutRow = await tx.sastRuleBundleCanaryRollout.findUnique({
          where: { id: decision.rolloutId }
        });
        if (!rolloutRow) {
          throw new SastRuleBundleCanaryPersistenceError('ROLLOUT_NOT_FOUND');
        }
        if (!eligibilityMatchesRollout(decision, rolloutFromRow(rolloutRow))) {
          throw new SastRuleBundleCanaryPersistenceError('INPUT_INVALID');
        }
        const existing =
          await tx.sastRuleBundleCanaryEligibilityDecision.findUnique({
            where: { id: decision.eligibilityDecisionId }
          });
        if (existing) return replayEligibility(existing, decision);
        const scope =
          await tx.sastRuleBundleCanaryEligibilityDecision.findUnique({
            where: {
              rolloutId_tenantId_repositoryBindingId_profileId: {
                rolloutId: decision.rolloutId,
                tenantId: decision.tenantId,
                repositoryBindingId: decision.repositoryBindingId,
                profileId: decision.profileId
              }
            }
          });
        if (scope) return replayEligibility(scope, decision);
        const created =
          await tx.sastRuleBundleCanaryEligibilityDecision.create({
            data: eligibilityData(decision)
          });
        return replayEligibility(created, decision, false);
      });
    try {
      return await persist();
    } catch (error) {
      if (isUniqueConflict(error)) return persistAfterUnique(persist);
      throw mapPrismaError(error);
    }
  }

  async findEligibilityDecision(input: {
    rolloutId: string;
    tenantId: string;
    repositoryBindingId: string;
    profileId: string;
  }): Promise<SastRuleBundleCanaryEligibilityDecision | null> {
    const row =
      await this.prisma.sastRuleBundleCanaryEligibilityDecision.findUnique({
        where: {
          rolloutId_tenantId_repositoryBindingId_profileId: input
        }
      });
    return row ? eligibilityFromRow(row) : null;
  }

  async recordAssignments(
    assignments: readonly Readonly<PendingSastRuleBundleCanaryAssignment>[]
  ): Promise<PersistedSastRuleBundleCanaryAssignment[]> {
    assertAssignmentBatchValid(assignments);
    const ordered = [...assignments].sort((left, right) =>
      left.membership.rolloutId.localeCompare(right.membership.rolloutId) ||
      left.membership.membershipId.localeCompare(right.membership.membershipId)
    );
    const persist = () =>
      this.runSerializable(async (tx) => {
        const heads = new Map<string, LockedCanaryHead>();
        for (const rolloutId of [...new Set(ordered.map((item) => item.membership.rolloutId))]) {
          heads.set(rolloutId, await lockRolloutHead(tx, rolloutId));
        }
        const result: PersistedSastRuleBundleCanaryAssignment[] = [];
        for (const item of ordered) {
          const { membership, assignment } = item;
          const head = heads.get(membership.rolloutId);
          if (!head || !assignmentMatchesHead(assignment, head)) {
            throw new SastRuleBundleCanaryPersistenceError('STEP_STALE');
          }
          if (head.latestOutcome === 'PAUSED') {
            throw new SastRuleBundleCanaryPersistenceError('ROLLOUT_PAUSED');
          }
          const completed =
            await tx.sastRuleBundleCanaryObservationReceipt.findUnique({
              where: { rolloutId: membership.rolloutId },
              select: { id: true }
            });
          if (completed) {
            throw new SastRuleBundleCanaryPersistenceError('STEP_STALE');
          }
          const eligibility =
            await tx.sastRuleBundleCanaryEligibilityDecision.findUnique({
              where: { id: membership.eligibilityDecisionId }
            });
          if (
            !eligibility ||
            !membershipMatchesEligibility(
              membership,
              eligibilityFromRow(eligibility)
            ) ||
            !assignmentMatchesMembership(assignment, membership)
          ) {
            throw new SastRuleBundleCanaryPersistenceError(
              'ELIGIBILITY_NOT_FOUND'
            );
          }
          let membershipRow =
            await tx.sastRuleBundleCanaryMembership.findUnique({
              where: {
                rolloutId_tenantId_repositoryBindingId_profileId: {
                  rolloutId: membership.rolloutId,
                  tenantId: membership.tenantId,
                  repositoryBindingId: membership.repositoryBindingId,
                  profileId: membership.profileId
                }
              }
            });
          let replayed = true;
          if (membershipRow) {
            assertSameDigest(
              membershipRow.membershipDigest,
              membership.membershipDigest
            );
          } else {
            membershipRow = await tx.sastRuleBundleCanaryMembership.create({
              data: membershipData(membership)
            });
            replayed = false;
          }
          const existing =
            await tx.sastRuleBundleCanaryAssignmentReceipt.findUnique({
              where: { id: assignment.assignmentReceiptId }
            });
          if (existing) {
            result.push(replayAssignment(membershipRow, existing, item));
            continue;
          }
          const created =
            await tx.sastRuleBundleCanaryAssignmentReceipt.create({
              data: assignmentData(assignment)
            });
          result.push({
            ...replayAssignment(membershipRow, created, item),
            replayed
          });
        }
        return result;
      });
    try {
      return await persist();
    } catch (error) {
      if (isUniqueConflict(error)) return persistAfterUnique(persist);
      throw mapPrismaError(error);
    }
  }

  async registerObservation(
    observation: Readonly<SastRuleBundleCanaryScanObservation>
  ): Promise<PersistedSastRuleBundleCanaryObservation> {
    assertObservationValid(observation);
    const persist = () =>
      this.runSerializable(async (tx) => {
        const head = await lockRolloutHead(tx, observation.rolloutId);
        if (head.latestOutcome === 'PAUSED') {
          throw new SastRuleBundleCanaryPersistenceError('ROLLOUT_PAUSED');
        }
        const completed =
          await tx.sastRuleBundleCanaryObservationReceipt.findUnique({
            where: { rolloutId: observation.rolloutId },
            select: { id: true }
          });
        if (completed) {
          throw new SastRuleBundleCanaryPersistenceError('STEP_STALE');
        }
        if (
          observation.step !== head.currentStep ||
          !observationHasValidAssignmentPair(observation)
        ) {
          throw new SastRuleBundleCanaryPersistenceError('STEP_STALE');
        }
        const rolloutRow = await tx.sastRuleBundleCanaryRollout.findUnique({
          where: { id: observation.rolloutId }
        });
        if (
          !rolloutRow ||
          !observationMatchesRollout(observation, rolloutFromRow(rolloutRow))
        ) {
          throw new SastRuleBundleCanaryPersistenceError('ROLLOUT_NOT_FOUND');
        }
        if (observation.cohortRole === 'CANDIDATE') {
          const assignment =
            await tx.sastRuleBundleCanaryAssignmentReceipt.findUnique({
              where: { id: observation.assignmentReceiptId! }
            });
          if (
            !assignment ||
            assignment.assignmentReceiptDigest !==
              observation.assignmentReceiptDigest ||
            assignment.selection !== 'CANDIDATE' ||
            assignment.rolloutId !== observation.rolloutId ||
            assignment.tenantId !== observation.tenantId ||
            assignment.repositoryBindingId !== observation.repositoryBindingId ||
            assignment.evaluatedAt.getTime() >
              Date.parse(observation.startedAt) ||
            !assignmentMatchesHead(assignmentFromRow(assignment), head)
          ) {
            throw new SastRuleBundleCanaryPersistenceError(
              'ASSIGNMENT_NOT_FOUND'
            );
          }
        }
        await assertObservationReferences(tx, observation);
        const existing =
          await tx.sastRuleBundleCanaryScanObservation.findUnique({
            where: { id: observation.observationId }
          });
        if (existing) return replayObservation(existing, observation);
        const created = await tx.sastRuleBundleCanaryScanObservation.create({
          data: observationData(observation)
        });
        return replayObservation(created, observation, false);
      });
    try {
      return await persist();
    } catch (error) {
      if (isUniqueConflict(error)) return persistAfterUnique(persist);
      throw mapPrismaError(error);
    }
  }

  async findObservations(input: {
    rolloutId: string;
    step: SastRuleBundleCanaryScanObservation['step'];
    windowStartedAt: string;
    windowEndedAt: string;
  }): Promise<SastRuleBundleCanaryScanObservation[]> {
    const rows = await this.prisma.sastRuleBundleCanaryScanObservation.findMany({
      where: {
        rolloutId: input.rolloutId,
        step: input.step,
        completedAt: {
          gte: new Date(input.windowStartedAt),
          lte: new Date(input.windowEndedAt)
        }
      },
      orderBy: { id: 'asc' }
    });
    return rows.map(observationFromRow);
  }

  async appendStepDecision(input: {
    decision: Readonly<SastRuleBundleCanaryStepDecision>;
    finalReceipt: Readonly<SastRuleBundleCanaryObservationReceipt> | null;
  }): Promise<PersistedSastRuleBundleCanaryStepDecision> {
    assertDecisionValid(input.decision);
    if (input.finalReceipt) assertReceiptValid(input.finalReceipt);
    const persist = () =>
      this.runSerializable(async (tx) => {
        const head = await lockRolloutHead(tx, input.decision.rolloutId);
        const existing =
          await tx.sastRuleBundleCanaryStepDecision.findUnique({
            where: { id: input.decision.decisionId }
          });
        if (existing) {
          return this.replayDecision(tx, existing, input);
        }
        if (head.latestOutcome === 'PAUSED') {
          throw new SastRuleBundleCanaryPersistenceError('ROLLOUT_PAUSED');
        }
        if (!decisionExtendsHead(input.decision, head)) {
          throw new SastRuleBundleCanaryPersistenceError('STEP_STALE');
        }
        await assertDecisionObservations(tx, input.decision);
        assertFinalReceiptMatchesDecision(input.finalReceipt, input.decision);
        const created = await tx.sastRuleBundleCanaryStepDecision.create({
          data: decisionData(input.decision)
        });
        if (input.decision.observations.length > 0) {
          await tx.sastRuleBundleCanaryStepDecisionObservation.createMany({
            data: input.decision.observations.map((binding, position) => ({
              decisionId: input.decision.decisionId,
              position,
              observationId: binding.observationId,
              observationDigest: binding.observationDigest
            }))
          });
        }
        if (input.decision.reasonCodes.length > 0) {
          await tx.sastRuleBundleCanaryStepDecisionReason.createMany({
            data: input.decision.reasonCodes.map((reasonCode, position) => ({
              decisionId: input.decision.decisionId,
              position,
              reasonCode
            }))
          });
        }
        let receipt: SastRuleBundleCanaryObservationReceipt | null = null;
        if (input.finalReceipt) {
          const receiptRow =
            await tx.sastRuleBundleCanaryObservationReceipt.create({
              data: receiptData(input.finalReceipt)
            });
          await tx.sastRuleBundleCanaryReceiptPassedStep.createMany({
            data: input.finalReceipt.passedSteps.map((binding, position) => ({
              receiptId: input.finalReceipt!.receiptRef,
              position,
              step: binding.step,
              decisionId: binding.decisionId,
              decisionDigest: binding.decisionDigest
            }))
          });
          receipt = receiptFromRow(receiptRow, input.finalReceipt.passedSteps);
        }
        return {
          decision: decisionFromRow(
            created,
            input.decision.reasonCodes,
            input.decision.observations
          ),
          receipt,
          replayed: false
        };
      });
    try {
      return await persist();
    } catch (error) {
      if (isUniqueConflict(error)) return persistAfterUnique(persist);
      throw mapPrismaError(error);
    }
  }

  async findObservationReceiptForAuthority(input: {
    manifestId: string;
    manifestDigest: string;
    bundleId: string;
    bundleDigest: string;
    promotionEvidenceId: string;
    promotionEvidenceDigest: string;
  }): Promise<SastRuleBundleCanaryObservationReceipt | null> {
    const row =
      await this.prisma.sastRuleBundleCanaryObservationReceipt.findFirst({
        where: {
          candidateManifestId: input.manifestId,
          candidateManifestDigest: input.manifestDigest,
          candidateBundleId: input.bundleId,
          candidateBundleDigest: input.bundleDigest,
          promotionEvidenceId: input.promotionEvidenceId,
          promotionEvidenceDigest: input.promotionEvidenceDigest
        },
        orderBy: [{ issuedAt: 'desc' }, { id: 'desc' }]
      });
    if (!row) return null;
    const steps = await this.prisma.sastRuleBundleCanaryReceiptPassedStep.findMany({
      where: { receiptId: row.id },
      orderBy: { position: 'asc' }
    });
    return receiptFromRow(
      row,
      steps.map((step) => ({
        step: step.step as SastRuleBundleCanaryPassedStepBinding['step'],
        decisionId: step.decisionId,
        decisionDigest: asDigest(step.decisionDigest)
      }))
    );
  }

  private async snapshot(
    tx: Prisma.TransactionClient,
    row: RolloutRow
  ): Promise<SastRuleBundleCanaryRolloutSnapshot> {
    const [steps, head, decisionRows, receiptRow] = await Promise.all([
      tx.sastRuleBundleCanaryRolloutStep.findMany({
        where: { rolloutId: row.id },
        orderBy: { position: 'asc' }
      }),
      tx.sastRuleBundleCanaryRolloutHead.findUnique({
        where: { rolloutId: row.id }
      }),
      tx.sastRuleBundleCanaryStepDecision.findMany({
        where: { rolloutId: row.id },
        orderBy: { sequence: 'asc' }
      }),
      tx.sastRuleBundleCanaryObservationReceipt.findUnique({
        where: { rolloutId: row.id }
      })
    ]);
    if (
      !head ||
      steps.length !== SAST_RULE_BUNDLE_CANARY_STEPS.length ||
      !steps.every(
        (entry, position) =>
          entry.position === position &&
          entry.step === SAST_RULE_BUNDLE_CANARY_STEPS[position]
      )
    ) {
      throw new SastRuleBundleCanaryPersistenceError('LEDGER_CORRUPT');
    }
    const decisions = await this.loadDecisions(tx, decisionRows);
    const latestDecision = decisions.at(-1) ?? null;
    if (!headMatchesDecision(head, latestDecision)) {
      throw new SastRuleBundleCanaryPersistenceError('LEDGER_CORRUPT');
    }
    let observationReceipt: SastRuleBundleCanaryObservationReceipt | null = null;
    if (receiptRow) {
      const passed =
        await tx.sastRuleBundleCanaryReceiptPassedStep.findMany({
          where: { receiptId: receiptRow.id },
          orderBy: { position: 'asc' }
        });
      observationReceipt = receiptFromRow(
        receiptRow,
        passed.map((binding) => ({
          step: binding.step as SastRuleBundleCanaryPassedStepBinding['step'],
          decisionId: binding.decisionId,
          decisionDigest: asDigest(binding.decisionDigest)
        }))
      );
    }
    return {
      rollout: rolloutFromRow(row),
      latestDecision,
      passedDecisions: decisions.filter((decision) => decision.outcome === 'PASSED'),
      observationReceipt
    };
  }

  private async loadDecisions(
    tx: Prisma.TransactionClient,
    rows: readonly DecisionRow[]
  ): Promise<SastRuleBundleCanaryStepDecision[]> {
    if (rows.length === 0) return [];
    const ids = rows.map((row) => row.id);
    const [reasons, observations] = await Promise.all([
      tx.sastRuleBundleCanaryStepDecisionReason.findMany({
        where: { decisionId: { in: ids } },
        orderBy: [{ decisionId: 'asc' }, { position: 'asc' }]
      }),
      tx.sastRuleBundleCanaryStepDecisionObservation.findMany({
        where: { decisionId: { in: ids } },
        orderBy: [{ decisionId: 'asc' }, { position: 'asc' }]
      })
    ]);
    return rows.map((row) =>
      decisionFromRow(
        row,
        reasons
          .filter((reason) => reason.decisionId === row.id)
          .map((reason) =>
            reason.reasonCode as SastRuleBundleCanaryStepDecision['reasonCodes'][number]
          ),
        observations
          .filter((binding) => binding.decisionId === row.id)
          .map((binding) => ({
            observationId: binding.observationId,
            observationDigest: asDigest(binding.observationDigest)
          }))
      )
    );
  }

  private async replayDecision(
    tx: Prisma.TransactionClient,
    row: DecisionRow,
    input: {
      decision: Readonly<SastRuleBundleCanaryStepDecision>;
      finalReceipt: Readonly<SastRuleBundleCanaryObservationReceipt> | null;
    }
  ): Promise<PersistedSastRuleBundleCanaryStepDecision> {
    const [reasons, observations, receiptRow] = await Promise.all([
      tx.sastRuleBundleCanaryStepDecisionReason.findMany({
        where: { decisionId: row.id },
        orderBy: { position: 'asc' }
      }),
      tx.sastRuleBundleCanaryStepDecisionObservation.findMany({
        where: { decisionId: row.id },
        orderBy: { position: 'asc' }
      }),
      tx.sastRuleBundleCanaryObservationReceipt.findUnique({
        where: { rolloutId: row.rolloutId }
      })
    ]);
    const decision = decisionFromRow(
      row,
      reasons.map((reason) =>
        reason.reasonCode as SastRuleBundleCanaryStepDecision['reasonCodes'][number]
      ),
      observations.map((binding) => ({
        observationId: binding.observationId,
        observationDigest: asDigest(binding.observationDigest)
      }))
    );
    assertSameDigest(decision.decisionDigest, input.decision.decisionDigest);
    let receipt: SastRuleBundleCanaryObservationReceipt | null = null;
    if (receiptRow) {
      const passed = await tx.sastRuleBundleCanaryReceiptPassedStep.findMany({
        where: { receiptId: receiptRow.id },
        orderBy: { position: 'asc' }
      });
      receipt = receiptFromRow(
        receiptRow,
        passed.map((binding) => ({
          step: binding.step as SastRuleBundleCanaryPassedStepBinding['step'],
          decisionId: binding.decisionId,
          decisionDigest: asDigest(binding.decisionDigest)
        }))
      );
    }
    if (
      (input.finalReceipt === null) !== (receipt === null) ||
      (input.finalReceipt && receipt?.receiptDigest !== input.finalReceipt.receiptDigest)
    ) {
      throw replayConflict();
    }
    return { decision, receipt, replayed: true };
  }

  private async runSerializable<T>(
    operation: (tx: Prisma.TransactionClient) => Promise<T>
  ): Promise<T> {
    for (let attempt = 1; attempt <= SERIALIZABLE_RETRIES; attempt += 1) {
      try {
        return await this.prisma.$transaction(operation, {
          isolationLevel: Prisma.TransactionIsolationLevel.Serializable,
          maxWait: SERIALIZABLE_MAX_WAIT_MILLISECONDS,
          timeout: SERIALIZABLE_TIMEOUT_MILLISECONDS
        });
      } catch (error) {
        if (!isSerializableConflict(error) || attempt === SERIALIZABLE_RETRIES) {
          throw error;
        }
      }
    }
    throw replayConflict();
  }
}

interface LockedCanaryHead {
  rolloutId: string;
  rolloutDigest: string;
  currentStep: string;
  latestDecisionId: string | null;
  latestDecisionDigest: string | null;
  latestSequence: number;
  latestOutcome: string | null;
  windowStartedAt: Date;
}

async function lockManifest(
  tx: Prisma.TransactionClient,
  manifestId: string
): Promise<void> {
  const rows = await tx.$queryRaw<Array<{ id: string }>>`
    SELECT "id" FROM "SastRuleBundleManifest"
    WHERE "id" = ${manifestId}
    FOR UPDATE
  `;
  if (rows.length !== 1 || rows[0]?.id !== manifestId) {
    throw new SastRuleBundleCanaryPersistenceError('ROLLOUT_NOT_FOUND');
  }
}

async function lockRolloutHead(
  tx: Prisma.TransactionClient,
  rolloutId: string
): Promise<LockedCanaryHead> {
  const rows = await tx.$queryRaw<LockedCanaryHead[]>`
    SELECT "rolloutId", "rolloutDigest", "currentStep", "latestDecisionId",
           "latestDecisionDigest", "latestSequence", "latestOutcome", "windowStartedAt"
    FROM "SastRuleBundleCanaryRolloutHead"
    WHERE "rolloutId" = ${rolloutId}
    FOR UPDATE
  `;
  const head = rows[0];
  if (rows.length !== 1 || !head) {
    throw new SastRuleBundleCanaryPersistenceError('ROLLOUT_NOT_FOUND');
  }
  return head;
}

async function assertRolloutReferences(
  tx: Prisma.TransactionClient,
  rollout: Readonly<SastRuleBundleCanaryRollout>
): Promise<void> {
  const [
    candidate,
    baseline,
    evidence,
    transition,
    candidateHead,
    baselineHead
  ] = await Promise.all([
    tx.sastRuleBundleManifest.findUnique({ where: { id: rollout.candidateManifestId } }),
    tx.sastRuleBundleManifest.findUnique({ where: { id: rollout.baselineManifestId } }),
    tx.sastRuleBundlePromotionEvidence.findUnique({ where: { id: rollout.promotionEvidenceId } }),
    tx.sastRuleBundleLifecycleTransition.findUnique({ where: { id: rollout.canaryTransitionId } }),
    tx.sastRuleBundleLifecycleHead.findUnique({
      where: { manifestId: rollout.candidateManifestId }
    }),
    tx.sastRuleBundleLifecycleHead.findUnique({
      where: { manifestId: rollout.baselineManifestId }
    })
  ]);
  if (
    !candidate ||
    !baseline ||
    !evidence ||
    !transition ||
    !candidateHead ||
    !baselineHead
  ) {
    throw new SastRuleBundleCanaryPersistenceError('ROLLOUT_NOT_FOUND');
  }
  if (
    candidate.manifestDigest !== rollout.candidateManifestDigest ||
    candidate.bundleId !== rollout.candidateBundleId ||
    candidate.bundleDigest !== rollout.candidateBundleDigest ||
    baseline.manifestDigest !== rollout.baselineManifestDigest ||
    baseline.bundleId !== rollout.candidateBundleId ||
    baseline.bundleDigest !== rollout.baselineBundleDigest ||
    evidence.evidenceDigest !== rollout.promotionEvidenceDigest ||
    evidence.manifestId !== rollout.candidateManifestId ||
    evidence.baselineManifestId !== rollout.baselineManifestId ||
    evidence.profileId !== rollout.profileId ||
    transition.transitionDigest !== rollout.canaryTransitionDigest ||
    transition.manifestId !== rollout.candidateManifestId ||
    transition.promotionEvidenceId !== rollout.promotionEvidenceId ||
    transition.toState !== 'CANARY' ||
    candidateHead.transitionId !== rollout.canaryTransitionId ||
    candidateHead.transitionDigest !== rollout.canaryTransitionDigest ||
    candidateHead.lifecycleState !== 'CANARY' ||
    baselineHead.manifestDigest !== rollout.baselineManifestDigest ||
    baselineHead.bundleId !== rollout.candidateBundleId ||
    baselineHead.bundleDigest !== rollout.baselineBundleDigest ||
    baselineHead.lifecycleState !== 'ACTIVE' ||
    rollout.createdAt < candidateHead.transitionedAt.toISOString() ||
    rollout.createdAt < baselineHead.transitionedAt.toISOString()
  ) {
    throw new SastRuleBundleCanaryPersistenceError('INPUT_INVALID');
  }
}

async function assertObservationReferences(
  tx: Prisma.TransactionClient,
  observation: Readonly<SastRuleBundleCanaryScanObservation>
): Promise<void> {
  const [reservation, attempt, coverage, publication] = await Promise.all([
    tx.sastQueueReservation.findUnique({ where: { scanRequestId: observation.scanRequestId } }),
    tx.sastScanAttempt.findUnique({ where: { id: observation.attemptId } }),
    tx.sastScanCoverageDecision.findUnique({ where: { id: observation.coverageDecisionId } }),
    tx.sastExternalPublicationDecision.findUnique({ where: { id: observation.publicationDecisionId } })
  ]);
  if (!reservation || !attempt || !coverage || !publication) {
    throw new SastRuleBundleCanaryPersistenceError('OBSERVATION_NOT_FOUND');
  }
  if (
    reservation.tenantId !== observation.tenantId ||
    reservation.repositoryBindingId !== observation.repositoryBindingId ||
    reservation.lane !== observation.lane ||
    !observationMatchesReservationPlan(
      observation,
      reservation.immutablePlan
    ) ||
    attempt.tenantId !== observation.tenantId ||
    attempt.repositoryBindingId !== observation.repositoryBindingId ||
    attempt.scanRequestId !== observation.scanRequestId ||
    attempt.stage !== 'COMPLETED' ||
    !attempt.completedAt ||
    attempt.startedAt.toISOString() !== observation.startedAt ||
    attempt.completedAt.toISOString() !== observation.completedAt ||
    coverage.tenantId !== observation.tenantId ||
    coverage.repositoryBindingId !== observation.repositoryBindingId ||
    coverage.scanRequestId !== observation.scanRequestId ||
    coverage.attemptId !== observation.attemptId ||
    coverage.state === 'PENDING' ||
    observation.coverageComplete !== (coverage.state === 'COMPLETE') ||
    observation.measurements.incompleteCoverageCount !==
      (coverage.state === 'COMPLETE' ? 0 : 1) ||
    coverage.decisionDigest !== observation.coverageDecisionDigest ||
    publication.coverageDecisionId !== observation.coverageDecisionId ||
    publication.tenantId !== observation.tenantId ||
    publication.repositoryBindingId !== observation.repositoryBindingId ||
    publication.scanRequestId !== observation.scanRequestId ||
    publication.attemptId !== observation.attemptId ||
    publication.decisionDigest !== observation.publicationDecisionDigest ||
    observation.measurements.publicationDenialCount !==
      (publication.externalCommentAllowed ? 0 : 1)
  ) {
    throw new SastRuleBundleCanaryPersistenceError('INPUT_INVALID');
  }
}

async function assertDecisionObservations(
  tx: Prisma.TransactionClient,
  decision: Readonly<SastRuleBundleCanaryStepDecision>
): Promise<void> {
  const rows = await tx.sastRuleBundleCanaryScanObservation.findMany({
    where: {
      rolloutId: decision.rolloutId,
      step: decision.step,
      completedAt: {
        gte: new Date(decision.windowStartedAt),
        lte: new Date(decision.windowEndedAt)
      }
    },
    orderBy: { id: 'asc' }
  });
  if (rows.length !== decision.observations.length) {
    throw new SastRuleBundleCanaryPersistenceError('OBSERVATION_NOT_FOUND');
  }
  const expected = [...decision.observations].sort((left, right) =>
    left.observationId.localeCompare(right.observationId)
  );
  if (
    !rows.every(
      (row, index) =>
        row.id === expected[index]?.observationId &&
        row.observationDigest === expected[index]?.observationDigest &&
        row.rolloutId === decision.rolloutId &&
        row.step === decision.step
    )
  ) {
    throw new SastRuleBundleCanaryPersistenceError('OBSERVATION_NOT_FOUND');
  }
}

function rolloutData(
  rollout: Readonly<SastRuleBundleCanaryRollout>
): Prisma.SastRuleBundleCanaryRolloutUncheckedCreateInput {
  const { progression: _progression, version, rolloutId, ...rest } = rollout;
  void _progression;
  return {
    id: rolloutId,
    contractVersion: version,
    ...rest,
    progressionCount: rollout.progression.length,
    createdAt: new Date(rollout.createdAt)
  };
}

function eligibilityData(
  decision: Readonly<SastRuleBundleCanaryEligibilityDecision>
): Prisma.SastRuleBundleCanaryEligibilityDecisionUncheckedCreateInput {
  const { version, eligibilityDecisionId, ...rest } = decision;
  return {
    id: eligibilityDecisionId,
    contractVersion: version,
    ...rest,
    evaluatedAt: new Date(decision.evaluatedAt)
  };
}

function membershipData(
  membership: Readonly<SastRuleBundleCanaryMembership>
): Prisma.SastRuleBundleCanaryMembershipUncheckedCreateInput {
  const { version, membershipId, ...rest } = membership;
  return {
    id: membershipId,
    contractVersion: version,
    ...rest,
    evaluatedAt: new Date(membership.evaluatedAt)
  };
}

function assignmentData(
  assignment: Readonly<SastRuleBundleCanaryAssignmentReceipt>
): Prisma.SastRuleBundleCanaryAssignmentReceiptUncheckedCreateInput {
  const { version, assignmentReceiptId, ...rest } = assignment;
  return {
    id: assignmentReceiptId,
    contractVersion: version,
    ...rest,
    evaluatedAt: new Date(assignment.evaluatedAt)
  };
}

function observationData(
  observation: Readonly<SastRuleBundleCanaryScanObservation>
): Prisma.SastRuleBundleCanaryScanObservationUncheckedCreateInput {
  const {
    version,
    observationId,
    measurements,
    startedAt,
    completedAt,
    ...rest
  } = observation;
  return {
    id: observationId,
    contractVersion: version,
    ...rest,
    startedAt: new Date(startedAt),
    completedAt: new Date(completedAt),
    ...measurements,
    cpuMilliseconds: BigInt(measurements.cpuMilliseconds),
    peakMemoryBytes: BigInt(measurements.peakMemoryBytes),
    diskBytes: BigInt(measurements.diskBytes)
  };
}

function decisionData(
  decision: Readonly<SastRuleBundleCanaryStepDecision>
): Prisma.SastRuleBundleCanaryStepDecisionUncheckedCreateInput {
  const {
    version,
    decisionId,
    observations: _observations,
    reasonCodes: _reasonCodes,
    measurements,
    windowStartedAt,
    windowEndedAt,
    evaluatedAt,
    ...rest
  } = decision;
  void _observations;
  void _reasonCodes;
  return {
    id: decisionId,
    contractVersion: version,
    ...rest,
    ...measurements,
    observationCount: decision.observations.length,
    reasonCodeCount: decision.reasonCodes.length,
    candidateP95CpuMilliseconds: BigInt(measurements.candidateP95CpuMilliseconds),
    baselineP95CpuMilliseconds: BigInt(measurements.baselineP95CpuMilliseconds),
    candidateP95PeakMemoryBytes: BigInt(measurements.candidateP95PeakMemoryBytes),
    baselineP95PeakMemoryBytes: BigInt(measurements.baselineP95PeakMemoryBytes),
    candidateP95DiskBytes: BigInt(measurements.candidateP95DiskBytes),
    baselineP95DiskBytes: BigInt(measurements.baselineP95DiskBytes),
    windowStartedAt: new Date(windowStartedAt),
    windowEndedAt: new Date(windowEndedAt),
    evaluatedAt: new Date(evaluatedAt)
  };
}

function receiptData(
  receipt: Readonly<SastRuleBundleCanaryObservationReceipt>
): Prisma.SastRuleBundleCanaryObservationReceiptUncheckedCreateInput {
  const {
    version,
    receiptRef,
    passedSteps: _passedSteps,
    observedFrom,
    observedThrough,
    issuedAt,
    ...rest
  } = receipt;
  void _passedSteps;
  return {
    id: receiptRef,
    contractVersion: version,
    ...rest,
    passedStepCount: receipt.passedSteps.length,
    observedFrom: new Date(observedFrom),
    observedThrough: new Date(observedThrough),
    issuedAt: new Date(issuedAt)
  };
}

function rolloutFromRow(row: RolloutRow): SastRuleBundleCanaryRollout {
  const rollout: SastRuleBundleCanaryRollout = {
    version: row.contractVersion as SastRuleBundleCanaryRollout['version'],
    rolloutId: row.id,
    rolloutDigest: asDigest(row.rolloutDigest),
    candidateManifestId: row.candidateManifestId,
    candidateManifestDigest: asDigest(row.candidateManifestDigest),
    candidateBundleId: row.candidateBundleId,
    candidateBundleDigest: asDigest(row.candidateBundleDigest),
    baselineManifestId: row.baselineManifestId,
    baselineManifestDigest: asDigest(row.baselineManifestDigest),
    baselineBundleDigest: asDigest(row.baselineBundleDigest),
    profileId: row.profileId as SastRuleBundleCanaryRollout['profileId'],
    profileDigest: asDigest(row.profileDigest),
    promotionEvidenceId: row.promotionEvidenceId,
    promotionEvidenceDigest: asDigest(row.promotionEvidenceDigest),
    canaryTransitionId: row.canaryTransitionId,
    canaryTransitionDigest: asDigest(row.canaryTransitionDigest),
    cohortKeyRef: row.cohortKeyRef,
    cohortKeyVersion: row.cohortKeyVersion,
    eligibilityPolicyRef: row.eligibilityPolicyRef,
    eligibilityPolicyDigest: asDigest(row.eligibilityPolicyDigest),
    observationSourceRef: row.observationSourceRef,
    observationSourceDigest: asDigest(row.observationSourceDigest),
    progression: [...SAST_RULE_BUNDLE_CANARY_STEPS],
    immutable: row.immutable as true,
    customerInputAccepted: row.customerInputAccepted as false,
    repositoryContentStored: row.repositoryContentStored as false,
    findingContentStored: row.findingContentStored as false,
    secretKeyMaterialStored: row.secretKeyMaterialStored as false,
    createdAt: row.createdAt.toISOString()
  };
  assertRolloutValid(rollout, 'LEDGER_CORRUPT');
  return rollout;
}

function eligibilityFromRow(
  row: EligibilityRow
): SastRuleBundleCanaryEligibilityDecision {
  const decision: SastRuleBundleCanaryEligibilityDecision = {
    version: row.contractVersion as SastRuleBundleCanaryEligibilityDecision['version'],
    eligibilityDecisionId: row.id,
    eligibilityDecisionDigest: asDigest(row.eligibilityDecisionDigest),
    rolloutId: row.rolloutId,
    rolloutDigest: asDigest(row.rolloutDigest),
    tenantId: row.tenantId,
    repositoryBindingId: row.repositoryBindingId,
    profileId: row.profileId as SastRuleBundleCanaryEligibilityDecision['profileId'],
    profileDigest: asDigest(row.profileDigest),
    eligibilityClass: row.eligibilityClass as SastRuleBundleCanaryEligibilityDecision['eligibilityClass'],
    excluded: row.excluded,
    exclusionRef: row.exclusionRef,
    eligibilityPolicyRef: row.eligibilityPolicyRef,
    eligibilityPolicyDigest: asDigest(row.eligibilityPolicyDigest),
    actorRef: row.actorRef,
    auditRef: row.auditRef,
    evaluatedAt: row.evaluatedAt.toISOString(),
    platformManaged: row.platformManaged as true,
    customerOverrideAccepted: row.customerOverrideAccepted as false,
    repositoryContentUsed: row.repositoryContentUsed as false,
    findingOrSeverityUsed: row.findingOrSeverityUsed as false
  };
  assertEligibilityValid(decision, 'LEDGER_CORRUPT');
  return decision;
}

function membershipFromRow(row: MembershipRow): SastRuleBundleCanaryMembership {
  const membership: SastRuleBundleCanaryMembership = {
    version: row.contractVersion as SastRuleBundleCanaryMembership['version'],
    membershipId: row.id,
    membershipDigest: asDigest(row.membershipDigest),
    rolloutId: row.rolloutId,
    rolloutDigest: asDigest(row.rolloutDigest),
    tenantId: row.tenantId,
    repositoryBindingId: row.repositoryBindingId,
    profileId: row.profileId as SastRuleBundleCanaryMembership['profileId'],
    profileDigest: asDigest(row.profileDigest),
    eligibilityDecisionId: row.eligibilityDecisionId,
    eligibilityDecisionDigest: asDigest(row.eligibilityDecisionDigest),
    eligibilityClass: row.eligibilityClass as SastRuleBundleCanaryMembership['eligibilityClass'],
    excluded: row.excluded,
    exclusionRef: row.exclusionRef,
    eligibilityPolicyRef: row.eligibilityPolicyRef,
    eligibilityPolicyDigest: asDigest(row.eligibilityPolicyDigest),
    cohortKeyRef: row.cohortKeyRef,
    cohortKeyVersion: row.cohortKeyVersion,
    assignmentHmacDigest: asDigest(row.assignmentHmacDigest),
    bucketBasisPoints: row.bucketBasisPoints,
    evaluatedAt: row.evaluatedAt.toISOString(),
    immutableForRollout: row.immutableForRollout as true,
    repositoryContentUsed: row.repositoryContentUsed as false,
    findingOrSeverityUsed: row.findingOrSeverityUsed as false,
    customerAttributeUsed: row.customerAttributeUsed as false,
    secretKeyMaterialStored: row.secretKeyMaterialStored as false
  };
  assertMembershipValid(membership, 'LEDGER_CORRUPT');
  return membership;
}

function assignmentFromRow(
  row: AssignmentRow
): SastRuleBundleCanaryAssignmentReceipt {
  const assignment: SastRuleBundleCanaryAssignmentReceipt = {
    version: row.contractVersion as SastRuleBundleCanaryAssignmentReceipt['version'],
    assignmentReceiptId: row.id,
    assignmentReceiptDigest: asDigest(row.assignmentReceiptDigest),
    rolloutId: row.rolloutId,
    rolloutDigest: asDigest(row.rolloutDigest),
    membershipId: row.membershipId,
    membershipDigest: asDigest(row.membershipDigest),
    tenantId: row.tenantId,
    repositoryBindingId: row.repositoryBindingId,
    profileId: row.profileId as SastRuleBundleCanaryAssignmentReceipt['profileId'],
    profileDigest: asDigest(row.profileDigest),
    eligibilityClass: row.eligibilityClass as SastRuleBundleCanaryAssignmentReceipt['eligibilityClass'],
    excluded: row.excluded,
    bucketBasisPoints: row.bucketBasisPoints,
    step: row.step as SastRuleBundleCanaryAssignmentReceipt['step'],
    stepHeadDecisionId: row.stepHeadDecisionId,
    stepHeadDecisionDigest: nullableDigest(row.stepHeadDecisionDigest),
    candidateManifestId: row.candidateManifestId,
    candidateManifestDigest: asDigest(row.candidateManifestDigest),
    candidateBundleDigest: asDigest(row.candidateBundleDigest),
    baselineManifestId: row.baselineManifestId,
    baselineManifestDigest: asDigest(row.baselineManifestDigest),
    baselineBundleDigest: asDigest(row.baselineBundleDigest),
    selection: row.selection as SastRuleBundleCanaryAssignmentReceipt['selection'],
    selectedManifestId: row.selectedManifestId,
    selectedManifestDigest: nullableDigest(row.selectedManifestDigest),
    selectedBundleDigest: nullableDigest(row.selectedBundleDigest),
    evaluatedAt: row.evaluatedAt.toISOString(),
    deterministic: row.deterministic as true,
    immutable: row.immutable as true,
    customerOverrideAccepted: row.customerOverrideAccepted as false,
    repositoryContentUsed: row.repositoryContentUsed as false,
    findingOrSeverityUsed: row.findingOrSeverityUsed as false
  };
  assertAssignmentValid(assignment, 'LEDGER_CORRUPT');
  return assignment;
}

function observationFromRow(
  row: ObservationRow
): SastRuleBundleCanaryScanObservation {
  const observation: SastRuleBundleCanaryScanObservation = {
    version: row.contractVersion as SastRuleBundleCanaryScanObservation['version'],
    observationId: row.id,
    observationDigest: asDigest(row.observationDigest),
    rolloutId: row.rolloutId,
    rolloutDigest: asDigest(row.rolloutDigest),
    step: row.step as SastRuleBundleCanaryScanObservation['step'],
    cohortRole: row.cohortRole as SastRuleBundleCanaryScanObservation['cohortRole'],
    tenantId: row.tenantId,
    repositoryBindingId: row.repositoryBindingId,
    scanRequestId: row.scanRequestId,
    attemptId: row.attemptId,
    assignmentReceiptId: row.assignmentReceiptId,
    assignmentReceiptDigest: nullableDigest(row.assignmentReceiptDigest),
    selectedManifestId: row.selectedManifestId,
    selectedManifestDigest: asDigest(row.selectedManifestDigest),
    selectedBundleDigest: asDigest(row.selectedBundleDigest),
    profileId: row.profileId as SastRuleBundleCanaryScanObservation['profileId'],
    profileDigest: asDigest(row.profileDigest),
    lane: row.lane,
    repositorySizeBucket: row.repositorySizeBucket as SastRuleBundleCanaryScanObservation['repositorySizeBucket'],
    coverageDecisionId: row.coverageDecisionId,
    coverageDecisionDigest: asDigest(row.coverageDecisionDigest),
    publicationDecisionId: row.publicationDecisionId,
    publicationDecisionDigest: asDigest(row.publicationDecisionDigest),
    observationSourceRef: row.observationSourceRef,
    observationSourceDigest: asDigest(row.observationSourceDigest),
    telemetrySourceRef: row.telemetrySourceRef,
    telemetrySourceDigest: asDigest(row.telemetrySourceDigest),
    startedAt: row.startedAt.toISOString(),
    completedAt: row.completedAt.toISOString(),
    measurements: observationMeasurementsFromRow(row),
    terminalScanVerified: row.terminalScanVerified as true,
    immutablePlanVerified: row.immutablePlanVerified as true,
    coverageComplete: row.coverageComplete,
    telemetryComplete: row.telemetryComplete,
    sourceOrFindingContentStored: row.sourceOrFindingContentStored as false,
    secretValueStored: row.secretValueStored as false
  };
  assertObservationValid(observation, 'LEDGER_CORRUPT');
  return observation;
}

function decisionFromRow(
  row: DecisionRow,
  reasonCodes: SastRuleBundleCanaryStepDecision['reasonCodes'],
  observations: SastRuleBundleCanaryObservationBinding[]
): SastRuleBundleCanaryStepDecision {
  const decision: SastRuleBundleCanaryStepDecision = {
    version: row.contractVersion as SastRuleBundleCanaryStepDecision['version'],
    decisionId: row.id,
    decisionDigest: asDigest(row.decisionDigest),
    rolloutId: row.rolloutId,
    rolloutDigest: asDigest(row.rolloutDigest),
    candidateManifestId: row.candidateManifestId,
    candidateManifestDigest: asDigest(row.candidateManifestDigest),
    candidateBundleDigest: asDigest(row.candidateBundleDigest),
    baselineManifestId: row.baselineManifestId,
    baselineManifestDigest: asDigest(row.baselineManifestDigest),
    baselineBundleDigest: asDigest(row.baselineBundleDigest),
    profileId: row.profileId as SastRuleBundleCanaryStepDecision['profileId'],
    profileDigest: asDigest(row.profileDigest),
    sequence: row.sequence,
    step: row.step as SastRuleBundleCanaryStepDecision['step'],
    previousDecisionId: row.previousDecisionId,
    previousDecisionDigest: nullableDigest(row.previousDecisionDigest),
    windowStartedAt: row.windowStartedAt.toISOString(),
    windowEndedAt: row.windowEndedAt.toISOString(),
    observations,
    measurements: decisionMeasurementsFromRow(row),
    telemetryComplete: row.telemetryComplete,
    allProfileSizeBucketsCompared: row.allProfileSizeBucketsCompared,
    evaluatorRef: row.evaluatorRef,
    auditRef: row.auditRef,
    evaluatedAt: row.evaluatedAt.toISOString(),
    outcome: row.outcome as SastRuleBundleCanaryStepDecision['outcome'],
    reasonCodes,
    observationSetDigest: asDigest(row.observationSetDigest),
    thresholdsWaived: row.thresholdsWaived as false,
    customerInputAccepted: row.customerInputAccepted as false,
    immutable: row.immutable as true
  };
  assertDecisionValid(decision, 'LEDGER_CORRUPT');
  return decision;
}

function receiptFromRow(
  row: ReceiptRow,
  passedSteps: SastRuleBundleCanaryPassedStepBinding[]
): SastRuleBundleCanaryObservationReceipt {
  const receipt: SastRuleBundleCanaryObservationReceipt = {
    version: row.contractVersion as SastRuleBundleCanaryObservationReceipt['version'],
    receiptRef: row.id,
    receiptDigest: asDigest(row.receiptDigest),
    rolloutId: row.rolloutId,
    rolloutDigest: asDigest(row.rolloutDigest),
    candidateManifestId: row.candidateManifestId,
    candidateManifestDigest: asDigest(row.candidateManifestDigest),
    candidateBundleId: row.candidateBundleId,
    candidateBundleDigest: asDigest(row.candidateBundleDigest),
    baselineManifestId: row.baselineManifestId,
    baselineManifestDigest: asDigest(row.baselineManifestDigest),
    baselineBundleDigest: asDigest(row.baselineBundleDigest),
    profileId: row.profileId as SastRuleBundleCanaryObservationReceipt['profileId'],
    profileDigest: asDigest(row.profileDigest),
    promotionEvidenceId: row.promotionEvidenceId,
    promotionEvidenceDigest: asDigest(row.promotionEvidenceDigest),
    passedSteps,
    observedFrom: row.observedFrom.toISOString(),
    observedThrough: row.observedThrough.toISOString(),
    issuedAt: row.issuedAt.toISOString(),
    everyStepPassed: row.everyStepPassed as true,
    thresholdsWaived: row.thresholdsWaived as false,
    immutable: row.immutable as true,
    repositoryContentStored: row.repositoryContentStored as false,
    findingContentStored: row.findingContentStored as false
  };
  assertReceiptValid(receipt, 'LEDGER_CORRUPT');
  return receipt;
}

function observationMeasurementsFromRow(
  row: ObservationRow
): SastRuleBundleCanaryScanObservation['measurements'] {
  return {
    findingCount: row.findingCount,
    criticalHighFindingCount: row.criticalHighFindingCount,
    falsePositiveCount: row.falsePositiveCount,
    feedbackEligibleFindingCount: row.feedbackEligibleFindingCount,
    waiverCount: row.waiverCount,
    suppressionCount: row.suppressionCount,
    scannerFailureCount: row.scannerFailureCount,
    scannerTimeoutCount: row.scannerTimeoutCount,
    eligibleScannerAttemptCount: row.eligibleScannerAttemptCount,
    artifactRejectionCount: row.artifactRejectionCount,
    latencyMilliseconds: row.latencyMilliseconds,
    cpuMilliseconds: safeNumber(row.cpuMilliseconds),
    peakMemoryBytes: safeNumber(row.peakMemoryBytes),
    diskBytes: safeNumber(row.diskBytes),
    incompleteCoverageCount: row.incompleteCoverageCount,
    publicationDenialCount: row.publicationDenialCount,
    egressDenialCount: row.egressDenialCount,
    cleanupLagMilliseconds: row.cleanupLagMilliseconds,
    quarantineCount: row.quarantineCount,
    killSwitchSignalCount: row.killSwitchSignalCount,
    crossTenantEvents: row.crossTenantEvents,
    secretLeakEvents: row.secretLeakEvents,
    sandboxEscapeEvents: row.sandboxEscapeEvents,
    stalePublicationEvents: row.stalePublicationEvents,
    unauthorizedEgressEvents: row.unauthorizedEgressEvents,
    missingDestructionEvidenceEvents: row.missingDestructionEvidenceEvents,
    evidencePolicyViolationEvents: row.evidencePolicyViolationEvents,
    unsignedArtifactExecutionEvents: row.unsignedArtifactExecutionEvents
  };
}

function decisionMeasurementsFromRow(
  row: DecisionRow
): SastRuleBundleCanaryStepDecision['measurements'] {
  return {
    candidateCompletedScans: row.candidateCompletedScans,
    baselineCompletedScans: row.baselineCompletedScans,
    candidateFindingCount: row.candidateFindingCount,
    baselineFindingCount: row.baselineFindingCount,
    candidateCriticalHighFindingCount: row.candidateCriticalHighFindingCount,
    baselineCriticalHighFindingCount: row.baselineCriticalHighFindingCount,
    candidateFalsePositiveCount: row.candidateFalsePositiveCount,
    candidateFeedbackEligibleFindingCount: row.candidateFeedbackEligibleFindingCount,
    baselineFalsePositiveCount: row.baselineFalsePositiveCount,
    baselineFeedbackEligibleFindingCount: row.baselineFeedbackEligibleFindingCount,
    candidateWaiverCount: row.candidateWaiverCount,
    baselineWaiverCount: row.baselineWaiverCount,
    candidateSuppressionCount: row.candidateSuppressionCount,
    baselineSuppressionCount: row.baselineSuppressionCount,
    candidateScannerFailureCount: row.candidateScannerFailureCount,
    candidateEligibleScannerAttemptCount: row.candidateEligibleScannerAttemptCount,
    baselineScannerFailureCount: row.baselineScannerFailureCount,
    baselineEligibleScannerAttemptCount: row.baselineEligibleScannerAttemptCount,
    candidateScannerTimeoutCount: row.candidateScannerTimeoutCount,
    baselineScannerTimeoutCount: row.baselineScannerTimeoutCount,
    candidateP50LatencyMilliseconds: row.candidateP50LatencyMilliseconds,
    candidateP95LatencyMilliseconds: row.candidateP95LatencyMilliseconds,
    baselineP50LatencyMilliseconds: row.baselineP50LatencyMilliseconds,
    baselineP95LatencyMilliseconds: row.baselineP95LatencyMilliseconds,
    candidateP95CpuMilliseconds: safeNumber(row.candidateP95CpuMilliseconds),
    baselineP95CpuMilliseconds: safeNumber(row.baselineP95CpuMilliseconds),
    candidateP95PeakMemoryBytes: safeNumber(row.candidateP95PeakMemoryBytes),
    baselineP95PeakMemoryBytes: safeNumber(row.baselineP95PeakMemoryBytes),
    candidateP95DiskBytes: safeNumber(row.candidateP95DiskBytes),
    baselineP95DiskBytes: safeNumber(row.baselineP95DiskBytes),
    candidateArtifactRejectionCount: row.candidateArtifactRejectionCount,
    baselineArtifactRejectionCount: row.baselineArtifactRejectionCount,
    candidateIncompleteCoverageCount: row.candidateIncompleteCoverageCount,
    baselineIncompleteCoverageCount: row.baselineIncompleteCoverageCount,
    candidatePublicationDenialCount: row.candidatePublicationDenialCount,
    baselinePublicationDenialCount: row.baselinePublicationDenialCount,
    candidateEgressDenialCount: row.candidateEgressDenialCount,
    baselineEgressDenialCount: row.baselineEgressDenialCount,
    candidateP95CleanupLagMilliseconds: row.candidateP95CleanupLagMilliseconds,
    baselineP95CleanupLagMilliseconds: row.baselineP95CleanupLagMilliseconds,
    candidateQuarantineCount: row.candidateQuarantineCount,
    baselineQuarantineCount: row.baselineQuarantineCount,
    candidateKillSwitchSignalCount: row.candidateKillSwitchSignalCount,
    baselineKillSwitchSignalCount: row.baselineKillSwitchSignalCount,
    crossTenantEvents: row.crossTenantEvents,
    secretLeakEvents: row.secretLeakEvents,
    sandboxEscapeEvents: row.sandboxEscapeEvents,
    stalePublicationEvents: row.stalePublicationEvents,
    unauthorizedEgressEvents: row.unauthorizedEgressEvents,
    missingDestructionEvidenceEvents: row.missingDestructionEvidenceEvents,
    evidencePolicyViolationEvents: row.evidencePolicyViolationEvents,
    unsignedArtifactExecutionEvents: row.unsignedArtifactExecutionEvents
  };
}

function replayRollout(
  row: RolloutRow,
  expected: Readonly<SastRuleBundleCanaryRollout>,
  replayed = true
): PersistedSastRuleBundleCanaryRollout {
  const rollout = rolloutFromRow(row);
  assertSameDigest(rollout.rolloutDigest, expected.rolloutDigest);
  return { rollout, replayed };
}

function replayEligibility(
  row: EligibilityRow,
  expected: Readonly<SastRuleBundleCanaryEligibilityDecision>,
  replayed = true
): PersistedSastRuleBundleCanaryEligibilityDecision {
  const decision = eligibilityFromRow(row);
  assertSameDigest(
    decision.eligibilityDecisionDigest,
    expected.eligibilityDecisionDigest
  );
  return { decision, replayed };
}

function replayAssignment(
  membershipRow: MembershipRow,
  assignmentRow: AssignmentRow,
  expected: Readonly<PendingSastRuleBundleCanaryAssignment>
): PersistedSastRuleBundleCanaryAssignment {
  const membership = membershipFromRow(membershipRow);
  const assignment = assignmentFromRow(assignmentRow);
  assertSameDigest(membership.membershipDigest, expected.membership.membershipDigest);
  assertSameDigest(
    assignment.assignmentReceiptDigest,
    expected.assignment.assignmentReceiptDigest
  );
  return { membership, assignment, replayed: true };
}

function replayObservation(
  row: ObservationRow,
  expected: Readonly<SastRuleBundleCanaryScanObservation>,
  replayed = true
): PersistedSastRuleBundleCanaryObservation {
  const observation = observationFromRow(row);
  assertSameDigest(observation.observationDigest, expected.observationDigest);
  return { observation, replayed };
}

function eligibilityMatchesRollout(
  decision: Readonly<SastRuleBundleCanaryEligibilityDecision>,
  rollout: Readonly<SastRuleBundleCanaryRollout>
): boolean {
  return (
    decision.rolloutId === rollout.rolloutId &&
    decision.rolloutDigest === rollout.rolloutDigest &&
    decision.profileId === rollout.profileId &&
    decision.profileDigest === rollout.profileDigest &&
    decision.eligibilityPolicyRef === rollout.eligibilityPolicyRef &&
    decision.eligibilityPolicyDigest === rollout.eligibilityPolicyDigest &&
    Date.parse(decision.evaluatedAt) >= Date.parse(rollout.createdAt)
  );
}

function membershipMatchesEligibility(
  membership: Readonly<SastRuleBundleCanaryMembership>,
  eligibility: Readonly<SastRuleBundleCanaryEligibilityDecision>
): boolean {
  return (
    membership.eligibilityDecisionId === eligibility.eligibilityDecisionId &&
    membership.eligibilityDecisionDigest === eligibility.eligibilityDecisionDigest &&
    membership.rolloutId === eligibility.rolloutId &&
    membership.rolloutDigest === eligibility.rolloutDigest &&
    membership.tenantId === eligibility.tenantId &&
    membership.repositoryBindingId === eligibility.repositoryBindingId &&
    membership.profileId === eligibility.profileId &&
    membership.profileDigest === eligibility.profileDigest &&
    membership.eligibilityClass === eligibility.eligibilityClass &&
    membership.excluded === eligibility.excluded &&
    membership.exclusionRef === eligibility.exclusionRef &&
    membership.eligibilityPolicyRef === eligibility.eligibilityPolicyRef &&
    membership.eligibilityPolicyDigest === eligibility.eligibilityPolicyDigest &&
    membership.evaluatedAt === eligibility.evaluatedAt
  );
}

function assignmentMatchesMembership(
  assignment: Readonly<SastRuleBundleCanaryAssignmentReceipt>,
  membership: Readonly<SastRuleBundleCanaryMembership>
): boolean {
  return (
    assignment.membershipId === membership.membershipId &&
    assignment.membershipDigest === membership.membershipDigest &&
    assignment.rolloutId === membership.rolloutId &&
    assignment.rolloutDigest === membership.rolloutDigest &&
    assignment.tenantId === membership.tenantId &&
    assignment.repositoryBindingId === membership.repositoryBindingId &&
    assignment.profileId === membership.profileId &&
    assignment.profileDigest === membership.profileDigest &&
    assignment.eligibilityClass === membership.eligibilityClass &&
    assignment.excluded === membership.excluded &&
    assignment.bucketBasisPoints === membership.bucketBasisPoints &&
    Date.parse(assignment.evaluatedAt) >=
      Date.parse(membership.evaluatedAt) &&
    assignment.selection === 'CANDIDATE'
  );
}

function assignmentMatchesHead(
  assignment: Readonly<SastRuleBundleCanaryAssignmentReceipt>,
  head: Readonly<LockedCanaryHead>
): boolean {
  return (
    assignment.rolloutId === head.rolloutId &&
    assignment.rolloutDigest === head.rolloutDigest &&
    assignment.step === head.currentStep &&
    assignment.stepHeadDecisionId === head.latestDecisionId &&
    assignment.stepHeadDecisionDigest === head.latestDecisionDigest &&
    Date.parse(assignment.evaluatedAt) >= head.windowStartedAt.getTime()
  );
}

function observationHasValidAssignmentPair(
  observation: Readonly<SastRuleBundleCanaryScanObservation>
): boolean {
  return observation.cohortRole === 'CANDIDATE'
    ? observation.assignmentReceiptId !== null &&
        observation.assignmentReceiptDigest !== null
    : observation.assignmentReceiptId === null &&
        observation.assignmentReceiptDigest === null;
}

function observationMatchesRollout(
  observation: Readonly<SastRuleBundleCanaryScanObservation>,
  rollout: Readonly<SastRuleBundleCanaryRollout>
): boolean {
  const candidate = observation.cohortRole === 'CANDIDATE';
  return (
    observation.rolloutDigest === rollout.rolloutDigest &&
    observation.profileId === rollout.profileId &&
    observation.profileDigest === rollout.profileDigest &&
    observation.observationSourceRef === rollout.observationSourceRef &&
    observation.observationSourceDigest === rollout.observationSourceDigest &&
    observation.selectedManifestId ===
      (candidate ? rollout.candidateManifestId : rollout.baselineManifestId) &&
    observation.selectedManifestDigest ===
      (candidate
        ? rollout.candidateManifestDigest
        : rollout.baselineManifestDigest) &&
    observation.selectedBundleDigest ===
      (candidate ? rollout.candidateBundleDigest : rollout.baselineBundleDigest)
  );
}

function observationMatchesReservationPlan(
  observation: Readonly<SastRuleBundleCanaryScanObservation>,
  value: unknown
): boolean {
  const plan = value as SastScanPlan;
  if (!isSastScanPlanValid(plan)) return false;
  if (
    plan.tenantId !== observation.tenantId ||
    plan.repositoryState.repositoryBindingId !==
      observation.repositoryBindingId ||
    plan.profile.id !== observation.profileId ||
    plan.profileDigest !== observation.profileDigest
  ) {
    return false;
  }
  const bundle = plan.scannerSet.ruleBundles.find(
    (item) =>
      item.manifestId === observation.selectedManifestId &&
      item.manifestDigest === observation.selectedManifestDigest &&
      item.digest === observation.selectedBundleDigest
  );
  if (!bundle) return false;
  if (observation.cohortRole === 'BASELINE') {
    return (
      bundle.lifecycle.lifecycleState === 'ACTIVE' &&
      bundle.canaryAssignment === null
    );
  }
  const assignment = bundle.canaryAssignment;
  return (
    bundle.lifecycle.lifecycleState === 'CANARY' &&
    assignment !== null &&
    assignment.rolloutId === observation.rolloutId &&
    assignment.rolloutDigest === observation.rolloutDigest &&
    assignment.step === observation.step &&
    assignment.assignmentReceiptId === observation.assignmentReceiptId &&
    assignment.assignmentReceiptDigest ===
      observation.assignmentReceiptDigest
  );
}

function decisionExtendsHead(
  decision: Readonly<SastRuleBundleCanaryStepDecision>,
  head: Readonly<LockedCanaryHead>
): boolean {
  return (
    decision.rolloutDigest === head.rolloutDigest &&
    decision.sequence === head.latestSequence + 1 &&
    decision.step === head.currentStep &&
    decision.previousDecisionId === head.latestDecisionId &&
    decision.previousDecisionDigest === head.latestDecisionDigest &&
    decision.windowStartedAt === head.windowStartedAt.toISOString()
  );
}

function assertFinalReceiptMatchesDecision(
  receipt: Readonly<SastRuleBundleCanaryObservationReceipt> | null,
  decision: Readonly<SastRuleBundleCanaryStepDecision>
): void {
  const finalPass = decision.step === 'PERCENT_100' && decision.outcome === 'PASSED';
  if (finalPass !== (receipt !== null)) {
    throw new SastRuleBundleCanaryPersistenceError('INPUT_INVALID');
  }
  if (
    receipt &&
    (receipt.rolloutId !== decision.rolloutId ||
      receipt.rolloutDigest !== decision.rolloutDigest ||
      receipt.passedSteps.at(-1)?.decisionId !== decision.decisionId ||
      receipt.passedSteps.at(-1)?.decisionDigest !== decision.decisionDigest)
  ) {
    throw new SastRuleBundleCanaryPersistenceError('INPUT_INVALID');
  }
}

function headMatchesDecision(
  head: Readonly<LockedCanaryHead>,
  decision: Readonly<SastRuleBundleCanaryStepDecision> | null
): boolean {
  if (!decision) {
    return (
      head.currentStep === 'INTERNAL_CORPUS' &&
      head.latestDecisionId === null &&
      head.latestDecisionDigest === null &&
      head.latestSequence === 0 &&
      head.latestOutcome === null
    );
  }
  const expectedStep =
    decision.outcome === 'PASSED'
      ? nextSastRuleBundleCanaryStep(decision.step) ?? decision.step
      : decision.step;
  return (
    head.latestDecisionId === decision.decisionId &&
    head.latestDecisionDigest === decision.decisionDigest &&
    head.latestSequence === decision.sequence &&
    head.latestOutcome === decision.outcome &&
    head.currentStep === expectedStep
  );
}

function assertAssignmentBatchValid(
  assignments: readonly Readonly<PendingSastRuleBundleCanaryAssignment>[]
): void {
  if (
    assignments.length === 0 ||
    new Set(assignments.map((item) => item.membership.membershipId)).size !==
      assignments.length
  ) {
    throw new SastRuleBundleCanaryPersistenceError('INPUT_INVALID');
  }
  for (const item of assignments) {
    assertMembershipValid(item.membership);
    assertAssignmentValid(item.assignment);
    if (!assignmentMatchesMembership(item.assignment, item.membership)) {
      throw new SastRuleBundleCanaryPersistenceError('INPUT_INVALID');
    }
  }
}

function assertRolloutValid(
  value: unknown,
  reason: 'INPUT_INVALID' | 'LEDGER_CORRUPT' = 'INPUT_INVALID'
): asserts value is SastRuleBundleCanaryRollout {
  if (!isSastRuleBundleCanaryRolloutShapeValid(value, digestSastRuleBundleCanonical)) {
    throw new SastRuleBundleCanaryPersistenceError(reason);
  }
}

function assertEligibilityValid(
  value: unknown,
  reason: 'INPUT_INVALID' | 'LEDGER_CORRUPT' = 'INPUT_INVALID'
): asserts value is SastRuleBundleCanaryEligibilityDecision {
  if (!isSastRuleBundleCanaryEligibilityDecisionShapeValid(value, digestSastRuleBundleCanonical)) {
    throw new SastRuleBundleCanaryPersistenceError(reason);
  }
}

function assertMembershipValid(
  value: unknown,
  reason: 'INPUT_INVALID' | 'LEDGER_CORRUPT' = 'INPUT_INVALID'
): asserts value is SastRuleBundleCanaryMembership {
  if (!isSastRuleBundleCanaryMembershipShapeValid(value, digestSastRuleBundleCanonical)) {
    throw new SastRuleBundleCanaryPersistenceError(reason);
  }
}

function assertAssignmentValid(
  value: unknown,
  reason: 'INPUT_INVALID' | 'LEDGER_CORRUPT' = 'INPUT_INVALID'
): asserts value is SastRuleBundleCanaryAssignmentReceipt {
  if (!isSastRuleBundleCanaryAssignmentReceiptShapeValid(value, digestSastRuleBundleCanonical)) {
    throw new SastRuleBundleCanaryPersistenceError(reason);
  }
}

function assertObservationValid(
  value: unknown,
  reason: 'INPUT_INVALID' | 'LEDGER_CORRUPT' = 'INPUT_INVALID'
): asserts value is SastRuleBundleCanaryScanObservation {
  if (!isSastRuleBundleCanaryScanObservationShapeValid(value, digestSastRuleBundleCanonical)) {
    throw new SastRuleBundleCanaryPersistenceError(reason);
  }
}

function assertDecisionValid(
  value: unknown,
  reason: 'INPUT_INVALID' | 'LEDGER_CORRUPT' = 'INPUT_INVALID'
): asserts value is SastRuleBundleCanaryStepDecision {
  if (!isSastRuleBundleCanaryStepDecisionShapeValid(value, digestSastRuleBundleCanonical)) {
    throw new SastRuleBundleCanaryPersistenceError(reason);
  }
}

function assertReceiptValid(
  value: unknown,
  reason: 'INPUT_INVALID' | 'LEDGER_CORRUPT' = 'INPUT_INVALID'
): asserts value is SastRuleBundleCanaryObservationReceipt {
  if (!isSastRuleBundleCanaryObservationReceiptShapeValid(value, digestSastRuleBundleCanonical)) {
    throw new SastRuleBundleCanaryPersistenceError(reason);
  }
}

function assertSameDigest(actual: string, expected: string): void {
  if (actual !== expected) throw replayConflict();
}

function safeNumber(value: bigint): number {
  const converted = Number(value);
  if (!Number.isSafeInteger(converted)) {
    throw new SastRuleBundleCanaryPersistenceError('LEDGER_CORRUPT');
  }
  return converted;
}

function asDigest(value: string): `sha256:${string}` {
  return value as `sha256:${string}`;
}

function nullableDigest(value: string | null): `sha256:${string}` | null {
  return value === null ? null : asDigest(value);
}

function replayConflict(): SastRuleBundleCanaryPersistenceError {
  return new SastRuleBundleCanaryPersistenceError('REPLAY_CONFLICT');
}

async function persistAfterUnique<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    throw mapPrismaError(error);
  }
}

function mapPrismaError(error: unknown): unknown {
  if (error instanceof SastRuleBundleCanaryPersistenceError) return error;
  if (
    error instanceof Prisma.PrismaClientKnownRequestError &&
    (error.code === 'P2002' || error.code === 'P2003')
  ) {
    return replayConflict();
  }
  return error;
}

function isUniqueConflict(error: unknown): boolean {
  return (
    error instanceof Prisma.PrismaClientKnownRequestError &&
    error.code === 'P2002'
  );
}

function isSerializableConflict(error: unknown): boolean {
  return (
    error instanceof Prisma.PrismaClientKnownRequestError &&
    error.code === 'P2034'
  );
}
