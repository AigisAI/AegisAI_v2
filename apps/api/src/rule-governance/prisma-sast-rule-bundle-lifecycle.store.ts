import {
  isSastRuleBundleLifecycleSelectionReceiptShapeValid,
  isSastRuleBundleLifecycleTransitionShapeValid,
  isSastRuleBundlePromotionApprovalShapeValid,
  isSastRuleBundlePromotionEvidenceShapeValid,
  type SastRuleBundleLifecycleSelectionReceipt,
  type SastRuleBundleLifecycleTransition,
  type SastRuleBundlePromotionApproval,
  type SastRuleBundlePromotionEvidence
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';

import { PrismaService } from '../prisma/prisma.service';
import { digestSastRuleBundleCanonical } from './sast-rule-bundle-canonical';
import {
  SastRuleBundleLifecyclePersistenceError,
  SastRuleBundleLifecycleStore,
  type PersistedSastRuleBundleLifecycleSelection,
  type PersistedSastRuleBundleLifecycleTransition,
  type PersistedSastRuleBundlePromotionApproval,
  type PersistedSastRuleBundlePromotionEvidence,
  type SastRuleBundleLifecycleLedgerSnapshot
} from './sast-rule-bundle-lifecycle.store';

const SERIALIZABLE_RETRIES = 3;
const SERIALIZABLE_MAX_WAIT_MILLISECONDS = 5_000;
const SERIALIZABLE_TIMEOUT_MILLISECONDS = 120_000;

const TRANSITION_INCLUDE = {
  promotionEvidence: true,
  approvals: {
    orderBy: { position: 'asc' as const },
    include: { approval: true }
  }
} satisfies Prisma.SastRuleBundleLifecycleTransitionInclude;

type EvidenceRow = Prisma.SastRuleBundlePromotionEvidenceGetPayload<Record<string, never>>;
type ApprovalRow = Prisma.SastRuleBundlePromotionApprovalGetPayload<Record<string, never>>;
type TransitionRow = Prisma.SastRuleBundleLifecycleTransitionGetPayload<{
  include: typeof TRANSITION_INCLUDE;
}>;
type SelectionRow = Prisma.SastRuleBundleLifecycleSelectionReceiptGetPayload<Record<string, never>>;

@Injectable()
export class PrismaSastRuleBundleLifecycleStore extends SastRuleBundleLifecycleStore {
  constructor(private readonly prisma: PrismaService) {
    super();
  }

  async registerPromotionEvidence(
    evidence: Readonly<SastRuleBundlePromotionEvidence>
  ): Promise<PersistedSastRuleBundlePromotionEvidence> {
    assertEvidenceValid(evidence);
    try {
      return await this.runSerializable(async (tx) => {
        await assertEvidenceReferences(tx, evidence);
        const existing = await tx.sastRuleBundlePromotionEvidence.findUnique({
          where: { id: evidence.evidenceId }
        });
        if (existing) return replayEvidence(existing, evidence);
        const created = await tx.sastRuleBundlePromotionEvidence.create({
          data: evidenceData(evidence)
        });
        return replayEvidence(created, evidence, false);
      });
    } catch (error) {
      return this.replayEvidenceAfterConflict(error, evidence);
    }
  }

  async findPromotionEvidence(
    evidenceId: string
  ): Promise<PersistedSastRuleBundlePromotionEvidence | null> {
    const row = await this.prisma.sastRuleBundlePromotionEvidence.findUnique({
      where: { id: evidenceId }
    });
    return row ? { evidence: evidenceFromRow(row), replayed: true } : null;
  }

  async registerPromotionApproval(
    approval: Readonly<SastRuleBundlePromotionApproval>
  ): Promise<PersistedSastRuleBundlePromotionApproval> {
    assertApprovalValid(approval);
    try {
      return await this.runSerializable(async (tx) => {
        const evidenceRow =
          await tx.sastRuleBundlePromotionEvidence.findUnique({
            where: { id: approval.evidenceId }
          });
        if (!evidenceRow) {
          throw new SastRuleBundleLifecyclePersistenceError(
            'EVIDENCE_NOT_FOUND'
          );
        }
        const evidence = evidenceFromRow(evidenceRow);
        if (!approvalBoundToEvidence(approval, evidence)) {
          throw new SastRuleBundleLifecyclePersistenceError(
            'REFERENCE_INVALID'
          );
        }
        const existing = await tx.sastRuleBundlePromotionApproval.findUnique({
          where: { id: approval.approvalId }
        });
        if (existing) return replayApproval(existing, approval);
        const created = await tx.sastRuleBundlePromotionApproval.create({
          data: approvalData(approval)
        });
        return replayApproval(created, approval, false);
      });
    } catch (error) {
      return this.replayApprovalAfterConflict(error, approval);
    }
  }

  async findPromotionApprovals(
    approvalIds: readonly string[]
  ): Promise<SastRuleBundlePromotionApproval[]> {
    if (approvalIds.length === 0) return [];
    const rows = await this.prisma.sastRuleBundlePromotionApproval.findMany({
      where: { id: { in: [...approvalIds] } }
    });
    return rows.map(approvalFromRow).sort(compareApprovalsByRole);
  }

  async appendLifecycleTransition(
    transition: Readonly<SastRuleBundleLifecycleTransition>
  ): Promise<PersistedSastRuleBundleLifecycleTransition> {
    assertTransitionValid(transition);
    try {
      return await this.runSerializable(async (tx) => {
        await lockLifecycleManifest(tx, transition.manifestId);
        const existing = await tx.sastRuleBundleLifecycleTransition.findUnique({
          where: { id: transition.transitionId },
          include: TRANSITION_INCLUDE
        });
        if (existing) return replayTransition(existing, transition);

        await assertTransitionReferences(tx, transition);
        const latest = await tx.sastRuleBundleLifecycleTransition.findFirst({
          where: { manifestId: transition.manifestId },
          orderBy: { sequence: 'desc' },
          include: TRANSITION_INCLUDE
        });
        if (!transitionExtendsLatest(transition, latest)) {
          throw new SastRuleBundleLifecyclePersistenceError(
            'STALE_TRANSITION'
          );
        }

        const created = await tx.sastRuleBundleLifecycleTransition.create({
          data: transitionData(transition),
          include: TRANSITION_INCLUDE
        });
        return replayTransition(created, transition, false);
      });
    } catch (error) {
      return this.replayTransitionAfterConflict(error, transition);
    }
  }

  async findLatestLifecycleSnapshot(
    manifestId: string
  ): Promise<SastRuleBundleLifecycleLedgerSnapshot | null> {
    const row = await this.prisma.sastRuleBundleLifecycleTransition.findFirst({
      where: { manifestId },
      orderBy: { sequence: 'desc' },
      include: TRANSITION_INCLUDE
    });
    return row ? snapshotFromRow(row) : null;
  }

  async recordLifecycleSelections(
    receipts: readonly Readonly<SastRuleBundleLifecycleSelectionReceipt>[]
  ): Promise<PersistedSastRuleBundleLifecycleSelection[]> {
    if (receipts.length === 0) {
      throw new SastRuleBundleLifecyclePersistenceError('INPUT_INVALID');
    }
    receipts.forEach((receipt) => assertSelectionValid(receipt));
    const manifestIds = [...new Set(receipts.map((receipt) => receipt.manifestId))].sort();
    if (manifestIds.length !== receipts.length) {
      throw new SastRuleBundleLifecyclePersistenceError('INPUT_INVALID');
    }

    try {
      return await this.runSerializable(async (tx) => {
        for (const manifestId of manifestIds) {
          await lockLifecycleManifest(tx, manifestId);
        }

        const persisted: PersistedSastRuleBundleLifecycleSelection[] = [];
        for (const receipt of receipts) {
          const latest =
            await tx.sastRuleBundleLifecycleTransition.findFirst({
              where: { manifestId: receipt.manifestId },
              orderBy: { sequence: 'desc' },
              include: TRANSITION_INCLUDE
            });
          if (!latest) {
            throw new SastRuleBundleLifecyclePersistenceError(
              'TRANSITION_NOT_FOUND'
            );
          }
          const snapshot = snapshotFromRow(latest);
          if (!selectionMatchesLatest(receipt, snapshot.transition)) {
            throw new SastRuleBundleLifecyclePersistenceError(
              'STALE_TRANSITION'
            );
          }

          const existing =
            await tx.sastRuleBundleLifecycleSelectionReceipt.findUnique({
              where: { id: receipt.receiptId }
            });
          if (existing) {
            persisted.push(replaySelection(existing, receipt));
            continue;
          }
          const created =
            await tx.sastRuleBundleLifecycleSelectionReceipt.create({
              data: selectionData(receipt)
            });
          persisted.push(replaySelection(created, receipt, false));
        }
        return persisted;
      });
    } catch (error) {
      if (!isUniqueConflict(error)) throw mapPrismaError(error);
      return this.replaySelectionsAfterConflict(receipts, manifestIds);
    }
  }

  private async replayEvidenceAfterConflict(
    error: unknown,
    evidence: Readonly<SastRuleBundlePromotionEvidence>
  ): Promise<PersistedSastRuleBundlePromotionEvidence> {
    if (!isUniqueConflict(error)) throw mapPrismaError(error);
    return this.runSerializable(async (tx) => {
      const existing = await tx.sastRuleBundlePromotionEvidence.findUnique({
        where: { id: evidence.evidenceId }
      });
      if (!existing) throw replayConflict();
      return replayEvidence(existing, evidence);
    });
  }

  private async replayApprovalAfterConflict(
    error: unknown,
    approval: Readonly<SastRuleBundlePromotionApproval>
  ): Promise<PersistedSastRuleBundlePromotionApproval> {
    if (!isUniqueConflict(error)) throw mapPrismaError(error);
    return this.runSerializable(async (tx) => {
      const existing = await tx.sastRuleBundlePromotionApproval.findUnique({
        where: { id: approval.approvalId }
      });
      if (!existing) throw replayConflict();
      return replayApproval(existing, approval);
    });
  }

  private async replayTransitionAfterConflict(
    error: unknown,
    transition: Readonly<SastRuleBundleLifecycleTransition>
  ): Promise<PersistedSastRuleBundleLifecycleTransition> {
    if (!isUniqueConflict(error)) throw mapPrismaError(error);
    return this.runSerializable(async (tx) => {
      const existing = await tx.sastRuleBundleLifecycleTransition.findUnique({
        where: { id: transition.transitionId },
        include: TRANSITION_INCLUDE
      });
      if (!existing) throw replayConflict();
      return replayTransition(existing, transition);
    });
  }

  private async replaySelectionsAfterConflict(
    receipts: readonly Readonly<SastRuleBundleLifecycleSelectionReceipt>[],
    manifestIds: readonly string[]
  ): Promise<PersistedSastRuleBundleLifecycleSelection[]> {
    return this.runSerializable(async (tx) => {
      for (const manifestId of manifestIds) {
        await lockLifecycleManifest(tx, manifestId);
      }

      const persisted: PersistedSastRuleBundleLifecycleSelection[] = [];
      for (const receipt of receipts) {
        const latest =
          await tx.sastRuleBundleLifecycleTransition.findFirst({
            where: { manifestId: receipt.manifestId },
            orderBy: { sequence: 'desc' },
            include: TRANSITION_INCLUDE
          });
        if (!latest) {
          throw new SastRuleBundleLifecyclePersistenceError(
            'TRANSITION_NOT_FOUND'
          );
        }
        if (!selectionMatchesLatest(receipt, snapshotFromRow(latest).transition)) {
          throw new SastRuleBundleLifecyclePersistenceError('STALE_TRANSITION');
        }

        const existing =
          await tx.sastRuleBundleLifecycleSelectionReceipt.findUnique({
            where: { id: receipt.receiptId }
          });
        if (!existing) throw replayConflict();
        persisted.push(replaySelection(existing, receipt));
      }
      return persisted;
    });
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
        if (
          !isSerializableConflict(error) ||
          attempt === SERIALIZABLE_RETRIES
        ) {
          throw mapPrismaError(error);
        }
        await new Promise((resolve) =>
          setTimeout(resolve, 20 * attempt + Math.floor(Math.random() * 20))
        );
      }
    }
    throw replayConflict();
  }
}

async function lockLifecycleManifest(
  tx: Prisma.TransactionClient,
  manifestId: string
): Promise<void> {
  const rows = await tx.$queryRaw<Array<{ id: string }>>`
    SELECT "id"
    FROM "SastRuleBundleManifest"
    WHERE "id" = ${manifestId}
    FOR UPDATE
  `;
  if (rows.length !== 1 || rows[0]?.id !== manifestId) {
    throw new SastRuleBundleLifecyclePersistenceError('MANIFEST_NOT_FOUND');
  }
}

async function assertEvidenceReferences(
  tx: Prisma.TransactionClient,
  evidence: Readonly<SastRuleBundlePromotionEvidence>
): Promise<void> {
  const [candidate, baseline] = await Promise.all([
    tx.sastRuleBundleManifest.findUnique({
      where: { id: evidence.manifestId },
      include: {
        supplyChainAttestation: true,
        compatibilityEntries: { where: { kind: 'PROFILE_ID' } }
      }
    }),
    tx.sastRuleBundleManifest.findUnique({
      where: { id: evidence.baselineManifestId },
      include: {
        supplyChainAttestation: true,
        compatibilityEntries: { where: { kind: 'PROFILE_ID' } }
      }
    })
  ]);
  if (!candidate || !baseline) {
    throw new SastRuleBundleLifecyclePersistenceError('MANIFEST_NOT_FOUND');
  }
  const verification = candidate.supplyChainAttestation;
  const baselineVerification = baseline.supplyChainAttestation;
  if (
    !verification ||
    !baselineVerification ||
    candidate.manifestDigest !== evidence.manifestDigest ||
    candidate.bundleId !== evidence.bundleId ||
    candidate.bundleDigest !== evidence.bundleDigest ||
    candidate.rollbackTargetDigest !== evidence.rollbackTargetDigest ||
    verification.id !== evidence.verificationId ||
    verification.attestationDigest !== evidence.verificationDigest ||
    baseline.manifestDigest !== evidence.baselineManifestDigest ||
    baseline.bundleId !== evidence.bundleId ||
    baseline.bundleDigest !== evidence.baselineBundleDigest ||
    baseline.scanner !== candidate.scanner ||
    !candidate.compatibilityEntries.some(
      (entry) => entry.value === evidence.profileId
    ) ||
    !baseline.compatibilityEntries.some(
      (entry) => entry.value === evidence.profileId
    ) ||
    evidence.rollbackTargetDigest !== baseline.bundleDigest ||
    evidence.measuredAt < candidate.builtAt.toISOString() ||
    evidence.measuredAt < verification.verifiedAt.toISOString() ||
    evidence.measuredAt < baseline.builtAt.toISOString() ||
    evidence.measuredAt < baselineVerification.verifiedAt.toISOString()
  ) {
    throw new SastRuleBundleLifecyclePersistenceError('REFERENCE_INVALID');
  }
}

async function assertTransitionReferences(
  tx: Prisma.TransactionClient,
  transition: Readonly<SastRuleBundleLifecycleTransition>
): Promise<void> {
  const [manifest, evidenceRow, approvalRows] = await Promise.all([
    tx.sastRuleBundleManifest.findUnique({ where: { id: transition.manifestId } }),
    tx.sastRuleBundlePromotionEvidence.findUnique({
      where: { id: transition.promotionEvidenceId }
    }),
    tx.sastRuleBundlePromotionApproval.findMany({
      where: {
        id: { in: transition.approvals.map((approval) => approval.approvalId) }
      }
    })
  ]);
  if (!manifest) {
    throw new SastRuleBundleLifecyclePersistenceError('MANIFEST_NOT_FOUND');
  }
  if (!evidenceRow) {
    throw new SastRuleBundleLifecyclePersistenceError('EVIDENCE_NOT_FOUND');
  }
  if (approvalRows.length !== transition.approvals.length) {
    throw new SastRuleBundleLifecyclePersistenceError('APPROVAL_NOT_FOUND');
  }
  const evidence = evidenceFromRow(evidenceRow);
  const approvals = approvalRows.map(approvalFromRow);
  if (
    manifest.manifestDigest !== transition.manifestDigest ||
    manifest.bundleId !== transition.bundleId ||
    manifest.bundleDigest !== transition.bundleDigest ||
    evidence.evidenceDigest !== transition.promotionEvidenceDigest ||
    evidence.manifestId !== transition.manifestId ||
    evidence.candidateAuthorRef !== transition.candidateAuthorRef ||
    Date.parse(evidence.measuredAt) > Date.parse(transition.transitionedAt) ||
    !transition.approvals.every((binding) =>
      approvals.some(
        (approval) =>
          approval.approvalId === binding.approvalId &&
          approval.approvalDigest === binding.approvalDigest &&
          approval.evidenceId === evidence.evidenceId &&
          approval.role === binding.role &&
          approval.approverRef === binding.approverRef &&
          approval.approvedAt === binding.approvedAt &&
          approval.approverRef !== evidence.candidateAuthorRef &&
          Date.parse(approval.approvedAt) <=
            Date.parse(transition.transitionedAt)
      )
    )
  ) {
    throw new SastRuleBundleLifecyclePersistenceError('REFERENCE_INVALID');
  }
}

function transitionExtendsLatest(
  transition: Readonly<SastRuleBundleLifecycleTransition>,
  latest: TransitionRow | null
): boolean {
  if (!latest) {
    return (
      transition.sequence === 1 &&
      transition.fromState === 'DRAFT' &&
      transition.previousTransitionId === null &&
      transition.previousTransitionDigest === null
    );
  }
  const previous = transitionFromRow(latest);
  return (
    transition.sequence === previous.sequence + 1 &&
    transition.fromState === previous.toState &&
    transition.previousTransitionId === previous.transitionId &&
    transition.previousTransitionDigest === previous.transitionDigest &&
    Date.parse(transition.transitionedAt) >= Date.parse(previous.transitionedAt)
  );
}

function evidenceData(
  evidence: Readonly<SastRuleBundlePromotionEvidence>
): Prisma.SastRuleBundlePromotionEvidenceUncheckedCreateInput {
  return {
    id: evidence.evidenceId,
    contractVersion: evidence.version,
    evidenceDigest: evidence.evidenceDigest,
    manifestId: evidence.manifestId,
    manifestDigest: evidence.manifestDigest,
    verificationId: evidence.verificationId,
    verificationDigest: evidence.verificationDigest,
    bundleId: evidence.bundleId,
    bundleDigest: evidence.bundleDigest,
    profileId: evidence.profileId,
    candidateAuthorRef: evidence.candidateAuthorRef,
    baselineManifestId: evidence.baselineManifestId,
    baselineManifestDigest: evidence.baselineManifestDigest,
    baselineBundleDigest: evidence.baselineBundleDigest,
    rollbackTargetDigest: evidence.rollbackTargetDigest,
    environmentRef: evidence.environmentRef,
    goldenCorpusRef: evidence.corpusReferences.goldenCorpusRef,
    priorMustDetectCorpusRef:
      evidence.corpusReferences.priorMustDetectCorpusRef,
    maliciousCorpusRef: evidence.corpusReferences.maliciousCorpusRef,
    parserCorpusRef: evidence.corpusReferences.parserCorpusRef,
    fingerprintCorpusRef: evidence.corpusReferences.fingerprintCorpusRef,
    coverageCorpusRef: evidence.corpusReferences.coverageCorpusRef,
    performanceCorpusRef: evidence.corpusReferences.performanceCorpusRef,
    corpusSetDigest: evidence.corpusSetDigest,
    ...evidence.measurements,
    measurementDigest: evidence.measurementDigest,
    measuredAt: new Date(evidence.measuredAt),
    gatesPassed: evidence.gatesPassed,
    automatedEvidenceOnly: evidence.automatedEvidenceOnly,
    approvalGranted: evidence.approvalGranted,
    customerInputAccepted: evidence.customerInputAccepted,
    executableRuleContentStored: evidence.executableRuleContentStored,
    repositoryContentStored: evidence.repositoryContentStored,
    secretValueStored: evidence.secretValueStored
  };
}

function approvalData(
  approval: Readonly<SastRuleBundlePromotionApproval>
): Prisma.SastRuleBundlePromotionApprovalUncheckedCreateInput {
  return {
    id: approval.approvalId,
    contractVersion: approval.version,
    approvalDigest: approval.approvalDigest,
    evidenceId: approval.evidenceId,
    evidenceDigest: approval.evidenceDigest,
    manifestId: approval.manifestId,
    manifestDigest: approval.manifestDigest,
    bundleDigest: approval.bundleDigest,
    candidateAuthorRef: approval.candidateAuthorRef,
    role: approval.role,
    approverRef: approval.approverRef,
    approvalRef: approval.approvalRef,
    approvedAt: new Date(approval.approvedAt),
    approved: approval.approved,
    humanApproval: approval.humanApproval,
    automatedApproval: approval.automatedApproval,
    customerInputAccepted: approval.customerInputAccepted
  };
}

function transitionData(
  transition: Readonly<SastRuleBundleLifecycleTransition>
): Prisma.SastRuleBundleLifecycleTransitionUncheckedCreateInput {
  return {
    id: transition.transitionId,
    contractVersion: transition.version,
    transitionDigest: transition.transitionDigest,
    manifestId: transition.manifestId,
    manifestDigest: transition.manifestDigest,
    bundleId: transition.bundleId,
    bundleDigest: transition.bundleDigest,
    sequence: transition.sequence,
    fromState: transition.fromState,
    toState: transition.toState,
    previousTransitionId: transition.previousTransitionId,
    previousTransitionDigest: transition.previousTransitionDigest,
    promotionEvidenceId: transition.promotionEvidenceId,
    promotionEvidenceDigest: transition.promotionEvidenceDigest,
    candidateAuthorRef: transition.candidateAuthorRef,
    approvalSetDigest: transition.approvalSetDigest,
    externalAuthority: transition.externalAuthority,
    externalAuthorityReceiptRef: transition.externalAuthorityReceiptRef,
    externalAuthorityReceiptDigest:
      transition.externalAuthorityReceiptDigest,
    actorRef: transition.actorRef,
    reasonRef: transition.reasonRef,
    auditRef: transition.auditRef,
    transitionedAt: new Date(transition.transitionedAt),
    source: transition.source,
    immutable: transition.immutable,
    customerInputAccepted: transition.customerInputAccepted,
    executableRuleContentStored: transition.executableRuleContentStored,
    repositoryContentStored: transition.repositoryContentStored,
    secretValueStored: transition.secretValueStored,
    approvals: {
      create: transition.approvals.map((approval, position) => ({
        position,
        approvalId: approval.approvalId,
        approvalDigest: approval.approvalDigest,
        role: approval.role,
        approverRef: approval.approverRef,
        approvedAt: new Date(approval.approvedAt)
      }))
    }
  };
}

function selectionData(
  receipt: Readonly<SastRuleBundleLifecycleSelectionReceipt>
): Prisma.SastRuleBundleLifecycleSelectionReceiptUncheckedCreateInput {
  return {
    id: receipt.receiptId,
    contractVersion: receipt.version,
    receiptDigest: receipt.receiptDigest,
    manifestId: receipt.manifestId,
    manifestDigest: receipt.manifestDigest,
    bundleId: receipt.bundleId,
    bundleDigest: receipt.bundleDigest,
    lifecycleState: receipt.lifecycleState,
    lifecycleSequence: receipt.lifecycleSequence,
    transitionId: receipt.transitionId,
    transitionDigest: receipt.transitionDigest,
    promotionEvidenceId: receipt.promotionEvidenceId,
    promotionEvidenceDigest: receipt.promotionEvidenceDigest,
    approvalSetDigest: receipt.approvalSetDigest,
    evaluatedAt: new Date(receipt.evaluatedAt),
    selectable: receipt.selectable,
    latestTransitionVerified: receipt.latestTransitionVerified,
    approvalSeparationVerified: receipt.approvalSeparationVerified,
    customerInputAccepted: receipt.customerInputAccepted,
    executableRuleContentStored: receipt.executableRuleContentStored
  };
}

function evidenceFromRow(row: EvidenceRow): SastRuleBundlePromotionEvidence {
  const evidence: SastRuleBundlePromotionEvidence = {
    version:
      row.contractVersion as SastRuleBundlePromotionEvidence['version'],
    evidenceId: row.id,
    evidenceDigest: row.evidenceDigest as `sha256:${string}`,
    manifestId: row.manifestId,
    manifestDigest: row.manifestDigest as `sha256:${string}`,
    verificationId: row.verificationId,
    verificationDigest: row.verificationDigest as `sha256:${string}`,
    bundleId: row.bundleId,
    bundleDigest: row.bundleDigest as `sha256:${string}`,
    profileId: row.profileId as SastRuleBundlePromotionEvidence['profileId'],
    candidateAuthorRef: row.candidateAuthorRef,
    baselineManifestId: row.baselineManifestId,
    baselineManifestDigest:
      row.baselineManifestDigest as `sha256:${string}`,
    baselineBundleDigest: row.baselineBundleDigest as `sha256:${string}`,
    rollbackTargetDigest: row.rollbackTargetDigest as `sha256:${string}`,
    environmentRef: row.environmentRef,
    corpusReferences: {
      goldenCorpusRef: row.goldenCorpusRef,
      priorMustDetectCorpusRef: row.priorMustDetectCorpusRef,
      maliciousCorpusRef: row.maliciousCorpusRef,
      parserCorpusRef: row.parserCorpusRef,
      fingerprintCorpusRef: row.fingerprintCorpusRef,
      coverageCorpusRef: row.coverageCorpusRef,
      performanceCorpusRef: row.performanceCorpusRef
    },
    corpusSetDigest: row.corpusSetDigest as `sha256:${string}`,
    measurements: {
      positiveCases: row.positiveCases,
      negativeCases: row.negativeCases,
      performanceRuns: row.performanceRuns,
      goldenPassedCases: row.goldenPassedCases,
      goldenTotalCases: row.goldenTotalCases,
      priorMustDetectPassedCases: row.priorMustDetectPassedCases,
      priorMustDetectTotalCases: row.priorMustDetectTotalCases,
      mustDetectTruePositiveCases: row.mustDetectTruePositiveCases,
      mustDetectExpectedCases: row.mustDetectExpectedCases,
      criticalHighTruePositiveCases: row.criticalHighTruePositiveCases,
      criticalHighReportedCases: row.criticalHighReportedCases,
      maliciousPassedCases: row.maliciousPassedCases,
      maliciousTotalCases: row.maliciousTotalCases,
      parserRejectedCases: row.parserRejectedCases,
      parserExpectedRejectCases: row.parserExpectedRejectCases,
      fingerprintPassedCases: row.fingerprintPassedCases,
      fingerprintTotalCases: row.fingerprintTotalCases,
      coveragePassedCases: row.coveragePassedCases,
      coverageTotalCases: row.coverageTotalCases,
      falsePositiveIncreaseBasisPoints:
        row.falsePositiveIncreaseBasisPoints,
      scannerFailureRateBasisPoints: row.scannerFailureRateBasisPoints,
      p95LatencyIncreaseBasisPoints: row.p95LatencyIncreaseBasisPoints,
      candidateP95LatencyMilliseconds:
        row.candidateP95LatencyMilliseconds,
      crossTenantEvents: row.crossTenantEvents,
      secretLeakEvents: row.secretLeakEvents,
      sandboxEscapeEvents: row.sandboxEscapeEvents,
      stalePublicationEvents: row.stalePublicationEvents
    },
    measurementDigest: row.measurementDigest as `sha256:${string}`,
    measuredAt: row.measuredAt.toISOString(),
    gatesPassed: row.gatesPassed as true,
    automatedEvidenceOnly: row.automatedEvidenceOnly as true,
    approvalGranted: row.approvalGranted as false,
    customerInputAccepted: row.customerInputAccepted as false,
    executableRuleContentStored: row.executableRuleContentStored as false,
    repositoryContentStored: row.repositoryContentStored as false,
    secretValueStored: row.secretValueStored as false
  };
  assertEvidenceValid(evidence, 'LEDGER_CORRUPT');
  return evidence;
}

function approvalFromRow(row: ApprovalRow): SastRuleBundlePromotionApproval {
  const approval: SastRuleBundlePromotionApproval = {
    version:
      row.contractVersion as SastRuleBundlePromotionApproval['version'],
    approvalId: row.id,
    approvalDigest: row.approvalDigest as `sha256:${string}`,
    evidenceId: row.evidenceId,
    evidenceDigest: row.evidenceDigest as `sha256:${string}`,
    manifestId: row.manifestId,
    manifestDigest: row.manifestDigest as `sha256:${string}`,
    bundleDigest: row.bundleDigest as `sha256:${string}`,
    candidateAuthorRef: row.candidateAuthorRef,
    role: row.role as SastRuleBundlePromotionApproval['role'],
    approverRef: row.approverRef,
    approvalRef: row.approvalRef,
    approvedAt: row.approvedAt.toISOString(),
    approved: row.approved as true,
    humanApproval: row.humanApproval as true,
    automatedApproval: row.automatedApproval as false,
    customerInputAccepted: row.customerInputAccepted as false
  };
  assertApprovalValid(approval, 'LEDGER_CORRUPT');
  return approval;
}

function transitionFromRow(
  row: TransitionRow
): SastRuleBundleLifecycleTransition {
  const transition: SastRuleBundleLifecycleTransition = {
    version:
      row.contractVersion as SastRuleBundleLifecycleTransition['version'],
    transitionId: row.id,
    transitionDigest: row.transitionDigest as `sha256:${string}`,
    manifestId: row.manifestId,
    manifestDigest: row.manifestDigest as `sha256:${string}`,
    bundleId: row.bundleId,
    bundleDigest: row.bundleDigest as `sha256:${string}`,
    sequence: row.sequence,
    fromState: row.fromState as SastRuleBundleLifecycleTransition['fromState'],
    toState: row.toState as SastRuleBundleLifecycleTransition['toState'],
    previousTransitionId: row.previousTransitionId,
    previousTransitionDigest:
      row.previousTransitionDigest as `sha256:${string}` | null,
    promotionEvidenceId: row.promotionEvidenceId,
    promotionEvidenceDigest:
      row.promotionEvidenceDigest as `sha256:${string}`,
    candidateAuthorRef: row.candidateAuthorRef,
    approvals: row.approvals.map((binding) => ({
      approvalId: binding.approvalId,
      approvalDigest: binding.approvalDigest as `sha256:${string}`,
      role: binding.role as SastRuleBundlePromotionApproval['role'],
      approverRef: binding.approverRef,
      approvedAt: binding.approvedAt.toISOString()
    })),
    approvalSetDigest: row.approvalSetDigest as `sha256:${string}`,
    externalAuthority:
      row.externalAuthority as SastRuleBundleLifecycleTransition['externalAuthority'],
    externalAuthorityReceiptRef: row.externalAuthorityReceiptRef,
    externalAuthorityReceiptDigest:
      row.externalAuthorityReceiptDigest as `sha256:${string}` | null,
    actorRef: row.actorRef,
    reasonRef: row.reasonRef,
    auditRef: row.auditRef,
    transitionedAt: row.transitionedAt.toISOString(),
    source: row.source as 'PLATFORM_RULE_GOVERNANCE',
    immutable: row.immutable as true,
    customerInputAccepted: row.customerInputAccepted as false,
    executableRuleContentStored: row.executableRuleContentStored as false,
    repositoryContentStored: row.repositoryContentStored as false,
    secretValueStored: row.secretValueStored as false
  };
  assertTransitionValid(transition, 'LEDGER_CORRUPT');
  return transition;
}

function selectionFromRow(
  row: SelectionRow
): SastRuleBundleLifecycleSelectionReceipt {
  const receipt: SastRuleBundleLifecycleSelectionReceipt = {
    version:
      row.contractVersion as SastRuleBundleLifecycleSelectionReceipt['version'],
    receiptId: row.id,
    receiptDigest: row.receiptDigest as `sha256:${string}`,
    manifestId: row.manifestId,
    manifestDigest: row.manifestDigest as `sha256:${string}`,
    bundleId: row.bundleId,
    bundleDigest: row.bundleDigest as `sha256:${string}`,
    lifecycleState:
      row.lifecycleState as SastRuleBundleLifecycleSelectionReceipt['lifecycleState'],
    lifecycleSequence: row.lifecycleSequence,
    transitionId: row.transitionId,
    transitionDigest: row.transitionDigest as `sha256:${string}`,
    promotionEvidenceId: row.promotionEvidenceId,
    promotionEvidenceDigest:
      row.promotionEvidenceDigest as `sha256:${string}`,
    approvalSetDigest: row.approvalSetDigest as `sha256:${string}`,
    evaluatedAt: row.evaluatedAt.toISOString(),
    selectable: row.selectable as true,
    latestTransitionVerified: row.latestTransitionVerified as true,
    approvalSeparationVerified: row.approvalSeparationVerified as true,
    customerInputAccepted: row.customerInputAccepted as false,
    executableRuleContentStored: row.executableRuleContentStored as false
  };
  assertSelectionValid(receipt, 'LEDGER_CORRUPT');
  return receipt;
}

function snapshotFromRow(
  row: TransitionRow
): SastRuleBundleLifecycleLedgerSnapshot {
  const transition = transitionFromRow(row);
  const evidence = evidenceFromRow(row.promotionEvidence);
  const approvals = row.approvals.map((binding) =>
    approvalFromRow(binding.approval)
  );
  if (
    transition.promotionEvidenceId !== evidence.evidenceId ||
    transition.promotionEvidenceDigest !== evidence.evidenceDigest ||
    transition.approvals.length !== approvals.length ||
    !transition.approvals.every((binding) =>
      approvals.some(
        (approval) =>
          binding.approvalId === approval.approvalId &&
          binding.approvalDigest === approval.approvalDigest &&
          binding.role === approval.role &&
          binding.approverRef === approval.approverRef &&
          binding.approvedAt === approval.approvedAt
      )
    )
  ) {
    throw new SastRuleBundleLifecyclePersistenceError('LEDGER_CORRUPT');
  }
  return { transition, evidence, approvals };
}

function replayEvidence(
  row: EvidenceRow,
  expected: Readonly<SastRuleBundlePromotionEvidence>,
  replayed = true
): PersistedSastRuleBundlePromotionEvidence {
  const evidence = evidenceFromRow(row);
  if (evidence.evidenceDigest !== expected.evidenceDigest) {
    throw replayConflict();
  }
  return { evidence, replayed };
}

function replayApproval(
  row: ApprovalRow,
  expected: Readonly<SastRuleBundlePromotionApproval>,
  replayed = true
): PersistedSastRuleBundlePromotionApproval {
  const approval = approvalFromRow(row);
  if (approval.approvalDigest !== expected.approvalDigest) {
    throw replayConflict();
  }
  return { approval, replayed };
}

function replayTransition(
  row: TransitionRow,
  expected: Readonly<SastRuleBundleLifecycleTransition>,
  replayed = true
): PersistedSastRuleBundleLifecycleTransition {
  const transition = transitionFromRow(row);
  if (transition.transitionDigest !== expected.transitionDigest) {
    throw replayConflict();
  }
  return { transition, replayed };
}

function replaySelection(
  row: SelectionRow,
  expected: Readonly<SastRuleBundleLifecycleSelectionReceipt>,
  replayed = true
): PersistedSastRuleBundleLifecycleSelection {
  const receipt = selectionFromRow(row);
  if (receipt.receiptDigest !== expected.receiptDigest) {
    throw replayConflict();
  }
  return { receipt, replayed };
}

function approvalBoundToEvidence(
  approval: Readonly<SastRuleBundlePromotionApproval>,
  evidence: Readonly<SastRuleBundlePromotionEvidence>
): boolean {
  return (
    approval.evidenceId === evidence.evidenceId &&
    approval.evidenceDigest === evidence.evidenceDigest &&
    approval.manifestId === evidence.manifestId &&
    approval.manifestDigest === evidence.manifestDigest &&
    approval.bundleDigest === evidence.bundleDigest &&
    approval.candidateAuthorRef === evidence.candidateAuthorRef &&
    approval.approverRef !== evidence.candidateAuthorRef &&
    Date.parse(approval.approvedAt) >= Date.parse(evidence.measuredAt)
  );
}

function selectionMatchesLatest(
  receipt: Readonly<SastRuleBundleLifecycleSelectionReceipt>,
  transition: Readonly<SastRuleBundleLifecycleTransition>
): boolean {
  return (
    receipt.transitionId === transition.transitionId &&
    receipt.transitionDigest === transition.transitionDigest &&
    receipt.manifestId === transition.manifestId &&
    receipt.manifestDigest === transition.manifestDigest &&
    receipt.bundleId === transition.bundleId &&
    receipt.bundleDigest === transition.bundleDigest &&
    receipt.lifecycleSequence === transition.sequence &&
    receipt.lifecycleState === transition.toState &&
    receipt.promotionEvidenceId === transition.promotionEvidenceId &&
    receipt.promotionEvidenceDigest === transition.promotionEvidenceDigest &&
    receipt.approvalSetDigest === transition.approvalSetDigest &&
    Date.parse(receipt.evaluatedAt) >= Date.parse(transition.transitionedAt)
  );
}

function assertEvidenceValid(
  evidence: Readonly<SastRuleBundlePromotionEvidence>,
  reason: 'INPUT_INVALID' | 'LEDGER_CORRUPT' = 'INPUT_INVALID'
): void {
  if (
    !isSastRuleBundlePromotionEvidenceShapeValid(
      evidence,
      digestSastRuleBundleCanonical
    )
  ) {
    throw new SastRuleBundleLifecyclePersistenceError(reason);
  }
}

function assertApprovalValid(
  approval: Readonly<SastRuleBundlePromotionApproval>,
  reason: 'INPUT_INVALID' | 'LEDGER_CORRUPT' = 'INPUT_INVALID'
): void {
  if (
    !isSastRuleBundlePromotionApprovalShapeValid(
      approval,
      digestSastRuleBundleCanonical
    )
  ) {
    throw new SastRuleBundleLifecyclePersistenceError(reason);
  }
}

function assertTransitionValid(
  transition: Readonly<SastRuleBundleLifecycleTransition>,
  reason: 'INPUT_INVALID' | 'LEDGER_CORRUPT' = 'INPUT_INVALID'
): void {
  if (
    !isSastRuleBundleLifecycleTransitionShapeValid(
      transition,
      digestSastRuleBundleCanonical
    )
  ) {
    throw new SastRuleBundleLifecyclePersistenceError(reason);
  }
}

function assertSelectionValid(
  receipt: Readonly<SastRuleBundleLifecycleSelectionReceipt>,
  reason: 'INPUT_INVALID' | 'LEDGER_CORRUPT' = 'INPUT_INVALID'
): void {
  if (
    !isSastRuleBundleLifecycleSelectionReceiptShapeValid(
      receipt,
      digestSastRuleBundleCanonical
    )
  ) {
    throw new SastRuleBundleLifecyclePersistenceError(reason);
  }
}

function compareApprovalsByRole(
  left: Readonly<SastRuleBundlePromotionApproval>,
  right: Readonly<SastRuleBundlePromotionApproval>
): number {
  const order = {
    SECURITY_ENGINEERING: 0,
    SCAN_PLATFORM: 1,
    SECURITY_OPERATIONS: 2
  } as const;
  return order[left.role] - order[right.role];
}

function replayConflict(): SastRuleBundleLifecyclePersistenceError {
  return new SastRuleBundleLifecyclePersistenceError('REPLAY_CONFLICT');
}

function mapPrismaError(error: unknown): unknown {
  if (error instanceof SastRuleBundleLifecyclePersistenceError) return error;
  if (
    error instanceof Prisma.PrismaClientKnownRequestError &&
    error.code === 'P2003'
  ) {
    return new SastRuleBundleLifecyclePersistenceError('REFERENCE_INVALID');
  }
  return error;
}

function isSerializableConflict(error: unknown): boolean {
  return (
    error instanceof Prisma.PrismaClientKnownRequestError &&
    error.code === 'P2034'
  );
}

function isUniqueConflict(error: unknown): boolean {
  return (
    error instanceof Prisma.PrismaClientKnownRequestError &&
    error.code === 'P2002'
  );
}
