import { createHash } from 'node:crypto';

import {
  SAST_APPROVED_PROFILE_DIGESTS,
  SAST_KILL_SWITCH_GATES,
  SAST_SCANNER_KINDS,
  buildApplicableSastKillSwitchSelectors,
  buildSastKillSwitchEmergencySuspensionReceipt,
  buildSastKillSwitchHeadBinding,
  buildSastKillSwitchSelectorKey,
  buildSastKillSwitchEvaluation,
  isSastKillSwitchDecisionShapeValid,
  isSastKillSwitchEmergencySuspensionReceiptValid,
  isSastKillSwitchEvaluationContextValid,
  isSastKillSwitchEvaluationReceiptValid,
  isSastKillSwitchHeadBindingValid,
  isSastKillSwitchSelectorValid,
  isSastKillSwitchVerificationShapeValid,
  isSastScanPlanValid,
  type SastKillSwitchControlDecision,
  type SastKillSwitchEmergencySuspensionReceipt,
  type SastKillSwitchEvaluationContext,
  type SastKillSwitchEvaluationMatch,
  type SastKillSwitchEvaluationReceipt,
  type SastKillSwitchEvaluationResult,
  type SastKillSwitchGate,
  type SastKillSwitchHeadBinding,
  type SastKillSwitchSelector,
  type SastKillSwitchVerification,
  type SastProfileId,
  type SastScanPlan,
  type SastScannerKind
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';

import { PrismaService } from '../prisma/prisma.service';
import type { SastRuleBundleLifecycleAuthorityInput } from './sast-rule-bundle-lifecycle.authority';
import {
  SastKillSwitchPersistenceError,
  SastKillSwitchStore,
  type PersistedSastKillSwitchDecision,
  type SastKillSwitchPersistedPlanScope
} from './sast-kill-switch.store';

const SERIALIZABLE_RETRIES = 3;
const SERIALIZABLE_MAX_WAIT_MILLISECONDS = 5_000;
const SERIALIZABLE_TIMEOUT_MILLISECONDS = 120_000;
const HEAD_INSERT_CHUNK_SIZE = 500;

type DecisionRow = Prisma.SastKillSwitchDecisionGetPayload<Record<string, never>>;
type VerificationRow =
  Prisma.SastKillSwitchVerificationGetPayload<Record<string, never>>;
type HeadRow = Prisma.SastKillSwitchHeadGetPayload<Record<string, never>>;
type EvaluationRow =
  Prisma.SastKillSwitchEvaluationGetPayload<Record<string, never>>;
type EvaluationHeadRow =
  Prisma.SastKillSwitchEvaluationHeadGetPayload<Record<string, never>>;
type EvaluationMatchRow =
  Prisma.SastKillSwitchEvaluationMatchGetPayload<Record<string, never>>;
type SuspensionRow =
  Prisma.SastKillSwitchEmergencySuspensionReceiptGetPayload<Record<string, never>>;

interface LifecycleHeadRow {
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
}

interface KeyedSelector {
  selectorKey: string;
  selector: SastKillSwitchSelector;
}

@Injectable()
export class PrismaSastKillSwitchStore extends SastKillSwitchStore {
  constructor(private readonly prisma: PrismaService) {
    super();
  }

  async appendDecision(
    decision: Readonly<SastKillSwitchControlDecision>,
    verification: Readonly<SastKillSwitchVerification>
  ): Promise<PersistedSastKillSwitchDecision> {
    assertDecisionValid(decision);
    assertVerificationValid(verification);
    if (
      verification.decisionId !== decision.decisionId ||
      verification.decisionDigest !== decision.decisionDigest ||
      verification.selectorKey !== decision.selectorKey ||
      verification.signatureRef !== decision.signatureRef ||
      verification.provenanceRef !== decision.provenanceRef ||
      Date.parse(verification.verifiedAt) < Date.parse(decision.effectiveAt)
    ) {
      throw persistenceError('INPUT_INVALID');
    }

    try {
      return await this.runSerializable(async (tx) => {
        const existing = await tx.sastKillSwitchDecision.findUnique({
          where: { id: decision.decisionId }
        });
        if (existing) {
          const existingVerification =
            await tx.sastKillSwitchVerification.findUnique({
              where: { decisionId: decision.decisionId }
            });
          return replayDecision(
            existing,
            existingVerification,
            decision,
            verification
          );
        }

        const keyed: KeyedSelector = {
          selectorKey: decision.selectorKey,
          selector: decision.selector
        };
        await ensureHeadPlaceholders(tx, [keyed]);
        const [head] = await lockHeads(tx, [decision.selectorKey]);
        if (!head || !headMatchesSelector(head, keyed)) {
          throw persistenceError('LEDGER_CORRUPT');
        }
        assertDecisionExtendsHead(decision, head);

        const createdDecision = await tx.sastKillSwitchDecision.create({
          data: decisionData(decision)
        });
        const createdVerification =
          await tx.sastKillSwitchVerification.create({
            data: verificationData(verification)
          });
        return replayDecision(
          createdDecision,
          createdVerification,
          decision,
          verification,
          false
        );
      });
    } catch (error) {
      if (!isUniqueConflict(error)) throw mapPersistenceError(error);
      const [existing, existingVerification] = await Promise.all([
        this.prisma.sastKillSwitchDecision.findUnique({
          where: { id: decision.decisionId }
        }),
        this.prisma.sastKillSwitchVerification.findUnique({
          where: { decisionId: decision.decisionId }
        })
      ]);
      if (!existing) throw persistenceError('REPLAY_CONFLICT');
      return replayDecision(
        existing,
        existingVerification,
        decision,
        verification
      );
    }
  }

  async evaluate(
    context: Readonly<SastKillSwitchEvaluationContext>,
    gate: SastKillSwitchGate,
    evaluatedAt: string
  ): Promise<SastKillSwitchEvaluationResult> {
    if (
      !isSastKillSwitchEvaluationContextValid(context, digest) ||
      !SAST_KILL_SWITCH_GATES.includes(gate) ||
      !isCanonicalTimestamp(evaluatedAt)
    ) {
      throw persistenceError('INPUT_INVALID');
    }
    const selectors = buildApplicableSastKillSwitchSelectors(
      context,
      gate,
      digest
    );
    if (selectors.length === 0) throw persistenceError('INPUT_INVALID');

    try {
      return await this.runSerializable(async (tx) => {
        await ensureHeadPlaceholders(tx, selectors);
        const rows = await lockHeads(
          tx,
          selectors.map((entry) => entry.selectorKey)
        );
        const heads = buildBoundHeads(rows, selectors, evaluatedAt);
        const evaluation = buildSastKillSwitchEvaluation(
          { context, gate, heads, evaluatedAt },
          digest
        );
        if (!evaluation) {
          throw persistenceError('ACTIVE_DECISION_EXPIRED');
        }

        const existing = await tx.sastKillSwitchEvaluation.findUnique({
          where: { id: evaluation.receipt.evaluationId }
        });
        if (existing) {
          return replayEvaluation(tx, existing, evaluation);
        }

        await tx.sastKillSwitchEvaluation.create({
          data: evaluationData(evaluation.receipt)
        });
        await tx.sastKillSwitchEvaluationHead.createMany({
          data: evaluation.heads.map((head, position) =>
            evaluationHeadData(evaluation.receipt.evaluationId, position, head)
          )
        });
        if (evaluation.matches.length > 0) {
          await tx.sastKillSwitchEvaluationMatch.createMany({
            data: evaluation.matches.map((match, position) =>
              evaluationMatchData(
                evaluation.receipt.evaluationId,
                position,
                match
              )
            )
          });
        }
        return { ...evaluation, replayed: false };
      });
    } catch (error) {
      if (!isUniqueConflict(error)) throw mapPersistenceError(error);
      const candidate = buildReplayCandidate(context, gate, evaluatedAt);
      if (!candidate) throw persistenceError('REPLAY_CONFLICT');
      return this.runSerializable(async (tx) => {
        await ensureHeadPlaceholders(tx, selectors);
        const rows = await lockHeads(
          tx,
          selectors.map((entry) => entry.selectorKey)
        );
        const heads = buildBoundHeads(rows, selectors, evaluatedAt);
        const evaluation = buildSastKillSwitchEvaluation(
          { context, gate, heads, evaluatedAt },
          digest
        );
        if (!evaluation) throw persistenceError('ACTIVE_DECISION_EXPIRED');
        const existing = await tx.sastKillSwitchEvaluation.findUnique({
          where: { id: evaluation.receipt.evaluationId }
        });
        if (!existing) throw persistenceError('REPLAY_CONFLICT');
        return replayEvaluation(tx, existing, evaluation);
      });
    }
  }

  async loadPersistedPlan(
    scope: Readonly<SastKillSwitchPersistedPlanScope>
  ): Promise<SastScanPlan | null> {
    if (
      !isBounded(scope?.tenantId) ||
      !isBounded(scope?.repositoryBindingId) ||
      !isBounded(scope?.scanRequestId)
    ) {
      throw persistenceError('INPUT_INVALID');
    }
    const row = await this.prisma.sastQueueReservation.findUnique({
      where: { scanRequestId: scope.scanRequestId },
      select: {
        tenantId: true,
        repositoryBindingId: true,
        immutablePlan: true
      }
    });
    if (!row) return null;
    if (
      row.tenantId !== scope.tenantId ||
      row.repositoryBindingId !== scope.repositoryBindingId
    ) {
      throw persistenceError('PLAN_SCOPE_MISMATCH');
    }
    const plan = structuredClone(row.immutablePlan) as unknown as SastScanPlan;
    if (!isSastScanPlanValid(plan)) throw persistenceError('LEDGER_CORRUPT');
    return plan;
  }

  async authorizeEmergencySuspension(
    input: Readonly<SastRuleBundleLifecycleAuthorityInput>,
    verifiedAt: string
  ): Promise<SastKillSwitchEmergencySuspensionReceipt> {
    if (
      input?.authority !== 'EMERGENCY_SUSPENSION' ||
      (input.fromState !== 'CANARY' && input.fromState !== 'ACTIVE') ||
      input.toState !== 'SUSPENDED' ||
      !isCanonicalTimestamp(input.requestedAt) ||
      !isCanonicalTimestamp(verifiedAt) ||
      verifiedAt !== input.requestedAt
    ) {
      throw persistenceError('INPUT_INVALID');
    }

    try {
      return await this.runSerializable(async (tx) => {
        const lifecycleRows = await tx.$queryRaw<LifecycleHeadRow[]>`
          SELECT
            "manifestId", "manifestDigest", "bundleId", "bundleDigest",
            "transitionId", "transitionDigest", "sequence", "lifecycleState",
            "promotionEvidenceId", "promotionEvidenceDigest"
          FROM "SastRuleBundleLifecycleHead"
          WHERE "manifestId" = ${input.manifestId}
          FOR UPDATE
        `;
        const lifecycle = lifecycleRows[0];
        if (!lifecycle) throw persistenceError('LIFECYCLE_NOT_FOUND');
        if (!lifecycleMatchesInput(lifecycle, input)) {
          throw persistenceError('LIFECYCLE_SCOPE_MISMATCH');
        }

        const manifest = await tx.sastRuleBundleManifest.findUnique({
          where: { id: input.manifestId },
          include: {
            rules: { orderBy: { position: 'asc' } },
            compatibilityEntries: {
              where: { kind: { in: ['SCANNER_VERSION', 'PROFILE_ID'] } },
              orderBy: [{ kind: 'asc' }, { position: 'asc' }]
            }
          }
        });
        if (
          !manifest ||
          manifest.manifestDigest !== input.manifestDigest ||
          manifest.bundleId !== input.bundleId ||
          manifest.bundleDigest !== input.bundleDigest ||
          !SAST_SCANNER_KINDS.includes(manifest.scanner as SastScannerKind)
        ) {
          throw persistenceError('LIFECYCLE_SCOPE_MISMATCH');
        }

        const selectors = suspensionSelectors(manifest);
        await ensureHeadPlaceholders(tx, selectors);
        const rows = await lockHeads(
          tx,
          selectors.map((entry) => entry.selectorKey)
        );
        const verifiedMilliseconds = Date.parse(verifiedAt);
        if (
          rows.some(
            (head) =>
              head.active &&
              (!head.effectiveAt ||
                !head.expiresAt ||
                head.effectiveAt.getTime() > verifiedMilliseconds ||
                head.expiresAt.getTime() <= verifiedMilliseconds)
          )
        ) {
          throw persistenceError('AUTHORITY_UNAVAILABLE');
        }
        const active = rows
          .filter((head) => head.active)
          .sort((left, right) => compare(left.selectorKey, right.selectorKey));
        if (active.length === 0) {
          throw persistenceError('NO_ACTIVE_SUSPENSION_DECISION');
        }
        const trigger = active[0]!;
        if (!trigger.currentDecisionId || !trigger.currentDecisionDigest) {
          throw persistenceError('LEDGER_CORRUPT');
        }

        const activeDecisionSetDigest = digest(
          canonicalJson(
            active.map((head) => ({
              selectorKey: head.selectorKey,
              decisionId: head.currentDecisionId,
              decisionDigest: head.currentDecisionDigest
            }))
          )
        );
        const receipt = buildSastKillSwitchEmergencySuspensionReceipt({
          manifestId: input.manifestId,
          manifestDigest: input.manifestDigest,
          bundleId: input.bundleId,
          bundleDigest: input.bundleDigest,
          fromState: lifecycle.lifecycleState as 'CANARY' | 'ACTIVE',
          toState: 'SUSPENDED',
          lifecycleSequence: lifecycle.sequence,
          lifecycleTransitionId: lifecycle.transitionId,
          lifecycleTransitionDigest: asDigest(lifecycle.transitionDigest),
          promotionEvidenceId: input.promotionEvidenceId,
          promotionEvidenceDigest: input.promotionEvidenceDigest,
          triggerSelectorKey: trigger.selectorKey,
          triggerDecisionId: trigger.currentDecisionId,
          triggerDecisionDigest: asDigest(trigger.currentDecisionDigest),
          activeDecisionCount: active.length,
          activeDecisionSetDigest,
          requestedAt: input.requestedAt,
          verifiedAt
        }, digest);
        if (
          !receipt ||
          !isSastKillSwitchEmergencySuspensionReceiptValid(receipt, digest)
        ) {
          throw persistenceError('LEDGER_CORRUPT');
        }

        const existing =
          await tx.sastKillSwitchEmergencySuspensionReceipt.findUnique({
            where: { id: receipt.receiptId }
          });
        if (existing) return replaySuspension(existing, receipt);
        const created =
          await tx.sastKillSwitchEmergencySuspensionReceipt.create({
            data: suspensionData(receipt)
          });
        return replaySuspension(created, receipt);
      });
    } catch (error) {
      throw mapPersistenceError(error);
    }
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
          throw error;
        }
        await new Promise((resolve) =>
          setTimeout(resolve, 20 * attempt + Math.floor(Math.random() * 20))
        );
      }
    }
    throw persistenceError('AUTHORITY_UNAVAILABLE');
  }
}

async function ensureHeadPlaceholders(
  tx: Prisma.TransactionClient,
  selectors: readonly KeyedSelector[]
): Promise<void> {
  await tx.$queryRaw<Array<{ set_config: string }>>`
    SELECT set_config('aegis.kill_switch_head_writer', 'on', TRUE)
  `;
  for (let offset = 0; offset < selectors.length; offset += HEAD_INSERT_CHUNK_SIZE) {
    const chunk = selectors.slice(offset, offset + HEAD_INSERT_CHUNK_SIZE);
    const values = chunk.map((entry) => {
      const columns = selectorColumns(entry.selector);
      return Prisma.sql`(
        ${entry.selectorKey}, ${entry.selector.scope}, ${columns.runtime},
        ${columns.scanner}, ${columns.scannerVersion}, ${columns.bundleDigest},
        ${columns.ruleSemanticId}, ${columns.profileId}, ${columns.profileDigest},
        ${columns.tenantId}, ${columns.repositoryBindingId}, ${columns.capability},
        ${columns.publicationTargetScope}, 0, FALSE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
      )`;
    });
    await tx.$executeRaw(Prisma.sql`
      INSERT INTO "SastKillSwitchHead" (
        "selectorKey", "scope", "runtime", "scanner", "scannerVersion",
        "bundleDigest", "ruleSemanticId", "profileId", "profileDigest",
        "tenantId", "repositoryBindingId", "capability",
        "publicationTargetScope", "sequence", "active", "createdAt", "updatedAt"
      ) VALUES ${Prisma.join(values)}
      ON CONFLICT ("selectorKey") DO NOTHING
    `);
  }
}

async function lockHeads(
  tx: Prisma.TransactionClient,
  selectorKeys: readonly string[]
): Promise<HeadRow[]> {
  if (selectorKeys.length === 0) return [];
  return tx.$queryRaw<HeadRow[]>(Prisma.sql`
    SELECT *
    FROM "SastKillSwitchHead"
    WHERE "selectorKey" IN (${Prisma.join(selectorKeys)})
    ORDER BY "selectorKey"
    FOR UPDATE
  `);
}

function buildBoundHeads(
  rows: readonly HeadRow[],
  selectors: readonly KeyedSelector[],
  evaluatedAt: string
): SastKillSwitchHeadBinding[] {
  if (rows.length !== selectors.length) throw persistenceError('LEDGER_CORRUPT');
  const selectorByKey = new Map(
    selectors.map((entry) => [entry.selectorKey, entry] as const)
  );
  const evaluatedMilliseconds = Date.parse(evaluatedAt);
  return rows.map((row) => {
    const selector = selectorByKey.get(row.selectorKey);
    if (!selector || !headMatchesSelector(row, selector)) {
      throw persistenceError('LEDGER_CORRUPT');
    }
    if (
      row.active &&
      (!row.effectiveAt ||
        !row.expiresAt ||
        row.effectiveAt.getTime() > evaluatedMilliseconds ||
        row.expiresAt.getTime() <= evaluatedMilliseconds)
    ) {
      throw persistenceError('ACTIVE_DECISION_EXPIRED');
    }
    const binding = buildSastKillSwitchHeadBinding(
      {
        selectorKey: row.selectorKey,
        scope: row.scope as SastKillSwitchSelector['scope'],
        sequence: row.sequence,
        decisionId: row.currentDecisionId,
        decisionDigest: row.currentDecisionDigest
          ? asDigest(row.currentDecisionDigest)
          : null,
        action: row.currentAction as SastKillSwitchHeadBinding['action'],
        active: row.active,
        effectiveAt: row.effectiveAt?.toISOString() ?? null,
        expiresAt: row.expiresAt?.toISOString() ?? null
      },
      digest
    );
    if (!binding) throw persistenceError('LEDGER_CORRUPT');
    return binding;
  });
}

async function replayEvaluation(
  tx: Prisma.TransactionClient,
  row: EvaluationRow,
  expected: Omit<SastKillSwitchEvaluationResult, 'replayed'>
): Promise<SastKillSwitchEvaluationResult> {
  const [headRows, matchRows] = await Promise.all([
    tx.sastKillSwitchEvaluationHead.findMany({
      where: { evaluationId: row.id },
      orderBy: { position: 'asc' }
    }),
    tx.sastKillSwitchEvaluationMatch.findMany({
      where: { evaluationId: row.id },
      orderBy: { position: 'asc' }
    })
  ]);
  const receipt = evaluationFromRow(row);
  const heads = headRows.map(evaluationHeadFromRow);
  const matches = matchRows.map(evaluationMatchFromRow);
  if (
    receipt.receiptDigest !== expected.receipt.receiptDigest ||
    heads.length !== expected.heads.length ||
    matches.length !== expected.matches.length ||
    !heads.every(
      (head, index) => head.bindingDigest === expected.heads[index]?.bindingDigest
    ) ||
    !matches.every(
      (match, index) =>
        match.bindingDigest === expected.matches[index]?.bindingDigest
    )
  ) {
    throw persistenceError('REPLAY_CONFLICT');
  }
  return { receipt, heads, matches, replayed: true };
}

function decisionData(
  decision: Readonly<SastKillSwitchControlDecision>
): Prisma.SastKillSwitchDecisionUncheckedCreateInput {
  return {
    id: decision.decisionId,
    contractVersion: decision.version,
    decisionDigest: decision.decisionDigest,
    selectorKey: decision.selectorKey,
    scope: decision.selector.scope,
    ...selectorColumns(decision.selector),
    sequence: decision.sequence,
    previousDecisionId: decision.previousDecisionId,
    previousDecisionDigest: decision.previousDecisionDigest,
    action: decision.action,
    reasonCode: decision.reasonCode,
    incidentRef: decision.incidentRef,
    actorRef: decision.actorRef,
    actorRole: decision.actorRole,
    effectiveAt: new Date(decision.effectiveAt),
    reviewBy: new Date(decision.reviewBy),
    expiresAt: new Date(decision.expiresAt),
    rollbackTargetRef: decision.rollbackTargetRef,
    signatureRef: decision.signatureRef,
    provenanceRef: decision.provenanceRef,
    auditRef: decision.auditRef,
    source: decision.source,
    immutable: decision.immutable,
    customerInputAccepted: decision.customerInputAccepted,
    repositoryContentStored: decision.repositoryContentStored,
    findingContentStored: decision.findingContentStored,
    secretValueStored: decision.secretValueStored,
    arbitraryPayloadStored: decision.arbitraryPayloadStored
  };
}

function verificationData(
  verification: Readonly<SastKillSwitchVerification>
): Prisma.SastKillSwitchVerificationUncheckedCreateInput {
  return {
    id: verification.verificationId,
    contractVersion: verification.version,
    verificationDigest: verification.verificationDigest,
    decisionId: verification.decisionId,
    decisionDigest: verification.decisionDigest,
    selectorKey: verification.selectorKey,
    signerIdentity: verification.signerIdentity,
    signatureRef: verification.signatureRef,
    provenanceRef: verification.provenanceRef,
    signatureVerified: verification.signatureVerified,
    provenanceVerified: verification.provenanceVerified,
    trustedSigner: verification.trustedSigner,
    signatureBytesStored: verification.signatureBytesStored,
    provenancePayloadStored: verification.provenancePayloadStored,
    repositoryContentStored: verification.repositoryContentStored,
    secretValueStored: verification.secretValueStored,
    verifiedAt: new Date(verification.verifiedAt)
  };
}

function evaluationData(
  receipt: Readonly<SastKillSwitchEvaluationReceipt>
): Prisma.SastKillSwitchEvaluationUncheckedCreateInput {
  return {
    id: receipt.evaluationId,
    contractVersion: receipt.version,
    receiptDigest: receipt.receiptDigest,
    gate: receipt.gate,
    tenantId: receipt.tenantId,
    repositoryBindingId: receipt.repositoryBindingId,
    scanRequestId: receipt.scanRequestId,
    profileId: receipt.profileId,
    profileDigest: receipt.profileDigest,
    scannerSetDigest: receipt.scannerSetDigest,
    contextDigest: receipt.contextDigest,
    snapshotDigest: receipt.snapshotDigest,
    headCount: receipt.headCount,
    headSetDigest: receipt.headSetDigest,
    matchedDecisionCount: receipt.matchedDecisionCount,
    matchedDecisionSetDigest: receipt.matchedDecisionSetDigest,
    outcome: receipt.outcome,
    coverageEffect: receipt.coverageEffect,
    evaluatedAt: new Date(receipt.evaluatedAt),
    customerInputAccepted: receipt.customerInputAccepted,
    repositoryContentStored: receipt.repositoryContentStored,
    findingContentStored: receipt.findingContentStored,
    secretValueStored: receipt.secretValueStored,
    arbitraryPayloadStored: receipt.arbitraryPayloadStored
  };
}

function evaluationHeadData(
  evaluationId: string,
  position: number,
  head: Readonly<SastKillSwitchHeadBinding>
): Prisma.SastKillSwitchEvaluationHeadCreateManyInput {
  return {
    evaluationId,
    position,
    selectorKey: head.selectorKey,
    scope: head.scope,
    sequence: head.sequence,
    decisionId: head.decisionId,
    decisionDigest: head.decisionDigest,
    action: head.action,
    active: head.active,
    effectiveAt: head.effectiveAt ? new Date(head.effectiveAt) : null,
    expiresAt: head.expiresAt ? new Date(head.expiresAt) : null,
    bindingDigest: head.bindingDigest
  };
}

function evaluationMatchData(
  evaluationId: string,
  position: number,
  match: Readonly<SastKillSwitchEvaluationMatch>
): Prisma.SastKillSwitchEvaluationMatchCreateManyInput {
  return { evaluationId, position, ...match };
}

function suspensionData(
  receipt: Readonly<SastKillSwitchEmergencySuspensionReceipt>
): Prisma.SastKillSwitchEmergencySuspensionReceiptUncheckedCreateInput {
  return {
    id: receipt.receiptId,
    contractVersion: receipt.version,
    receiptDigest: receipt.receiptDigest,
    manifestId: receipt.manifestId,
    manifestDigest: receipt.manifestDigest,
    bundleId: receipt.bundleId,
    bundleDigest: receipt.bundleDigest,
    fromState: receipt.fromState,
    toState: receipt.toState,
    lifecycleSequence: receipt.lifecycleSequence,
    lifecycleTransitionId: receipt.lifecycleTransitionId,
    lifecycleTransitionDigest: receipt.lifecycleTransitionDigest,
    promotionEvidenceId: receipt.promotionEvidenceId,
    promotionEvidenceDigest: receipt.promotionEvidenceDigest,
    triggerSelectorKey: receipt.triggerSelectorKey,
    triggerDecisionId: receipt.triggerDecisionId,
    triggerDecisionDigest: receipt.triggerDecisionDigest,
    activeDecisionCount: receipt.activeDecisionCount,
    activeDecisionSetDigest: receipt.activeDecisionSetDigest,
    requestedAt: new Date(receipt.requestedAt),
    verifiedAt: new Date(receipt.verifiedAt),
    customerInputAccepted: receipt.customerInputAccepted,
    repositoryContentStored: receipt.repositoryContentStored,
    findingContentStored: receipt.findingContentStored,
    secretValueStored: receipt.secretValueStored
  };
}

function decisionFromRow(row: DecisionRow): SastKillSwitchControlDecision {
  const decision: SastKillSwitchControlDecision = {
    version: row.contractVersion as SastKillSwitchControlDecision['version'],
    decisionId: row.id,
    selectorKey: row.selectorKey,
    selector: selectorFromRow(row),
    sequence: row.sequence,
    previousDecisionId: row.previousDecisionId,
    previousDecisionDigest: row.previousDecisionDigest
      ? asDigest(row.previousDecisionDigest)
      : null,
    action: row.action as SastKillSwitchControlDecision['action'],
    reasonCode: row.reasonCode as SastKillSwitchControlDecision['reasonCode'],
    incidentRef: row.incidentRef,
    actorRef: row.actorRef,
    actorRole: row.actorRole as SastKillSwitchControlDecision['actorRole'],
    effectiveAt: row.effectiveAt.toISOString(),
    reviewBy: row.reviewBy.toISOString(),
    expiresAt: row.expiresAt.toISOString(),
    rollbackTargetRef: row.rollbackTargetRef,
    signatureRef: row.signatureRef,
    provenanceRef: row.provenanceRef,
    auditRef: row.auditRef,
    source: row.source as 'PLATFORM_MANAGED',
    immutable: row.immutable as true,
    customerInputAccepted: row.customerInputAccepted as false,
    repositoryContentStored: row.repositoryContentStored as false,
    findingContentStored: row.findingContentStored as false,
    secretValueStored: row.secretValueStored as false,
    arbitraryPayloadStored: row.arbitraryPayloadStored as false,
    decisionDigest: asDigest(row.decisionDigest)
  };
  assertDecisionValid(decision, 'LEDGER_CORRUPT');
  return decision;
}

function verificationFromRow(row: VerificationRow): SastKillSwitchVerification {
  const verification: SastKillSwitchVerification = {
    version: row.contractVersion as SastKillSwitchVerification['version'],
    verificationId: row.id,
    decisionId: row.decisionId,
    decisionDigest: asDigest(row.decisionDigest),
    selectorKey: row.selectorKey,
    signerIdentity: row.signerIdentity,
    signatureRef: row.signatureRef,
    provenanceRef: row.provenanceRef,
    signatureVerified: row.signatureVerified as true,
    provenanceVerified: row.provenanceVerified as true,
    trustedSigner: row.trustedSigner as true,
    signatureBytesStored: row.signatureBytesStored as false,
    provenancePayloadStored: row.provenancePayloadStored as false,
    repositoryContentStored: row.repositoryContentStored as false,
    secretValueStored: row.secretValueStored as false,
    verifiedAt: row.verifiedAt.toISOString(),
    verificationDigest: asDigest(row.verificationDigest)
  };
  assertVerificationValid(verification, 'LEDGER_CORRUPT');
  return verification;
}

function evaluationFromRow(row: EvaluationRow): SastKillSwitchEvaluationReceipt {
  const receipt: SastKillSwitchEvaluationReceipt = {
    version: row.contractVersion as SastKillSwitchEvaluationReceipt['version'],
    evaluationId: row.id,
    gate: row.gate as SastKillSwitchGate,
    tenantId: row.tenantId,
    repositoryBindingId: row.repositoryBindingId,
    scanRequestId: row.scanRequestId,
    profileId: row.profileId as SastProfileId,
    profileDigest: asDigest(row.profileDigest),
    scannerSetDigest: asDigest(row.scannerSetDigest),
    contextDigest: asDigest(row.contextDigest),
    snapshotDigest: asDigest(row.snapshotDigest),
    headCount: row.headCount,
    headSetDigest: asDigest(row.headSetDigest),
    matchedDecisionCount: row.matchedDecisionCount,
    matchedDecisionSetDigest: asDigest(row.matchedDecisionSetDigest),
    outcome: row.outcome as SastKillSwitchEvaluationReceipt['outcome'],
    coverageEffect:
      row.coverageEffect as SastKillSwitchEvaluationReceipt['coverageEffect'],
    evaluatedAt: row.evaluatedAt.toISOString(),
    customerInputAccepted: row.customerInputAccepted as false,
    repositoryContentStored: row.repositoryContentStored as false,
    findingContentStored: row.findingContentStored as false,
    secretValueStored: row.secretValueStored as false,
    arbitraryPayloadStored: row.arbitraryPayloadStored as false,
    receiptDigest: asDigest(row.receiptDigest)
  };
  if (!isSastKillSwitchEvaluationReceiptValid(receipt, digest)) {
    throw persistenceError('LEDGER_CORRUPT');
  }
  return receipt;
}

function evaluationHeadFromRow(row: EvaluationHeadRow): SastKillSwitchHeadBinding {
  const binding: SastKillSwitchHeadBinding = {
    selectorKey: row.selectorKey,
    scope: row.scope as SastKillSwitchSelector['scope'],
    sequence: row.sequence,
    decisionId: row.decisionId,
    decisionDigest: row.decisionDigest ? asDigest(row.decisionDigest) : null,
    action: row.action as SastKillSwitchHeadBinding['action'],
    active: row.active,
    effectiveAt: row.effectiveAt?.toISOString() ?? null,
    expiresAt: row.expiresAt?.toISOString() ?? null,
    bindingDigest: asDigest(row.bindingDigest)
  };
  if (!isSastKillSwitchHeadBindingValid(binding, digest)) {
    throw persistenceError('LEDGER_CORRUPT');
  }
  return binding;
}

function evaluationMatchFromRow(
  row: EvaluationMatchRow
): SastKillSwitchEvaluationMatch {
  return {
    selectorKey: row.selectorKey,
    scope: row.scope as SastKillSwitchSelector['scope'],
    decisionId: row.decisionId,
    decisionDigest: asDigest(row.decisionDigest),
    bindingDigest: asDigest(row.bindingDigest)
  };
}

function suspensionFromRow(
  row: SuspensionRow
): SastKillSwitchEmergencySuspensionReceipt {
  const receipt: SastKillSwitchEmergencySuspensionReceipt = {
    version:
      row.contractVersion as SastKillSwitchEmergencySuspensionReceipt['version'],
    receiptId: row.id,
    receiptRef: row.id,
    manifestId: row.manifestId,
    manifestDigest: asDigest(row.manifestDigest),
    bundleId: row.bundleId,
    bundleDigest: asDigest(row.bundleDigest),
    fromState: row.fromState as 'CANARY' | 'ACTIVE',
    toState: row.toState as 'SUSPENDED',
    lifecycleSequence: row.lifecycleSequence,
    lifecycleTransitionId: row.lifecycleTransitionId,
    lifecycleTransitionDigest: asDigest(row.lifecycleTransitionDigest),
    promotionEvidenceId: row.promotionEvidenceId,
    promotionEvidenceDigest: asDigest(row.promotionEvidenceDigest),
    triggerSelectorKey: row.triggerSelectorKey,
    triggerDecisionId: row.triggerDecisionId,
    triggerDecisionDigest: asDigest(row.triggerDecisionDigest),
    activeDecisionCount: row.activeDecisionCount,
    activeDecisionSetDigest: asDigest(row.activeDecisionSetDigest),
    requestedAt: row.requestedAt.toISOString(),
    verifiedAt: row.verifiedAt.toISOString(),
    customerInputAccepted: row.customerInputAccepted as false,
    repositoryContentStored: row.repositoryContentStored as false,
    findingContentStored: row.findingContentStored as false,
    secretValueStored: row.secretValueStored as false,
    receiptDigest: asDigest(row.receiptDigest)
  };
  if (!isSastKillSwitchEmergencySuspensionReceiptValid(receipt, digest)) {
    throw persistenceError('LEDGER_CORRUPT');
  }
  return receipt;
}

function replayDecision(
  decisionRow: DecisionRow,
  verificationRow: VerificationRow | null,
  expectedDecision: Readonly<SastKillSwitchControlDecision>,
  expectedVerification: Readonly<SastKillSwitchVerification>,
  replayed = true
): PersistedSastKillSwitchDecision {
  if (!verificationRow) throw persistenceError('LEDGER_CORRUPT');
  const decision = decisionFromRow(decisionRow);
  const verification = verificationFromRow(verificationRow);
  if (
    decision.decisionDigest !== expectedDecision.decisionDigest ||
    verification.verificationDigest !== expectedVerification.verificationDigest
  ) {
    throw persistenceError('REPLAY_CONFLICT');
  }
  return { decision, verification, replayed };
}

function replaySuspension(
  row: SuspensionRow,
  expected: Readonly<SastKillSwitchEmergencySuspensionReceipt>
): SastKillSwitchEmergencySuspensionReceipt {
  const receipt = suspensionFromRow(row);
  if (receipt.receiptDigest !== expected.receiptDigest) {
    throw persistenceError('REPLAY_CONFLICT');
  }
  return receipt;
}

function selectorColumns(selector: Readonly<SastKillSwitchSelector>): {
  runtime: string | null;
  scanner: string | null;
  scannerVersion: string | null;
  bundleDigest: string | null;
  ruleSemanticId: string | null;
  profileId: string | null;
  profileDigest: string | null;
  tenantId: string | null;
  repositoryBindingId: string | null;
  capability: string | null;
  publicationTargetScope: string | null;
} {
  const empty = {
    runtime: null,
    scanner: null,
    scannerVersion: null,
    bundleDigest: null,
    ruleSemanticId: null,
    profileId: null,
    profileDigest: null,
    tenantId: null,
    repositoryBindingId: null,
    capability: null,
    publicationTargetScope: null
  };
  switch (selector.scope) {
    case 'GLOBAL':
      return { ...empty, runtime: selector.runtime };
    case 'SCANNER_VERSION':
      return {
        ...empty,
        scanner: selector.scanner,
        scannerVersion: selector.scannerVersion
      };
    case 'RULE_BUNDLE':
      return { ...empty, bundleDigest: selector.bundleDigest };
    case 'SEMANTIC_RULE':
      return { ...empty, ruleSemanticId: selector.ruleSemanticId };
    case 'PROFILE':
      return {
        ...empty,
        profileId: selector.profileId,
        profileDigest: selector.profileDigest
      };
    case 'TENANT':
      return { ...empty, tenantId: selector.tenantId };
    case 'REPOSITORY_BINDING':
      return {
        ...empty,
        tenantId: selector.tenantId,
        repositoryBindingId: selector.repositoryBindingId
      };
    case 'CAPABILITY':
      return { ...empty, capability: selector.capability };
    case 'EXTERNAL_PUBLICATION':
      return {
        ...empty,
        tenantId: selector.tenantId,
        repositoryBindingId: selector.repositoryBindingId,
        publicationTargetScope: selector.targetScope
      };
  }
}

function selectorFromRow(
  row: Pick<
    DecisionRow,
    | 'scope'
    | 'runtime'
    | 'scanner'
    | 'scannerVersion'
    | 'bundleDigest'
    | 'ruleSemanticId'
    | 'profileId'
    | 'profileDigest'
    | 'tenantId'
    | 'repositoryBindingId'
    | 'capability'
    | 'publicationTargetScope'
  >
): SastKillSwitchSelector {
  let selector: SastKillSwitchSelector;
  switch (row.scope) {
    case 'GLOBAL':
      selector = { scope: 'GLOBAL', runtime: row.runtime as 'SAST' };
      break;
    case 'SCANNER_VERSION':
      selector = {
        scope: 'SCANNER_VERSION',
        scanner: row.scanner as SastScannerKind,
        scannerVersion: row.scannerVersion ?? ''
      };
      break;
    case 'RULE_BUNDLE':
      selector = {
        scope: 'RULE_BUNDLE',
        bundleDigest: asDigest(row.bundleDigest ?? '')
      };
      break;
    case 'SEMANTIC_RULE':
      selector = {
        scope: 'SEMANTIC_RULE',
        ruleSemanticId: row.ruleSemanticId ?? ''
      };
      break;
    case 'PROFILE':
      selector = {
        scope: 'PROFILE',
        profileId: row.profileId as SastProfileId,
        profileDigest: asDigest(row.profileDigest ?? '')
      };
      break;
    case 'TENANT':
      selector = { scope: 'TENANT', tenantId: row.tenantId ?? '' };
      break;
    case 'REPOSITORY_BINDING':
      selector = {
        scope: 'REPOSITORY_BINDING',
        tenantId: row.tenantId ?? '',
        repositoryBindingId: row.repositoryBindingId ?? ''
      };
      break;
    case 'CAPABILITY':
      selector = {
        scope: 'CAPABILITY',
        capability: row.capability as Extract<
          SastKillSwitchSelector,
          { scope: 'CAPABILITY' }
        >['capability']
      };
      break;
    case 'EXTERNAL_PUBLICATION':
      if (row.publicationTargetScope === 'GLOBAL') {
        selector = {
          scope: 'EXTERNAL_PUBLICATION',
          targetScope: 'GLOBAL',
          tenantId: null,
          repositoryBindingId: null
        };
      } else if (row.publicationTargetScope === 'TENANT') {
        selector = {
          scope: 'EXTERNAL_PUBLICATION',
          targetScope: 'TENANT',
          tenantId: row.tenantId ?? '',
          repositoryBindingId: null
        };
      } else {
        selector = {
          scope: 'EXTERNAL_PUBLICATION',
          targetScope: 'REPOSITORY_BINDING',
          tenantId: row.tenantId ?? '',
          repositoryBindingId: row.repositoryBindingId ?? ''
        };
      }
      break;
    default:
      throw persistenceError('LEDGER_CORRUPT');
  }
  if (!isSastKillSwitchSelectorValid(selector)) {
    throw persistenceError('LEDGER_CORRUPT');
  }
  return selector;
}

function headMatchesSelector(row: HeadRow, expected: KeyedSelector): boolean {
  if (row.selectorKey !== expected.selectorKey || row.scope !== expected.selector.scope) {
    return false;
  }
  const columns = selectorColumns(expected.selector);
  return (Object.keys(columns) as Array<keyof typeof columns>).every(
    (key) => row[key] === columns[key]
  );
}

function assertDecisionExtendsHead(
  decision: Readonly<SastKillSwitchControlDecision>,
  head: Readonly<HeadRow>
): void {
  if (
    decision.sequence !== head.sequence + 1 ||
    (decision.sequence === 1 &&
      (decision.previousDecisionId !== null ||
        decision.previousDecisionDigest !== null)) ||
    (decision.sequence > 1 &&
      (decision.previousDecisionId !== head.currentDecisionId ||
        decision.previousDecisionDigest !== head.currentDecisionDigest))
  ) {
    throw persistenceError('STALE_DECISION');
  }
  if (decision.action === 'DEACTIVATE' && !head.active) {
    throw persistenceError('DEACTIVATION_WITHOUT_ACTIVE_HEAD');
  }
}

function suspensionSelectors(manifest: {
  scanner: string;
  bundleDigest: string;
  rules: Array<{ ruleSemanticId: string }>;
  compatibilityEntries: Array<{ kind: string; value: string }>;
}): KeyedSelector[] {
  const scanner = manifest.scanner as SastScannerKind;
  const selectors: SastKillSwitchSelector[] = [
    { scope: 'GLOBAL', runtime: 'SAST' },
    { scope: 'RULE_BUNDLE', bundleDigest: asDigest(manifest.bundleDigest) },
    ...manifest.compatibilityEntries
      .filter((entry) => entry.kind === 'SCANNER_VERSION')
      .map<SastKillSwitchSelector>((entry) => ({
        scope: 'SCANNER_VERSION',
        scanner,
        scannerVersion: entry.value
      })),
    ...manifest.rules.map<SastKillSwitchSelector>((rule) => ({
      scope: 'SEMANTIC_RULE',
      ruleSemanticId: rule.ruleSemanticId
    })),
    ...manifest.compatibilityEntries
      .filter((entry) => entry.kind === 'PROFILE_ID')
      .map<SastKillSwitchSelector>((entry) => ({
        scope: 'PROFILE',
        profileId: entry.value as SastProfileId,
        profileDigest:
          SAST_APPROVED_PROFILE_DIGESTS[entry.value as SastProfileId]
      }))
  ];
  const keyed = selectors.map((selector) => {
    if (!isSastKillSwitchSelectorValid(selector)) {
      throw persistenceError('LEDGER_CORRUPT');
    }
    return {
      selectorKey: buildSastKillSwitchSelectorKey(selector, digest),
      selector
    };
  });
  return [...new Map(keyed.map((entry) => [entry.selectorKey, entry])).values()].sort(
    (left, right) => compare(left.selectorKey, right.selectorKey)
  );
}

function lifecycleMatchesInput(
  row: Readonly<LifecycleHeadRow>,
  input: Readonly<SastRuleBundleLifecycleAuthorityInput>
): boolean {
  return (
    row.manifestId === input.manifestId &&
    row.manifestDigest === input.manifestDigest &&
    row.bundleId === input.bundleId &&
    row.bundleDigest === input.bundleDigest &&
    row.lifecycleState === input.fromState &&
    row.promotionEvidenceId === input.promotionEvidenceId &&
    row.promotionEvidenceDigest === input.promotionEvidenceDigest
  );
}

function assertDecisionValid(
  decision: Readonly<SastKillSwitchControlDecision>,
  reason: 'INPUT_INVALID' | 'LEDGER_CORRUPT' = 'INPUT_INVALID'
): void {
  if (!isSastKillSwitchDecisionShapeValid(decision, digest)) {
    throw persistenceError(reason);
  }
}

function assertVerificationValid(
  verification: Readonly<SastKillSwitchVerification>,
  reason: 'INPUT_INVALID' | 'LEDGER_CORRUPT' = 'INPUT_INVALID'
): void {
  if (!isSastKillSwitchVerificationShapeValid(verification, digest)) {
    throw persistenceError(reason);
  }
}

function buildReplayCandidate(
  context: Readonly<SastKillSwitchEvaluationContext>,
  gate: SastKillSwitchGate,
  evaluatedAt: string
): true | null {
  return isSastKillSwitchEvaluationContextValid(context, digest) &&
    SAST_KILL_SWITCH_GATES.includes(gate) &&
    isCanonicalTimestamp(evaluatedAt)
    ? true
    : null;
}

function persistenceError(
  reason: ConstructorParameters<typeof SastKillSwitchPersistenceError>[0]
): SastKillSwitchPersistenceError {
  return new SastKillSwitchPersistenceError(reason);
}

function mapPersistenceError(error: unknown): unknown {
  if (error instanceof SastKillSwitchPersistenceError) return error;
  if (
    error instanceof Prisma.PrismaClientKnownRequestError &&
    error.code === 'P2003'
  ) {
    return persistenceError('LEDGER_CORRUPT');
  }
  if (
    error instanceof Prisma.PrismaClientKnownRequestError &&
    (error.code === 'P2002' || error.code === 'P2034')
  ) {
    return persistenceError('REPLAY_CONFLICT');
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

function digest(value: string): `sha256:${string}` {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalJson(entry)).join(',')}]`;
  }
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(',')}}`;
}

function asDigest(value: string): `sha256:${string}` {
  if (!/^sha256:[a-f0-9]{64}$/u.test(value)) {
    throw persistenceError('LEDGER_CORRUPT');
  }
  return value as `sha256:${string}`;
}

function isCanonicalTimestamp(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const milliseconds = Date.parse(value);
  return (
    Number.isFinite(milliseconds) &&
    new Date(milliseconds).toISOString() === value
  );
}

function isBounded(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 512;
}

function compare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
