import {
  SAST_AI_ADVISORY_AUTHORITY_LIMITS,
  SAST_AI_ADVISORY_AUTHORITY_PROOF_VERSION,
  buildSastAiAdvisoryAuthorityProof,
  buildSastAiAdvisoryAuthorityStateSnapshot,
  isSastAiAdvisoryAuthorityProofShapeValid,
  isSastAiAdvisoryPolicyReferenceShapeValid,
  type SastAiAdvisoryAuthorityProof,
  type SastAiAdvisoryAuthorityProofScope,
  type SastAiAdvisoryAuthorityStateSnapshot,
  type SastAiAdvisoryPolicyReference
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';

import { PrismaService } from '../prisma/prisma.service';
import {
  digestAuthorityCanonical,
  stableAuthorityJson
} from './sast-ai-advisory-authority-canonical';
import {
  SastAiAdvisoryAuthorityPersistenceError,
  SastAiAdvisoryAuthorityStore,
  type PersistedSastAiAdvisoryAuthorityProof
} from './sast-ai-advisory-authority.store';

const SERIALIZABLE_RETRIES = 3;
const SERIALIZABLE_TIMEOUT_MILLISECONDS = 10_000;

interface AuthorityContext {
  scope: SastAiAdvisoryAuthorityProofScope;
  advisoryCreatedAt: string;
  lineageId: string;
  lifecycleContextKey: string;
}

interface AuthorityProofRow {
  id: string;
  advisoryId: string;
  handoffId: string;
  tenantId: string;
  repositoryBindingId: string;
  scanRequestId: string;
  attemptId: string;
  occurrenceId: string;
  normalizedFindingId: string;
  findingFingerprint: string;
  requestDigest: string;
  handoffDigest: string;
  normalizedFindingCount: number;
  normalizedFindingSetDigest: string;
  targetFindingDigest: string;
  lifecycleStateCount: number;
  lifecycleStateSetDigest: string;
  policyDecisionCount: number;
  policyDecisionSetDigest: string;
  waiverCount: number;
  waiverSetDigest: string;
  suppressionCount: number;
  suppressionSetDigest: string;
  beforeStateDigest: string;
  afterStateDigest: string;
  findingCreateAuthority: boolean;
  findingStatusMutationAuthority: boolean;
  findingSeverityMutationAuthority: boolean;
  lifecycleMutationAuthority: boolean;
  waiverMutationAuthority: boolean;
  suppressionMutationAuthority: boolean;
  policyOverrideAuthority: boolean;
  blockDecisionAuthority: boolean;
  publicationAuthority: boolean;
  scmWriteAuthority: boolean;
  advisoryOnly: boolean;
  proofLedgerWritten: boolean;
  authoritativeFindingWritten: boolean;
  lifecycleStateWritten: boolean;
  policyDecisionWritten: boolean;
  waiverWritten: boolean;
  suppressionWritten: boolean;
  callerAuthorityFieldsAccepted: boolean;
  advisoryContentStored: boolean;
  sourceContentStored: boolean;
  secretValueStored: boolean;
  verifiedAt: Date;
  proofDigest: string;
}

@Injectable()
export class PrismaSastAiAdvisoryAuthorityStore extends SastAiAdvisoryAuthorityStore {
  constructor(private readonly prisma: PrismaService) {
    super();
  }

  async createProof(input: {
    tenantId: string;
    advisoryId: string;
    verifiedAt: string;
  }): Promise<PersistedSastAiAdvisoryAuthorityProof> {
    try {
      return await this.runSerializable(async (tx) => {
        await acquireAdvisoryContextFence(tx, input);
        const context = await loadAuthorityContext(tx, input);
        if (!context) {
          throw new SastAiAdvisoryAuthorityPersistenceError(
            'CONTEXT_DRIFT'
          );
        }

        await acquireAuthorityFence(tx, context);

        const existing =
          await tx.sastAiAdvisoryAuthorityProof.findUnique({
            where: { advisoryId: input.advisoryId }
          });
        if (existing) {
          const replayed = replayProof(existing, context);
          const current = await captureAuthorityState(tx, context);
          if (
            current.stateDigest !== replayed.proof.before.stateDigest
          ) {
            throw new SastAiAdvisoryAuthorityPersistenceError(
              'STATE_DRIFT'
            );
          }
          return replayed;
        }

        const before = await captureAuthorityState(tx, context);
        const proof = buildSastAiAdvisoryAuthorityProof({
          scope: context.scope,
          before,
          after: before,
          verifiedAt: input.verifiedAt,
          digestCanonical: digestAuthorityCanonical
        });
        if (!proof) {
          throw new SastAiAdvisoryAuthorityPersistenceError(
            'OUTPUT_INVALID'
          );
        }

        const created =
          await tx.sastAiAdvisoryAuthorityProof.create({
            data: proofData(proof)
          });
        return replayProof(created, context, false);
      });
    } catch (error) {
      if (!isUniqueConflict(error)) throw error;
      return this.runSerializable(async (tx) => {
        await acquireAdvisoryContextFence(tx, input);
        const context = await loadAuthorityContext(tx, input);
        if (!context) {
          throw new SastAiAdvisoryAuthorityPersistenceError(
            'REPLAY_CONFLICT'
          );
        }
        await acquireAuthorityFence(tx, context);
        const existing =
          await tx.sastAiAdvisoryAuthorityProof.findUnique({
            where: { advisoryId: input.advisoryId }
          });
        if (!existing) {
          throw new SastAiAdvisoryAuthorityPersistenceError(
            'REPLAY_CONFLICT'
          );
        }
        const replayed = replayProof(existing, context);
        const current = await captureAuthorityState(tx, context);
        if (current.stateDigest !== replayed.proof.before.stateDigest) {
          throw new SastAiAdvisoryAuthorityPersistenceError(
            'STATE_DRIFT'
          );
        }
        return replayed;
      });
    }
  }

  async verifyPolicyReference(input: {
    tenantId: string;
    normalizedFindingId: string;
    reference: Readonly<SastAiAdvisoryPolicyReference>;
  }): Promise<boolean> {
    if (!isSastAiAdvisoryPolicyReferenceShapeValid(input.reference)) {
      return false;
    }
    const row = await this.prisma.sastAiAdvisoryAuthorityProof.findFirst({
      where: {
        id: input.reference.authorityProofId,
        proofDigest: input.reference.authorityProofDigest,
        advisoryId: input.reference.advisoryId,
        tenantId: input.tenantId,
        normalizedFindingId: input.normalizedFindingId
      }
    });
    if (!row) return false;
    const proof = proofFromRow(row);
    return proof !== null &&
      proof.proofId === input.reference.authorityProofId &&
      proof.proofDigest === input.reference.authorityProofDigest &&
      proof.scope.advisoryId === input.reference.advisoryId;
  }

  private async runSerializable<T>(
    operation: (tx: Prisma.TransactionClient) => Promise<T>
  ): Promise<T> {
    for (let attempt = 1; attempt <= SERIALIZABLE_RETRIES; attempt += 1) {
      try {
        return await this.prisma.$transaction(operation, {
          isolationLevel: Prisma.TransactionIsolationLevel.Serializable,
          maxWait: SERIALIZABLE_TIMEOUT_MILLISECONDS,
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
          setTimeout(
            resolve,
            20 * attempt + Math.floor(Math.random() * 20)
          )
        );
      }
    }
    throw new SastAiAdvisoryAuthorityPersistenceError(
      'REPLAY_CONFLICT'
    );
  }
}

async function acquireAdvisoryContextFence(
  tx: Prisma.TransactionClient,
  input: Readonly<{ tenantId: string; advisoryId: string }>
): Promise<void> {
  const rows = await tx.$queryRaw<
    Array<{ lockedContextCount: bigint | number }>
  >`
    SELECT "acquire_sast_ai_advisory_context_fence"(
      ${input.tenantId},
      ${input.advisoryId}
    ) AS "lockedContextCount"
  `;
  if (rows.length !== 1 || Number(rows[0].lockedContextCount) !== 1) {
    throw new SastAiAdvisoryAuthorityPersistenceError(
      'CONTEXT_DRIFT'
    );
  }
}

async function acquireAuthorityFence(
  tx: Prisma.TransactionClient,
  context: Readonly<AuthorityContext>
): Promise<void> {
  const rows = await tx.$queryRaw<Array<{ lockedScopeCount: bigint | number }>>`
    SELECT "acquire_sast_ai_advisory_authority_fence"(
      ${context.scope.tenantId},
      ${context.scope.scanRequestId},
      ${context.scope.repositoryBindingId},
      ${context.lifecycleContextKey},
      ${context.lineageId},
      ${context.scope.normalizedFindingId}
    ) AS "lockedScopeCount"
  `;
  if (rows.length !== 1 || Number(rows[0].lockedScopeCount) !== 3) {
    throw new SastAiAdvisoryAuthorityPersistenceError(
      'CONTEXT_DRIFT'
    );
  }
}

async function loadAuthorityContext(
  client: Prisma.TransactionClient,
  input: { tenantId: string; advisoryId: string; verifiedAt: string }
): Promise<AuthorityContext | null> {
  const advisory = await client.aiAdvisoryMetadata.findFirst({
    where: { id: input.advisoryId, tenantId: input.tenantId },
    select: {
      id: true,
      sastHandoffId: true,
      tenantId: true,
      scanRequestId: true,
      findingId: true,
      advisoryOnly: true,
      redactedEvidenceOnly: true,
      createdAt: true
    }
  });
  if (
    !advisory ||
    !advisory.sastHandoffId ||
    advisory.advisoryOnly !== true ||
    advisory.redactedEvidenceOnly !== true ||
    Date.parse(input.verifiedAt) < advisory.createdAt.getTime()
  ) {
    return null;
  }

  const handoff = await client.sastAiAdvisoryHandoff.findUnique({
    where: { id: advisory.sastHandoffId },
    select: {
      id: true,
      advisoryId: true,
      tenantId: true,
      repositoryBindingId: true,
      scanRequestId: true,
      attemptId: true,
      occurrenceId: true,
      normalizedFindingId: true,
      findingFingerprint: true,
      requestDigest: true,
      handoffDigest: true,
      advisoryOnly: true,
      policyAuthority: true,
      publicationAuthority: true,
      lifecycleMutationAuthority: true,
      scmWriteAuthority: true
    }
  });
  if (
    !handoff ||
    handoff.advisoryId !== advisory.id ||
    handoff.tenantId !== advisory.tenantId ||
    handoff.scanRequestId !== advisory.scanRequestId ||
    handoff.normalizedFindingId !== advisory.findingId ||
    handoff.advisoryOnly !== true ||
    handoff.policyAuthority !== false ||
    handoff.publicationAuthority !== false ||
    handoff.lifecycleMutationAuthority !== false ||
    handoff.scmWriteAuthority !== false
  ) {
    return null;
  }

  const occurrence = await client.sastFindingOccurrence.findFirst({
    where: {
      id: handoff.occurrenceId,
      tenantId: handoff.tenantId,
      repositoryBindingId: handoff.repositoryBindingId,
      scanRequestId: handoff.scanRequestId,
      attemptId: handoff.attemptId,
      normalizedFindingId: handoff.normalizedFindingId,
      stableFingerprint: handoff.findingFingerprint
    },
    select: {
      id: true,
      lineageId: true,
      observationBatch: {
        select: { lifecycleContextKey: true }
      }
    }
  });
  if (!occurrence) return null;

  return {
    scope: {
      tenantId: handoff.tenantId,
      repositoryBindingId: handoff.repositoryBindingId,
      scanRequestId: handoff.scanRequestId,
      attemptId: handoff.attemptId,
      advisoryId: handoff.advisoryId,
      handoffId: handoff.id,
      requestDigest: handoff.requestDigest as `sha256:${string}`,
      handoffDigest: handoff.handoffDigest as `sha256:${string}`,
      normalizedFindingId: handoff.normalizedFindingId,
      occurrenceId: handoff.occurrenceId,
      findingFingerprint:
        handoff.findingFingerprint as `sha256:${string}`
    },
    advisoryCreatedAt: advisory.createdAt.toISOString(),
    lineageId: occurrence.lineageId,
    lifecycleContextKey:
      occurrence.observationBatch.lifecycleContextKey
  };
}

async function captureAuthorityState(
  tx: Prisma.TransactionClient,
  context: Readonly<AuthorityContext>
): Promise<SastAiAdvisoryAuthorityStateSnapshot> {
  const scope = context.scope;
  const [
    findings,
    lifecycleStates,
    policyDecisions,
    waivers,
    suppressions
  ] = await Promise.all([
    tx.normalizedFinding.findMany({
      where: {
        tenantId: scope.tenantId,
        scanRequestId: scope.scanRequestId
      },
      select: {
        id: true,
        status: true,
        severity: true,
        updatedAt: true
      },
      orderBy: { id: 'asc' },
      take:
        SAST_AI_ADVISORY_AUTHORITY_LIMITS.maximumNormalizedFindings + 1
    }),
    tx.sastFindingLifecycleState.findMany({
      where: {
        tenantId: scope.tenantId,
        repositoryBindingId: scope.repositoryBindingId,
        lineageId: context.lineageId,
        lifecycleContextKey: context.lifecycleContextKey
      },
      select: {
        id: true,
        targetRef: true,
        status: true,
        revision: true,
        lastObservedBatchId: true,
        lastObservedScanRequestId: true,
        lastObservedCommitSha: true,
        lastObservedAt: true,
        lastReconciliationSequence: true,
        fixedAt: true,
        reopenedAt: true,
        updatedAt: true
      },
      orderBy: { id: 'asc' },
      take: 2
    }),
    tx.policyDecision.findMany({
      where: {
        tenantId: scope.tenantId,
        findingId: scope.normalizedFindingId
      },
      select: {
        id: true,
        enforcementAction: true,
        commentAllowed: true,
        dashboardVisible: true,
        ticketRequested: true,
        blockRequested: true,
        reasonCodes: true,
        requiredCoverage: true,
        waiverApplied: true,
        staleSuppressed: true,
        aiAdvisoryVisible: true,
        createdAt: true,
        updatedAt: true
      },
      orderBy: { id: 'asc' },
      take: SAST_AI_ADVISORY_AUTHORITY_LIMITS.maximumPolicyDecisions + 1
    }),
    tx.waiver.findMany({
      where: {
        tenantId: scope.tenantId,
        scope: `finding:${scope.normalizedFindingId}`
      },
      select: {
        id: true,
        owner: true,
        reason: true,
        scope: true,
        expiresAt: true,
        lastReviewedAt: true,
        createdAt: true,
        updatedAt: true
      },
      orderBy: { id: 'asc' },
      take: SAST_AI_ADVISORY_AUTHORITY_LIMITS.maximumWaivers + 1
    }),
    tx.suppression.findMany({
      where: {
        tenantId: scope.tenantId,
        findingId: scope.normalizedFindingId
      },
      select: {
        id: true,
        scanRequestId: true,
        findingId: true,
        reason: true,
        createdAt: true,
        updatedAt: true
      },
      orderBy: { id: 'asc' },
      take: SAST_AI_ADVISORY_AUTHORITY_LIMITS.maximumSuppressions + 1
    })
  ]);

  if (lifecycleStates.length === 0) {
    throw new SastAiAdvisoryAuthorityPersistenceError(
      'CONTEXT_DRIFT'
    );
  }
  if (
    findings.length >
      SAST_AI_ADVISORY_AUTHORITY_LIMITS.maximumNormalizedFindings ||
    lifecycleStates.length > 1 ||
    policyDecisions.length >
      SAST_AI_ADVISORY_AUTHORITY_LIMITS.maximumPolicyDecisions ||
    waivers.length > SAST_AI_ADVISORY_AUTHORITY_LIMITS.maximumWaivers ||
    suppressions.length >
      SAST_AI_ADVISORY_AUTHORITY_LIMITS.maximumSuppressions
  ) {
    throw new SastAiAdvisoryAuthorityPersistenceError(
      'STATE_TOO_BROAD'
    );
  }

  const findingDigests = findings
    .map((row) => rowDigest('normalized-finding', row))
    .sort();
  const targetIndex = findings.findIndex(
    (row) => row.id === scope.normalizedFindingId
  );
  if (targetIndex < 0) {
    throw new SastAiAdvisoryAuthorityPersistenceError(
      'CONTEXT_DRIFT'
    );
  }
  const targetFindingDigest = rowDigest(
    'normalized-finding',
    findings[targetIndex]
  );
  const snapshot = buildSastAiAdvisoryAuthorityStateSnapshot({
    normalizedFindingDigests: findingDigests,
    targetFindingDigest,
    lifecycleStateDigests: lifecycleStates
      .map((row) => rowDigest('finding-lifecycle-state', row))
      .sort(),
    policyDecisionDigests: policyDecisions
      .map((row) => rowDigest('policy-decision', row))
      .sort(),
    waiverDigests: waivers
      .map((row) => rowDigest('waiver', row))
      .sort(),
    suppressionDigests: suppressions
      .map((row) => rowDigest('suppression', row))
      .sort(),
    digestCanonical: digestAuthorityCanonical
  });
  if (!snapshot) {
    throw new SastAiAdvisoryAuthorityPersistenceError(
      'OUTPUT_INVALID'
    );
  }
  return snapshot;
}

function proofData(proof: Readonly<SastAiAdvisoryAuthorityProof>) {
  const state = proof.before;
  return {
    id: proof.proofId,
    advisoryId: proof.scope.advisoryId,
    handoffId: proof.scope.handoffId,
    tenantId: proof.scope.tenantId,
    repositoryBindingId: proof.scope.repositoryBindingId,
    scanRequestId: proof.scope.scanRequestId,
    attemptId: proof.scope.attemptId,
    occurrenceId: proof.scope.occurrenceId,
    normalizedFindingId: proof.scope.normalizedFindingId,
    findingFingerprint: proof.scope.findingFingerprint,
    requestDigest: proof.scope.requestDigest,
    handoffDigest: proof.scope.handoffDigest,
    normalizedFindingCount: state.normalizedFindingCount,
    normalizedFindingSetDigest: state.normalizedFindingSetDigest,
    targetFindingDigest: state.targetFindingDigest,
    lifecycleStateCount: state.lifecycleStateCount,
    lifecycleStateSetDigest: state.lifecycleStateSetDigest,
    policyDecisionCount: state.policyDecisionCount,
    policyDecisionSetDigest: state.policyDecisionSetDigest,
    waiverCount: state.waiverCount,
    waiverSetDigest: state.waiverSetDigest,
    suppressionCount: state.suppressionCount,
    suppressionSetDigest: state.suppressionSetDigest,
    beforeStateDigest: proof.before.stateDigest,
    afterStateDigest: proof.after.stateDigest,
    ...proof.authority,
    ...proof.audit,
    verifiedAt: new Date(proof.verifiedAt),
    proofDigest: proof.proofDigest
  };
}

function replayProof(
  row: AuthorityProofRow,
  context: Readonly<AuthorityContext>,
  replayed = true
): PersistedSastAiAdvisoryAuthorityProof {
  const proof = proofFromRow(row);
  if (
    !proof ||
    stableAuthorityJson(proof.scope) !==
      stableAuthorityJson(context.scope) ||
    Date.parse(proof.verifiedAt) <
      Date.parse(context.advisoryCreatedAt)
  ) {
    throw new SastAiAdvisoryAuthorityPersistenceError(
      'REPLAY_CONFLICT'
    );
  }
  return { proof, replayed };
}

function proofFromRow(
  row: AuthorityProofRow
): SastAiAdvisoryAuthorityProof | null {
  const snapshot: SastAiAdvisoryAuthorityStateSnapshot = {
    normalizedFindingCount: row.normalizedFindingCount,
    normalizedFindingSetDigest:
      row.normalizedFindingSetDigest as `sha256:${string}`,
    targetFindingDigest: row.targetFindingDigest as `sha256:${string}`,
    lifecycleStateCount: row.lifecycleStateCount as 1,
    lifecycleStateSetDigest:
      row.lifecycleStateSetDigest as `sha256:${string}`,
    policyDecisionCount: row.policyDecisionCount,
    policyDecisionSetDigest:
      row.policyDecisionSetDigest as `sha256:${string}`,
    waiverCount: row.waiverCount,
    waiverSetDigest: row.waiverSetDigest as `sha256:${string}`,
    suppressionCount: row.suppressionCount,
    suppressionSetDigest:
      row.suppressionSetDigest as `sha256:${string}`,
    stateDigest: row.beforeStateDigest as `sha256:${string}`
  };
  const proof: SastAiAdvisoryAuthorityProof = {
    version: SAST_AI_ADVISORY_AUTHORITY_PROOF_VERSION,
    proofId: row.id,
    scope: {
      tenantId: row.tenantId,
      repositoryBindingId: row.repositoryBindingId,
      scanRequestId: row.scanRequestId,
      attemptId: row.attemptId,
      advisoryId: row.advisoryId,
      handoffId: row.handoffId,
      requestDigest: row.requestDigest as `sha256:${string}`,
      handoffDigest: row.handoffDigest as `sha256:${string}`,
      normalizedFindingId: row.normalizedFindingId,
      occurrenceId: row.occurrenceId,
      findingFingerprint: row.findingFingerprint as `sha256:${string}`
    },
    before: snapshot,
    after: {
      ...snapshot,
      stateDigest: row.afterStateDigest as `sha256:${string}`
    },
    authority: {
      findingCreateAuthority: row.findingCreateAuthority as false,
      findingStatusMutationAuthority:
        row.findingStatusMutationAuthority as false,
      findingSeverityMutationAuthority:
        row.findingSeverityMutationAuthority as false,
      lifecycleMutationAuthority: row.lifecycleMutationAuthority as false,
      waiverMutationAuthority: row.waiverMutationAuthority as false,
      suppressionMutationAuthority:
        row.suppressionMutationAuthority as false,
      policyOverrideAuthority: row.policyOverrideAuthority as false,
      blockDecisionAuthority: row.blockDecisionAuthority as false,
      publicationAuthority: row.publicationAuthority as false,
      scmWriteAuthority: row.scmWriteAuthority as false,
      advisoryOnly: row.advisoryOnly as true
    },
    audit: {
      proofLedgerWritten: row.proofLedgerWritten as true,
      authoritativeFindingWritten:
        row.authoritativeFindingWritten as false,
      lifecycleStateWritten: row.lifecycleStateWritten as false,
      policyDecisionWritten: row.policyDecisionWritten as false,
      waiverWritten: row.waiverWritten as false,
      suppressionWritten: row.suppressionWritten as false,
      callerAuthorityFieldsAccepted:
        row.callerAuthorityFieldsAccepted as false,
      advisoryContentStored: row.advisoryContentStored as false,
      sourceContentStored: row.sourceContentStored as false,
      secretValueStored: row.secretValueStored as false
    },
    verifiedAt: row.verifiedAt.toISOString(),
    proofDigest: row.proofDigest as `sha256:${string}`
  };
  return isSastAiAdvisoryAuthorityProofShapeValid(
    proof,
    digestAuthorityCanonical
  )
    ? proof
    : null;
}

function rowDigest(kind: string, row: object): `sha256:${string}` {
  return digestAuthorityCanonical(stableAuthorityJson({ kind, row }));
}

function isSerializableConflict(error: unknown): boolean {
  return error instanceof Prisma.PrismaClientKnownRequestError &&
    error.code === 'P2034';
}

function isUniqueConflict(error: unknown): boolean {
  return error instanceof Prisma.PrismaClientKnownRequestError &&
    error.code === 'P2002';
}
