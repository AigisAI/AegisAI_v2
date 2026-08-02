import { createHash, randomInt } from 'node:crypto';
import { setTimeout as wait } from 'node:timers/promises';

import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import {
  SAST_APPROVED_PROFILE_DIGESTS,
  SAST_CAPABILITIES,
  SAST_FINDING_CORRELATION_LIMITS,
  SAST_FINDING_CORRELATION_SOURCE_VERSION,
  SAST_SCAN_PROFILES,
  SAST_SCANNER_RESPONSIBILITIES,
  buildSastFindingCorrelationBatchKeyPreimage,
  buildSastFindingCorrelationSourceSetPreimage,
  buildSastScanPlanDigestPreimage,
  canonicalizeSastFindingCorrelationSourceBinding,
  canonicalizeSastFingerprintedFinding,
  isSastFindingCorrelationEdgeShapeValid,
  isSastFindingCorrelationProvenanceShapeValid,
  isSastFindingCorrelationScopeValid,
  isSastFindingCorrelationSourceBindingShapeValid,
  isSastFingerprintedFindingShapeValid,
  isSastScanPlanValid,
  type SastCapability,
  type SastFindingCorrelationProvenance,
  type SastFindingCorrelationSourceBindingCore,
  type SastProfileId,
  type SastScanPlan
} from '@aegisai/shared';

import { PrismaService } from '../prisma/prisma.service';
import {
  SastFindingCorrelationAuthorityError,
  SastFindingCorrelationDurableScopeError,
  SastFindingCorrelationOccurrenceError,
  SastFindingCorrelationReplayConflictError,
  SastFindingCorrelationSourceSetIncompleteError,
  SastFindingCorrelationStore,
  type PersistSastFindingCorrelationEdge,
  type PersistSastFindingCorrelationInput,
  type PersistedSastFindingCorrelation,
  type SastFindingCorrelationContext,
  type SastFindingCorrelationOccurrence
} from './sast-finding-correlation.store';

const SERIALIZABLE_ATTEMPTS = 3;
const SERIALIZABLE_MAX_WAIT_MILLISECONDS = 5_000;
const SERIALIZABLE_TIMEOUT_MILLISECONDS = 120_000;
const SERIALIZABLE_RETRY_BASE_DELAY_MILLISECONDS = 10;
const SERIALIZABLE_RETRY_MAX_DELAY_MILLISECONDS = 100;
const CREATE_MANY_CHUNK_SIZE = 250;

type FindingCapability = Exclude<SastCapability, 'SBOM'>;

const OBSERVATION_SELECT = Prisma.validator<Prisma.SastFindingObservationBatchSelect>()({
  id: true,
  tenantId: true,
  repositoryBindingId: true,
  scanRequestId: true,
  attemptId: true,
  scannerRunId: true,
  lifecycleContextKey: true,
  targetRef: true,
  commitSha: true,
  lane: true,
  scanner: true,
  capabilities: true,
  profileId: true,
  profileDigest: true,
  canonicalScanKey: true,
  planDigest: true,
  sourceIdentityBatchDigest: true,
  findingCount: true,
  observedAt: true
});

const OCCURRENCE_SELECT = Prisma.validator<Prisma.SastFindingOccurrenceSelect>()({
  id: true,
  tenantId: true,
  repositoryBindingId: true,
  scanRequestId: true,
  attemptId: true,
  scannerRunId: true,
  observationBatchId: true,
  lineageId: true,
  normalizedFindingId: true,
  ordinal: true,
  capability: true,
  fingerprintVersion: true,
  stableFingerprint: true,
  fingerprintDecisionDigest: true,
  sourceFinding: true,
  observedAt: true
});

const EXISTING_SELECT = Prisma.validator<Prisma.SastFindingCorrelationBatchSelect>()({
  id: true,
  tenantId: true,
  repositoryBindingId: true,
  scanRequestId: true,
  attemptId: true,
  lifecycleContextKey: true,
  targetRef: true,
  commitSha: true,
  lane: true,
  profileId: true,
  profileDigest: true,
  canonicalScanKey: true,
  planDigest: true,
  sourceSetDigest: true,
  sourceBatchCount: true,
  occurrenceCount: true,
  edgeCount: true,
  exactFingerprintCount: true,
  sameDependencyCveCount: true,
  supportingEvidenceCount: true,
  possibleOverlapCount: true,
  correlatedAt: true,
  sources: {
    orderBy: { observationBatchId: 'asc' },
    select: {
      id: true,
      observationBatchId: true,
      scannerRunId: true,
      scanner: true,
      capabilities: true,
      sourceIdentityBatchDigest: true,
      sourceBindingDigest: true,
      lifecycleContextKey: true,
      findingCount: true,
      occurrenceCount: true,
      observedAt: true
    }
  },
  edges: {
    orderBy: [
      { sourceOccurrenceId: 'asc' },
      { targetOccurrenceId: 'asc' }
    ],
    select: {
      id: true,
      kind: true,
      sourceOccurrenceId: true,
      targetOccurrenceId: true,
      basisDigests: true,
      confidenceBasisPoints: true,
      sourceProvenanceDigest: true,
      targetProvenanceDigest: true,
      safety: true,
      decidedAt: true,
      edgeDigest: true,
      provenances: {
        orderBy: { side: 'asc' },
        select: {
          id: true,
          side: true,
          occurrenceId: true,
          observationBatchId: true,
          lineageId: true,
          normalizedFindingId: true,
          scannerRunId: true,
          scanner: true,
          capability: true,
          authorityLevel: true,
          severity: true,
          fingerprintVersion: true,
          stableFingerprint: true,
          fingerprintDecisionDigest: true,
          sourceFindingDigest: true,
          scannerVersion: true,
          scannerImageDigest: true,
          ruleId: true,
          ruleRevision: true,
          ruleBundleDigest: true,
          artifactDigest: true,
          vulnerabilityDatabaseDigest: true,
          provenanceDigest: true
        }
      }
    }
  }
});

type ObservationRow = Prisma.SastFindingObservationBatchGetPayload<{
  select: typeof OBSERVATION_SELECT;
}>;
type OccurrenceRow = Prisma.SastFindingOccurrenceGetPayload<{
  select: typeof OCCURRENCE_SELECT;
}>;
type ExistingRow = Prisma.SastFindingCorrelationBatchGetPayload<{
  select: typeof EXISTING_SELECT;
}>;
type CorrelationReader = Pick<
  Prisma.TransactionClient,
  | 'sastFindingObservationBatch'
  | 'sastFindingOccurrence'
  | 'sastFindingCorrelationBatch'
  | 'sastScanAttempt'
>;

@Injectable()
export class PrismaSastFindingCorrelationStore
  extends SastFindingCorrelationStore {
  constructor(private readonly prisma: PrismaService) {
    super();
  }

  async loadContext(
    observationBatchIds: readonly string[]
  ): Promise<SastFindingCorrelationContext | null> {
    return this.readContext(this.prisma, observationBatchIds);
  }

  async correlate(
    input: Readonly<PersistSastFindingCorrelationInput>
  ): Promise<PersistedSastFindingCorrelation> {
    validatePersistenceInput(input);
    return this.runSerializable((transaction) =>
      this.correlateInTransaction(transaction, input)
    );
  }

  private async correlateInTransaction(
    transaction: Prisma.TransactionClient,
    input: Readonly<PersistSastFindingCorrelationInput>
  ): Promise<PersistedSastFindingCorrelation> {
    const currentContext = await this.readContext(
      transaction,
      input.sources.map((source) => source.observationBatchId)
    );
    if (!currentContext || !sameContext(currentContext, input.context)) {
      throw new SastFindingCorrelationDurableScopeError();
    }
    const scope = currentContext.scope;
    const existing =
      await transaction.sastFindingCorrelationBatch.findFirst({
        where: {
          tenantId: scope.tenantId,
          OR: [
            { id: input.correlationBatchId },
            { sourceSetDigest: input.sourceSetDigest },
            {
              repositoryBindingId: scope.repositoryBindingId,
              scanRequestId: scope.scanRequestId,
              attemptId: scope.attemptId,
              lifecycleContextKey: scope.lifecycleContextKey
            }
          ]
        },
        select: EXISTING_SELECT
      });
    if (existing) return replayCorrelation(existing, input);

    const counts = correlationCounts(input.edges);
    const correlatedAt = new Date(input.correlatedAt);
    await transaction.sastFindingCorrelationBatch.create({
      data: {
        id: input.correlationBatchId,
        tenantId: scope.tenantId,
        repositoryBindingId: scope.repositoryBindingId,
        scanRequestId: scope.scanRequestId,
        attemptId: scope.attemptId,
        lifecycleContextKey: scope.lifecycleContextKey,
        targetRef: scope.targetRef,
        commitSha: scope.commitSha,
        lane: scope.lane,
        profileId: scope.profileId,
        profileDigest: scope.profileDigest,
        canonicalScanKey: scope.canonicalScanKey,
        planDigest: scope.planDigest,
        sourceSetDigest: input.sourceSetDigest,
        sourceBatchCount: input.sources.length,
        occurrenceCount: input.context.occurrences.length,
        edgeCount: input.edges.length,
        ...counts,
        correlatedAt
      }
    });

    const sourceRows: Prisma.SastFindingCorrelationSourceCreateManyInput[] =
      input.sources.map((source) => ({
        id: deterministicId(
          'finding-correlation-source',
          `${input.correlationBatchId}\0${source.sourceBindingDigest}`
        ),
        correlationBatchId: input.correlationBatchId,
        tenantId: scope.tenantId,
        repositoryBindingId: scope.repositoryBindingId,
        scanRequestId: scope.scanRequestId,
        attemptId: scope.attemptId,
        observationBatchId: source.observationBatchId,
        scannerRunId: source.scannerRunId,
        scanner: source.scanner,
        capabilities:
          source.capabilities as unknown as Prisma.InputJsonValue,
        sourceIdentityBatchDigest:
          source.sourceIdentityBatchDigest,
        sourceBindingDigest: source.sourceBindingDigest,
        lifecycleContextKey: source.lifecycleContextKey,
        findingCount: source.findingCount,
        occurrenceCount: source.occurrenceCount,
        observedAt: new Date(source.observedAt),
        createdAt: correlatedAt
      }));
    await createManyInChunks(
      sourceRows,
      (rows) =>
        transaction.sastFindingCorrelationSource.createMany({
          data: rows
        })
    );

    const edgeRows: Prisma.SastFindingCorrelationEdgeCreateManyInput[] = [];
    const provenanceRows: Prisma.SastFindingCorrelationProvenanceCreateManyInput[] =
      [];
    for (const edge of input.edges) {
      const edgeId = deterministicId(
        'finding-correlation-edge',
        edge.decision.edgeDigest
      );
      edgeRows.push({
        id: edgeId,
        correlationBatchId: input.correlationBatchId,
        tenantId: scope.tenantId,
        repositoryBindingId: scope.repositoryBindingId,
        scanRequestId: scope.scanRequestId,
        attemptId: scope.attemptId,
        kind: edge.decision.kind,
        sourceOccurrenceId: edge.decision.sourceOccurrenceId,
        targetOccurrenceId: edge.decision.targetOccurrenceId,
        basisDigests:
          edge.decision.basisDigests as unknown as Prisma.InputJsonValue,
        confidenceBasisPoints:
          edge.decision.confidenceBasisPoints,
        sourceProvenanceDigest:
          edge.decision.sourceProvenanceDigest,
        targetProvenanceDigest:
          edge.decision.targetProvenanceDigest,
        safety:
          edge.decision.safety as unknown as Prisma.InputJsonValue,
        decidedAt: new Date(edge.decision.decidedAt),
        edgeDigest: edge.decision.edgeDigest,
        createdAt: correlatedAt
      });
      provenanceRows.push(
        provenanceRow(
          edgeId,
          input.correlationBatchId,
          scope,
          edge.sourceProvenance,
          correlatedAt
        ),
        provenanceRow(
          edgeId,
          input.correlationBatchId,
          scope,
          edge.targetProvenance,
          correlatedAt
        )
      );
    }
    await createManyInChunks(
      edgeRows,
      (rows) =>
        transaction.sastFindingCorrelationEdge.createMany({
          data: rows
        })
    );
    await createManyInChunks(
      provenanceRows,
      (rows) =>
        transaction.sastFindingCorrelationProvenance.createMany({
          data: rows
        })
    );

    await transaction.auditEvent.create({
      data: {
        id: deterministicId(
          'finding-audit',
          `${input.correlationBatchId}\0CORRELATED`
        ),
        tenantId: scope.tenantId,
        scanRequestId: scope.scanRequestId,
        attemptId: scope.attemptId,
        eventType: 'finding.correlated',
        actor: 'scan-plane-finding-correlation',
        targetType: 'sast_finding_correlation_batch',
        targetId: input.correlationBatchId,
        occurredAt: correlatedAt,
        metadata: {
          version: 'sast-finding-correlation-v1',
          sourceSetDigest: input.sourceSetDigest,
          lifecycleContextKey: scope.lifecycleContextKey,
          sourceBatchCount: input.sources.length,
          occurrenceCount: input.context.occurrences.length,
          edgeCount: input.edges.length,
          ...counts,
          findingMergeAllowed: false,
          severityInheritanceAllowed: false,
          lifecycleInheritanceAllowed: false,
          coverageCalculationAuthority: false,
          policyAuthority: false,
          publicationAuthority: false,
          aiPayloadEligible: false
        }
      }
    });

    return {
      correlationBatchId: input.correlationBatchId,
      sourceSetDigest: input.sourceSetDigest,
      lifecycleContextKey: scope.lifecycleContextKey,
      sourceBatchCount: input.sources.length,
      occurrenceCount: input.context.occurrences.length,
      edgeCount: input.edges.length,
      ...counts,
      replayed: false,
      correlatedAt: input.correlatedAt
    };
  }

  private async readContext(
    reader: CorrelationReader,
    observationBatchIds: readonly string[]
  ): Promise<SastFindingCorrelationContext | null> {
    const orderedIds = [...observationBatchIds].sort(compareStrings);
    if (
      orderedIds.length === 0 ||
      orderedIds.length >
        SAST_FINDING_CORRELATION_LIMITS.maximumObservationBatches ||
      orderedIds.some(
        (id, index) =>
          !/^finding-observation:\/\/[a-f0-9]{64}$/u.test(id) ||
          (index > 0 && orderedIds[index - 1] === id)
      )
    ) {
      throw new SastFindingCorrelationDurableScopeError();
    }
    const batches = await reader.sastFindingObservationBatch.findMany({
      where: { id: { in: orderedIds } },
      select: OBSERVATION_SELECT,
      orderBy: { id: 'asc' }
    });
    if (
      batches.length !== orderedIds.length ||
      batches.some((batch, index) => batch.id !== orderedIds[index])
    ) {
      throw new SastFindingCorrelationSourceSetIncompleteError();
    }
    const first = batches[0];
    if (!first || !observationRowsShareScope(batches, first)) {
      throw new SastFindingCorrelationDurableScopeError();
    }
    const profileId = first.profileId as SastProfileId;
    const profile = SAST_SCAN_PROFILES[profileId];
    if (
      !profile ||
      first.profileDigest !== SAST_APPROVED_PROFILE_DIGESTS[profileId] ||
      first.lane !== profile.lane
    ) {
      throw new SastFindingCorrelationDurableScopeError();
    }
    const attempt = await reader.sastScanAttempt.findFirst({
      where: {
        id: first.attemptId,
        tenantId: first.tenantId,
        repositoryBindingId: first.repositoryBindingId,
        scanRequestId: first.scanRequestId,
        stage: {
          in: ['SCANNING', 'CLEANUP_PENDING', 'COMPLETED']
        },
        scanRequest: {
          status: { in: ['RUNNING', 'COMPLETED'] }
        }
      },
      select: {
        scanRequest: {
          select: {
            lane: true,
            targetRef: true,
            commitSha: true,
            canonicalKey: true,
            sastQueueReservation: {
              select: { immutablePlan: true }
            }
          }
        }
      }
    });
    const plan = parsePlan(
      attempt?.scanRequest.sastQueueReservation?.immutablePlan
    );
    if (
      !attempt ||
      !plan ||
      plan.tenantId !== first.tenantId ||
      plan.scanRequestId !== first.scanRequestId ||
      plan.repositoryState.repositoryBindingId !==
        first.repositoryBindingId ||
      plan.repositoryState.targetRef !== first.targetRef ||
      plan.repositoryState.fixedCommitSha !== first.commitSha ||
      plan.canonicalScanKey !== first.canonicalScanKey ||
      plan.profile.id !== profileId ||
      plan.profileDigest !== first.profileDigest ||
      plan.profile.lane !== first.lane ||
      attempt.scanRequest.targetRef !== first.targetRef ||
      attempt.scanRequest.commitSha !== first.commitSha ||
      attempt.scanRequest.canonicalKey !== first.canonicalScanKey ||
      attempt.scanRequest.lane !== first.lane ||
      digest(buildSastScanPlanDigestPreimage(plan)) !==
        first.planDigest ||
      batches.some(
        (batch) =>
          !(
            profile.requiredScanners.includes(
              batch.scanner as 'OPENGREP' | 'TRIVY'
            ) ||
            profile.optionalScanners.includes(
              batch.scanner as 'OPENGREP' | 'TRIVY'
            )
          )
      )
    ) {
      throw new SastFindingCorrelationDurableScopeError();
    }

    const allBatches =
      await reader.sastFindingObservationBatch.findMany({
        where: {
          tenantId: first.tenantId,
          repositoryBindingId: first.repositoryBindingId,
          scanRequestId: first.scanRequestId,
          attemptId: first.attemptId
        },
        select: { id: true },
        orderBy: { id: 'asc' }
      });
    if (
      allBatches.length !== orderedIds.length ||
      allBatches.some((batch, index) => batch.id !== orderedIds[index])
    ) {
      throw new SastFindingCorrelationSourceSetIncompleteError();
    }

    const sourceCores = batches.map(toSourceCore);
    const sourceById = new Map(
      sourceCores.map((source) => [source.observationBatchId, source])
    );
    const expectedOccurrenceCount = sourceCores.reduce(
      (count, source) => count + source.occurrenceCount,
      0
    );
    if (
      expectedOccurrenceCount >
      SAST_FINDING_CORRELATION_LIMITS.maximumOccurrences
    ) {
      throw new SastFindingCorrelationOccurrenceError();
    }
    const occurrenceRows =
      await reader.sastFindingOccurrence.findMany({
        where: {
          tenantId: first.tenantId,
          repositoryBindingId: first.repositoryBindingId,
          scanRequestId: first.scanRequestId,
          attemptId: first.attemptId,
          observationBatchId: { in: orderedIds }
        },
        select: OCCURRENCE_SELECT,
        orderBy: [
          { observationBatchId: 'asc' },
          { ordinal: 'asc' }
        ],
        take: expectedOccurrenceCount + 1
      });
    if (occurrenceRows.length !== expectedOccurrenceCount) {
      throw new SastFindingCorrelationOccurrenceError();
    }
    const occurrences = parseOccurrences(
      occurrenceRows,
      sourceById,
      first
    );
    verifySourceCapabilities(sourceCores, occurrences);

    const existing =
      await reader.sastFindingCorrelationBatch.findFirst({
        where: {
          tenantId: first.tenantId,
          repositoryBindingId: first.repositoryBindingId,
          scanRequestId: first.scanRequestId,
          attemptId: first.attemptId,
          lifecycleContextKey: first.lifecycleContextKey
        },
        select: {
          id: true,
          sourceSetDigest: true,
          correlatedAt: true
        }
      });
    const context: SastFindingCorrelationContext = {
      scope: {
        tenantId: first.tenantId,
        repositoryBindingId: first.repositoryBindingId,
        scanRequestId: first.scanRequestId,
        attemptId: first.attemptId,
        lifecycleContextKey:
          first.lifecycleContextKey as `sha256:${string}`,
        targetRef: first.targetRef,
        commitSha: first.commitSha,
        lane: first.lane,
        canonicalScanKey:
          first.canonicalScanKey as `sha256:${string}`,
        planDigest: first.planDigest as `sha256:${string}`,
        profileId,
        profileDigest: first.profileDigest as `sha256:${string}`
      },
      requiredCapabilities: profile.requiredCapabilities.filter(
        (capability): capability is FindingCapability =>
          capability !== 'SBOM'
      ),
      sources: sourceCores,
      occurrences,
      ...(existing
        ? {
            existingCorrelation: {
              correlationBatchId: existing.id,
              sourceSetDigest:
                existing.sourceSetDigest as `sha256:${string}`,
              correlatedAt: existing.correlatedAt.toISOString()
            }
          }
        : {})
    };
    return isSastFindingCorrelationScopeValid(context.scope)
      ? context
      : null;
  }

  private async runSerializable<T>(
    operation: (
      transaction: Prisma.TransactionClient
    ) => Promise<T>
  ): Promise<T> {
    let lastError: unknown;
    for (
      let attempt = 0;
      attempt < SERIALIZABLE_ATTEMPTS;
      attempt += 1
    ) {
      try {
        return await this.prisma.$transaction(operation, {
          isolationLevel:
            Prisma.TransactionIsolationLevel.Serializable,
          maxWait: SERIALIZABLE_MAX_WAIT_MILLISECONDS,
          timeout: SERIALIZABLE_TIMEOUT_MILLISECONDS
        });
      } catch (error) {
        lastError = error;
        if (!isRetryableTransactionError(error)) throw error;
        if (attempt + 1 < SERIALIZABLE_ATTEMPTS) {
          await wait(serializableRetryDelay(attempt));
        }
      }
    }
    throw lastError;
  }
}

function validatePersistenceInput(
  input: Readonly<PersistSastFindingCorrelationInput>
): void {
  if (
    !isSastFindingCorrelationScopeValid(input.context.scope) ||
    !isCanonicalIsoTimestamp(input.correlatedAt) ||
    input.sources.length === 0 ||
    input.sources.length !== input.context.sources.length ||
    input.sources.length >
      SAST_FINDING_CORRELATION_LIMITS.maximumObservationBatches ||
    input.context.occurrences.length >
      SAST_FINDING_CORRELATION_LIMITS.maximumOccurrences ||
    input.edges.length > SAST_FINDING_CORRELATION_LIMITS.maximumEdges ||
    input.sources.some(
      (source) =>
        !isSastFindingCorrelationSourceBindingShapeValid(source, digest)
    ) ||
    digest(buildSastFindingCorrelationSourceSetPreimage(input.sources)) !==
      input.sourceSetDigest ||
    `finding-correlation://${digestHex(
      buildSastFindingCorrelationBatchKeyPreimage({
        scope: input.context.scope,
        sourceSetDigest: input.sourceSetDigest
      })
    )}` !== input.correlationBatchId
  ) {
    throw new SastFindingCorrelationDurableScopeError();
  }
  const contextSourceById = new Map(
    input.context.sources.map((source) => [
      source.observationBatchId,
      source
    ])
  );
  if (contextSourceById.size !== input.context.sources.length) {
    throw new SastFindingCorrelationDurableScopeError();
  }
  for (let index = 0; index < input.sources.length; index += 1) {
    const source = input.sources[index];
    if (!source) throw new SastFindingCorrelationDurableScopeError();
    const contextSource = contextSourceById.get(
      source.observationBatchId
    );
    const { sourceBindingDigest, ...sourceCore } = source;
    if (
      (index > 0 &&
        compareStrings(
          input.sources[index - 1]?.observationBatchId ?? '',
          source.observationBatchId
        ) >= 0) ||
      !contextSource ||
      canonicalizeSastFindingCorrelationSourceBinding(sourceCore) !==
        canonicalizeSastFindingCorrelationSourceBinding(contextSource) ||
      digest(
        canonicalizeSastFindingCorrelationSourceBinding(sourceCore)
      ) !== sourceBindingDigest
    ) {
      throw new SastFindingCorrelationDurableScopeError();
    }
  }
  const occurrenceById = new Map(
    input.context.occurrences.map((occurrence) => [
      occurrence.id,
      occurrence
    ])
  );
  const pairs = new Set<string>();
  const edgeDigests = new Set<string>();
  let previousPair: string | undefined;
  for (const edge of input.edges) {
    const pair = `${edge.decision.sourceOccurrenceId}\0${edge.decision.targetOccurrenceId}`;
    if (
      pairs.has(pair) ||
      edgeDigests.has(edge.decision.edgeDigest) ||
      (previousPair !== undefined &&
        compareStrings(previousPair, pair) >= 0) ||
      edge.decision.correlationBatchId !== input.correlationBatchId ||
      edge.decision.decidedAt !== input.correlatedAt ||
      !isSastFindingCorrelationEdgeShapeValid(edge.decision, digest) ||
      !isSastFindingCorrelationProvenanceShapeValid(
        edge.sourceProvenance,
        digest
      ) ||
      !isSastFindingCorrelationProvenanceShapeValid(
        edge.targetProvenance,
        digest
      ) ||
      !edgeMatchesOccurrences(
        edge,
        occurrenceById,
        contextSourceById,
        input.context.requiredCapabilities
      )
    ) {
      throw new SastFindingCorrelationOccurrenceError();
    }
    pairs.add(pair);
    edgeDigests.add(edge.decision.edgeDigest);
    previousPair = pair;
  }
}

function edgeMatchesOccurrences(
  edge: Readonly<PersistSastFindingCorrelationEdge>,
  occurrenceById: ReadonlyMap<
    string,
    Readonly<SastFindingCorrelationOccurrence>
  >,
  sourceByObservation: ReadonlyMap<
    string,
    Readonly<SastFindingCorrelationSourceBindingCore>
  >,
  requiredCapabilities: readonly FindingCapability[]
): boolean {
  const source = occurrenceById.get(
    edge.decision.sourceOccurrenceId
  );
  const target = occurrenceById.get(
    edge.decision.targetOccurrenceId
  );
  const sourceBinding = sourceByObservation.get(
    source?.observationBatchId ?? ''
  );
  const targetBinding = sourceByObservation.get(
    target?.observationBatchId ?? ''
  );
  return (
    Boolean(source) &&
    Boolean(target) &&
    Boolean(sourceBinding) &&
    Boolean(targetBinding) &&
    provenanceMatchesOccurrence(
      edge.sourceProvenance,
      'SOURCE',
      source,
      sourceBinding,
      requiredCapabilities
    ) &&
    provenanceMatchesOccurrence(
      edge.targetProvenance,
      'TARGET',
      target,
      targetBinding,
      requiredCapabilities
    ) &&
    edge.sourceProvenance.provenanceDigest ===
      edge.decision.sourceProvenanceDigest &&
    edge.targetProvenance.provenanceDigest ===
      edge.decision.targetProvenanceDigest
  );
}

function provenanceMatchesOccurrence(
  provenance: Readonly<SastFindingCorrelationProvenance>,
  side: 'SOURCE' | 'TARGET',
  occurrence: Readonly<SastFindingCorrelationOccurrence> | undefined,
  source: Readonly<SastFindingCorrelationSourceBindingCore> | undefined,
  requiredCapabilities: readonly FindingCapability[]
): boolean {
  if (!occurrence || !source) return false;
  const finding = occurrence.sourceFinding;
  const vulnerabilityDatabaseDigest =
    'vulnerabilityDatabaseDigest' in finding.provenance
      ? finding.provenance.vulnerabilityDatabaseDigest
      : undefined;
  return (
    provenance.side === side &&
    provenance.occurrenceId === occurrence.id &&
    provenance.observationBatchId === occurrence.observationBatchId &&
    provenance.lineageId === occurrence.lineageId &&
    provenance.normalizedFindingId === occurrence.normalizedFindingId &&
    provenance.scannerRunId === occurrence.scannerRunId &&
    provenance.scannerRunId === source.scannerRunId &&
    provenance.scanner === source.scanner &&
    provenance.capability === finding.capability &&
    source.capabilities.includes(finding.capability) &&
    provenance.authorityLevel ===
      (requiredCapabilities.includes(finding.capability)
        ? 'AUTHORITATIVE'
        : 'SUPPORTING_ONLY') &&
    provenance.severity === finding.severity &&
    provenance.fingerprintVersion === finding.fingerprint.version &&
    provenance.stableFingerprint ===
      finding.fingerprint.stableFingerprint &&
    provenance.fingerprintDecisionDigest ===
      finding.fingerprint.decisionDigest &&
    provenance.sourceFindingDigest ===
      digest(canonicalizeSastFingerprintedFinding(finding)) &&
    provenance.scannerVersion === finding.provenance.scannerVersion &&
    provenance.scannerImageDigest ===
      finding.provenance.scannerImageDigest &&
    provenance.ruleId === finding.provenance.ruleId &&
    provenance.ruleRevision === finding.provenance.ruleRevision &&
    provenance.ruleBundleDigest ===
      finding.provenance.ruleBundleDigest &&
    provenance.artifactDigest === finding.provenance.artifactDigest &&
    provenance.vulnerabilityDatabaseDigest ===
      vulnerabilityDatabaseDigest
  );
}

function observationRowsShareScope(
  rows: readonly ObservationRow[],
  first: Readonly<ObservationRow>
): boolean {
  return rows.every(
    (row) =>
      row.tenantId === first.tenantId &&
      row.repositoryBindingId === first.repositoryBindingId &&
      row.scanRequestId === first.scanRequestId &&
      row.attemptId === first.attemptId &&
      row.lifecycleContextKey === first.lifecycleContextKey &&
      row.targetRef === first.targetRef &&
      row.commitSha === first.commitSha &&
      row.lane === first.lane &&
      row.profileId === first.profileId &&
      row.profileDigest === first.profileDigest &&
      row.canonicalScanKey === first.canonicalScanKey &&
      row.planDigest === first.planDigest &&
      (row.scanner === 'OPENGREP' || row.scanner === 'TRIVY') &&
      isCanonicalCapabilities(row.capabilities) &&
      (row.capabilities as string[]).every((capability) =>
        (
          SAST_SCANNER_RESPONSIBILITIES[
            row.scanner as 'OPENGREP' | 'TRIVY'
          ].authoritativeCapabilities as readonly SastCapability[]
        ).includes(
          capability as FindingCapability
        )
      ) &&
      isDigest(row.lifecycleContextKey) &&
      isDigest(row.profileDigest) &&
      isDigest(row.canonicalScanKey) &&
      isDigest(row.planDigest) &&
      isDigest(row.sourceIdentityBatchDigest) &&
      row.findingCount >= 0 &&
      row.findingCount <=
        SAST_FINDING_CORRELATION_LIMITS.maximumOccurrences
  );
}

function toSourceCore(
  row: Readonly<ObservationRow>
): SastFindingCorrelationSourceBindingCore {
  if (
    row.scanner !== 'OPENGREP' &&
    row.scanner !== 'TRIVY'
  ) {
    throw new SastFindingCorrelationAuthorityError();
  }
  return {
    version: SAST_FINDING_CORRELATION_SOURCE_VERSION,
    observationBatchId: row.id,
    sourceIdentityBatchDigest:
      row.sourceIdentityBatchDigest as `sha256:${string}`,
    scannerRunId: row.scannerRunId,
    scanner: row.scanner,
    capabilities: [...(row.capabilities as FindingCapability[])],
    lifecycleContextKey:
      row.lifecycleContextKey as `sha256:${string}`,
    findingCount: row.findingCount,
    occurrenceCount: row.findingCount,
    observedAt: row.observedAt.toISOString()
  };
}

function parseOccurrences(
  rows: readonly OccurrenceRow[],
  sourceById: ReadonlyMap<
    string,
    Readonly<SastFindingCorrelationSourceBindingCore>
  >,
  scope: Readonly<ObservationRow>
): SastFindingCorrelationOccurrence[] {
  const expectedOrdinal = new Map<string, number>();
  const occurrenceIds = new Set<string>();
  const normalizedIds = new Set<string>();
  return rows.map((row) => {
    const source = sourceById.get(row.observationBatchId);
    const ordinal = expectedOrdinal.get(row.observationBatchId) ?? 0;
    if (
      !source ||
      row.ordinal !== ordinal ||
      occurrenceIds.has(row.id) ||
      normalizedIds.has(row.normalizedFindingId) ||
      row.tenantId !== scope.tenantId ||
      row.repositoryBindingId !== scope.repositoryBindingId ||
      row.scanRequestId !== scope.scanRequestId ||
      row.attemptId !== scope.attemptId ||
      row.scannerRunId !== source.scannerRunId ||
      row.observedAt.toISOString() !== source.observedAt ||
      !isSastFingerprintedFindingShapeValid(
        row.sourceFinding,
        digest,
        digest
      )
    ) {
      throw new SastFindingCorrelationOccurrenceError();
    }
    const finding = row.sourceFinding;
    if (
      finding.capability !== row.capability ||
      finding.fingerprint.version !== row.fingerprintVersion ||
      finding.fingerprint.stableFingerprint !==
        row.stableFingerprint ||
      finding.fingerprint.decisionDigest !==
        row.fingerprintDecisionDigest ||
      finding.provenance.scanner !== source.scanner
    ) {
      throw new SastFindingCorrelationOccurrenceError();
    }
    expectedOrdinal.set(row.observationBatchId, ordinal + 1);
    occurrenceIds.add(row.id);
    normalizedIds.add(row.normalizedFindingId);
    return {
      id: row.id,
      observationBatchId: row.observationBatchId,
      lineageId: row.lineageId,
      normalizedFindingId: row.normalizedFindingId,
      scannerRunId: row.scannerRunId,
      ordinal: row.ordinal,
      sourceFinding: finding
    };
  });
}

function verifySourceCapabilities(
  sources: readonly Readonly<SastFindingCorrelationSourceBindingCore>[],
  occurrences: readonly Readonly<SastFindingCorrelationOccurrence>[]
): void {
  const capabilitiesByBatch = new Map<string, Set<FindingCapability>>();
  for (const occurrence of occurrences) {
    const values =
      capabilitiesByBatch.get(occurrence.observationBatchId) ??
      new Set<FindingCapability>();
    values.add(occurrence.sourceFinding.capability);
    capabilitiesByBatch.set(occurrence.observationBatchId, values);
  }
  for (const source of sources) {
    const actual = SAST_CAPABILITIES.filter(
      (capability): capability is FindingCapability =>
        capability !== 'SBOM' &&
        (capabilitiesByBatch.get(source.observationBatchId)?.has(
          capability
        ) ?? false)
    );
    if (!sameStringArray(actual, source.capabilities)) {
      throw new SastFindingCorrelationAuthorityError();
    }
  }
}

function sameContext(
  left: Readonly<SastFindingCorrelationContext>,
  right: Readonly<SastFindingCorrelationContext>
): boolean {
  if (
    stableJson(left.scope) !== stableJson(right.scope) ||
    !sameStringArray(
      left.requiredCapabilities,
      right.requiredCapabilities
    ) ||
    left.sources.length !== right.sources.length ||
    left.occurrences.length !== right.occurrences.length
  ) {
    return false;
  }
  const rightSourceById = new Map(
    right.sources.map((source) => [source.observationBatchId, source])
  );
  if (
    left.sources.some((source) => {
      const other = rightSourceById.get(source.observationBatchId);
      return (
        !other ||
        canonicalizeSastFindingCorrelationSourceBinding(source) !==
          canonicalizeSastFindingCorrelationSourceBinding(other)
      );
    })
  ) {
    return false;
  }
  const rightOccurrenceById = new Map(
    right.occurrences.map((occurrence) => [occurrence.id, occurrence])
  );
  return left.occurrences.every((occurrence) => {
    const other = rightOccurrenceById.get(occurrence.id);
    return (
      Boolean(other) &&
      occurrence.observationBatchId === other?.observationBatchId &&
      occurrence.lineageId === other.lineageId &&
      occurrence.normalizedFindingId === other.normalizedFindingId &&
      occurrence.scannerRunId === other.scannerRunId &&
      occurrence.ordinal === other.ordinal &&
      canonicalizeSastFingerprintedFinding(
        occurrence.sourceFinding
      ) === canonicalizeSastFingerprintedFinding(other.sourceFinding)
    );
  });
}

function replayCorrelation(
  existing: Readonly<ExistingRow>,
  input: Readonly<PersistSastFindingCorrelationInput>
): PersistedSastFindingCorrelation {
  const scope = input.context.scope;
  const counts = correlationCounts(input.edges);
  const sourceByObservation = new Map(
    input.sources.map((source) => [
      source.observationBatchId,
      source
    ])
  );
  const edgeByDigest = new Map(
    input.edges.map((edge) => [edge.decision.edgeDigest, edge])
  );
  if (
    existing.id !== input.correlationBatchId ||
    existing.tenantId !== scope.tenantId ||
    existing.repositoryBindingId !== scope.repositoryBindingId ||
    existing.scanRequestId !== scope.scanRequestId ||
    existing.attemptId !== scope.attemptId ||
    existing.lifecycleContextKey !== scope.lifecycleContextKey ||
    existing.targetRef !== scope.targetRef ||
    existing.commitSha !== scope.commitSha ||
    existing.lane !== scope.lane ||
    existing.profileId !== scope.profileId ||
    existing.profileDigest !== scope.profileDigest ||
    existing.canonicalScanKey !== scope.canonicalScanKey ||
    existing.planDigest !== scope.planDigest ||
    existing.sourceSetDigest !== input.sourceSetDigest ||
    existing.sourceBatchCount !== input.sources.length ||
    existing.occurrenceCount !== input.context.occurrences.length ||
    existing.edgeCount !== input.edges.length ||
    existing.exactFingerprintCount !== counts.exactFingerprintCount ||
    existing.sameDependencyCveCount !== counts.sameDependencyCveCount ||
    existing.supportingEvidenceCount !== counts.supportingEvidenceCount ||
    existing.possibleOverlapCount !== counts.possibleOverlapCount ||
    existing.correlatedAt.toISOString() !== input.correlatedAt ||
    existing.sources.length !== input.sources.length ||
    existing.edges.length !== input.edges.length
  ) {
    throw new SastFindingCorrelationReplayConflictError();
  }
  for (const row of existing.sources) {
    const source = sourceByObservation.get(row.observationBatchId);
    if (
      !source ||
      row.id !==
        deterministicId(
          'finding-correlation-source',
          `${input.correlationBatchId}\0${source.sourceBindingDigest}`
        ) ||
      row.scannerRunId !== source.scannerRunId ||
      row.scanner !== source.scanner ||
      stableJson(row.capabilities) !==
        stableJson(source.capabilities) ||
      row.sourceIdentityBatchDigest !==
        source.sourceIdentityBatchDigest ||
      row.sourceBindingDigest !== source.sourceBindingDigest ||
      row.lifecycleContextKey !== source.lifecycleContextKey ||
      row.findingCount !== source.findingCount ||
      row.occurrenceCount !== source.occurrenceCount ||
      row.observedAt.toISOString() !== source.observedAt
    ) {
      throw new SastFindingCorrelationReplayConflictError();
    }
  }
  for (const row of existing.edges) {
    const edge = edgeByDigest.get(
      row.edgeDigest as `sha256:${string}`
    );
    if (!edge || !edgeReplayMatches(row, edge)) {
      throw new SastFindingCorrelationReplayConflictError();
    }
  }
  return {
    correlationBatchId: existing.id,
    sourceSetDigest: existing.sourceSetDigest as `sha256:${string}`,
    lifecycleContextKey:
      existing.lifecycleContextKey as `sha256:${string}`,
    sourceBatchCount: existing.sourceBatchCount,
    occurrenceCount: existing.occurrenceCount,
    edgeCount: existing.edgeCount,
    exactFingerprintCount: existing.exactFingerprintCount,
    sameDependencyCveCount: existing.sameDependencyCveCount,
    supportingEvidenceCount: existing.supportingEvidenceCount,
    possibleOverlapCount: existing.possibleOverlapCount,
    replayed: true,
    correlatedAt: existing.correlatedAt.toISOString()
  };
}

function edgeReplayMatches(
  row: Readonly<ExistingRow['edges'][number]>,
  edge: Readonly<PersistSastFindingCorrelationEdge>
): boolean {
  const decision = edge.decision;
  const provenanceBySide = new Map(
    row.provenances.map((provenance) => [provenance.side, provenance])
  );
  return (
    row.id ===
      deterministicId(
        'finding-correlation-edge',
        decision.edgeDigest
      ) &&
    row.kind === decision.kind &&
    row.sourceOccurrenceId === decision.sourceOccurrenceId &&
    row.targetOccurrenceId === decision.targetOccurrenceId &&
    stableJson(row.basisDigests) ===
      stableJson(decision.basisDigests) &&
    row.confidenceBasisPoints === decision.confidenceBasisPoints &&
    row.sourceProvenanceDigest ===
      decision.sourceProvenanceDigest &&
    row.targetProvenanceDigest ===
      decision.targetProvenanceDigest &&
    stableJson(row.safety) === stableJson(decision.safety) &&
    row.decidedAt.toISOString() === decision.decidedAt &&
    row.provenances.length === 2 &&
    provenanceReplayMatches(
      provenanceBySide.get('SOURCE'),
      edge.sourceProvenance,
      row.id
    ) &&
    provenanceReplayMatches(
      provenanceBySide.get('TARGET'),
      edge.targetProvenance,
      row.id
    )
  );
}

function provenanceReplayMatches(
  row: ExistingRow['edges'][number]['provenances'][number] | undefined,
  provenance: Readonly<SastFindingCorrelationProvenance>,
  edgeId: string
): boolean {
  return (
    Boolean(row) &&
    row?.id ===
      deterministicId(
        'finding-correlation-provenance',
        `${edgeId}\0${provenance.side}\0${provenance.provenanceDigest}`
      ) &&
    row.side === provenance.side &&
    row.occurrenceId === provenance.occurrenceId &&
    row.observationBatchId === provenance.observationBatchId &&
    row.lineageId === provenance.lineageId &&
    row.normalizedFindingId === provenance.normalizedFindingId &&
    row.scannerRunId === provenance.scannerRunId &&
    row.scanner === provenance.scanner &&
    row.capability === provenance.capability &&
    row.authorityLevel === provenance.authorityLevel &&
    row.severity === provenance.severity &&
    row.fingerprintVersion === provenance.fingerprintVersion &&
    row.stableFingerprint === provenance.stableFingerprint &&
    row.fingerprintDecisionDigest ===
      provenance.fingerprintDecisionDigest &&
    row.sourceFindingDigest === provenance.sourceFindingDigest &&
    row.scannerVersion === provenance.scannerVersion &&
    row.scannerImageDigest === provenance.scannerImageDigest &&
    row.ruleId === provenance.ruleId &&
    row.ruleRevision === provenance.ruleRevision &&
    row.ruleBundleDigest === provenance.ruleBundleDigest &&
    row.artifactDigest === provenance.artifactDigest &&
    (row.vulnerabilityDatabaseDigest ?? undefined) ===
      provenance.vulnerabilityDatabaseDigest &&
    row.provenanceDigest === provenance.provenanceDigest
  );
}

function provenanceRow(
  edgeId: string,
  correlationBatchId: string,
  scope: Readonly<SastFindingCorrelationContext['scope']>,
  provenance: Readonly<SastFindingCorrelationProvenance>,
  createdAt: Date
): Prisma.SastFindingCorrelationProvenanceCreateManyInput {
  return {
    id: deterministicId(
      'finding-correlation-provenance',
      `${edgeId}\0${provenance.side}\0${provenance.provenanceDigest}`
    ),
    correlationEdgeId: edgeId,
    correlationBatchId,
    tenantId: scope.tenantId,
    repositoryBindingId: scope.repositoryBindingId,
    scanRequestId: scope.scanRequestId,
    attemptId: scope.attemptId,
    side: provenance.side,
    occurrenceId: provenance.occurrenceId,
    observationBatchId: provenance.observationBatchId,
    lineageId: provenance.lineageId,
    normalizedFindingId: provenance.normalizedFindingId,
    scannerRunId: provenance.scannerRunId,
    scanner: provenance.scanner,
    capability: provenance.capability,
    authorityLevel: provenance.authorityLevel,
    severity: provenance.severity,
    fingerprintVersion: provenance.fingerprintVersion,
    stableFingerprint: provenance.stableFingerprint,
    fingerprintDecisionDigest:
      provenance.fingerprintDecisionDigest,
    sourceFindingDigest: provenance.sourceFindingDigest,
    scannerVersion: provenance.scannerVersion,
    scannerImageDigest: provenance.scannerImageDigest,
    ruleId: provenance.ruleId,
    ruleRevision: provenance.ruleRevision,
    ruleBundleDigest: provenance.ruleBundleDigest,
    artifactDigest: provenance.artifactDigest,
    vulnerabilityDatabaseDigest:
      provenance.vulnerabilityDatabaseDigest ?? null,
    provenanceDigest: provenance.provenanceDigest,
    createdAt
  };
}

function correlationCounts(
  edges: readonly Readonly<PersistSastFindingCorrelationEdge>[]
) {
  return {
    exactFingerprintCount: edges.filter(
      (edge) => edge.decision.kind === 'EXACT_FINGERPRINT'
    ).length,
    sameDependencyCveCount: edges.filter(
      (edge) => edge.decision.kind === 'SAME_DEPENDENCY_CVE'
    ).length,
    supportingEvidenceCount: edges.filter(
      (edge) => edge.decision.kind === 'SUPPORTING_EVIDENCE'
    ).length,
    possibleOverlapCount: edges.filter(
      (edge) => edge.decision.kind === 'POSSIBLE_OVERLAP'
    ).length
  };
}

async function createManyInChunks<T>(
  rows: readonly T[],
  create: (chunk: T[]) => Promise<{ count: number }>
): Promise<void> {
  for (let index = 0; index < rows.length; index += CREATE_MANY_CHUNK_SIZE) {
    const chunk = rows.slice(index, index + CREATE_MANY_CHUNK_SIZE);
    const result = await create(chunk);
    if (result.count !== chunk.length) {
      throw new SastFindingCorrelationReplayConflictError();
    }
  }
}

function isCanonicalCapabilities(value: Prisma.JsonValue): boolean {
  if (!Array.isArray(value)) return false;
  const capabilities = value as string[];
  const findingCapabilities = SAST_CAPABILITIES.filter(
    (capability): capability is FindingCapability => capability !== 'SBOM'
  );
  return capabilities.every(
    (capability, index) =>
      findingCapabilities.includes(capability as FindingCapability) &&
      (index === 0 ||
        findingCapabilities.indexOf(
          capabilities[index - 1] as FindingCapability
        ) <
          findingCapabilities.indexOf(
            capability as FindingCapability
          ))
  );
}

function parsePlan(value: Prisma.JsonValue | undefined): SastScanPlan | null {
  const candidate = value as unknown as SastScanPlan;
  return candidate && isSastScanPlanValid(candidate)
    ? candidate
    : null;
}

function sameStringArray(
  left: readonly string[],
  right: readonly string[]
): boolean {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(stableJson).join(',')}]`;
  }
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort(compareStrings)
      .map(
        (key) =>
          `${JSON.stringify(key)}:${stableJson(record[key])}`
      )
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

function deterministicId(prefix: string, value: string): string {
  return `${prefix}://${digestHex(value)}`;
}

function digest(value: string): `sha256:${string}` {
  return `sha256:${digestHex(value)}`;
}

function digestHex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function isDigest(value: unknown): value is `sha256:${string}` {
  return (
    typeof value === 'string' &&
    /^sha256:[a-f0-9]{64}$/u.test(value)
  );
}

function isCanonicalIsoTimestamp(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const timestamp = Date.parse(value);
  return (
    Number.isFinite(timestamp) &&
    new Date(timestamp).toISOString() === value
  );
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function serializableRetryDelay(attempt: number): number {
  const ceiling = Math.min(
    SERIALIZABLE_RETRY_BASE_DELAY_MILLISECONDS * 2 ** attempt,
    SERIALIZABLE_RETRY_MAX_DELAY_MILLISECONDS
  );
  return randomInt(1, ceiling + 1);
}

function isRetryableTransactionError(error: unknown): boolean {
  return (
    error instanceof Prisma.PrismaClientKnownRequestError &&
    (error.code === 'P2034' || error.code === 'P2002')
  );
}
