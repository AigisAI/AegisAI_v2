import { Prisma } from '@prisma/client';
import {
  buildSastScanPlanDigestPreimage,
  canonicalizeSastFindingCorrelationEdge,
  canonicalizeSastFindingCorrelationProvenance,
  type SastScanPlan
} from '@aegisai/shared';

import {
  SastFindingCorrelationService
} from '../../src/scan-plane/sast-finding-correlation.service';
import {
  SastFindingCorrelationDurableScopeError,
  SastFindingCorrelationOccurrenceError,
  SastFindingCorrelationStore,
  type PersistSastFindingCorrelationInput,
  type SastFindingCorrelationContext
} from '../../src/scan-plane/sast-finding-correlation.store';
import {
  PrismaSastFindingCorrelationStore
} from '../../src/scan-plane/prisma-sast-finding-correlation.store';
import { PrismaService } from '../../src/prisma/prisma.service';
import {
  correlationFixture,
  correlationFixtureClock
} from '../support/sast-finding-correlation-fixtures';
import { fixtureDigest } from '../support/sast-finding-lineage-fixtures';
import { durableSastScanPlan } from '../support/sast-scan-plan-fixtures';

describe('PrismaSastFindingCorrelationStore', () => {
  it('loads the complete durable context through the real authority readers', async () => {
    const plan = durableSastScanPlan();
    const planDigest = fixtureDigest(
      buildSastScanPlanDigestPreimage(plan)
    );
    const fixture = await correlationFixture({ planDigest });
    const reader = correlationReader(fixture.context, plan);
    const store = new PrismaSastFindingCorrelationStore(
      reader as unknown as PrismaService
    );

    await expect(
      store.loadContext(
        fixture.context.sources.map(
          (source) => source.observationBatchId
        )
      )
    ).resolves.toEqual(fixture.context);
    expect(
      reader.sastFindingOccurrence.findMany
    ).toHaveBeenCalledWith(
      expect.objectContaining({
        take: fixture.context.occurrences.length + 1
      })
    );
  });

  it('rejects a durable context change during the serializable re-read', async () => {
    const plan = durableSastScanPlan();
    const planDigest = fixtureDigest(
      buildSastScanPlanDigestPreimage(plan)
    );
    const fixture = await correlationFixture({ planDigest });
    const reader = correlationReader(fixture.context, plan);
    const transaction = durableCorrelationTransaction(
      fixture.context,
      plan,
      { observedAtOffsetMilliseconds: 1 }
    );
    const prisma = {
      ...reader,
      $transaction: jest.fn(
        async (
          operation: (
            client: typeof transaction
          ) => Promise<unknown>
        ) => operation(transaction)
      )
    };
    const store = new PrismaSastFindingCorrelationStore(
      prisma as unknown as PrismaService
    );

    const initialContext = await store.loadContext(
      fixture.context.sources.map(
        (source) => source.observationBatchId
      )
    );
    expect(initialContext).toEqual(fixture.context);
    if (!initialContext) {
      throw new Error('Missing initial durable correlation context.');
    }
    const input = await buildPersistenceInput({
      observations: fixture.observations,
      context: initialContext
    });
    await expect(store.correlate(input)).rejects.toBeInstanceOf(
      SastFindingCorrelationDurableScopeError
    );
    expect(
      transaction.sastFindingCorrelationBatch.create
    ).not.toHaveBeenCalled();
  });

  it('writes the complete source, edge, and two-sided provenance ledger in one serializable transaction', async () => {
    const fixture = await correlationFixture({
      repeatedOpenGrep: true,
      crossToolCve: true
    });
    const input = await buildPersistenceInput(fixture);
    const transaction = correlationTransaction();
    const prisma = serializablePrisma(transaction);
    const store = new PrismaSastFindingCorrelationStore(
      prisma as unknown as PrismaService
    );
    mockCorrelationContext(store, fixture.context);

    const result = await store.correlate(input);

    expect(result).toMatchObject({
      sourceBatchCount: 2,
      occurrenceCount: 3,
      edgeCount: input.edges.length,
      replayed: false
    });
    expect(prisma.$transaction).toHaveBeenCalledWith(
      expect.any(Function),
      {
        isolationLevel: 'Serializable',
        maxWait: 5_000,
        timeout: 120_000
      }
    );
    expect(
      transaction.sastFindingCorrelationBatch.create
    ).toHaveBeenCalledWith({
      data: expect.objectContaining({
        id: input.correlationBatchId,
        sourceSetDigest: input.sourceSetDigest,
        sourceBatchCount: 2,
        occurrenceCount: 3,
        edgeCount: input.edges.length
      })
    });
    expect(
      transaction.sastFindingCorrelationSource.createMany
    ).toHaveBeenCalledWith({
      data: expect.arrayContaining([
        expect.objectContaining({ scanner: 'OPENGREP' }),
        expect.objectContaining({ scanner: 'TRIVY' })
      ])
    });
    const edgeRows =
      transaction.sastFindingCorrelationEdge.createMany.mock.calls[0]?.[0]
        ?.data ?? [];
    const provenanceRows =
      transaction.sastFindingCorrelationProvenance.createMany.mock.calls[0]?.[0]
        ?.data ?? [];
    expect(edgeRows).toHaveLength(input.edges.length);
    expect(provenanceRows).toHaveLength(input.edges.length * 2);
    expect(
      new Set(
        provenanceRows.map((row: { side: string }) => row.side)
      )
    ).toEqual(new Set(['SOURCE', 'TARGET']));
    expect(transaction.auditEvent.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        eventType: 'finding.correlated',
        metadata: expect.objectContaining({
          findingMergeAllowed: false,
          severityInheritanceAllowed: false,
          publicationAuthority: false
        })
      })
    });
  });

  it('retries serialization and uniqueness races with a fresh exact-set read', async () => {
    const fixture = await correlationFixture();
    const input = await buildPersistenceInput(fixture);
    const transaction = correlationTransaction();
    const retryError = new Prisma.PrismaClientKnownRequestError(
      'serialization race',
      { code: 'P2034', clientVersion: '5.22.0' }
    );
    const prisma = {
      $transaction: jest
        .fn()
        .mockRejectedValueOnce(retryError)
        .mockImplementation(
          async (
            operation: (client: typeof transaction) => Promise<unknown>
          ) => operation(transaction)
        )
    };
    const store = new PrismaSastFindingCorrelationStore(
      prisma as unknown as PrismaService
    );
    mockCorrelationContext(store, fixture.context);

    await expect(store.correlate(input)).resolves.toMatchObject({
      occurrenceCount: 1,
      replayed: false
    });
    expect(prisma.$transaction).toHaveBeenCalledTimes(2);
  });

  it('rejects source bindings that are not the exact canonical durable context set', async () => {
    const fixture = await correlationFixture({ crossToolCve: true });
    const input = await buildPersistenceInput(fixture);
    const prisma = serializablePrisma(correlationTransaction());
    const store = new PrismaSastFindingCorrelationStore(
      prisma as unknown as PrismaService
    );
    const forgedContext: SastFindingCorrelationContext = {
      ...input.context,
      sources: input.context.sources.map((source, index) =>
        index === 0
          ? { ...source, scannerRunId: `${source.scannerRunId}-forged` }
          : source
      )
    };

    await expect(
      store.correlate({ ...input, context: forgedContext })
    ).rejects.toBeInstanceOf(SastFindingCorrelationDurableScopeError);
    expect(prisma.$transaction).not.toHaveBeenCalled();
  });

  it('rejects a non-canonical edge order before opening a transaction', async () => {
    const fixture = await correlationFixture({
      repeatedOpenGrep: true,
      crossToolCve: true
    });
    const input = await buildPersistenceInput(fixture);
    expect(input.edges.length).toBeGreaterThan(1);
    const prisma = serializablePrisma(correlationTransaction());
    const store = new PrismaSastFindingCorrelationStore(
      prisma as unknown as PrismaService
    );

    await expect(
      store.correlate({ ...input, edges: [...input.edges].reverse() })
    ).rejects.toBeInstanceOf(SastFindingCorrelationOccurrenceError);
    expect(prisma.$transaction).not.toHaveBeenCalled();
  });

  it('rejects self-consistent provenance that does not match its durable occurrence', async () => {
    const fixture = await correlationFixture({
      repeatedOpenGrep: true
    });
    const input = await buildPersistenceInput(fixture);
    const edge = input.edges[0];
    if (!edge) throw new Error('Expected an exact correlation edge.');
    const {
      provenanceDigest: _provenanceDigest,
      ...provenanceCore
    } = edge.sourceProvenance;
    expect(_provenanceDigest).toMatch(/^sha256:/u);
    const forgedProvenanceCore = {
      ...provenanceCore,
      severity:
        provenanceCore.severity === 'CRITICAL'
          ? ('LOW' as const)
          : ('CRITICAL' as const)
    };
    const forgedProvenance = {
      ...forgedProvenanceCore,
      provenanceDigest: fixtureDigest(
        canonicalizeSastFindingCorrelationProvenance(
          forgedProvenanceCore
        )
      )
    };
    const { edgeDigest: _edgeDigest, ...decisionCore } = edge.decision;
    expect(_edgeDigest).toMatch(/^sha256:/u);
    const forgedDecisionCore = {
      ...decisionCore,
      sourceProvenanceDigest: forgedProvenance.provenanceDigest
    };
    const forgedEdge = {
      ...edge,
      sourceProvenance: forgedProvenance,
      decision: {
        ...forgedDecisionCore,
        edgeDigest: fixtureDigest(
          canonicalizeSastFindingCorrelationEdge(
            forgedDecisionCore
          )
        )
      }
    };
    const prisma = serializablePrisma(correlationTransaction());
    const store = new PrismaSastFindingCorrelationStore(
      prisma as unknown as PrismaService
    );

    await expect(
      store.correlate({ ...input, edges: [forgedEdge] })
    ).rejects.toBeInstanceOf(SastFindingCorrelationOccurrenceError);
    expect(prisma.$transaction).not.toHaveBeenCalled();
  });
});

async function buildPersistenceInput(fixture: {
  observations: Awaited<ReturnType<typeof correlationFixture>>['observations'];
  context: SastFindingCorrelationContext;
}): Promise<PersistSastFindingCorrelationInput> {
  const handoffStore = {
    loadContext: jest.fn().mockResolvedValue(fixture.context),
    correlate: jest.fn().mockImplementation(
      (input: PersistSastFindingCorrelationInput) => ({
        correlationBatchId: input.correlationBatchId,
        sourceSetDigest: input.sourceSetDigest,
        lifecycleContextKey:
          input.context.scope.lifecycleContextKey,
        sourceBatchCount: input.sources.length,
        occurrenceCount: input.context.occurrences.length,
        edgeCount: input.edges.length,
        exactFingerprintCount: input.edges.filter(
          (edge) => edge.decision.kind === 'EXACT_FINGERPRINT'
        ).length,
        sameDependencyCveCount: input.edges.filter(
          (edge) => edge.decision.kind === 'SAME_DEPENDENCY_CVE'
        ).length,
        supportingEvidenceCount: input.edges.filter(
          (edge) => edge.decision.kind === 'SUPPORTING_EVIDENCE'
        ).length,
        possibleOverlapCount: input.edges.filter(
          (edge) => edge.decision.kind === 'POSSIBLE_OVERLAP'
        ).length,
        replayed: false,
        correlatedAt: input.correlatedAt
      })
    )
  } as unknown as SastFindingCorrelationStore;
  const service = new SastFindingCorrelationService(handoffStore);
  const result = await service.correlate(
    { observations: fixture.observations },
    correlationFixtureClock
  );
  if (result.outcome !== 'CORRELATED') {
    throw new Error('Correlation persistence fixture rejected.');
  }
  const input = (handoffStore.correlate as jest.Mock).mock.calls[0]?.[0];
  if (!input) throw new Error('Correlation persistence input missing.');
  return input as PersistSastFindingCorrelationInput;
}

function correlationTransaction() {
  return {
    sastFindingCorrelationBatch: {
      findFirst: jest.fn().mockResolvedValue(null),
      create: jest.fn().mockResolvedValue({ id: 'correlation-1' })
    },
    sastFindingCorrelationSource: {
      createMany: jest.fn().mockImplementation(
        ({ data }: { data: unknown[] }) => ({ count: data.length })
      )
    },
    sastFindingCorrelationEdge: {
      createMany: jest.fn().mockImplementation(
        ({ data }: { data: unknown[] }) => ({ count: data.length })
      )
    },
    sastFindingCorrelationProvenance: {
      createMany: jest.fn().mockImplementation(
        ({ data }: { data: unknown[] }) => ({ count: data.length })
      )
    },
    auditEvent: {
      create: jest.fn().mockResolvedValue({ id: 'audit-1' })
    }
  };
}

function correlationReader(
  context: Readonly<SastFindingCorrelationContext>,
  plan: Readonly<SastScanPlan>,
  options: { observedAtOffsetMilliseconds?: number } = {}
) {
  const offset = options.observedAtOffsetMilliseconds ?? 0;
  const observedAtByBatch = new Map(
    context.sources.map((source) => [
      source.observationBatchId,
      new Date(Date.parse(source.observedAt) + offset)
    ])
  );
  const observationRows = context.sources.map((source) => ({
    id: source.observationBatchId,
    tenantId: context.scope.tenantId,
    repositoryBindingId: context.scope.repositoryBindingId,
    scanRequestId: context.scope.scanRequestId,
    attemptId: context.scope.attemptId,
    scannerRunId: source.scannerRunId,
    lifecycleContextKey: context.scope.lifecycleContextKey,
    targetRef: context.scope.targetRef,
    commitSha: context.scope.commitSha,
    lane: context.scope.lane,
    scanner: source.scanner,
    capabilities: [...source.capabilities],
    profileId: context.scope.profileId,
    profileDigest: context.scope.profileDigest,
    canonicalScanKey: context.scope.canonicalScanKey,
    planDigest: context.scope.planDigest,
    sourceIdentityBatchDigest: source.sourceIdentityBatchDigest,
    findingCount: source.findingCount,
    observedAt: observedAtByBatch.get(source.observationBatchId)
  }));
  const occurrenceRows = context.occurrences.map((occurrence) => {
    const observedAt = observedAtByBatch.get(
      occurrence.observationBatchId
    );
    if (!observedAt) {
      throw new Error('Missing durable correlation source fixture.');
    }
    const finding = occurrence.sourceFinding;
    return {
      id: occurrence.id,
      tenantId: context.scope.tenantId,
      repositoryBindingId: context.scope.repositoryBindingId,
      scanRequestId: context.scope.scanRequestId,
      attemptId: context.scope.attemptId,
      scannerRunId: occurrence.scannerRunId,
      observationBatchId: occurrence.observationBatchId,
      lineageId: occurrence.lineageId,
      normalizedFindingId: occurrence.normalizedFindingId,
      ordinal: occurrence.ordinal,
      capability: finding.capability,
      fingerprintVersion: finding.fingerprint.version,
      stableFingerprint: finding.fingerprint.stableFingerprint,
      fingerprintDecisionDigest: finding.fingerprint.decisionDigest,
      sourceFinding: finding,
      observedAt
    };
  });
  return {
    sastFindingObservationBatch: {
      findMany: jest.fn(
        async (input: { select?: Record<string, unknown> }) =>
          input.select?.id === true &&
          Object.keys(input.select).length === 1
            ? context.sources.map((source) => ({
                id: source.observationBatchId
              }))
            : observationRows
      )
    },
    sastFindingOccurrence: {
      findMany: jest.fn().mockResolvedValue(occurrenceRows)
    },
    sastFindingCorrelationBatch: {
      findFirst: jest.fn().mockResolvedValue(null)
    },
    sastScanAttempt: {
      findFirst: jest.fn().mockResolvedValue({
        scanRequest: {
          lane: context.scope.lane,
          targetRef: context.scope.targetRef,
          commitSha: context.scope.commitSha,
          canonicalKey: context.scope.canonicalScanKey,
          sastQueueReservation: { immutablePlan: plan }
        }
      })
    }
  };
}

function durableCorrelationTransaction(
  context: Readonly<SastFindingCorrelationContext>,
  plan: Readonly<SastScanPlan>,
  options: { observedAtOffsetMilliseconds?: number } = {}
) {
  const writes = correlationTransaction();
  const reader = correlationReader(context, plan, options);
  return {
    ...writes,
    ...reader,
    sastFindingCorrelationBatch: {
      ...writes.sastFindingCorrelationBatch,
      ...reader.sastFindingCorrelationBatch
    }
  };
}

function serializablePrisma<T extends object>(transaction: T) {
  return {
    $transaction: jest.fn(
      async (operation: (client: T) => Promise<unknown>) =>
        operation(transaction)
    )
  };
}

function mockCorrelationContext(
  store: PrismaSastFindingCorrelationStore,
  context: SastFindingCorrelationContext
): void {
  jest
    .spyOn(
      store as unknown as {
        readContext: (
          ...args: unknown[]
        ) => Promise<SastFindingCorrelationContext | null>;
      },
      'readContext'
    )
    .mockResolvedValue(context);
}
