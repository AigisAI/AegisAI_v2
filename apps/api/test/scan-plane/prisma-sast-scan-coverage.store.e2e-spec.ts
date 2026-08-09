import { createHash } from 'node:crypto';

import { Prisma } from '@prisma/client';
import {
  SAST_APPROVED_PROFILE_DIGESTS,
  SAST_FINDING_CORRELATION_VERSION,
  canonicalizeSastExternalPublicationDecision,
  canonicalizeSastFindingCorrelationResult,
  sastFindingCorrelationAuthority,
  type SastFindingCorrelationResult
} from '@aegisai/shared';

import { PrismaService } from '../../src/prisma/prisma.service';
import { PrismaSastScanCoverageStore } from '../../src/scan-plane/prisma-sast-scan-coverage.store';
import { SastScanCoverageService } from '../../src/scan-plane/sast-scan-coverage.service';
import {
  SastScanCoverageStore,
  type PersistSastScanCoverageInput,
  type SastScanCoverageContext,
  type SastScannerCoverageDurableEvidence
} from '../../src/scan-plane/sast-scan-coverage.store';

describe('PrismaSastScanCoverageStore', () => {
  it('writes scanner records, coverage, and zero-publication authority atomically', async () => {
    const fixture = await persistenceFixture();
    const transaction = coverageTransaction();
    const prisma = serializablePrisma(transaction);
    const store = new PrismaSastScanCoverageStore(
      prisma as unknown as PrismaService
    );
    mockCoverageContext(store, fixture.context);

    const result = await store.persist(fixture.input);

    expect(result).toMatchObject({
      coverageDecisionId:
        fixture.input.decision.coverageDecisionId,
      publicationDecisionId:
        fixture.input.publication.publicationDecisionId,
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
      transaction.sastScanCoverageDecision.create
    ).toHaveBeenCalledWith({
      data: expect.objectContaining({
        state: 'COMPLETE',
        recordsDigest: fixture.input.decision.recordsDigest,
        decisionDigest: fixture.input.decision.decisionDigest
      })
    });
    const recordRows =
      transaction.sastScannerCoverageRecord.createMany.mock.calls[0]?.[0]
        ?.data ?? [];
    expect(recordRows).toHaveLength(3);
    expect(recordRows).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ scanner: 'OPENGREP', required: true }),
        expect.objectContaining({ scanner: 'TRIVY', required: true }),
        expect.objectContaining({
          scanner: 'SYFT',
          required: false,
          executionStatus: 'NOT_STARTED'
        })
      ])
    );
    expect(
      transaction.sastExternalPublicationDecision.create
    ).toHaveBeenCalledWith({
      data: expect.objectContaining({
        externalCommentAllowed: false,
        blockingStatusAllowed: false,
        aiAdvisoryAllowed: false,
        lifecycleMutationAllowed: false,
        latestTargetAuthority: 'UNAVAILABLE',
        staleStatus: 'UNKNOWN',
        comparabilityStatus: 'UNKNOWN'
      })
    });
  });

  it('retries a serialization race with a fresh durable context read', async () => {
    const fixture = await persistenceFixture();
    const transaction = coverageTransaction();
    const retry = new Prisma.PrismaClientKnownRequestError(
      'serialization race',
      { code: 'P2034', clientVersion: '5.22.0' }
    );
    const prisma = {
      $transaction: jest
        .fn()
        .mockImplementationOnce(
          async (
            operation: (client: typeof transaction) => Promise<unknown>
          ) => {
            await operation(transaction);
            throw retry;
          }
        )
        .mockImplementation(
          async (
            operation: (client: typeof transaction) => Promise<unknown>
          ) => operation(transaction)
        )
    };
    const store = new PrismaSastScanCoverageStore(
      prisma as unknown as PrismaService
    );
    const read = mockCoverageContext(store, fixture.context);

    await expect(store.persist(fixture.input)).resolves.toMatchObject({
      replayed: false
    });
    expect(prisma.$transaction).toHaveBeenCalledTimes(2);
    expect(read).toHaveBeenCalledTimes(2);
  });

  it('rejects late durable-state drift before any coverage row is written', async () => {
    const fixture = await persistenceFixture();
    const transaction = coverageTransaction();
    const prisma = serializablePrisma(transaction);
    const store = new PrismaSastScanCoverageStore(
      prisma as unknown as PrismaService
    );
    mockCoverageContext(store, {
      ...fixture.context,
      scanners: fixture.context.scanners.map((scanner) =>
        scanner.scanner === 'TRIVY'
          ? { ...scanner, artifactDigest: digest('late-drift') }
          : scanner
      )
    });

    await expect(store.persist(fixture.input)).rejects.toMatchObject({
      name: 'SastScanCoverageDurableScopeError',
      reason: 'CONTEXT_DRIFT'
    });
    expect(
      transaction.sastScanCoverageDecision.create
    ).not.toHaveBeenCalled();
  });

  it('accepts only an exact replay and performs no duplicate writes', async () => {
    const fixture = await persistenceFixture();
    const transaction = coverageTransaction(
      existingCoverage(fixture.input)
    );
    const store = new PrismaSastScanCoverageStore(
      serializablePrisma(transaction) as unknown as PrismaService
    );
    mockCoverageContext(store, fixture.context);

    await expect(store.persist(fixture.input)).resolves.toMatchObject({
      replayed: true,
      decisionDigest: fixture.input.decision.decisionDigest,
      publicationDecisionDigest:
        fixture.input.publication.decisionDigest
    });
    expect(
      transaction.sastScanCoverageDecision.create
    ).not.toHaveBeenCalled();
    expect(
      transaction.sastScannerCoverageRecord.createMany
    ).not.toHaveBeenCalled();
    expect(
      transaction.sastExternalPublicationDecision.create
    ).not.toHaveBeenCalled();
  });

  it('rejects reordered records before opening a transaction', async () => {
    const fixture = await persistenceFixture();
    const prisma = serializablePrisma(coverageTransaction());
    const store = new PrismaSastScanCoverageStore(
      prisma as unknown as PrismaService
    );

    await expect(
      store.persist({
        ...fixture.input,
        records: [...fixture.input.records].reverse()
      })
    ).rejects.toMatchObject({
      name: 'SastScanCoverageDurableScopeError',
      reason: 'RECORD_SET_INVALID'
    });
    expect(prisma.$transaction).not.toHaveBeenCalled();
  });

  it('refuses to persist a nonterminal pending snapshot', async () => {
    const fixture = await persistenceFixture();
    const pending = await pendingPersistenceFixture();
    const prisma = serializablePrisma(coverageTransaction());
    const store = new PrismaSastScanCoverageStore(
      prisma as unknown as PrismaService
    );

    await expect(store.persist(pending)).rejects.toMatchObject({
      name: 'SastScanCoverageDurableScopeError',
      reason: 'RECORD_SET_INVALID'
    });
    expect(prisma.$transaction).not.toHaveBeenCalled();
    expect(fixture.input.decision.state).toBe('COMPLETE');
  });

  it('rejects a publication projection that omits a mandatory fail-closed reason', async () => {
    const fixture = await persistenceFixture();
    const prisma = serializablePrisma(coverageTransaction());
    const store = new PrismaSastScanCoverageStore(
      prisma as unknown as PrismaService
    );
    const { decisionDigest: _decisionDigest, ...publicationCore } =
      fixture.input.publication;
    const changedCore = {
      ...publicationCore,
      reasonCodes: publicationCore.reasonCodes.filter(
        (reason) => reason !== 'STALE_STATUS_UNKNOWN'
      )
    };
    const changedPublication = {
      ...changedCore,
      decisionDigest: digest(
        canonicalizeSastExternalPublicationDecision(changedCore)
      )
    };

    await expect(
      store.persist({
        ...fixture.input,
        publication: changedPublication
      })
    ).rejects.toMatchObject({
      name: 'SastScanCoverageDurableScopeError',
      reason: 'PUBLICATION_PROJECTION_INVALID'
    });
    expect(prisma.$transaction).not.toHaveBeenCalled();
    void _decisionDigest;
  });
});

class HandoffCoverageStore extends SastScanCoverageStore {
  persisted?: Readonly<PersistSastScanCoverageInput>;

  constructor(private readonly context: SastScanCoverageContext) {
    super();
  }

  async loadContext(): Promise<SastScanCoverageContext> {
    return this.context;
  }

  async persist(input: Readonly<PersistSastScanCoverageInput>) {
    this.persisted = input;
    return {
      coverageDecisionId: input.decision.coverageDecisionId,
      decisionDigest: input.decision.decisionDigest,
      publicationDecisionId:
        input.publication.publicationDecisionId,
      publicationDecisionDigest: input.publication.decisionDigest,
      decidedAt: input.decision.decidedAt,
      replayed: false
    };
  }

  async verifyLifecycleSource() {
    return 'REJECTED' as const;
  }
}

async function persistenceFixture(): Promise<{
  context: SastScanCoverageContext;
  input: PersistSastScanCoverageInput;
}> {
  const context = coverageContext();
  const handoff = new HandoffCoverageStore(context);
  const result = await new SastScanCoverageService(handoff).evaluate(
    { correlation: correlationResult(context) },
    () => new Date('2026-08-02T13:00:00.000Z')
  );
  if (result.outcome !== 'EVALUATED' || !handoff.persisted) {
    throw new Error('Coverage persistence fixture was rejected.');
  }
  return { context, input: handoff.persisted };
}

async function pendingPersistenceFixture(): Promise<PersistSastScanCoverageInput> {
  const context = coverageContext();
  context.scanners = context.scanners.map((scanner) =>
    scanner.scanner === 'TRIVY'
      ? {
          ...scanner,
          executionStatus: 'RUNNING',
          artifactIngestionId: null,
          artifactEnvelopeDigest: null,
          artifactDigest: null,
          dispositionDecisionId: null,
          dispositionDecisionDigest: null,
          artifactAccepted: false,
          normalizationEligible: false,
          correlationSourceId: null,
          observationBatchId: null,
          correlationSourceBindingDigest: null,
          correlationSourceValid: false
        }
      : scanner
  );
  const handoff = new HandoffCoverageStore(context);
  const result = await new SastScanCoverageService(handoff).evaluate(
    { correlation: correlationResult(context) },
    () => new Date('2026-08-02T13:00:00.000Z')
  );
  if (result.outcome !== 'EVALUATED' || result.decision.state !== 'PENDING') {
    throw new Error('Pending coverage fixture was rejected.');
  }
  return {
    context,
    records: result.records,
    decision: result.decision,
    publication: result.publication
  };
}

function coverageContext(): SastScanCoverageContext {
  const correlationBatchId = id('finding-correlation', 'coverage');
  const sourceSetDigest = digest('source-set');
  const lifecycleContextKey = digest('lifecycle-context');
  return {
    scope: {
      tenantId: 'tenant-1',
      repositoryBindingId: 'repository-1',
      scanRequestId: 'scan-1',
      attemptId: 'attempt-1',
      lifecycleContextKey,
      targetRef: 'refs/heads/main',
      commitSha: 'a'.repeat(40),
      lane: 'FAST',
      profileId: 'JAVA_FAST_V1',
      profileDigest: SAST_APPROVED_PROFILE_DIGESTS.JAVA_FAST_V1,
      canonicalScanKey: digest('canonical-key'),
      planDigest: digest('plan'),
      scannerSetDigest: digest('scanner-set'),
      correlationBatchId,
      correlationSourceSetDigest: sourceSetDigest
    },
    correlation: {
      correlationBatchId,
      sourceSetDigest,
      lifecycleContextKey,
      sourceBatchCount: 2,
      occurrenceCount: 0,
      edgeCount: 0,
      exactFingerprintCount: 0,
      sameDependencyCveCount: 0,
      supportingEvidenceCount: 0,
      possibleOverlapCount: 0,
      correlatedAt: '2026-08-02T12:59:00.000Z',
      sourceSetValid: true
    },
    scanners: [
      scannerEvidence('OPENGREP'),
      scannerEvidence('TRIVY')
    ]
  };
}

function correlationResult(
  context: Readonly<SastScanCoverageContext>
): SastFindingCorrelationResult {
  const core = {
    version: SAST_FINDING_CORRELATION_VERSION,
    outcome: 'CORRELATED' as const,
    correlationBatchId: context.correlation.correlationBatchId,
    sourceSetDigest: context.correlation.sourceSetDigest,
    lifecycleContextKey: context.correlation.lifecycleContextKey,
    sourceBatchCount: context.correlation.sourceBatchCount,
    occurrenceCount: context.correlation.occurrenceCount,
    edgeCount: context.correlation.edgeCount,
    exactFingerprintCount:
      context.correlation.exactFingerprintCount,
    sameDependencyCveCount:
      context.correlation.sameDependencyCveCount,
    supportingEvidenceCount:
      context.correlation.supportingEvidenceCount,
    possibleOverlapCount:
      context.correlation.possibleOverlapCount,
    replayed: false,
    correlatedAt: context.correlation.correlatedAt,
    authority: sastFindingCorrelationAuthority()
  };
  return {
    ...core,
    resultDigest: digest(
      canonicalizeSastFindingCorrelationResult(core)
    )
  };
}

function scannerEvidence(
  scanner: 'OPENGREP' | 'TRIVY'
): SastScannerCoverageDurableEvidence {
  return {
    scanner,
    executionStatus: 'SUCCEEDED',
    requiredBinding: true,
    scannerRunId: `scanner-run-${scanner.toLowerCase()}`,
    scannerVersion: '1.0.0',
    scannerImageDigest: digest(`${scanner}-image`),
    wrapperDigest: digest(`${scanner}-wrapper`),
    ruleBundleDigest: digest(`${scanner}-rules`),
    vulnerabilityDatabaseDigest:
      scanner === 'TRIVY' ? digest('trivy-db') : null,
    schemaBundleDigest: digest('schema-bundle'),
    normalizerBundleDigest: digest('normalizer-bundle'),
    provenanceValid: true,
    artifactIngestionId: `ingestion-${scanner.toLowerCase()}`,
    artifactEnvelopeDigest: digest(`${scanner}-envelope`),
    artifactDigest: digest(`${scanner}-artifact`),
    dispositionDecisionId: `disposition-${scanner.toLowerCase()}`,
    dispositionDecisionDigest: digest(`${scanner}-disposition`),
    artifactAccepted: true,
    normalizationEligible: true,
    artifactBindingValid: true,
    correlationSourceId: `correlation-source-${scanner.toLowerCase()}`,
    observationBatchId: id('finding-observation', scanner),
    correlationSourceBindingDigest: digest(`${scanner}-source`),
    correlationSourceValid: true
  };
}

function coverageTransaction(existing: unknown = null) {
  return {
    sastScanCoverageDecision: {
      findFirst: jest.fn().mockResolvedValue(existing),
      create: jest.fn().mockResolvedValue({ id: 'coverage-1' })
    },
    sastScannerCoverageRecord: {
      createMany: jest.fn().mockImplementation(
        async ({ data }: { data: unknown[] }) => ({ count: data.length })
      )
    },
    sastExternalPublicationDecision: {
      create: jest.fn().mockResolvedValue({ id: 'publication-1' })
    }
  };
}

function existingCoverage(
  input: Readonly<PersistSastScanCoverageInput>
) {
  const scope = input.context.scope;
  return {
    id: input.decision.coverageDecisionId,
    tenantId: scope.tenantId,
    repositoryBindingId: scope.repositoryBindingId,
    scanRequestId: scope.scanRequestId,
    attemptId: scope.attemptId,
    correlationBatchId: scope.correlationBatchId,
    state: input.decision.state,
    recordsDigest: input.decision.recordsDigest,
    decision: input.decision,
    decisionDigest: input.decision.decisionDigest,
    decidedAt: new Date(input.decision.decidedAt),
    scannerRecords: input.records.map((record) => ({
      id: record.scannerCoverageId,
      scanner: record.scanner,
      scannerRunId: record.scannerRunId,
      artifactIngestionId: record.artifactIngestionId,
      dispositionDecisionId: record.dispositionDecisionId,
      correlationSourceId: record.correlationSourceId,
      record,
      recordDigest: record.recordDigest
    })),
    publicationDecision: {
      id: input.publication.publicationDecisionId,
      coverageDecisionId: input.decision.coverageDecisionId,
      tenantId: scope.tenantId,
      repositoryBindingId: scope.repositoryBindingId,
      scanRequestId: scope.scanRequestId,
      attemptId: scope.attemptId,
      coverageState: input.publication.coverageState,
      externalCommentAllowed: false,
      blockingStatusAllowed: false,
      aiAdvisoryAllowed: false,
      lifecycleMutationAllowed: false,
      latestTargetAuthority: 'UNAVAILABLE',
      staleStatus: 'UNKNOWN',
      comparabilityStatus: 'UNKNOWN',
      decision: input.publication,
      decisionDigest: input.publication.decisionDigest,
      decidedAt: new Date(input.publication.decidedAt)
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

function mockCoverageContext(
  store: PrismaSastScanCoverageStore,
  context: SastScanCoverageContext
) {
  return jest
    .spyOn(
      store as unknown as {
        readContext: (
          ...args: unknown[]
        ) => Promise<SastScanCoverageContext | null>;
      },
      'readContext'
    )
    .mockResolvedValue(context);
}

function id(prefix: string, value: string): string {
  return `${prefix}://${createHash('sha256')
    .update(value, 'utf8')
    .digest('hex')}`;
}

function digest(value: string): `sha256:${string}` {
  return `sha256:${createHash('sha256')
    .update(value, 'utf8')
    .digest('hex')}`;
}
