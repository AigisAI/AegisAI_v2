import {
  SAST_FINDING_LINEAGE_VERSION,
  canonicalizeSastFindingLineageObservationResult,
  isSastFindingCorrelationResultShapeValid,
  type SastFindingLineageObservationResult,
  type SastFindingLineageObservationResultCore
} from '@aegisai/shared';

import { SastFindingCorrelationService } from '../../src/scan-plane/sast-finding-correlation.service';
import {
  SastFindingCorrelationStore,
  type PersistSastFindingCorrelationInput,
  type PersistedSastFindingCorrelation,
  type SastFindingCorrelationContext
} from '../../src/scan-plane/sast-finding-correlation.store';
import {
  correlationFixture,
  correlationFixtureClock
} from '../support/sast-finding-correlation-fixtures';
import { fixtureDigest } from '../support/sast-finding-lineage-fixtures';

describe('SastFindingCorrelationService', () => {
  it('retains repeated occurrences and both severities behind an exact-fingerprint edge', async () => {
    const fixture = await correlationFixture({
      repeatedOpenGrep: true
    });
    const store = correlationStore(fixture.context);
    const service = new SastFindingCorrelationService(store);

    const result = await service.correlate(
      { observations: fixture.observations },
      correlationFixtureClock
    );

    expect(result).toMatchObject({
      outcome: 'CORRELATED',
      occurrenceCount: 2,
      edgeCount: 1,
      exactFingerprintCount: 1,
      authority: {
        correlationAuthority: true,
        provenancePreservationAuthority: true,
        findingMergeAuthority: false,
        severityAuthority: false,
        lifecycleAuthority: false,
        coverageCalculationAuthority: false,
        policyAuthority: false,
        publicationAuthority: false,
        aiPayloadEligible: false
      }
    });
    expect(
      isSastFindingCorrelationResultShapeValid(result, fixtureDigest)
    ).toBe(true);
    const persisted = persistedInput(store);
    expect(persisted.edges).toHaveLength(1);
    expect(persisted.edges[0]).toMatchObject({
      decision: {
        kind: 'EXACT_FINGERPRINT',
        confidenceBasisPoints: 10_000,
        safety: {
          findingMergeAllowed: false,
          severityInheritanceAllowed: false,
          lifecycleInheritanceAllowed: false,
          policyInheritanceAllowed: false,
          coverageInheritanceAllowed: false,
          occurrenceProvenancePreserved: true
        }
      },
      sourceProvenance: { severity: 'CRITICAL' },
      targetProvenance: { severity: 'LOW' }
    });
    expect(
      persisted.edges[0]?.sourceProvenance.occurrenceId
    ).not.toBe(
      persisted.edges[0]?.targetProvenance.occurrenceId
    );
  });

  it('keeps two authoritative capability families as display-only possible overlap', async () => {
    const fixture = await correlationFixture({ crossToolCve: true });
    const store = correlationStore(fixture.context);
    const service = new SastFindingCorrelationService(store);

    await expect(
      service.correlate(
        { observations: [...fixture.observations].reverse() },
        correlationFixtureClock
      )
    ).resolves.toMatchObject({
      outcome: 'CORRELATED',
      possibleOverlapCount: 1,
      supportingEvidenceCount: 0
    });

    const edge = persistedInput(store).edges[0];
    expect(edge).toMatchObject({
      decision: {
        kind: 'POSSIBLE_OVERLAP',
        confidenceBasisPoints: 5_000
      },
      sourceProvenance: { authorityLevel: 'AUTHORITATIVE' },
      targetProvenance: { authorityLevel: 'AUTHORITATIVE' }
    });
    expect(
      new Set([
        edge?.sourceProvenance.capability,
        edge?.targetProvenance.capability
      ])
    ).toEqual(new Set(['SAST', 'DEPENDENCY_VULNERABILITY']));
  });

  it('marks optional-profile scanner output only as supporting evidence', async () => {
    const fixture = await correlationFixture({
      crossToolCve: true,
      supportingOpenGrep: true
    });
    const store = correlationStore(fixture.context);
    const service = new SastFindingCorrelationService(store);

    await expect(
      service.correlate(
        { observations: fixture.observations },
        correlationFixtureClock
      )
    ).resolves.toMatchObject({
      outcome: 'CORRELATED',
      supportingEvidenceCount: 1,
      possibleOverlapCount: 0
    });
    const edge = persistedInput(store).edges[0];
    expect(edge?.decision.kind).toBe('SUPPORTING_EVIDENCE');
    expect(
      new Set([
        edge?.sourceProvenance.authorityLevel,
        edge?.targetProvenance.authorityLevel
      ])
    ).toEqual(new Set(['AUTHORITATIVE', 'SUPPORTING_ONLY']));
  });

  it('uses the canonical ecosystem, package, installed version, and CVE tuple without merging lineages', async () => {
    const fixture = await correlationFixture({ crossToolCve: true });
    const trivySource = fixture.context.sources.find(
      (source) => source.scanner === 'TRIVY'
    );
    const trivyOccurrence = fixture.context.occurrences.find(
      (occurrence) =>
        occurrence.sourceFinding.capability ===
        'DEPENDENCY_VULNERABILITY'
    );
    if (!trivySource || !trivyOccurrence) {
      throw new Error('Missing Trivy dependency fixture.');
    }
    const duplicate = {
      ...trivyOccurrence,
      id: testId('finding-occurrence', 999),
      lineageId: testId('finding-lineage', 999),
      normalizedFindingId: testId('normalized-finding', 999),
      ordinal: 1
    };
    const context: SastFindingCorrelationContext = {
      ...fixture.context,
      sources: fixture.context.sources.map((source) =>
        source.observationBatchId === trivySource.observationBatchId
          ? { ...source, findingCount: 2, occurrenceCount: 2 }
          : source
      ),
      occurrences: [...fixture.context.occurrences, duplicate]
    };
    const observations = fixture.observations.map((observation) =>
      observation.observationBatchId === trivySource.observationBatchId
        ? rebuildObservation(observation, {
            findingCount: 2,
            occurrenceCount: 2,
            distinctFingerprintCount: 2,
            createdLineageCount: 2
          })
        : observation
    );
    const store = correlationStore(context);
    const service = new SastFindingCorrelationService(store);

    await expect(
      service.correlate({ observations }, correlationFixtureClock)
    ).resolves.toMatchObject({
      outcome: 'CORRELATED',
      sameDependencyCveCount: 1
    });
    const dependencyEdge = persistedInput(store).edges.find(
      (edge) => edge.decision.kind === 'SAME_DEPENDENCY_CVE'
    );
    expect(dependencyEdge).toBeDefined();
    expect(dependencyEdge?.decision.safety.findingMergeAllowed).toBe(
      false
    );
    expect(dependencyEdge?.sourceProvenance.lineageId).not.toBe(
      dependencyEdge?.targetProvenance.lineageId
    );
  });

  it('rejects a missing durable zero-or-nonzero observation source without exposing identifiers', async () => {
    const fixture = await correlationFixture({ crossToolCve: true });
    const store = correlationStore(fixture.context);
    const service = new SastFindingCorrelationService(store);

    const result = await service.correlate(
      { observations: fixture.observations.slice(0, 1) },
      correlationFixtureClock
    );

    expect(result).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: ['FINDING_CORRELATION_SOURCE_SET_INCOMPLETE'],
      observationBatchIdsStored: false,
      sourceResultDigestsStored: false,
      sourceFindingStored: false,
      correlationBasisStored: false,
      secretValueStored: false
    });
    expect(JSON.stringify(result)).not.toContain(
      fixture.observations[0]?.observationBatchId
    );
    expect(store.correlate).not.toHaveBeenCalled();
  });

  it('rejects durable authority that diverges from the immutable active profile', async () => {
    const fixture = await correlationFixture();
    const context: SastFindingCorrelationContext = {
      ...fixture.context,
      requiredCapabilities: fixture.context.requiredCapabilities.slice(1)
    };
    const store = correlationStore(context);
    const service = new SastFindingCorrelationService(store);

    await expect(
      service.correlate(
        { observations: fixture.observations },
        correlationFixtureClock
      )
    ).resolves.toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: ['FINDING_CORRELATION_AUTHORITY_INVALID']
    });
    expect(store.correlate).not.toHaveBeenCalled();
  });

  it('rejects a non-finite correlation clock without opening persistence', async () => {
    const fixture = await correlationFixture();
    const store = correlationStore(fixture.context);
    const service = new SastFindingCorrelationService(store);

    await expect(
      service.correlate(
        { observations: fixture.observations },
        () => new Date(Number.NaN)
      )
    ).resolves.toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: ['FINDING_CORRELATION_INPUT_INVALID']
    });
    expect(store.correlate).not.toHaveBeenCalled();
  });

  it('keeps replay identity independent from the T037 replay flag and result digest', async () => {
    const fixture = await correlationFixture();
    const store = correlationStore(fixture.context);
    const service = new SastFindingCorrelationService(store);

    const first = await service.correlate(
      { observations: fixture.observations },
      correlationFixtureClock
    );
    if (first.outcome !== 'CORRELATED') {
      throw new Error('Initial correlation fixture rejected.');
    }
    fixture.context.existingCorrelation = {
      correlationBatchId: first.correlationBatchId,
      sourceSetDigest: first.sourceSetDigest,
      correlatedAt: first.correlatedAt
    };
    const replayedObservations = fixture.observations.map(
      (observation) =>
        rebuildObservation(observation, { replayed: true })
    );
    (store.correlate as jest.Mock).mockImplementationOnce(
      (input: PersistSastFindingCorrelationInput) => ({
        ...persistedResult(input),
        replayed: true
      })
    );

    const replay = await service.correlate(
      { observations: replayedObservations },
      () => new Date('2030-01-01T00:00:00.000Z')
    );

    expect(replay).toMatchObject({
      outcome: 'CORRELATED',
      correlationBatchId: first.correlationBatchId,
      sourceSetDigest: first.sourceSetDigest,
      correlatedAt: first.correlatedAt,
      replayed: true
    });
    expect(replayedObservations[0]?.resultDigest).not.toBe(
      fixture.observations[0]?.resultDigest
    );
  });

  it('yields across preparation, grouping, and edge construction before occurrence 65', async () => {
    const fixture = await correlationFixture();
    const firstOccurrence = fixture.context.occurrences[0];
    const firstSource = fixture.context.sources[0];
    const firstObservation = fixture.observations[0];
    if (!firstOccurrence || !firstSource || !firstObservation) {
      throw new Error('Missing bounded correlation fixture.');
    }
    const occurrences = Array.from({ length: 65 }, (_, ordinal) => ({
      ...firstOccurrence,
      id: testId('finding-occurrence', ordinal + 1),
      normalizedFindingId: testId('normalized-finding', ordinal + 1),
      ordinal
    }));
    const context: SastFindingCorrelationContext = {
      ...fixture.context,
      sources: [
        { ...firstSource, findingCount: 65, occurrenceCount: 65 }
      ],
      occurrences
    };
    const observations = [
      rebuildObservation(firstObservation, {
        findingCount: 65,
        occurrenceCount: 65
      })
    ];
    const store = correlationStore(context);
    const service = new YieldCountingCorrelationService(store);

    await expect(
      service.correlate({ observations }, correlationFixtureClock)
    ).resolves.toMatchObject({
      outcome: 'CORRELATED',
      occurrenceCount: 65,
      exactFingerprintCount: 64
    });
    expect(service.yieldCount).toBe(3);
  });
});

class YieldCountingCorrelationService extends SastFindingCorrelationService {
  yieldCount = 0;

  protected override async yieldEventLoop(): Promise<void> {
    this.yieldCount += 1;
  }
}

function correlationStore(
  context: SastFindingCorrelationContext
): SastFindingCorrelationStore {
  return {
    loadContext: jest.fn().mockResolvedValue(context),
    correlate: jest
      .fn()
      .mockImplementation((input: PersistSastFindingCorrelationInput) =>
        persistedResult(input)
      )
  } as unknown as SastFindingCorrelationStore;
}

function persistedResult(
  input: PersistSastFindingCorrelationInput
): PersistedSastFindingCorrelation {
  return {
    correlationBatchId: input.correlationBatchId,
    sourceSetDigest: input.sourceSetDigest,
    lifecycleContextKey: input.context.scope.lifecycleContextKey,
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
  };
}

function persistedInput(
  store: SastFindingCorrelationStore
): PersistSastFindingCorrelationInput {
  const value = (store.correlate as jest.Mock).mock.calls[0]?.[0];
  if (!value) throw new Error('No correlation persistence call.');
  return value as PersistSastFindingCorrelationInput;
}

function rebuildObservation(
  observation: SastFindingLineageObservationResult,
  overrides: Partial<SastFindingLineageObservationResultCore>
): SastFindingLineageObservationResult {
  const { resultDigest: _resultDigest, ...currentCore } = observation;
  void _resultDigest;
  const core: SastFindingLineageObservationResultCore = {
    ...currentCore,
    ...overrides,
    version: SAST_FINDING_LINEAGE_VERSION,
    outcome: 'OBSERVED',
    operation: 'OBSERVE'
  };
  return {
    ...core,
    resultDigest: fixtureDigest(
      canonicalizeSastFindingLineageObservationResult(core)
    )
  };
}

function testId(prefix: string, value: number): string {
  return `${prefix}://${value.toString(16).padStart(64, '0')}`;
}
