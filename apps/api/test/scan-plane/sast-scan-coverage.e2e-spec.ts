import { createHash } from 'node:crypto';

import {
  SAST_APPROVED_PROFILE_DIGESTS,
  SAST_FINDING_CORRELATION_VERSION,
  SAST_FINDING_LIFECYCLE_COVERAGE_VERSION,
  SAST_SCAN_PROFILES,
  canonicalizeSastFindingCorrelationResult,
  canonicalizeSastFindingLifecycleCoverageDecision,
  sastFindingCorrelationAuthority,
  type SastFindingCorrelationResult,
  type SastFindingLifecycleCoverageDecision,
  type SastProfileId,
  type SastScannerKind
} from '@aegisai/shared';

import { SastScanCoverageService } from '../../src/scan-plane/sast-scan-coverage.service';
import {
  SastScanCoverageStore,
  type PersistSastScanCoverageInput,
  type SastScanCoverageContext,
  type SastScannerCoverageDurableEvidence
} from '../../src/scan-plane/sast-scan-coverage.store';

describe('SastScanCoverageService', () => {
  it('persists complete Java Deep coverage while denying every publication authority', async () => {
    const fixture = coverageFixture('JAVA_DEEP_V1');
    const store = new MemoryCoverageStore(fixture.context);
    const service = new SastScanCoverageService(store);

    const result = await service.evaluate(
      { correlation: fixture.correlation },
      coverageClock
    );

    expect(result.outcome).toBe('EVALUATED');
    if (result.outcome !== 'EVALUATED') return;
    expect(result.decision.state).toBe('COMPLETE');
    expect(result.decision.achievedRequiredCapabilities).toEqual([
      'SAST',
      'DEPENDENCY_VULNERABILITY',
      'SECRET_DETECTION',
      'IAC_MISCONFIGURATION',
      'SBOM'
    ]);
    expect(result.decision.authority).toEqual({
      coverageCalculationAuthority: true,
      scannerExecutionAuthority: false,
      artifactAcceptanceAuthority: false,
      correlationAuthority: false,
      lifecycleAuthority: false,
      evidenceAuthority: false,
      policyAuthority: false,
      publicationAuthority: false,
      aiPayloadEligible: false
    });
    expect(result.publication).toMatchObject({
      coverageState: 'COMPLETE',
      externalCommentAllowed: false,
      blockingStatusAllowed: false,
      aiAdvisoryAllowed: false,
      lifecycleMutationAllowed: false,
      latestTargetAuthority: 'UNAVAILABLE',
      staleStatus: 'UNKNOWN',
      comparabilityStatus: 'UNKNOWN'
    });
    expect(store.persisted?.records).toHaveLength(3);
  });

  it('does not let an absent optional Fast scanner lower required coverage', async () => {
    const fixture = coverageFixture('JAVA_FAST_V1', {
      omitScanners: ['SYFT']
    });
    const result = await new SastScanCoverageService(
      new MemoryCoverageStore(fixture.context)
    ).evaluate({ correlation: fixture.correlation }, coverageClock);

    expect(result.outcome).toBe('EVALUATED');
    if (result.outcome !== 'EVALUATED') return;
    expect(result.decision.state).toBe('COMPLETE');
    expect(result.decision.optionalIncompleteScanners).toEqual([
      'SYFT'
    ]);
    expect(result.decision.reasonCodes).toEqual([
      'OPTIONAL_SCANNER_INCOMPLETE'
    ]);
    expect(
      result.records.find((record) => record.scanner === 'SYFT')
    ).toMatchObject({
      required: false,
      executionStatus: 'NOT_STARTED',
      reasonCodes: ['SCANNER_NOT_STARTED']
    });
  });

  it('completes the Common profile without optional OpenGrep and keeps AI ineligible', async () => {
    const fixture = coverageFixture('COMMON_DEEP_V1', {
      omitScanners: ['OPENGREP']
    });
    const result = await new SastScanCoverageService(
      new MemoryCoverageStore(fixture.context)
    ).evaluate({ correlation: fixture.correlation }, coverageClock);

    expect(result.outcome).toBe('EVALUATED');
    if (result.outcome !== 'EVALUATED') return;
    expect(result.decision.state).toBe('COMPLETE');
    expect(result.decision.requiredScanners).toEqual(['TRIVY', 'SYFT']);
    expect(result.decision.optionalScanners).toEqual(['OPENGREP']);
    expect(result.decision.optionalIncompleteScanners).toEqual([
      'OPENGREP'
    ]);
    expect(result.publication.aiAdvisoryAllowed).toBe(false);
    expect(result.publication.reasonCodes).toContain(
      'PROFILE_AI_INELIGIBLE'
    );
  });

  it('keeps a running required scanner pending without publishing', async () => {
    const fixture = coverageFixture('JAVA_DEEP_V1', {
      scannerStatus: { SYFT: 'RUNNING' }
    });
    const result = await new SastScanCoverageService(
      new MemoryCoverageStore(fixture.context)
    ).evaluate({ correlation: fixture.correlation }, coverageClock);

    expect(result.outcome).toBe('EVALUATED');
    if (result.outcome !== 'EVALUATED') return;
    expect(result.decision.state).toBe('PENDING');
    expect(result.decision.pendingRequiredScanners).toEqual(['SYFT']);
    expect(result.publication.externalCommentAllowed).toBe(false);
  });

  it('fails coverage on quarantine or a tampered T038 source closure', async () => {
    const quarantined = coverageFixture('JAVA_DEEP_V1', {
      scannerStatus: { TRIVY: 'QUARANTINED' }
    });
    const tampered = coverageFixture('JAVA_DEEP_V1', {
      sourceSetValid: false
    });

    const first = await new SastScanCoverageService(
      new MemoryCoverageStore(quarantined.context)
    ).evaluate({ correlation: quarantined.correlation }, coverageClock);
    const second = await new SastScanCoverageService(
      new MemoryCoverageStore(tampered.context)
    ).evaluate({ correlation: tampered.correlation }, coverageClock);

    expect(first.outcome).toBe('EVALUATED');
    expect(second.outcome).toBe('EVALUATED');
    if (first.outcome === 'EVALUATED') {
      expect(first.decision.state).toBe('FAILED');
      expect(first.decision.reasonCodes).toContain('SECURITY_BLOCKED');
    }
    if (second.outcome === 'EVALUATED') {
      expect(second.decision.state).toBe('FAILED');
      expect(second.decision.reasonCodes).toContain(
        'CORRELATION_SOURCE_SET_INCOMPLETE'
      );
    }
  });

  it('distinguishes ordinary required failure from artifact-binding tamper', async () => {
    const partial = coverageFixture('JAVA_DEEP_V1', {
      scannerStatus: { SYFT: 'FAILED' }
    });
    const baseTampered = coverageFixture('JAVA_DEEP_V1');
    const tampered = {
      ...baseTampered,
      context: {
        ...baseTampered.context,
        scanners: baseTampered.context.scanners.map((scanner) =>
          scanner.scanner === 'TRIVY'
            ? { ...scanner, artifactBindingValid: false }
            : scanner
        )
      }
    };

    const partialResult = await new SastScanCoverageService(
      new MemoryCoverageStore(partial.context)
    ).evaluate({ correlation: partial.correlation }, coverageClock);
    const failedResult = await new SastScanCoverageService(
      new MemoryCoverageStore(tampered.context)
    ).evaluate({ correlation: tampered.correlation }, coverageClock);

    expect(partialResult.outcome).toBe('EVALUATED');
    expect(failedResult.outcome).toBe('EVALUATED');
    if (partialResult.outcome === 'EVALUATED') {
      expect(partialResult.decision.state).toBe('PARTIAL');
      expect(partialResult.decision.failedRequiredScanners).toEqual([
        'SYFT'
      ]);
    }
    if (failedResult.outcome === 'EVALUATED') {
      expect(failedResult.decision.state).toBe('FAILED');
      expect(failedResult.decision.reasonCodes).toContain(
        'ARTIFACT_AUTHORITY_INVALID'
      );
    }
  });

  it('rejects a changed T038 handoff before opening persistence', async () => {
    const fixture = coverageFixture('JAVA_DEEP_V1');
    const store = new MemoryCoverageStore(fixture.context);
    const service = new SastScanCoverageService(store);

    const result = await service.evaluate({
      correlation: {
        ...fixture.correlation,
        sourceSetDigest: digest('changed-source-set')
      }
    });

    expect(result).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: ['SCAN_COVERAGE_INPUT_INVALID'],
      scannerRunIdsStored: false,
      artifactReferencesStored: false,
      correlationReferencesStored: false,
      publicationAttempted: false,
      secretValueStored: false
    });
    expect(store.persisted).toBeUndefined();
  });

  it('returns an exact replay without creating a second decision', async () => {
    const fixture = coverageFixture('JAVA_DEEP_V1');
    const store = new MemoryCoverageStore(fixture.context, true);
    const result = await new SastScanCoverageService(store).evaluate(
      { correlation: fixture.correlation },
      coverageClock
    );

    expect(result.outcome).toBe('EVALUATED');
    if (result.outcome === 'EVALUATED') {
      expect(result.replayed).toBe(true);
    }
    expect(store.persistCount).toBe(1);
  });

  it('keeps lifecycle authority denied even when the canonical T039 source matches', async () => {
    const fixture = coverageFixture('JAVA_DEEP_V1');
    const store = new MemoryCoverageStore(fixture.context);
    store.lifecycleVerification = 'MATCHED';
    const decision = lifecycleDecision();

    expect(
      await new SastScanCoverageService(store).verify(decision)
    ).toBe('REJECTED');
    expect(store.lifecycleDecision).toEqual(decision);
  });
});

class MemoryCoverageStore extends SastScanCoverageStore {
  persisted?: Readonly<PersistSastScanCoverageInput>;
  persistCount = 0;
  lifecycleDecision?: Readonly<SastFindingLifecycleCoverageDecision>;
  lifecycleVerification: 'MATCHED' | 'REJECTED' = 'REJECTED';

  constructor(
    private readonly context: Readonly<SastScanCoverageContext>,
    private readonly replayed = false
  ) {
    super();
  }

  async loadContext(): Promise<SastScanCoverageContext> {
    return this.context;
  }

  async persist(input: Readonly<PersistSastScanCoverageInput>) {
    this.persisted = input;
    this.persistCount += 1;
    return {
      coverageDecisionId: input.decision.coverageDecisionId,
      decisionDigest: input.decision.decisionDigest,
      publicationDecisionId:
        input.publication.publicationDecisionId,
      publicationDecisionDigest: input.publication.decisionDigest,
      decidedAt: input.decision.decidedAt,
      replayed: this.replayed
    };
  }

  async verifyLifecycleSource(
    decision: Readonly<SastFindingLifecycleCoverageDecision>
  ) {
    this.lifecycleDecision = decision;
    return this.lifecycleVerification;
  }
}

function coverageFixture(
  profileId: SastProfileId,
  options: {
    omitScanners?: SastScannerKind[];
    scannerStatus?: Partial<
      Record<
        SastScannerKind,
        SastScannerCoverageDurableEvidence['executionStatus']
      >
    >;
    sourceSetValid?: boolean;
  } = {}
): {
  context: SastScanCoverageContext;
  correlation: SastFindingCorrelationResult;
} {
  const profile = SAST_SCAN_PROFILES[profileId];
  const correlationBatchId = id('finding-correlation', profileId);
  const sourceSetDigest = digest(`${profileId}-source-set`);
  const lifecycleContextKey = digest(`${profileId}-context`);
  const correlatedAt = '2026-08-02T12:59:00.000Z';
  const correlationCore = {
    version: SAST_FINDING_CORRELATION_VERSION,
    outcome: 'CORRELATED' as const,
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
    replayed: false,
    correlatedAt,
    authority: sastFindingCorrelationAuthority()
  };
  const correlation: SastFindingCorrelationResult = {
    ...correlationCore,
    resultDigest: digest(
      canonicalizeSastFindingCorrelationResult(correlationCore)
    )
  };
  const scanners = (['OPENGREP', 'TRIVY', 'SYFT'] as const)
    .filter((scanner) => !options.omitScanners?.includes(scanner))
    .map((scanner) =>
      scannerEvidence(
        scanner,
        profile.requiredScanners.includes(scanner),
        options.scannerStatus?.[scanner] ?? 'SUCCEEDED'
      )
    );
  return {
    correlation,
    context: {
      scope: {
        tenantId: 'tenant-1',
        repositoryBindingId: 'repository-1',
        scanRequestId: `scan-${profileId.toLowerCase()}`,
        attemptId: `attempt-${profileId.toLowerCase()}`,
        lifecycleContextKey,
        targetRef: 'refs/heads/main',
        commitSha: 'a'.repeat(40),
        lane: profile.lane,
        profileId,
        profileDigest: SAST_APPROVED_PROFILE_DIGESTS[profileId],
        canonicalScanKey: digest(`${profileId}-canonical-key`),
        planDigest: digest(`${profileId}-plan`),
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
        correlatedAt,
        sourceSetValid: options.sourceSetValid ?? true
      },
      scanners
    }
  };
}

function scannerEvidence(
  scanner: SastScannerKind,
  required: boolean,
  executionStatus: SastScannerCoverageDurableEvidence['executionStatus']
): SastScannerCoverageDurableEvidence {
  const findingScanner = scanner !== 'SYFT';
  const succeeded = executionStatus === 'SUCCEEDED';
  return {
    scanner,
    executionStatus,
    requiredBinding: required,
    scannerRunId: `scanner-run-${scanner.toLowerCase()}`,
    scannerVersion: '1.0.0',
    scannerImageDigest: digest(`${scanner}-image`),
    wrapperDigest: digest(`${scanner}-wrapper`),
    ruleBundleDigest:
      scanner === 'SYFT' ? null : digest(`${scanner}-rules`),
    vulnerabilityDatabaseDigest:
      scanner === 'TRIVY' ? digest('trivy-db') : null,
    schemaBundleDigest: digest('schema-bundle'),
    normalizerBundleDigest: digest('normalizer-bundle'),
    provenanceValid: true,
    artifactIngestionId: succeeded
      ? `ingestion-${scanner.toLowerCase()}`
      : null,
    artifactEnvelopeDigest: succeeded
      ? digest(`${scanner}-envelope`)
      : null,
    artifactDigest: succeeded ? digest(`${scanner}-artifact`) : null,
    dispositionDecisionId: succeeded
      ? `disposition-${scanner.toLowerCase()}`
      : null,
    dispositionDecisionDigest: succeeded
      ? digest(`${scanner}-disposition`)
      : null,
    artifactAccepted: succeeded,
    normalizationEligible: succeeded,
    artifactBindingValid: true,
    correlationSourceId:
      findingScanner && succeeded
        ? `correlation-source-${scanner.toLowerCase()}`
        : null,
    observationBatchId:
      findingScanner && succeeded
        ? id('finding-observation', scanner)
        : null,
    correlationSourceBindingDigest:
      findingScanner && succeeded
        ? digest(`${scanner}-source`)
        : null,
    correlationSourceValid: findingScanner && succeeded
  };
}

function lifecycleDecision(): SastFindingLifecycleCoverageDecision {
  const core = {
    version: SAST_FINDING_LIFECYCLE_COVERAGE_VERSION,
    tenantId: 'tenant-1',
    repositoryBindingId: 'repository-1',
    scanRequestId: 'scan-java_deep_v1',
    attemptId: 'attempt-java_deep_v1',
    canonicalScanKey: digest('JAVA_DEEP_V1-canonical-key'),
    planDigest: digest('JAVA_DEEP_V1-plan'),
    commitSha: 'a'.repeat(40),
    lifecycleContextKey: digest('JAVA_DEEP_V1-context'),
    profileId: 'JAVA_DEEP_V1' as const,
    profileDigest: SAST_APPROVED_PROFILE_DIGESTS.JAVA_DEEP_V1,
    state: 'COMPLETE' as const,
    stale: false as const,
    comparable: true as const,
    sequence: 2,
    previousScanRequestId: 'scan-previous',
    previousCommitSha: 'b'.repeat(40),
    completeCapabilities: [
      'SAST',
      'DEPENDENCY_VULNERABILITY',
      'SECRET_DETECTION',
      'IAC_MISCONFIGURATION'
    ] as const,
    eligibleLineageIds: [id('finding-lineage', 'one')],
    expectedObservationBatchDigests: [digest('observation')],
    sourceCoverageDecisionDigest: digest('coverage-decision'),
    sourceCoverageDecisionRef: id('sast-coverage', 'coverage'),
    completedAt: '2026-08-02T13:00:00.000Z',
    decidedAt: '2026-08-02T13:01:00.000Z'
  };
  return {
    ...core,
    completeCapabilities: [...core.completeCapabilities],
    decisionDigest: digest(
      canonicalizeSastFindingLifecycleCoverageDecision({
        ...core,
        completeCapabilities: [...core.completeCapabilities]
      })
    )
  };
}

function coverageClock(): Date {
  return new Date('2026-08-02T13:00:00.000Z');
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
