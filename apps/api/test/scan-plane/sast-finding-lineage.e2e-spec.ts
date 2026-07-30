import {
  isSastFindingLifecycleReconciliationResultShapeValid,
  isSastFindingLineageObservationResultShapeValid,
  type SastFindingLifecycleCoverageDecision
} from '@aegisai/shared';

import {
  SastFindingLifecycleCoverageGate
} from '../../src/scan-plane/sast-finding-lifecycle-coverage.gate';
import {
  SastFindingLineageService
} from '../../src/scan-plane/sast-finding-lineage.service';
import {
  SastFindingLineageObservationIncompleteError,
  SastFindingLineageStore
} from '../../src/scan-plane/sast-finding-lineage.store';
import {
  SastFindingRenameAttestationVerifier
} from '../../src/scan-plane/sast-finding-rename-attestation.verifier';
import {
  LINEAGE_FIXTURE_TIME,
  fingerprintedFindingBatch,
  fixtureDigest,
  lifecycleCoverageDecision,
  lineageContextKey,
  lineageFixtureClock,
  lineageObservationContext,
  reconciliationContext,
  renameAttestation
} from '../support/sast-finding-lineage-fixtures';

describe('SastFindingLineageService', () => {
  it('revalidates the full T036 handoff and persists every repeated occurrence', async () => {
    const batch = await fingerprintedFindingBatch([
      {
        location: {
          kind: 'FILE',
          normalizedPath: 'src/config.ts',
          lineStart: 4,
          lineEnd: 4
        }
      },
      {
        location: {
          kind: 'FILE',
          normalizedPath: 'src/config.ts',
          lineStart: 40,
          lineEnd: 40
        },
        identityMaterial: {
          ruleSemanticId: 'javascript.hardcoded-secret',
          symbolAnchor: '',
          sinkKind: '',
          structuralHash: fixtureDigest('structure'),
          scannerMatchBasedId: 'rules.secret:match-2'
        }
      }
    ]);
    const context = lineageObservationContext(batch);
    const store = observationStore(context, {
      findingCount: 2,
      occurrenceCount: 2,
      distinctFingerprintCount: 1,
      createdLineageCount: 1,
      exactMatchCount: 0,
      renamedMatchCount: 0
    });
    const service = serviceWith(store);
    const snapshot = structuredClone(batch);

    const result = await service.observe(
      { batch },
      lineageFixtureClock
    );

    expect(batch).toEqual(snapshot);
    expect(result).toMatchObject({
      outcome: 'OBSERVED',
      findingCount: 2,
      occurrenceCount: 2,
      distinctFingerprintCount: 1,
      authority: {
        normalizedFindingPersistenceAuthority: true,
        occurrenceAuthority: true,
        lifecycleAuthority: true,
        renameAuthority: true,
        correlationAuthority: false,
        coverageCalculationAuthority: false,
        policyAuthority: false,
        publicationAuthority: false,
        aiPayloadEligible: false
      }
    });
    expect(
      isSastFindingLineageObservationResultShapeValid(
        result,
        fixtureDigest
      )
    ).toBe(true);
    expect(store.observe).toHaveBeenCalledWith(
      expect.objectContaining({
        batch,
        context,
        renameCandidates: []
      })
    );
  });

  it('fails closed when durable scan scope differs from the signed batch', async () => {
    const batch = await fingerprintedFindingBatch();
    const context = {
      ...lineageObservationContext(batch),
      commitSha: 'b'.repeat(40)
    };
    const store = observationStore(context);
    const service = serviceWith(store);

    await expect(
      service.observe({ batch }, lineageFixtureClock)
    ).resolves.toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: [
        'FINDING_LINEAGE_DURABLE_SCOPE_INVALID'
      ],
      sourceBatchDigestStored: false,
      sourceFindingStored: false
    });
    expect(store.observe).not.toHaveBeenCalled();
  });

  it('rejects cross-tenant durable scope drift without exposing either tenant', async () => {
    const batch = await fingerprintedFindingBatch();
    const context = lineageObservationContext(batch);
    const store = observationStore({
      ...context,
      scope: {
        ...context.scope,
        tenantId: 'tenant-cross-scope'
      }
    });
    const service = serviceWith(store);

    const result = await service.observe(
      { batch },
      lineageFixtureClock
    );

    expect(result).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: [
        'FINDING_LINEAGE_DURABLE_SCOPE_INVALID'
      ],
      sourceFindingStored: false,
      secretValueStored: false
    });
    expect(JSON.stringify(result)).not.toContain('tenant-1');
    expect(JSON.stringify(result)).not.toContain(
      'tenant-cross-scope'
    );
    expect(store.observe).not.toHaveBeenCalled();
  });

  it('rejects a non-canonical durable target context before persistence', async () => {
    const batch = await fingerprintedFindingBatch();
    const context = {
      ...lineageObservationContext(batch),
      targetRef: 'refs/heads/cafe\u0301'
    };
    const store = observationStore(context);
    const service = serviceWith(store);

    await expect(
      service.observe({ batch }, lineageFixtureClock)
    ).resolves.toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: [
        'FINDING_LINEAGE_DURABLE_SCOPE_INVALID'
      ]
    });
    expect(store.observe).not.toHaveBeenCalled();
  });

  it('persists a zero-finding observation batch without inventing a lineage', async () => {
    const batch = await fingerprintedFindingBatch([]);
    const context = lineageObservationContext(batch);
    const store = observationStore(context, {
      findingCount: 0,
      occurrenceCount: 0,
      distinctFingerprintCount: 0,
      createdLineageCount: 0
    });
    const service = serviceWith(store);

    await expect(
      service.observe({ batch }, lineageFixtureClock)
    ).resolves.toMatchObject({
      outcome: 'OBSERVED',
      findingCount: 0,
      occurrenceCount: 0,
      distinctFingerprintCount: 0
    });
  });

  it('accepts only verified fixed-commit rename evidence and projects the previous path fingerprint', async () => {
    const batch = await fingerprintedFindingBatch();
    const context = lineageObservationContext(batch);
    const attestation = renameAttestation(context);
    const store = observationStore(context, {
      createdLineageCount: 0,
      exactMatchCount: 0,
      renamedMatchCount: 1
    });
    const renameVerifier = {
      verify: jest.fn().mockResolvedValue('VERIFIED')
    } as unknown as SastFindingRenameAttestationVerifier;
    const service = serviceWith(store, renameVerifier);

    const result = await service.observe(
      { batch, renameAttestation: attestation },
      lineageFixtureClock
    );

    expect(result).toMatchObject({
      outcome: 'OBSERVED',
      renamedMatchCount: 1
    });
    const persisted = (
      store.observe as jest.Mock
    ).mock.calls[0]?.[0];
    expect(persisted).toMatchObject({
      renameAttestationDigest:
        attestation.attestationDigest,
      renameAttestation: attestation,
      renameCandidates: [
        {
          capability: 'SAST',
          currentStableFingerprint:
            batch.findings[0]?.fingerprint.stableFingerprint,
          fromNormalizedPath: 'src/old-config.ts',
          toNormalizedPath: 'src/config.ts'
        }
      ]
    });
    expect(
      persisted.renameCandidates[0].previousStableFingerprint
    ).not.toBe(
      batch.findings[0]?.fingerprint.stableFingerprint
    );
    expect(renameVerifier.verify).toHaveBeenCalledTimes(1);
  });

  it('does not persist rename claims when the verifier is unavailable', async () => {
    const batch = await fingerprintedFindingBatch();
    const context = lineageObservationContext(batch);
    const store = observationStore(context);
    const service = serviceWith(store);

    await expect(
      service.observe(
        {
          batch,
          renameAttestation: renameAttestation(context)
        },
        lineageFixtureClock
      )
    ).resolves.toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: [
        'FINDING_LINEAGE_RENAME_AUTHORITY_UNAVAILABLE'
      ]
    });
    expect(store.observe).not.toHaveBeenCalled();
  });

  it('keeps UNKNOWN locations exact-only and never invents rename continuity', async () => {
    const batch = await fingerprintedFindingBatch([
      {
        location: {
          kind: 'UNKNOWN',
          reasonCode: 'SCANNER_LOCATION_OMITTED'
        }
      }
    ]);
    const context = lineageObservationContext(batch);
    const store = observationStore(context);
    const verifier = {
      verify: jest.fn().mockResolvedValue('VERIFIED')
    } as unknown as SastFindingRenameAttestationVerifier;
    const service = serviceWith(store, verifier);

    await expect(
      service.observe(
        {
          batch,
          renameAttestation: renameAttestation(context)
        },
        lineageFixtureClock
      )
    ).resolves.toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: [
        'FINDING_LINEAGE_RENAME_ATTESTATION_INVALID'
      ]
    });
    expect(
      batch.findings[0]?.fingerprint.normalizedPath
    ).toBe('');
    expect(store.observe).not.toHaveBeenCalled();
  });

  it('applies only a verified complete, non-stale, comparable coverage decision', async () => {
    const context = reconciliationContext();
    const decision = lifecycleCoverageDecision();
    const store = reconciliationStore(context, {
      eligibleLineageCount: 1,
      observedLineageCount: 0,
      fixedCount: 1,
      reopenedCount: 0,
      unchangedOpenCount: 0,
      unchangedFixedCount: 0,
      replayed: false,
      reconciledAt: LINEAGE_FIXTURE_TIME
    });
    const coverageGate = {
      verify: jest.fn().mockResolvedValue('VERIFIED')
    } as unknown as SastFindingLifecycleCoverageGate;
    const service = serviceWith(
      store,
      undefined,
      coverageGate
    );

    const result = await service.reconcile(
      { coverageDecision: decision },
      lineageFixtureClock
    );

    expect(result).toMatchObject({
      outcome: 'RECONCILED',
      fixedCount: 1,
      reopenedCount: 0,
      replayed: false
    });
    expect(
      isSastFindingLifecycleReconciliationResultShapeValid(
        result,
        fixtureDigest
      )
    ).toBe(true);
    expect(coverageGate.verify).toHaveBeenCalledWith(decision);
  });

  it('fails closed when lifecycle coverage authority is unavailable', async () => {
    const store = reconciliationStore(
      reconciliationContext()
    );
    const service = serviceWith(store);

    await expect(
      service.reconcile(
        {
          coverageDecision: lifecycleCoverageDecision()
        },
        lineageFixtureClock
      )
    ).resolves.toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: [
        'FINDING_LINEAGE_COVERAGE_AUTHORITY_UNAVAILABLE'
      ]
    });
    expect(
      store.loadReconciliationContext
    ).not.toHaveBeenCalled();
    expect(store.reconcile).not.toHaveBeenCalled();
  });

  it('isolates lifecycle reconciliation from a different target context', async () => {
    const decision = lifecycleCoverageDecision();
    const context = {
      ...reconciliationContext(),
      targetRef: 'refs/heads/release'
    };
    const store = reconciliationStore(context);
    const coverageGate = {
      verify: jest.fn().mockResolvedValue('VERIFIED')
    } as unknown as SastFindingLifecycleCoverageGate;
    const service = serviceWith(
      store,
      undefined,
      coverageGate
    );

    await expect(
      service.reconcile(
        { coverageDecision: decision },
        lineageFixtureClock
      )
    ).resolves.toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: [
        'FINDING_LINEAGE_DURABLE_SCOPE_INVALID'
      ]
    });
    expect(store.reconcile).not.toHaveBeenCalled();
  });

  it.each([
    {
      patch: { state: 'PARTIAL' },
      reason: 'FINDING_LINEAGE_SCAN_INCOMPLETE'
    },
    {
      patch: { stale: true },
      reason: 'FINDING_LINEAGE_SCAN_STALE'
    },
    {
      patch: { comparable: false },
      reason: 'FINDING_LINEAGE_SCAN_NOT_COMPARABLE'
    }
  ])(
    'rejects lifecycle mutation for $reason',
    async ({ patch, reason }) => {
      const decision = {
        ...lifecycleCoverageDecision(),
        ...patch
      } as unknown as SastFindingLifecycleCoverageDecision;
      const store = reconciliationStore(
        reconciliationContext()
      );
      const service = serviceWith(store);

      await expect(
        service.reconcile(
          { coverageDecision: decision },
          lineageFixtureClock
        )
      ).resolves.toMatchObject({
        outcome: 'REJECTED',
        reasonCodes: [reason]
      });
      expect(store.reconcile).not.toHaveBeenCalled();
    }
  );

  it('maps an incomplete observation ledger to bounded zero-payload rejection metadata', async () => {
    const decision = lifecycleCoverageDecision();
    const store = reconciliationStore(
      reconciliationContext(),
      new SastFindingLineageObservationIncompleteError()
    );
    const gate = {
      verify: jest.fn().mockResolvedValue('VERIFIED')
    } as unknown as SastFindingLifecycleCoverageGate;
    const service = serviceWith(store, undefined, gate);

    const result = await service.reconcile(
      { coverageDecision: decision },
      lineageFixtureClock
    );

    expect(result).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: [
        'FINDING_LINEAGE_OBSERVATION_INCOMPLETE'
      ],
      eligibleLineageIdsStored: false
    });
    expect(JSON.stringify(result)).not.toContain(
      decision.eligibleLineageIds[0]
    );
  });

  it('yields cooperatively while retaining a bounded large observation batch', async () => {
    const findings = Array.from({ length: 65 }, (_, index) => ({
      location: {
        kind: 'FILE' as const,
        normalizedPath: `src/config-${index
          .toString()
          .padStart(2, '0')}.ts`,
        lineStart: 1,
        lineEnd: 1
      }
    }));
    const batch = await fingerprintedFindingBatch(findings);
    const context = lineageObservationContext(batch);
    const store = observationStore(context, {
      findingCount: 65,
      occurrenceCount: 65,
      distinctFingerprintCount: 65,
      createdLineageCount: 65
    });
    const service =
      new YieldObservingSastFindingLineageService(
        store,
        {
          verify: jest.fn().mockResolvedValue('UNAVAILABLE')
        } as unknown as SastFindingRenameAttestationVerifier,
        {
          verify: jest.fn().mockResolvedValue('UNAVAILABLE')
        } as unknown as SastFindingLifecycleCoverageGate
      );

    await expect(
      service.observe({ batch }, lineageFixtureClock)
    ).resolves.toMatchObject({ outcome: 'OBSERVED' });
    expect(service.yieldCount).toBe(1);
  });
});

class YieldObservingSastFindingLineageService
  extends SastFindingLineageService {
  yieldCount = 0;

  protected override async yieldEventLoop(): Promise<void> {
    this.yieldCount += 1;
  }
}

function serviceWith(
  store: SastFindingLineageStore,
  renameVerifier: SastFindingRenameAttestationVerifier = {
    verify: jest.fn().mockResolvedValue('UNAVAILABLE')
  } as unknown as SastFindingRenameAttestationVerifier,
  coverageGate: SastFindingLifecycleCoverageGate = {
    verify: jest.fn().mockResolvedValue('UNAVAILABLE')
  } as unknown as SastFindingLifecycleCoverageGate
): SastFindingLineageService {
  return new SastFindingLineageService(
    store,
    renameVerifier,
    coverageGate
  );
}

function observationStore(
  context: ReturnType<typeof lineageObservationContext>,
  countOverrides: Partial<{
    findingCount: number;
    occurrenceCount: number;
    distinctFingerprintCount: number;
    createdLineageCount: number;
    exactMatchCount: number;
    renamedMatchCount: number;
  }> = {}
): SastFindingLineageStore & {
  observe: jest.Mock;
  reconcile: jest.Mock;
} {
  const counts = {
    findingCount: 1,
    occurrenceCount: 1,
    distinctFingerprintCount: 1,
    createdLineageCount: 1,
    exactMatchCount: 0,
    renamedMatchCount: 0,
    ...countOverrides
  };
  return {
    loadObservationContext: jest.fn().mockResolvedValue(context),
    loadReconciliationContext: jest.fn(),
    observe: jest.fn().mockImplementation((input) => ({
      observationBatchId: input.observationBatchId,
      sourceIdentityBatchDigest: input.batch.batchDigest,
      lifecycleContextKey: lineageContextKey(context),
      ...counts,
      replayed: false,
      observedAt: LINEAGE_FIXTURE_TIME
    })),
    reconcile: jest.fn()
  } as unknown as SastFindingLineageStore & {
    observe: jest.Mock;
    reconcile: jest.Mock;
  };
}

function reconciliationStore(
  context: ReturnType<typeof reconciliationContext>,
  resultOrError?: unknown
): SastFindingLineageStore & {
  observe: jest.Mock;
  reconcile: jest.Mock;
} {
  const reconcile =
    resultOrError instanceof Error
      ? jest.fn().mockRejectedValue(resultOrError)
      : jest.fn().mockImplementation((input) => ({
          eligibleLineageCount:
            input.decision.eligibleLineageIds.length,
          observedLineageCount: 1,
          fixedCount: 0,
          reopenedCount: 0,
          unchangedOpenCount: 1,
          unchangedFixedCount: 0,
          replayed: false,
          reconciledAt: LINEAGE_FIXTURE_TIME,
          ...(resultOrError ?? {}),
          reconciliationId: input.reconciliationId,
          coverageDecisionDigest:
            input.decision.decisionDigest,
          lifecycleContextKey:
            input.decision.lifecycleContextKey,
          sequence: input.decision.sequence
        }));
  return {
    loadObservationContext: jest.fn(),
    loadReconciliationContext:
      jest.fn().mockResolvedValue(context),
    observe: jest.fn(),
    reconcile
  } as unknown as SastFindingLineageStore & {
    observe: jest.Mock;
    reconcile: jest.Mock;
  };
}
