import { createHash } from 'node:crypto';

import { Prisma } from '@prisma/client';
import {
  SAST_APPROVED_PROFILE_DIGESTS,
  SAST_FORBIDDEN_CAPABILITIES,
  SAST_SCAN_PROFILES,
  buildFindingFingerprintPreimage,
  buildSastFindingLifecycleContextPreimage,
  isSastScanPlanValid,
  projectRenamedSastFindingFingerprintInput,
  type SastScanPlan
} from '@aegisai/shared';
import type {
  SastFindingLineageScanContext,
  SastFindingReconciliationScanContext
} from '../../src/scan-plane/sast-finding-lineage.store';
import {
  SastFindingLineageObservationIncompleteError,
  SastFindingLineageReplayConflictError,
  SastFindingLineageRenameAmbiguousError
} from '../../src/scan-plane/sast-finding-lineage.store';
import {
  PrismaSastFindingLineageStore
} from '../../src/scan-plane/prisma-sast-finding-lineage.store';
import { PrismaService } from '../../src/prisma/prisma.service';
import {
  LINEAGE_FIXTURE_TIME,
  fingerprintedFindingBatch,
  fixtureDigest as batchIndependentDigest,
  lifecycleCoverageDecision,
  lineageContextKey,
  lineageObservationContext,
  reconciliationContext,
  renameAttestation
} from '../support/sast-finding-lineage-fixtures';

describe('PrismaSastFindingLineageStore', () => {
  it('loads only an accepted scanner run bound to one valid immutable plan and retention ledger', async () => {
    const plan = durablePlan();
    expect(isSastScanPlanValid(plan)).toBe(true);
    const retentionExpiresAt = new Date(
      '2026-08-01T00:00:00.000Z'
    );
    const scannerRun = {
      findFirst: jest.fn().mockResolvedValue(
        durableObservationRow(plan, retentionExpiresAt)
      )
    };
    const store = new PrismaSastFindingLineageStore(
      {
        scannerRun
      } as unknown as PrismaService
    );

    const context = await store.loadObservationContext({
      tenantId: plan.tenantId,
      repositoryBindingId:
        plan.repositoryState.repositoryBindingId,
      scanRequestId: plan.scanRequestId,
      attemptId: 'attempt-1',
      scannerRunId: 'scanner-run-1'
    });

    expect(context).toMatchObject({
      targetRef: plan.repositoryState.targetRef,
      commitSha: plan.repositoryState.fixedCommitSha,
      canonicalScanKey: plan.canonicalScanKey,
      profileId: plan.profile.id,
      profileDigest: plan.profileDigest,
      scanner: 'OPENGREP',
      source: {
        ingestionId: 'ingestion-1',
        retentionExpiresAt:
          retentionExpiresAt.toISOString()
      }
    });
    expect(context?.planDigest).toMatch(
      /^sha256:[a-f0-9]{64}$/
    );
    expect(scannerRun.findFirst).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          status: 'COMPLETED',
          artifactIngestion: {
            status: 'ACCEPTED',
            dispositionDecision: {
              disposition: 'ACCEPTED',
              normalizationEligible: true
            }
          }
        })
      })
    );
  });

  it('rejects scanner provenance that drifts from the immutable plan', async () => {
    const plan = durablePlan();
    const retentionExpiresAt = new Date(
      '2026-08-01T00:00:00.000Z'
    );
    const scannerRun = {
      findFirst: jest.fn().mockResolvedValue(
        durableObservationRow(plan, retentionExpiresAt, {
          scannerImageDigest:
            batchIndependentDigest('unapproved-image')
        })
      )
    };
    const store = new PrismaSastFindingLineageStore(
      {
        scannerRun
      } as unknown as PrismaService
    );

    await expect(
      store.loadObservationContext({
        tenantId: plan.tenantId,
        repositoryBindingId:
          plan.repositoryState.repositoryBindingId,
        scanRequestId: plan.scanRequestId,
        attemptId: 'attempt-1',
        scannerRunId: 'scanner-run-1'
      })
    ).resolves.toBeNull();
  });

  it.each([
    'wrapperDigest',
    'scannerSetDigest',
    'scannerWorkspaceInventoryDigest'
  ] as const)(
    'rejects durable %s drift from the immutable plan',
    async (field) => {
      const plan = durablePlan();
      const scannerRun = {
        findFirst: jest.fn().mockResolvedValue(
          durableObservationRow(
            plan,
            new Date('2026-08-01T00:00:00.000Z'),
            {
              [field]: batchIndependentDigest(
                `tampered-${field}`
              )
            }
          )
        )
      };
      const store = new PrismaSastFindingLineageStore(
        {
          scannerRun
        } as unknown as PrismaService
      );

      await expect(
        store.loadObservationContext({
          tenantId: plan.tenantId,
          repositoryBindingId:
            plan.repositoryState.repositoryBindingId,
          scanRequestId: plan.scanRequestId,
          attemptId: 'attempt-1',
          scannerRunId: 'scanner-run-1'
        })
      ).resolves.toBeNull();
    }
  );

  it('creates one lineage while retaining every repeated occurrence in a serializable transaction', async () => {
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
          lineStart: 44,
          lineEnd: 44
        },
        identityMaterial: {
          ruleSemanticId: 'javascript.hardcoded-secret',
          symbolAnchor: '',
          sinkKind: '',
          structuralHash:
            batchIndependentDigest('structure'),
          scannerMatchBasedId: 'rules.secret:match-2'
        }
      }
    ]);
    const context = lineageObservationContext(batch);
    const transaction = observationTransaction();
    const prisma = serializablePrisma(transaction);
    const store = new PrismaSastFindingLineageStore(
      prisma as unknown as PrismaService
    );
    mockObservationContext(store, context);

    const result = await store.observe({
      observationBatchId:
        `finding-observation://${'1'.repeat(64)}`,
      lifecycleContextKey: lineageContextKey(context),
      observedAt: LINEAGE_FIXTURE_TIME,
      batch,
      context: reorderObservationContext(context),
      renameCandidates: []
    });

    expect(result).toMatchObject({
      findingCount: 2,
      occurrenceCount: 2,
      distinctFingerprintCount: 1,
      createdLineageCount: 1,
      exactMatchCount: 0,
      renamedMatchCount: 0,
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
      transaction.sastFindingLineage.createMany
    ).toHaveBeenCalledWith({
      data: [
        expect.objectContaining({
          capability: 'SAST',
          fingerprintVersion: 'sast-fingerprint-v1'
        })
      ]
    });
    expect(
      transaction.sastFindingLineage.findMany
    ).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          tenantId: context.scope.tenantId,
          repositoryBindingId:
            context.scope.repositoryBindingId,
          id: expect.any(Object)
        })
      })
    );
    expect(
      transaction.normalizedFinding.createMany
    ).toHaveBeenCalledWith({
      data: expect.arrayContaining([
        expect.objectContaining({
          status: 'OPEN',
          sastCapability: 'SAST'
        }),
        expect.objectContaining({
          status: 'OPEN',
          sastCapability: 'SAST'
        })
      ])
    });
    expect(
      transaction.sastFindingOccurrence.createMany
    ).toHaveBeenCalledTimes(1);
    const occurrenceRows =
      (transaction.sastFindingOccurrence.createMany.mock
        .calls[0]?.[0]?.data ?? []) as Array<{
          lineageId: string;
          ordinal: number;
        }>;
    expect(occurrenceRows).toHaveLength(2);
    expect(
      new Set(occurrenceRows.map((row) => row.lineageId)).size
    ).toBe(1);
    expect(
      occurrenceRows.map((row) => row.ordinal)
    ).toEqual([0, 1]);
    expect(
      transaction.sastFindingObservationBatch.create
    ).toHaveBeenCalledWith({
      data: expect.objectContaining({
        capabilities: ['SAST'],
        findingCount: 2,
        distinctFingerprintCount: 1
      })
    });
  });

  it.each(['P2034', 'P2002'] as const)(
    'retries a %s serialization or uniqueness race in a fresh transaction',
    async (code) => {
      const batch = await fingerprintedFindingBatch();
      const context = lineageObservationContext(batch);
      const transaction = observationTransaction();
      const prisma = {
        $transaction: jest
          .fn()
          .mockRejectedValueOnce(
            new Prisma.PrismaClientKnownRequestError(
              'concurrent lineage write',
              {
                code,
                clientVersion: '5.22.0'
              }
            )
          )
          .mockImplementation(
            async (
              operation: (
                client: typeof transaction
              ) => Promise<unknown>
            ) => operation(transaction)
          )
      };
      const store = new PrismaSastFindingLineageStore(
        prisma as unknown as PrismaService
      );
      mockObservationContext(store, context);

      await expect(
        store.observe({
          observationBatchId:
            `finding-observation://${'c'.repeat(64)}`,
          lifecycleContextKey: lineageContextKey(context),
          observedAt: LINEAGE_FIXTURE_TIME,
          batch,
          context,
          renameCandidates: []
        })
      ).resolves.toMatchObject({
        findingCount: 1,
        occurrenceCount: 1,
        replayed: false
      });
      expect(prisma.$transaction).toHaveBeenCalledTimes(2);
      expect(
        transaction.sastFindingObservationBatch.create
      ).toHaveBeenCalledTimes(1);
    }
  );

  it('rejects a verified rename claim when no durable predecessor alias exists', async () => {
    const batch = await fingerprintedFindingBatch();
    const context = lineageObservationContext(batch);
    const attestation = renameAttestation(context);
    const previousPlan = previousPlanForRename(
      attestation,
      context
    );
    const transaction = observationTransaction({
      previousScan: scanRequestRowForPlan(previousPlan)
    });
    const prisma = serializablePrisma(transaction);
    const store = new PrismaSastFindingLineageStore(
      prisma as unknown as PrismaService
    );
    mockObservationContext(store, context);
    const finding = batch.findings[0];
    if (!finding) throw new Error('Missing rename fixture finding.');

    await expect(
      store.observe({
        observationBatchId:
          `finding-observation://${'9'.repeat(64)}`,
        lifecycleContextKey: lineageContextKey(context),
        observedAt: LINEAGE_FIXTURE_TIME,
        batch,
        context,
        renameAttestation: attestation,
        renameAttestationDigest:
          attestation.attestationDigest,
        renameCandidates: [
          {
            capability: finding.capability,
            currentStableFingerprint:
              finding.fingerprint.stableFingerprint,
            previousStableFingerprint: batchIndependentDigest(
              buildFindingFingerprintPreimage(
                projectRenamedSastFindingFingerprintInput(
                  finding.fingerprint,
                  'src/old-config.ts'
                )
              )
            ),
            fromNormalizedPath: 'src/old-config.ts',
            toNormalizedPath: 'src/config.ts'
          }
        ]
      })
    ).rejects.toBeInstanceOf(
      SastFindingLineageRenameAmbiguousError
    );
    expect(
      transaction.sastFindingObservationBatch.create
    ).not.toHaveBeenCalled();
  });

  it('records a verified rename-back without duplicating a retained alias', async () => {
    const batch = await fingerprintedFindingBatch([
      {
        location: {
          kind: 'FILE',
          normalizedPath: 'src/old-config.ts',
          lineStart: 4,
          lineEnd: 4
        }
      }
    ]);
    const context = lineageObservationContext(batch);
    const attestation = renameAttestation(context, {
      entries: [
        {
          fromNormalizedPath: 'src/config.ts',
          toNormalizedPath: 'src/old-config.ts'
        }
      ]
    });
    const previousPlan = previousPlanForRename(
      attestation,
      context
    );
    const finding = batch.findings[0];
    if (!finding) throw new Error('Missing rename-back fixture.');
    const predecessorFingerprint = batchIndependentDigest(
      buildFindingFingerprintPreimage(
        projectRenamedSastFindingFingerprintInput(
          finding.fingerprint,
          'src/config.ts'
        )
      )
    );
    const lineageId =
      `finding-lineage://${'5'.repeat(64)}`;
    const stateId = `finding-state://${'6'.repeat(64)}`;
    const transaction = observationTransaction({
      previousScan: scanRequestRowForPlan(previousPlan),
      aliases: [
        {
          lineageId,
          capability: finding.capability,
          stableFingerprint:
            finding.fingerprint.stableFingerprint,
          normalizedPath: 'src/old-config.ts'
        },
        {
          lineageId,
          capability: finding.capability,
          stableFingerprint: predecessorFingerprint,
          normalizedPath: 'src/config.ts'
        }
      ],
      lineages: [
        {
          id: lineageId,
          tenantId: context.scope.tenantId,
          repositoryBindingId:
            context.scope.repositoryBindingId,
          capability: finding.capability,
          fingerprintVersion: 'sast-fingerprint-v1'
        }
      ],
      states: [
        {
          id: stateId,
          lineageId,
          status: 'OPEN',
          revision: 2,
          targetRef: context.targetRef,
          lastObservedAt: new Date(
            '2026-07-29T23:59:00.000Z'
          )
        }
      ]
    });
    const prisma = serializablePrisma(transaction);
    const store = new PrismaSastFindingLineageStore(
      prisma as unknown as PrismaService
    );
    mockObservationContext(store, context);

    await expect(
      store.observe({
        observationBatchId:
          `finding-observation://${'b'.repeat(64)}`,
        lifecycleContextKey: lineageContextKey(context),
        observedAt: LINEAGE_FIXTURE_TIME,
        batch,
        context,
        renameAttestation: attestation,
        renameAttestationDigest:
          attestation.attestationDigest,
        renameCandidates: [
          {
            capability: finding.capability,
            currentStableFingerprint:
              finding.fingerprint.stableFingerprint,
            previousStableFingerprint:
              predecessorFingerprint,
            fromNormalizedPath: 'src/config.ts',
            toNormalizedPath: 'src/old-config.ts'
          }
        ]
      })
    ).resolves.toMatchObject({
      createdLineageCount: 0,
      exactMatchCount: 0,
      renamedMatchCount: 1
    });
    expect(
      transaction.sastFindingIdentityAlias.createMany
    ).not.toHaveBeenCalled();
    expect(
      transaction.sastFindingLifecycleEvent.createMany
    ).toHaveBeenCalledWith({
      data: [
        expect.objectContaining({
          lifecycleStateId: stateId,
          kind: 'RENAMED',
          revision: 3,
          renameAttestationDigest:
            attestation.attestationDigest
        })
      ]
    });
  });

  it('replays only an identical complete occurrence ledger', async () => {
    const batch = await fingerprintedFindingBatch();
    const context = lineageObservationContext(batch);
    const observationBatchId =
      `finding-observation://${'2'.repeat(64)}`;
    const finding = batch.findings[0];
    if (!finding) throw new Error('Missing replay fixture finding.');
    const lineageId =
      `finding-lineage://${'7'.repeat(64)}`;
    const occurrenceId = deterministicTestId(
      'finding-occurrence',
      `${observationBatchId}\0${0}\0${finding.fingerprint.decisionDigest}`
    );
    const persistedOccurrence = {
      id: occurrenceId,
      tenantId: context.scope.tenantId,
      repositoryBindingId:
        context.scope.repositoryBindingId,
      scanRequestId: context.scope.scanRequestId,
      attemptId: context.scope.attemptId,
      scannerRunId: context.scope.scannerRunId,
      observationBatchId,
      lineageId,
      normalizedFindingId: deterministicTestId(
        'normalized-finding',
        occurrenceId
      ),
      ordinal: 0,
      capability: finding.capability,
      fingerprintVersion: 'sast-fingerprint-v1',
      stableFingerprint:
        finding.fingerprint.stableFingerprint,
      fingerprintDecisionDigest:
        finding.fingerprint.decisionDigest,
      sourceFinding: finding,
      observedAt: new Date(LINEAGE_FIXTURE_TIME)
    };
    const transaction = observationTransaction({
      existingBatch: {
        id: observationBatchId,
        tenantId: context.scope.tenantId,
        repositoryBindingId:
          context.scope.repositoryBindingId,
        scanRequestId: context.scope.scanRequestId,
        attemptId: context.scope.attemptId,
        scannerRunId: context.scope.scannerRunId,
        lifecycleContextKey: lineageContextKey(context),
        targetRef: context.targetRef,
        commitSha: context.commitSha,
        lane: context.lane,
        scanner: context.scanner,
        capabilities: ['SAST'],
        profileId: context.profileId,
        profileDigest: context.profileDigest,
        canonicalScanKey: context.canonicalScanKey,
        planDigest: context.planDigest,
        sourceIdentityBatchDigest: batch.batchDigest,
        renameAttestationDigest: null,
        findingCount: 1,
        distinctFingerprintCount: 1,
        createdLineageCount: 1,
        exactMatchCount: 0,
        renamedMatchCount: 0,
        observedAt: new Date(LINEAGE_FIXTURE_TIME)
      },
      aliases: [
        {
          lineageId,
          capability: finding.capability,
          stableFingerprint:
            finding.fingerprint.stableFingerprint,
          normalizedPath:
            finding.fingerprint.normalizedPath
        }
      ],
      lineages: [
        {
          id: lineageId,
          tenantId: context.scope.tenantId,
          repositoryBindingId:
            context.scope.repositoryBindingId,
          capability: finding.capability,
          fingerprintVersion: 'sast-fingerprint-v1'
        }
      ],
      occurrences: [persistedOccurrence]
    });
    const prisma = serializablePrisma(transaction);
    const store = new PrismaSastFindingLineageStore(
      prisma as unknown as PrismaService
    );
    mockObservationContext(store, context);

    await expect(
      store.observe({
        observationBatchId,
        lifecycleContextKey: lineageContextKey(context),
        observedAt: LINEAGE_FIXTURE_TIME,
        batch,
        context,
        renameCandidates: []
      })
    ).resolves.toMatchObject({
      replayed: true,
      occurrenceCount: 1
    });
    expect(
      transaction.sastFindingObservationBatch.create
    ).not.toHaveBeenCalled();
    expect(
      transaction.normalizedFinding.createMany
    ).not.toHaveBeenCalled();

    transaction.sastFindingOccurrence.findMany.mockResolvedValue([
      {
        ...persistedOccurrence,
        fingerprintDecisionDigest:
          batchIndependentDigest('tampered-decision')
      }
    ]);
    await expect(
      store.observe({
        observationBatchId,
        lifecycleContextKey: lineageContextKey(context),
        observedAt: LINEAGE_FIXTURE_TIME,
        batch,
        context,
        renameCandidates: []
      })
    ).rejects.toBeInstanceOf(
      SastFindingLineageReplayConflictError
    );
  });

  it.each([
    {
      status: 'OPEN',
      observedRows: [],
      expectedKind: 'FIXED',
      expectedStatus: 'FIXED',
      countField: 'fixedCount'
    },
    {
      status: 'FIXED',
      observedRows: [
        {
          lineageId:
            `finding-lineage://${'1'.repeat(64)}`
        }
      ],
      expectedKind: 'REOPENED',
      expectedStatus: 'OPEN',
      countField: 'reopenedCount'
    }
  ] as const)(
    'persists an append-only $expectedKind transition without mutating policy status',
    async ({
      status,
      observedRows,
      expectedKind,
      expectedStatus,
      countField
    }) => {
      const decision = lifecycleCoverageDecision();
      const context = reconciliationContext();
      const transaction = reconciliationTransaction({
        decision,
        status,
        observedRows
      });
      const prisma = serializablePrisma(transaction);
      const store = new PrismaSastFindingLineageStore(
        prisma as unknown as PrismaService
      );
      mockReconciliationContext(store, context);

      const result = await store.reconcile({
        reconciliationId:
          `finding-reconciliation://${'3'.repeat(64)}`,
        reconciledAt: LINEAGE_FIXTURE_TIME,
        decision,
        context: reorderReconciliationContext(context)
      });

      expect(result[countField]).toBe(1);
      expect(
        transaction.sastFindingLifecycleState.updateMany
      ).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            status: expectedStatus,
            revision: { increment: 1 },
            lastReconciliationSequence: 1
          })
        })
      );
      expect(
        transaction.sastFindingLifecycleEvent.createMany
      ).toHaveBeenCalledWith({
        data: [
          expect.objectContaining({
            kind: expectedKind,
            previousStatus: status,
            nextStatus: expectedStatus,
            revision: 2
          })
        ]
      });
      expect(
        transaction.normalizedFinding.updateMany
      ).not.toHaveBeenCalled();
      expect(
        transaction.normalizedFinding.createMany
      ).not.toHaveBeenCalled();
      expect(
        transaction.sastFindingLifecycleReconciliation.create
      ).toHaveBeenCalledWith({
        data: expect.objectContaining({
          coverageDecisionDigest:
            decision.decisionDigest,
          coverageDecision: decision
        })
      });
      expect(
        transaction.sastFindingLifecycleReconciliation.findFirst
      ).toHaveBeenNthCalledWith(
        1,
        expect.objectContaining({
          where: expect.objectContaining({
            tenantId: decision.tenantId,
            repositoryBindingId:
              decision.repositoryBindingId,
            OR: expect.any(Array)
          })
        })
      );
    }
  );

  it('catches a newly eligible target state up to the next global reconciliation sequence', async () => {
    const context = {
      ...reconciliationContext(),
      scanRequestId: 'scan-2',
      attemptId: 'attempt-2',
      commitSha: 'c'.repeat(40),
      canonicalScanKey:
        batchIndependentDigest('canonical-scan-2'),
      planDigest: batchIndependentDigest('plan-2')
    };
    const decision = lifecycleCoverageDecision({
      scanRequestId: context.scanRequestId,
      attemptId: context.attemptId,
      canonicalScanKey: context.canonicalScanKey,
      planDigest: context.planDigest,
      commitSha: context.commitSha,
      sequence: 2,
      previousScanRequestId: 'scan-1',
      previousCommitSha: 'a'.repeat(40)
    });
    const transaction = reconciliationTransaction({
      decision,
      context,
      status: 'OPEN',
      stateSequence: 0,
      observedRows: [
        {
          lineageId: decision.eligibleLineageIds[0]
        }
      ],
      latest: {
        sequence: 1,
        scanRequestId: 'scan-1',
        reconciledAt: new Date(
          '2026-07-29T23:59:30.000Z'
        )
      }
    });
    const prisma = serializablePrisma(transaction);
    const store = new PrismaSastFindingLineageStore(
      prisma as unknown as PrismaService
    );
    mockReconciliationContext(store, context);

    await expect(
      store.reconcile({
        reconciliationId:
          `finding-reconciliation://${'d'.repeat(64)}`,
        reconciledAt: LINEAGE_FIXTURE_TIME,
        decision,
        context
      })
    ).resolves.toMatchObject({
      sequence: 2,
      unchangedOpenCount: 1
    });
    expect(
      transaction.sastFindingLifecycleState.updateMany
    ).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          lastReconciliationSequence: { lte: 1 }
        }),
        data: expect.objectContaining({
          lastReconciliationSequence: 2
        })
      })
    );
  });

  it('rejects partial observation coverage before changing lifecycle state', async () => {
    const decision = lifecycleCoverageDecision();
    const context = reconciliationContext();
    const transaction = reconciliationTransaction({
      decision,
      status: 'OPEN',
      observedRows: [],
      observationDigest: batchIndependentDigest('unexpected')
    });
    const prisma = serializablePrisma(transaction);
    const store = new PrismaSastFindingLineageStore(
      prisma as unknown as PrismaService
    );
    mockReconciliationContext(store, context);

    await expect(
      store.reconcile({
        reconciliationId:
          `finding-reconciliation://${'4'.repeat(64)}`,
        reconciledAt: LINEAGE_FIXTURE_TIME,
        decision,
        context
      })
    ).rejects.toBeInstanceOf(
      SastFindingLineageObservationIncompleteError
    );
    expect(
      transaction.sastFindingLifecycleState.updateMany
    ).not.toHaveBeenCalled();
    expect(
      transaction.sastFindingLifecycleReconciliation.create
    ).not.toHaveBeenCalled();
  });

  it('rejects an omitted zero-finding observation batch from the exact scan ledger', async () => {
    const decision = lifecycleCoverageDecision();
    const context = reconciliationContext();
    const transaction = reconciliationTransaction({
      decision,
      status: 'OPEN',
      observedRows: [],
      additionalBatches: [
        reconciliationBatch(
          context,
          batchIndependentDigest('zero-finding-batch'),
          []
        )
      ]
    });
    const prisma = serializablePrisma(transaction);
    const store = new PrismaSastFindingLineageStore(
      prisma as unknown as PrismaService
    );
    mockReconciliationContext(store, context);

    await expect(
      store.reconcile({
        reconciliationId:
          `finding-reconciliation://${'8'.repeat(64)}`,
        reconciledAt: LINEAGE_FIXTURE_TIME,
        decision,
        context
      })
    ).rejects.toBeInstanceOf(
      SastFindingLineageObservationIncompleteError
    );
    expect(
      transaction.sastFindingLifecycleState.updateMany
    ).not.toHaveBeenCalled();
  });

  it('rejects a mismatched-context batch even when every current-attempt digest is declared', async () => {
    const validDigest =
      lifecycleCoverageDecision()
        .expectedObservationBatchDigests[0];
    const extraDigest = batchIndependentDigest(
      'mismatched-context-batch'
    );
    const decision = lifecycleCoverageDecision({
      expectedObservationBatchDigests: [
        validDigest,
        extraDigest
      ].sort()
    });
    const context = reconciliationContext();
    const transaction = reconciliationTransaction({
      decision,
      status: 'OPEN',
      observedRows: [],
      observationDigest: validDigest,
      additionalBatches: [
        {
          ...reconciliationBatch(
            context,
            extraDigest,
            []
          ),
          lifecycleContextKey:
            batchIndependentDigest('other-target-context')
        }
      ]
    });
    const prisma = serializablePrisma(transaction);
    const store = new PrismaSastFindingLineageStore(
      prisma as unknown as PrismaService
    );
    mockReconciliationContext(store, context);

    await expect(
      store.reconcile({
        reconciliationId:
          `finding-reconciliation://${'e'.repeat(64)}`,
        reconciledAt: LINEAGE_FIXTURE_TIME,
        decision,
        context
      })
    ).rejects.toBeInstanceOf(
      SastFindingLineageObservationIncompleteError
    );
    expect(
      transaction.sastFindingObservationBatch.findMany
    ).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          tenantId: decision.tenantId,
          repositoryBindingId:
            decision.repositoryBindingId,
          scanRequestId: decision.scanRequestId,
          attemptId: decision.attemptId
        }
      })
    );
    expect(
      transaction.sastFindingLifecycleState.updateMany
    ).not.toHaveBeenCalled();
  });
});

function observationTransaction(options: {
  existingBatch?: Record<string, unknown>;
  aliases?: readonly Record<string, unknown>[];
  lineages?: readonly Record<string, unknown>[];
  states?: readonly Record<string, unknown>[];
  occurrences?: readonly Record<string, unknown>[];
  previousScan?: Record<string, unknown>;
} = {}) {
  return {
    scanRequest: {
      findFirst: jest.fn().mockResolvedValue(
        options.previousScan ?? null
      )
    },
    sastFindingObservationBatch: {
      findFirst: jest.fn().mockResolvedValue(
        options.existingBatch ?? null
      ),
      create: jest.fn().mockResolvedValue({ id: 'batch-1' })
    },
    sastFindingIdentityAlias: {
      findMany: jest.fn().mockResolvedValue(
        options.aliases ?? []
      ),
      createMany: jest.fn().mockResolvedValue({ count: 1 })
    },
    sastFindingLineage: {
      findMany: jest.fn().mockResolvedValue(
        options.lineages ?? []
      ),
      createMany: jest.fn().mockResolvedValue({ count: 1 }),
      updateMany: jest.fn().mockResolvedValue({ count: 1 })
    },
    sastFindingLifecycleState: {
      findMany: jest.fn().mockResolvedValue(
        options.states ?? []
      ),
      createMany: jest.fn().mockResolvedValue({ count: 1 }),
      updateMany: jest.fn().mockResolvedValue({ count: 1 })
    },
    sastFindingLifecycleEvent: {
      createMany: jest.fn().mockResolvedValue({ count: 1 })
    },
    normalizedFinding: {
      createMany: jest.fn().mockResolvedValue({ count: 2 })
    },
    sastFindingOccurrence: {
      count: jest.fn().mockResolvedValue(
        options.occurrences?.length ?? 0
      ),
      findMany: jest.fn().mockResolvedValue(
        options.occurrences ?? []
      ),
      createMany: jest.fn().mockResolvedValue({ count: 2 })
    },
    auditEvent: {
      create: jest.fn().mockResolvedValue({ id: 'audit-1' })
    }
  };
}

function reconciliationTransaction(input: {
  decision: ReturnType<typeof lifecycleCoverageDecision>;
  context?: SastFindingReconciliationScanContext;
  status: 'OPEN' | 'FIXED';
  stateSequence?: number;
  observedRows: readonly { lineageId: string }[];
  observationDigest?: string;
  additionalBatches?: readonly Record<string, unknown>[];
  latest?: {
    sequence: number;
    scanRequestId: string;
    reconciledAt: Date;
  };
}) {
  const lineageId = input.decision.eligibleLineageIds[0];
  const context = input.context ?? reconciliationContext();
  const previousPlan = previousPlanForDecision(
    input.decision,
    context
  );
  return {
    sastFindingLifecycleReconciliation: {
      findFirst: jest
        .fn()
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(input.latest ?? null),
      create: jest.fn().mockResolvedValue({ id: 'reconciliation-1' })
    },
    scanRequest: {
      findFirst: jest.fn().mockResolvedValue(
        scanRequestRowForPlan(previousPlan)
      )
    },
    sastFindingObservationBatch: {
      findMany: jest.fn().mockResolvedValue([
        reconciliationBatch(
          context,
          input.observationDigest ??
            input.decision
              .expectedObservationBatchDigests[0],
          ['SAST']
        ),
        ...(input.additionalBatches ?? [])
      ])
    },
    sastFindingLineage: {
      findMany: jest.fn().mockResolvedValue([
        {
          id: lineageId,
          capability:
            input.decision.completeCapabilities[0],
          fingerprintVersion: 'sast-fingerprint-v1'
        }
      ])
    },
    sastFindingOccurrence: {
      findMany: jest.fn().mockResolvedValue(
        input.observedRows.map((row) => ({
          ...row,
          capability:
            input.decision.completeCapabilities[0],
          fingerprintVersion: 'sast-fingerprint-v1',
          lineage: {
            capability:
              input.decision.completeCapabilities[0],
            fingerprintVersion: 'sast-fingerprint-v1'
          }
        }))
      )
    },
    normalizedFinding: {
      updateMany: jest.fn(),
      createMany: jest.fn()
    },
    sastFindingLifecycleState: {
      findMany: jest.fn().mockResolvedValue([
        {
          id: `finding-state://${'6'.repeat(64)}`,
          lineageId,
          status: input.status,
          revision: 1,
          targetRef: 'refs/heads/main',
          lastReconciliationSequence:
            input.stateSequence ?? 0
        }
      ]),
      updateMany: jest.fn().mockResolvedValue({ count: 1 })
    },
    sastFindingLifecycleEvent: {
      createMany: jest.fn().mockResolvedValue({ count: 1 })
    },
    auditEvent: {
      create: jest.fn().mockResolvedValue({ id: 'audit-1' })
    }
  };
}

function reconciliationBatch(
  context: SastFindingReconciliationScanContext,
  sourceIdentityBatchDigest: string,
  capabilities: readonly string[]
) {
  return {
    id: deterministicTestId(
      'finding-observation',
      sourceIdentityBatchDigest
    ),
    sourceIdentityBatchDigest,
    lifecycleContextKey: batchIndependentDigest(
      buildSastFindingLifecycleContextPreimage({
        tenantId: context.tenantId,
        repositoryBindingId:
          context.repositoryBindingId,
        targetRef: context.targetRef
      })
    ),
    capabilities,
    scanner: 'OPENGREP',
    targetRef: context.targetRef,
    commitSha: context.commitSha,
    lane: context.lane,
    profileId: context.profileId,
    profileDigest: context.profileDigest,
    canonicalScanKey: context.canonicalScanKey,
    planDigest: context.planDigest,
    observedAt: new Date(
      '2026-07-29T23:58:30.000Z'
    )
  };
}

function previousPlanForRename(
  attestation: ReturnType<typeof renameAttestation>,
  context: SastFindingLineageScanContext
): SastScanPlan {
  const plan = durablePlan();
  return {
    ...plan,
    tenantId: attestation.tenantId,
    scanRequestId: attestation.fromScanRequestId,
    canonicalScanKey:
      batchIndependentDigest('rename-previous-canonical'),
    profile: SAST_SCAN_PROFILES[attestation.profileId],
    profileDigest: attestation.profileDigest,
    repositoryState: {
      ...plan.repositoryState,
      repositoryBindingId:
        attestation.repositoryBindingId,
      fixedCommitSha: attestation.fromCommitSha,
      targetRef: context.targetRef
    }
  };
}

function scanRequestRowForPlan(plan: SastScanPlan) {
  return {
    lane: plan.profile.lane,
    targetRef: plan.repositoryState.targetRef,
    commitSha: plan.repositoryState.fixedCommitSha,
    canonicalKey: plan.canonicalScanKey,
    sastQueueReservation: {
      immutablePlan: plan
    }
  };
}

function previousPlanForDecision(
  decision: ReturnType<typeof lifecycleCoverageDecision>,
  context: SastFindingReconciliationScanContext
): SastScanPlan {
  const plan = durablePlan();
  return {
    ...plan,
    tenantId: decision.tenantId,
    scanRequestId: decision.previousScanRequestId,
    canonicalScanKey:
      batchIndependentDigest('previous-canonical-scan'),
    profile: SAST_SCAN_PROFILES[decision.profileId],
    profileDigest: decision.profileDigest,
    repositoryState: {
      ...plan.repositoryState,
      repositoryBindingId:
        decision.repositoryBindingId,
      fixedCommitSha: decision.previousCommitSha,
      targetRef: context.targetRef
    }
  };
}

function serializablePrisma<T extends object>(transaction: T) {
  return {
    $transaction: jest.fn(
      async (
        operation: (client: T) => Promise<unknown>
      ) => operation(transaction)
    )
  };
}

function mockObservationContext(
  store: PrismaSastFindingLineageStore,
  context: SastFindingLineageScanContext
): void {
  jest
    .spyOn(
      store as unknown as {
        readObservationContext: (
          ...args: unknown[]
        ) => Promise<SastFindingLineageScanContext | null>;
      },
      'readObservationContext'
    )
    .mockResolvedValue(context);
}

function reorderObservationContext(
  context: Readonly<SastFindingLineageScanContext>
): SastFindingLineageScanContext {
  return {
    source: {
      retentionExpiresAt:
        context.source.retentionExpiresAt,
      dispositionDecisionDigest:
        context.source.dispositionDecisionDigest,
      validationResultDigest:
        context.source.validationResultDigest,
      artifactDigest: context.source.artifactDigest,
      envelopeDigest: context.source.envelopeDigest,
      artifactSchemaVersion:
        context.source.artifactSchemaVersion,
      artifactSchema: context.source.artifactSchema,
      preflightInventoryDigest:
        context.source.preflightInventoryDigest,
      preflightAttestationRef:
        context.source.preflightAttestationRef,
      normalizerBundleDigest:
        context.source.normalizerBundleDigest,
      schemaBundleDigest:
        context.source.schemaBundleDigest,
      ...(context.source.vulnerabilityDatabaseDigest
        ? {
            vulnerabilityDatabaseDigest:
              context.source.vulnerabilityDatabaseDigest
          }
        : {}),
      ...(context.source.ruleBundleDigest
        ? {
            ruleBundleDigest:
              context.source.ruleBundleDigest
          }
        : {}),
      scannerImageDigest:
        context.source.scannerImageDigest,
      scannerVersion: context.source.scannerVersion,
      ingestionId: context.source.ingestionId
    },
    scanner: context.scanner,
    profileDigest: context.profileDigest,
    profileId: context.profileId,
    planDigest: context.planDigest,
    canonicalScanKey: context.canonicalScanKey,
    commitSha: context.commitSha,
    lane: context.lane,
    targetRef: context.targetRef,
    scope: {
      scannerRunId: context.scope.scannerRunId,
      attemptId: context.scope.attemptId,
      scanRequestId: context.scope.scanRequestId,
      repositoryBindingId:
        context.scope.repositoryBindingId,
      tenantId: context.scope.tenantId
    }
  };
}

function mockReconciliationContext(
  store: PrismaSastFindingLineageStore,
  context: SastFindingReconciliationScanContext
): void {
  jest
    .spyOn(
      store as unknown as {
        readReconciliationContext: (
          ...args: unknown[]
        ) => Promise<SastFindingReconciliationScanContext | null>;
      },
      'readReconciliationContext'
    )
    .mockResolvedValue(context);
}

function reorderReconciliationContext(
  context: Readonly<SastFindingReconciliationScanContext>
): SastFindingReconciliationScanContext {
  return {
    profileDigest: context.profileDigest,
    profileId: context.profileId,
    planDigest: context.planDigest,
    canonicalScanKey: context.canonicalScanKey,
    commitSha: context.commitSha,
    lane: context.lane,
    targetRef: context.targetRef,
    attemptId: context.attemptId,
    scanRequestId: context.scanRequestId,
    repositoryBindingId: context.repositoryBindingId,
    tenantId: context.tenantId
  };
}

function deterministicTestId(
  prefix: string,
  value: string
): string {
  return `${prefix}://${createHash('sha256')
    .update(value, 'utf8')
    .digest('hex')}`;
}

function durableObservationRow(
  plan: SastScanPlan,
  retentionExpiresAt: Date,
  overrides: Record<string, unknown> = {}
) {
  return {
    scanner: 'OPENGREP',
    scannerVersion:
      plan.scannerSet.scanners.OPENGREP.version,
    wrapperDigest:
      plan.scannerSet.scanners.OPENGREP.wrapper.digest,
    scannerImageDigest:
      plan.scannerSet.scanners.OPENGREP.digest,
    scannerSetDigest:
      plan.scannerSet.scannerSetDigest,
    ruleBundleDigest:
      plan.scannerSet.ruleBundles.find(
        (bundle) => bundle.scanner === 'OPENGREP'
      )?.digest,
    databaseDigest: null,
    schemaBundleDigest:
      plan.scannerSet.schemaBundle.digest,
    normalizerBundleDigest:
      plan.scannerSet.normalizerBundle.digest,
    profileId: plan.profile.id,
    profileDigest: plan.profileDigest,
    preflightAttestationRef:
      plan.repositoryState.attestationRef,
    preflightInventoryDigest:
      plan.repositoryState.inventoryDigest,
    scannerWorkspaceInventoryDigest:
      plan.repositoryState.inventoryDigest,
    artifactSchema: 'OPENGREP_SARIF',
    artifactSchemaVersion: '2.1.0',
    scanRequest: {
      lane: plan.profile.lane,
      targetRef: plan.repositoryState.targetRef,
      commitSha:
        plan.repositoryState.fixedCommitSha,
      canonicalKey: plan.canonicalScanKey,
      sastQueueReservation: {
        immutablePlan: plan
      }
    },
    artifactIngestion: {
      id: 'ingestion-1',
      envelopeDigest:
        batchIndependentDigest('envelope'),
      observedContentDigest:
        batchIndependentDigest('artifact'),
      retentionExpiresAt,
      dispositionDecision: {
        validationResultDigest:
          batchIndependentDigest('validation'),
        decisionDigest:
          batchIndependentDigest('disposition'),
        retentionExpiresAt
      }
    },
    ...overrides
  };
}

function durablePlan(): SastScanPlan {
  const profile = SAST_SCAN_PROFILES.JAVA_FAST_V1;
  return {
    tenantId: 'tenant-1',
    scanRequestId: 'scan-1',
    canonicalScanKey:
      batchIndependentDigest('canonical-scan'),
    profile,
    profileDigest:
      SAST_APPROVED_PROFILE_DIGESTS[profile.id],
    policyVersion: 'policy-v1',
    repositoryState: {
      repositoryBindingId: 'repository-1',
      fixedCommitSha: 'a'.repeat(40),
      targetRef: 'refs/heads/main',
      inventoryDigest:
        batchIndependentDigest('inventory'),
      attestationRef: 'preflight://attempt-1',
      shallowFetchPreferred: true,
      submodulesEnabled: false,
      lfsObjectsFetched: false
    },
    scannerSet: {
      scannerSetVersion: 'scanner-set-v1',
      scannerSetDigest:
        batchIndependentDigest('scanner-set'),
      signatureRef: 'signature://scanner-set-v1',
      provenanceRef: 'provenance://scanner-set-v1',
      scanners: {
        OPENGREP: scannerDescriptor(
          'OPENGREP',
          '1.22.0',
          'opengrep'
        ),
        TRIVY: scannerDescriptor(
          'TRIVY',
          '0.66.0',
          'trivy'
        ),
        SYFT: scannerDescriptor('SYFT', '1.44.0', 'syft')
      },
      ruleBundles: [
        ruleBundle('OPENGREP', 'opengrep'),
        ruleBundle('TRIVY', 'trivy')
      ],
      vulnerabilityDatabase: {
        databaseVersion: '2026-07-30',
        publishedAt: '2026-07-30T00:00:00.000Z',
        digest: batchIndependentDigest('trivy-db'),
        signatureRef: 'signature://trivy-db',
        provenanceRef: 'provenance://trivy-db'
      },
      schemaBundle: {
        digest: batchIndependentDigest('schema'),
        signatureRef: 'signature://schema',
        provenanceRef: 'provenance://schema'
      },
      normalizerBundle: {
        digest: batchIndependentDigest('normalizer'),
        signatureRef: 'signature://normalizer',
        provenanceRef: 'provenance://normalizer'
      },
      sbomSchema: 'CYCLONEDX_JSON',
      rollbackRef: 'rollback://scanner-set-v1'
    },
    isolationClass: 'HARDENED',
    resultIngressRef: 'result-ingress://tenant-1/scan-1',
    evidenceOutputRef: 'evidence-output://tenant-1/scan-1',
    auditSinkRef: 'audit-sink://tenant-1/scan-1',
    forbiddenCapabilities: [...SAST_FORBIDDEN_CAPABILITIES],
    createdAt: '2026-07-29T23:00:00.000Z'
  };
}

function scannerDescriptor(
  scanner: 'OPENGREP' | 'TRIVY' | 'SYFT',
  version: string,
  seed: string
) {
  return {
    scanner,
    version,
    digest: batchIndependentDigest(`${seed}-image`),
    signatureRef: `signature://${seed}-image`,
    provenanceRef: `provenance://${seed}-image`,
    sbomRef: `sbom://${seed}-image`,
    wrapper: {
      digest: batchIndependentDigest(`${seed}-wrapper`),
      signatureRef: `signature://${seed}-wrapper`,
      provenanceRef: `provenance://${seed}-wrapper`
    }
  };
}

function ruleBundle(
  scanner: 'OPENGREP' | 'TRIVY',
  seed: string
) {
  return {
    bundleId: `${seed}-bundle-v1`,
    version: '1',
    state: 'ACTIVE' as const,
    digest: batchIndependentDigest(`${seed}-bundle`),
    signatureRef: `signature://${seed}-bundle`,
    provenanceRef: `provenance://${seed}-bundle`,
    compatibilityRef: `compatibility://${seed}-bundle`,
    rolloutPolicyRef: `rollout://${seed}-bundle`,
    killSwitchRef: `kill-switch://${seed}-bundle`,
    scanner,
    source: 'PLATFORM_MANAGED' as const,
    immutable: true as const,
    customerExecutableConfigAllowed: false as const,
    rules: [
      {
        ruleId: `${seed}.fixture`,
        ruleRevision: '1',
        ruleSemanticId: `${seed}.fixture`,
        metadataDigest:
          batchIndependentDigest(`${seed}-metadata`)
      }
    ]
  };
}
