import type {
  SastArtifactDispositionDecision,
  SastArtifactDispositionIntent
} from '@aegisai/shared';

import { PrismaService } from '../../src/prisma/prisma.service';
import { PrismaSastArtifactDispositionStore } from '../../src/scan-plane/prisma-sast-artifact-disposition.store';
import {
  SastArtifactDispositionFenceError
} from '../../src/scan-plane/sast-artifact-disposition.store';

const DIGEST = `sha256:${'a'.repeat(64)}` as const;
const OPERATION_ID =
  `sast-artifact-disposition-v1:${'a'.repeat(64)}`;
const CLAIMED_AT = '2026-07-26T12:01:00.000Z';
const LEASE_EXPIRES_AT = '2026-07-26T12:02:00.000Z';

describe('PrismaSastArtifactDispositionStore', () => {
  it('claims only a terminal scanner artifact with a fenced lease', async () => {
    const transaction = {
      sastArtifactIngestion: {
        findFirst: jest.fn().mockResolvedValue(claimableRow()),
        updateMany: jest.fn().mockResolvedValue({ count: 1 })
      }
    };
    const prisma = {
      $transaction: jest.fn(
        async (
          operation: (client: typeof transaction) => Promise<unknown>
        ) => operation(transaction)
      )
    };
    const store = new PrismaSastArtifactDispositionStore(
      prisma as unknown as PrismaService
    );

    await expect(
      store.claimNext({
        workerId: 'worker-1',
        leaseToken: 'lease-1',
        claimedAt: CLAIMED_AT,
        leaseExpiresAt: LEASE_EXPIRES_AT
      })
    ).resolves.toEqual(
      expect.objectContaining({
        ingestionId: 'ingestion-1',
        leaseToken: 'lease-1',
        leaseExpiresAt: LEASE_EXPIRES_AT,
        scannerRunStatus: 'COMPLETED',
        scannerArtifactRef:
          'result-ingress://tenant-1/scan-1/opengrep'
      })
    );

    expect(
      transaction.sastArtifactIngestion.findFirst
    ).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          status: 'PENDING_VALIDATION',
          scannerRun: {
            status: {
              in: [
                'COMPLETED',
                'FAILED',
                'TIMED_OUT',
                'QUARANTINED',
                'KILLED'
              ]
            },
            completedAt: { not: null }
          }
        })
      })
    );
    expect(
      transaction.sastArtifactIngestion.updateMany
    ).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          id: 'ingestion-1',
          status: 'PENDING_VALIDATION'
        }),
        data: expect.objectContaining({
          dispositionLeaseOwner: 'worker-1',
          dispositionLeaseToken: 'lease-1',
          dispositionAttemptCount: { increment: 1 }
        })
      })
    );
  });

  it('returns no candidate when another worker wins the claim fence', async () => {
    const transaction = {
      sastArtifactIngestion: {
        findFirst: jest.fn().mockResolvedValue(claimableRow()),
        updateMany: jest.fn().mockResolvedValue({ count: 0 })
      }
    };
    const prisma = {
      $transaction: jest.fn(
        async (
          operation: (client: typeof transaction) => Promise<unknown>
        ) => operation(transaction)
      )
    };
    const store = new PrismaSastArtifactDispositionStore(
      prisma as unknown as PrismaService
    );

    await expect(
      store.claimNext({
        workerId: 'worker-loser',
        leaseToken: 'lease-loser',
        claimedAt: CLAIMED_AT,
        leaseExpiresAt: LEASE_EXPIRES_AT
      })
    ).resolves.toBeNull();
  });

  it('persists immutable intent only under the live lease and expected digest', async () => {
    const prisma = {
      sastArtifactIngestion: {
        updateMany: jest.fn().mockResolvedValue({ count: 1 })
      }
    };
    const store = new PrismaSastArtifactDispositionStore(
      prisma as unknown as PrismaService
    );
    const intent = acceptedIntent();

    await expect(
      store.saveIntent({
        ingestionId: 'ingestion-1',
        leaseToken: 'lease-1',
        expectedIntentDigest: null,
        intent,
        operationId: OPERATION_ID,
        savedAt: CLAIMED_AT
      })
    ).resolves.toBeUndefined();

    expect(
      prisma.sastArtifactIngestion.updateMany
    ).toHaveBeenCalledWith({
      where: {
        id: 'ingestion-1',
        status: 'PENDING_VALIDATION',
        dispositionLeaseToken: 'lease-1',
        dispositionLeaseExpiresAt: {
          gt: new Date(CLAIMED_AT)
        },
        dispositionIntentDigest: null
      },
      data: expect.objectContaining({
        dispositionIntent: intent,
        dispositionIntentDigest: intent.intentDigest,
        dispositionOperationId: OPERATION_ID,
        retentionExpiresAt: new Date(
          '2026-08-02T12:00:00.000Z'
        )
      })
    });
  });

  it('atomically fences final state, scanner status, audit, and immutable decision', async () => {
    const transaction = {
      sastArtifactIngestion: {
        updateMany: jest.fn().mockResolvedValue({ count: 1 })
      },
      scannerRun: {
        updateMany: jest.fn().mockResolvedValue({ count: 1 })
      },
      auditEvent: {
        create: jest.fn().mockResolvedValue({ id: 'audit-1' })
      },
      sastArtifactDispositionDecision: {
        create: jest.fn().mockResolvedValue({ id: 'decision-1' })
      }
    };
    const prisma = {
      $transaction: jest.fn(
        async (
          operation: (client: typeof transaction) => Promise<unknown>
        ) => operation(transaction)
      )
    };
    const store = new PrismaSastArtifactDispositionStore(
      prisma as unknown as PrismaService
    );
    const decision = quarantinedDecision();

    await expect(
      store.finalize({
        decisionId: 'decision-1',
        auditEventId: 'audit-1',
        ingestionId: 'ingestion-1',
        scope: scope(),
        leaseToken: 'lease-1',
        operationId: OPERATION_ID,
        decision,
        fencedAt: '2026-07-26T12:01:02.000Z',
        finalObjectKey:
          'restricted/sast-artifact-quarantine/opaque-1'
      })
    ).resolves.toBeUndefined();

    expect(
      transaction.sastArtifactIngestion.updateMany
    ).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          id: 'ingestion-1',
          status: 'PENDING_VALIDATION',
          dispositionLeaseToken: 'lease-1',
          dispositionIntentDigest: decision.intentDigest,
          dispositionOperationId: OPERATION_ID
        }),
        data: expect.objectContaining({
          status: 'QUARANTINED',
          dispositionLeaseToken: null,
          dispositionDecidedAt: new Date(decision.decidedAt)
        })
      })
    );
    expect(transaction.scannerRun.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          id: 'scanner-run-1',
          status: {
            in: [
              'COMPLETED',
              'FAILED',
              'TIMED_OUT',
              'QUARANTINED',
              'KILLED'
            ]
          }
        }),
        data: expect.objectContaining({
          status: 'QUARANTINED'
        })
      })
    );
    const auditData =
      transaction.auditEvent.create.mock.calls[0]![0].data;
    const decisionData =
      transaction.sastArtifactDispositionDecision.create.mock
        .calls[0]![0].data;
    expect(auditData.metadata).not.toHaveProperty('objectKey');
    expect(decisionData.decision).not.toHaveProperty('objectKey');
    expect(decisionData).not.toHaveProperty('objectKey');
    expect(decisionData).toEqual(
      expect.objectContaining({
        tenantId: 'tenant-1',
        scannerRunId: 'scanner-run-1',
        auditEventId: 'audit-1',
        normalizationEligible: false
      })
    );
  });

  it('rejects finalization after the database fence is lost', async () => {
    const transaction = {
      sastArtifactIngestion: {
        updateMany: jest.fn().mockResolvedValue({ count: 0 })
      },
      scannerRun: { updateMany: jest.fn() },
      auditEvent: { create: jest.fn() },
      sastArtifactDispositionDecision: { create: jest.fn() }
    };
    const prisma = {
      $transaction: jest.fn(
        async (
          operation: (client: typeof transaction) => Promise<unknown>
        ) => operation(transaction)
      )
    };
    const store = new PrismaSastArtifactDispositionStore(
      prisma as unknown as PrismaService
    );

    await expect(
      store.finalize({
        decisionId: 'decision-1',
        auditEventId: 'audit-1',
        ingestionId: 'ingestion-1',
        scope: scope(),
        leaseToken: 'expired-lease',
        operationId: OPERATION_ID,
        decision: quarantinedDecision(),
        fencedAt: '2026-07-26T12:01:02.000Z',
        finalObjectKey:
          'restricted/sast-artifact-quarantine/opaque-1'
      })
    ).rejects.toBeInstanceOf(SastArtifactDispositionFenceError);
    expect(transaction.auditEvent.create).not.toHaveBeenCalled();
    expect(
      transaction.sastArtifactDispositionDecision.create
    ).not.toHaveBeenCalled();
  });

  it('does not let an expired worker release or reschedule another lease', async () => {
    const prisma = {
      sastArtifactIngestion: {
        updateMany: jest.fn().mockResolvedValue({ count: 0 })
      }
    };
    const store = new PrismaSastArtifactDispositionStore(
      prisma as unknown as PrismaService
    );

    await expect(
      store.release({
        ingestionId: 'ingestion-1',
        leaseToken: 'expired-lease',
        errorCode: 'ARTIFACT_DISPOSITION_RETRYABLE_FAILURE',
        releasedAt: '2026-07-26T12:02:01.000Z',
        retryAt: '2026-07-26T12:03:01.000Z'
      })
    ).rejects.toBeInstanceOf(SastArtifactDispositionFenceError);

    expect(
      prisma.sastArtifactIngestion.updateMany
    ).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          dispositionLeaseToken: 'expired-lease',
          dispositionLeaseExpiresAt: {
            gt: new Date('2026-07-26T12:02:01.000Z')
          }
        })
      })
    );
  });
});

function claimableRow() {
  return {
    id: 'ingestion-1',
    tenantId: 'tenant-1',
    repositoryBindingId: 'repository-1',
    scanRequestId: 'scan-1',
    attemptId: 'attempt-1',
    scannerRunId: 'scanner-run-1',
    workloadIdentityRef: 'spiffe://aegis/scan/attempt-1',
    identityValidated: true,
    envelope: {},
    envelopeDigest: DIGEST,
    declaredContentDigest: DIGEST,
    observedContentDigest: DIGEST,
    declaredByteSize: 128,
    observedByteSize: 128,
    objectKey: 'ingress/opaque-1',
    validationMetadata: {},
    receivedAt: new Date('2026-07-26T12:00:00.000Z'),
    dispositionIntent: null,
    dispositionIntentDigest: null,
    dispositionOperationId: null,
    scannerRun: {
      scanner: 'OPENGREP',
      scannerVersion: '1.1.0',
      scannerImageDigest: DIGEST,
      wrapperDigest: DIGEST,
      ruleBundleDigest: DIGEST,
      databaseDigest: null,
      scannerSetDigest: DIGEST,
      schemaBundleDigest: DIGEST,
      normalizerBundleDigest: DIGEST,
      profileId: 'JAVA_FAST_V1',
      profileDigest: DIGEST,
      scannerWorkspaceInventoryDigest: DIGEST,
      artifactSchema: 'OPENGREP_SARIF',
      artifactSchemaVersion: '2.1.0',
      exitCode: 0,
      timedOut: false,
      outputLimitExceeded: false,
      status: 'COMPLETED',
      completedAt: new Date('2026-07-26T12:00:30.000Z'),
      rawArtifactObjectKey: 'ingress/opaque-1',
      artifactMetadata: {
        artifactRef: 'result-ingress://tenant-1/scan-1/opengrep',
        byteSize: 128
      },
      preflightAttestationRef: 'preflight://attempt-1',
      preflightInventoryDigest: DIGEST
    },
    scanRequest: {
      sastQueueReservation: {
        immutablePlan: {}
      }
    }
  };
}

function scope() {
  return {
    tenantId: 'tenant-1',
    repositoryBindingId: 'repository-1',
    scanRequestId: 'scan-1',
    attemptId: 'attempt-1',
    scannerRunId: 'scanner-run-1'
  };
}

function acceptedIntent(): SastArtifactDispositionIntent {
  return {
    version: 'sast-artifact-disposition-v1',
    ingestionId: 'ingestion-1',
    scope: scope(),
    disposition: 'ACCEPTED',
    storageAction: 'RETAIN_ACCEPTED',
    reasonCodes: ['ARTIFACT_VALIDATION_ACCEPTED'],
    validationReasonCodes: [],
    validationResultDigest: DIGEST,
    normalizationEligible: true,
    retentionExpiresAt: '2026-08-02T12:00:00.000Z',
    acceptanceControlRef: 'kill-switch-evaluation://allow-1',
    createdAt: CLAIMED_AT,
    intentDigest: DIGEST
  };
}

function quarantinedDecision(): SastArtifactDispositionDecision {
  return {
    version: 'sast-artifact-disposition-v1',
    ingestionId: 'ingestion-1',
    disposition: 'QUARANTINED',
    storageAction: 'MOVE_REENCRYPT_QUARANTINE',
    failureClass: 'SECURITY_VIOLATION',
    reasonCodes: ['ARTIFACT_VALIDATION_FAILED'],
    validationReasonCodes: ['ARTIFACT_JSON_MALFORMED'],
    validationResultDigest: DIGEST,
    normalizationEligible: false,
    retentionExpiresAt: '2026-08-02T12:00:00.000Z',
    intentDigest: DIGEST,
    storageOperationId: OPERATION_ID,
    storageReceiptRef: 'storage-receipt://quarantine-1',
    storageReceiptDigest: DIGEST,
    encryptionContextDigest: DIGEST,
    decidedAt: '2026-07-26T12:01:01.000Z',
    decisionDigest: DIGEST
  };
}
