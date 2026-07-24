import type { SastScanPlan } from '@aegisai/shared';

import { PrismaService } from '../../src/prisma/prisma.service';
import { PrismaSastArtifactIngressStore } from '../../src/scan-plane/prisma-sast-artifact-ingress.store';
import {
  SastArtifactIngressReplayConflictError,
  type SastArtifactIngressExpectedBinding
} from '../../src/scan-plane/sast-artifact-ingress.store';

const DIGEST = `sha256:${'a'.repeat(64)}` as const;

describe('PrismaSastArtifactIngressStore', () => {
  it('reserves one scanner-run-bound ingress in a serializable lifecycle transaction', async () => {
    const transaction = {
      sastArtifactIngestion: {
        findUnique: jest.fn().mockResolvedValue(null),
        create: jest.fn().mockResolvedValue({ id: 'ingestion-1' })
      },
      sastScanAttempt: {
        findFirst: jest.fn().mockResolvedValue({ id: 'attempt-1' })
      },
      scannerRun: {
        findFirst: jest.fn().mockResolvedValue({ id: 'scanner-run-1' })
      },
      auditEvent: {
        create: jest.fn().mockResolvedValue({ id: 'audit-1' })
      }
    };
    const prisma = {
      $transaction: jest.fn(
        async (
          operation: (client: typeof transaction) => Promise<unknown>
        ) => operation(transaction)
      )
    };
    const store = new PrismaSastArtifactIngressStore(
      prisma as unknown as PrismaService
    );
    const now = '2026-07-24T18:00:00.000Z';

    await expect(
      store.reserve({
        ingestionId: 'ingestion-1',
        envelopeDigest: DIGEST,
        idempotencyKey: `sast-ingress-v1:scanner-run-1:${DIGEST}`,
        expected: expectedBinding(),
        declaredContentDigest: DIGEST,
        declaredByteSize: 128,
        now
      })
    ).resolves.toEqual({
      kind: 'RESERVED',
      ingestionId: 'ingestion-1',
      state: 'RECEIVING'
    });
    expect(transaction.sastScanAttempt.findFirst).toHaveBeenCalledWith({
      where: {
        id: 'attempt-1',
        tenantId: 'tenant-1',
        repositoryBindingId: 'repository-1',
        scanRequestId: 'scan-1',
        workloadIdentityRef: 'spiffe://aegis/scan/attempt-1',
        stage: 'SCANNING',
        attemptDeadlineAt: {
          gt: new Date(now)
        }
      },
      select: { id: true }
    });
    expect(transaction.scannerRun.findFirst).toHaveBeenCalledWith({
      where: {
        id: 'scanner-run-1',
        attemptId: 'attempt-1',
        tenantId: 'tenant-1',
        repositoryBindingId: 'repository-1',
        scanRequestId: 'scan-1',
        scanner: 'OPENGREP',
        status: 'RUNNING'
      },
      select: { id: true }
    });
    expect(transaction.sastArtifactIngestion.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        id: 'ingestion-1',
        scannerRunId: 'scanner-run-1',
        workloadIdentityRef: 'spiffe://aegis/scan/attempt-1',
        identityValidated: true,
        status: 'RECEIVING'
      })
    });
  });

  it('atomically binds the opaque object key to ingestion and running scanner metadata', async () => {
    const transaction = {
      sastArtifactIngestion: {
        findUnique: jest.fn().mockResolvedValue({
          tenantId: 'tenant-1',
          scanRequestId: 'scan-1',
          repositoryBindingId: 'repository-1',
          attemptId: 'attempt-1',
          scannerRunId: 'scanner-run-1',
          workloadIdentityRef: 'spiffe://aegis/scan/attempt-1',
          status: 'RECEIVING'
        }),
        updateMany: jest.fn().mockResolvedValue({ count: 1 })
      },
      sastScanAttempt: {
        findFirst: jest.fn().mockResolvedValue({ id: 'attempt-1' })
      },
      scannerRun: {
        updateMany: jest.fn().mockResolvedValue({ count: 1 })
      },
      auditEvent: {
        create: jest.fn().mockResolvedValue({ id: 'audit-1' })
      }
    };
    const prisma = {
      $transaction: jest.fn(
        async (
          operation: (client: typeof transaction) => Promise<unknown>
        ) => operation(transaction)
      )
    };
    const store = new PrismaSastArtifactIngressStore(
      prisma as unknown as PrismaService
    );

    await store.complete({
      ingestionId: 'ingestion-1',
      objectKey: 'raw-sast/ingestion-1',
      observedContentDigest: DIGEST,
      observedByteSize: 128,
      receivedAt: '2026-07-24T18:00:01.000Z'
    });

    expect(transaction.scannerRun.updateMany).toHaveBeenCalledWith({
      where: {
        id: 'scanner-run-1',
        tenantId: 'tenant-1',
        scanRequestId: 'scan-1',
        attemptId: 'attempt-1',
        status: 'RUNNING',
        rawArtifactObjectKey: null
      },
      data: {
        rawArtifactObjectKey: 'raw-sast/ingestion-1'
      }
    });
    expect(transaction.sastScanAttempt.findFirst).toHaveBeenCalledWith({
      where: {
        id: 'attempt-1',
        tenantId: 'tenant-1',
        repositoryBindingId: 'repository-1',
        scanRequestId: 'scan-1',
        stage: 'SCANNING',
        attemptDeadlineAt: {
          gt: new Date('2026-07-24T18:00:01.000Z')
        }
      },
      select: { id: true }
    });
    expect(transaction.auditEvent.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        eventType: 'artifact.ingress_received',
        targetId: 'ingestion-1'
      })
    });
  });

  it('rejects a changed envelope replay without replacing the first artifact', async () => {
    const existing = {
      id: 'ingestion-1',
      envelopeDigest: DIGEST,
      idempotencyKey: `sast-ingress-v1:scanner-run-1:${DIGEST}`,
      declaredContentDigest: DIGEST,
      declaredByteSize: 128,
      status: 'PENDING_VALIDATION',
      receivedAt: new Date('2026-07-24T18:00:01.000Z')
    };
    const transaction = {
      sastScanAttempt: {
        findFirst: jest.fn().mockResolvedValue({ id: 'attempt-1' })
      },
      sastArtifactIngestion: {
        findUnique: jest.fn().mockResolvedValue(existing)
      }
    };
    const prisma = {
      $transaction: jest.fn(
        async (
          operation: (client: typeof transaction) => Promise<unknown>
        ) => operation(transaction)
      )
    };
    const store = new PrismaSastArtifactIngressStore(
      prisma as unknown as PrismaService
    );

    await expect(
      store.reserve({
        ingestionId: 'ingestion-2',
        envelopeDigest: `sha256:${'b'.repeat(64)}`,
        idempotencyKey: existing.idempotencyKey,
        expected: expectedBinding(),
        declaredContentDigest: DIGEST,
        declaredByteSize: 128,
        now: '2026-07-24T18:00:02.000Z'
      })
    ).rejects.toBeInstanceOf(SastArtifactIngressReplayConflictError);
  });
});

function expectedBinding(): SastArtifactIngressExpectedBinding {
  return {
    plan: {
      tenantId: 'tenant-1',
      scanRequestId: 'scan-1',
      repositoryState: {
        repositoryBindingId: 'repository-1'
      }
    } as unknown as SastScanPlan,
    attemptId: 'attempt-1',
    scannerRunId: 'scanner-run-1',
    workloadIdentityRef: 'spiffe://aegis/scan/attempt-1',
    preflightAttestationRef: 'preflight://attempt-1',
    preflightInventoryDigest: DIGEST,
    scanner: 'OPENGREP',
    artifactRef: 'result-ingress://tenant-1/scan-1/opengrep',
    attemptStage: 'SCANNING',
    attemptDeadlineAt: '2026-07-24T18:05:00.000Z',
    scannerRunStatus: 'RUNNING'
  };
}
