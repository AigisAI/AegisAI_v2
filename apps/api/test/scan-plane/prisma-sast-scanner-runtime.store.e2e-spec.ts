import type { PrismaService } from '../../src/prisma/prisma.service';
import {
  isSastAttemptSequenceEligible,
  PrismaSastScannerRuntimeStore
} from '../../src/scan-plane/prisma-sast-scanner-runtime.store';
import type {
  SastScannerInvocation,
  SastScannerWrapperExecutionRequest
} from '@aegisai/shared';

describe('PrismaSastScannerRuntimeStore', () => {
  it('persists semantic schema and immutable schema/normalizer bundle bindings', async () => {
    const create = jest.fn().mockResolvedValue({ id: 'scanner-run-1' });
    const store = new PrismaSastScannerRuntimeStore({
      scannerRun: { create }
    } as unknown as PrismaService);
    const request = {
      attemptId: 'attempt-1',
      plan: {
        tenantId: 'tenant-1',
        scanRequestId: 'scan-1',
        repositoryState: {
          repositoryBindingId: 'repository-1'
        },
        resultIngressRef: 'result-ingress://tenant-1/scan-1'
      }
    } as unknown as SastScannerWrapperExecutionRequest;
    const invocation = {
      scanner: 'OPENGREP',
      scannerVersion: '1.1.0',
      required: true,
      wrapperDigest: digest('1'),
      scannerImageDigest: digest('2'),
      ruleBundleDigest: digest('3'),
      scannerSetDigest: digest('4'),
      schemaBundleDigest: digest('5'),
      normalizerBundleDigest: digest('6'),
      profileId: 'JAVA_FAST_V1',
      profileDigest: digest('7'),
      preflightAttestationRef: 'preflight://attempt-1',
      preflightInventoryDigest: digest('8'),
      artifactSchema: 'OPENGREP_SARIF',
      artifactSchemaVersion: '2.1.0'
    } as unknown as SastScannerInvocation;

    await store.beginScannerRun(
      request,
      'scanner-run-1',
      invocation,
      '2026-07-24T12:00:00.000Z'
    );

    expect(create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        artifactSchema: 'OPENGREP_SARIF',
        artifactSchemaVersion: '2.1.0',
        schemaBundleDigest: digest('5'),
        normalizerBundleDigest: digest('6')
      })
    });
  });

  it('admits attempt two only after attempt one has a durable retry-eligible infrastructure failure', () => {
    const eligibleAttemptOne = {
      attemptNumber: 1,
      stage: 'FAILED' as const,
      failureClass: 'RETRYABLE_INFRASTRUCTURE' as const,
      retryEligible: true,
      completedAt: new Date('2026-07-24T12:00:00.000Z'),
      finalAuditEventId: 'audit-attempt-1'
    };

    expect(isSastAttemptSequenceEligible(1, null)).toBe(true);
    expect(isSastAttemptSequenceEligible(1, eligibleAttemptOne)).toBe(false);
    expect(isSastAttemptSequenceEligible(2, eligibleAttemptOne)).toBe(true);
    expect(
      isSastAttemptSequenceEligible(2, {
        ...eligibleAttemptOne,
        failureClass: 'SCANNER_DEFECT'
      })
    ).toBe(false);
    expect(
      isSastAttemptSequenceEligible(2, {
        ...eligibleAttemptOne,
        retryEligible: false
      })
    ).toBe(false);
    expect(
      isSastAttemptSequenceEligible(2, {
        ...eligibleAttemptOne,
        finalAuditEventId: null
      })
    ).toBe(false);
    expect(isSastAttemptSequenceEligible(3, eligibleAttemptOne)).toBe(false);
  });

  it('atomically fails overdue active attempts with an attempt-scoped final audit event', async () => {
    const attemptDeadlineAt = new Date('2026-07-24T12:00:00.000Z');
    const auditCreate = jest.fn().mockResolvedValue({ id: 'audit-created' });
    const attemptUpdate = jest.fn().mockResolvedValue({ count: 1 });
    const transaction = {
      sastScanAttempt: {
        findFirst: jest.fn().mockResolvedValue({
          id: 'attempt-1',
          tenantId: 'tenant-1',
          repositoryBindingId: 'repository-1',
          scanRequestId: 'scan-1',
          sandboxId: 'sandbox-1',
          workloadIdentityRef: 'spiffe://aegis/scan/attempt-1',
          attemptDeadlineAt
        }),
        updateMany: attemptUpdate
      },
      auditEvent: { create: auditCreate }
    };
    const findMany = jest.fn().mockResolvedValue([{ id: 'attempt-1' }]);
    const prisma = {
      sastScanAttempt: { findMany },
      $transaction: jest.fn(
        async (
          operation: (client: typeof transaction) => Promise<unknown>
        ) => operation(transaction)
      )
    };
    const store = new PrismaSastScannerRuntimeStore(
      prisma as unknown as PrismaService
    );
    const referenceTime = '2026-07-24T12:01:01.000Z';

    await expect(store.failOverdueAttempts(referenceTime)).resolves.toBe(1);
    expect(findMany).toHaveBeenCalledWith({
      where: {
        stage: { in: ['VALIDATING', 'SCANNING', 'CLEANUP_PENDING'] },
        attemptDeadlineAt: {
          lte: new Date('2026-07-24T12:00:01.000Z')
        }
      },
      select: { id: true },
      orderBy: [{ attemptDeadlineAt: 'asc' }, { id: 'asc' }],
      take: 100
    });
    const auditData = auditCreate.mock.calls[0][0].data as {
      id: string;
      attemptId: string;
      tenantId: string;
      eventType: string;
    };
    expect(auditData).toMatchObject({
      attemptId: 'attempt-1',
      tenantId: 'tenant-1',
      eventType: 'sandbox.cleanup_failed'
    });
    expect(attemptUpdate).toHaveBeenCalledWith({
      where: {
        id: 'attempt-1',
        tenantId: 'tenant-1',
        stage: { in: ['VALIDATING', 'SCANNING', 'CLEANUP_PENDING'] }
      },
      data: {
        stage: 'CLEANUP_FAILED',
        failureClass: 'SECURITY_VIOLATION',
        failureReason: 'SANDBOX_CLEANUP_EVIDENCE_OVERDUE',
        retryEligible: false,
        finalAuditEventId: auditData.id,
        completedAt: new Date(referenceTime)
      }
    });
  });

  it('does not close an attempt while artifact bytes are still being received', async () => {
    const attemptUpdate = jest.fn();
    const transaction = {
      sastArtifactIngestion: {
        count: jest.fn().mockResolvedValue(1)
      },
      sastScanAttempt: {
        updateMany: attemptUpdate
      }
    };
    const prisma = {
      $transaction: jest.fn(
        async (
          operation: (client: typeof transaction) => Promise<unknown>
        ) => operation(transaction)
      )
    };
    const store = new PrismaSastScannerRuntimeStore(
      prisma as unknown as PrismaService
    );
    const request = {
      attemptId: 'attempt-1',
      sandboxId: 'sandbox-1',
      workloadIdentityRef: 'spiffe://aegis/scan/attempt-1',
      plan: {
        tenantId: 'tenant-1',
        scanRequestId: 'scan-1',
        repositoryState: {
          repositoryBindingId: 'repository-1'
        }
      }
    } as unknown as SastScannerWrapperExecutionRequest;

    await expect(
      store.markStage(request, 'CLEANUP_PENDING')
    ).rejects.toMatchObject({
      failureClass: 'SECURITY_VIOLATION',
      reasonCode: 'ARTIFACT_INGRESS_STILL_RECEIVING'
    });
    expect(attemptUpdate).not.toHaveBeenCalled();
  });
});

function digest(character: string): `sha256:${string}` {
  return `sha256:${character.repeat(64)}`;
}
