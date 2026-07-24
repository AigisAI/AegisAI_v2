import type { PrismaService } from '../../src/prisma/prisma.service';
import { PrismaSastScannerRuntimeStore } from '../../src/scan-plane/prisma-sast-scanner-runtime.store';

describe('PrismaSastScannerRuntimeStore', () => {
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
});
