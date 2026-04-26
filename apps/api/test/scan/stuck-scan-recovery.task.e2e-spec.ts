import { StuckScanRecoveryTask } from '../../src/scan/stuck-scan-recovery.task';

describe('StuckScanRecoveryTask', () => {
  it('marks stale pending and running scans as failed', async () => {
    const prisma = {
      scan: {
        updateMany: jest.fn().mockResolvedValue({ count: 2 })
      }
    };

    const task = new StuckScanRecoveryTask(prisma as never);

    await expect(task.recover()).resolves.toBe(2);

    expect(prisma.scan.updateMany).toHaveBeenCalledWith({
      where: {
        status: { in: ['PENDING', 'RUNNING'] },
        updatedAt: { lt: expect.any(Date) }
      },
      data: {
        status: 'FAILED',
        errorMessage: 'Scan recovery marked this scan as failed after exceeding the active timeout.',
        completedAt: expect.any(Date)
      }
    });
  });
});
