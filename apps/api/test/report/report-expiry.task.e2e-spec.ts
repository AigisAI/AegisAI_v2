import { ReportExpiryTask } from '../../src/report/report-expiry.task';

describe('ReportExpiryTask', () => {
  it('expires ready reports whose expiry time has passed and deletes local files', async () => {
    const prisma = {
      report: {
        findMany: jest.fn().mockResolvedValue([
          {
            id: 'report-1',
            filePath: './tmp/reports/report-1.pdf'
          }
        ]),
        updateMany: jest.fn().mockResolvedValue({
          count: 1
        })
      }
    };
    const storage = {
      delete: jest.fn().mockResolvedValue(undefined)
    };

    const task = new ReportExpiryTask(prisma as never, storage as never);

    await task.expireReadyReports(new Date('2026-03-30T00:00:00.000Z'));

    expect(prisma.report.findMany).toHaveBeenCalledWith({
      where: {
        status: 'READY',
        expiresAt: {
          lte: new Date('2026-03-30T00:00:00.000Z')
        }
      }
    });
    expect(storage.delete).toHaveBeenCalledWith('./tmp/reports/report-1.pdf');
    expect(prisma.report.updateMany).toHaveBeenCalledWith({
      where: {
        id: {
          in: ['report-1']
        }
      },
      data: {
        status: 'EXPIRED',
        downloadUrl: null,
        errorMessage: 'Report expired.'
      }
    });
  });

  it('does nothing when there are no expired ready reports', async () => {
    const prisma = {
      report: {
        findMany: jest.fn().mockResolvedValue([]),
        updateMany: jest.fn()
      }
    };
    const storage = {
      delete: jest.fn()
    };

    const task = new ReportExpiryTask(prisma as never, storage as never);

    await task.expireReadyReports(new Date('2026-03-30T00:00:00.000Z'));

    expect(prisma.report.findMany).toHaveBeenCalled();
    expect(storage.delete).not.toHaveBeenCalled();
    expect(prisma.report.updateMany).not.toHaveBeenCalled();
  });

  it('continues expiring reports even when one file deletion fails', async () => {
    const prisma = {
      report: {
        findMany: jest.fn().mockResolvedValue([
          {
            id: 'report-1',
            filePath: './tmp/reports/report-1.pdf'
          },
          {
            id: 'report-2',
            filePath: './tmp/reports/report-2.pdf'
          }
        ]),
        updateMany: jest.fn().mockResolvedValue({ count: 2 })
      }
    };
    const storage = {
      delete: jest
        .fn()
        .mockRejectedValueOnce(new Error('permission denied'))
        .mockResolvedValueOnce(undefined)
    };

    const task = new ReportExpiryTask(prisma as never, storage as never);

    await expect(
      task.expireReadyReports(new Date('2026-03-30T00:00:00.000Z'))
    ).resolves.toBeUndefined();

    expect(storage.delete).toHaveBeenCalledTimes(2);
    expect(prisma.report.updateMany).toHaveBeenCalled();
  });
});
