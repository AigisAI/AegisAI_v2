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
});
