import {
  BadRequestException,
  NotFoundException,
  ServiceUnavailableException
} from '@nestjs/common';
import { ReportService } from '../../src/report/report.service';

describe('ReportService', () => {
  it('creates a generating report and enqueues a report job for an owned done scan', async () => {
    const reportDelegate = {
      findFirst: jest.fn().mockResolvedValue(null),
      create: jest.fn().mockResolvedValue({
        id: 'report-1',
        status: 'GENERATING'
      }),
      update: jest.fn()
    };
    const prisma = {
      scan: {
        findFirst: jest.fn().mockResolvedValue({
          id: 'scan-1',
          status: 'DONE',
          connectedRepo: {
            userId: 'user-1'
          }
        })
      },
      report: reportDelegate
    };
    const queue = {
      add: jest.fn().mockResolvedValue({ id: 'report-1' })
    };
    const storage = {
      exists: jest.fn().mockResolvedValue(false)
    };

    const service = new ReportService(prisma as never, queue as never, storage as never);

    await expect(
      service.requestReport({
        userId: 'user-1',
        scanId: 'scan-1'
      })
    ).resolves.toEqual({
      reportId: 'report-1',
      status: 'GENERATING',
      message: 'PDF report generation has started.'
    });

    expect(prisma.scan.findFirst).toHaveBeenCalledWith({
      where: {
        id: 'scan-1',
        connectedRepo: {
          userId: 'user-1'
        }
      }
    });
    expect(reportDelegate.create).toHaveBeenCalledWith({
      data: {
        scanId: 'scan-1',
        userId: 'user-1',
        status: 'GENERATING'
      }
    });
    expect(queue.add).toHaveBeenCalledWith(
      'generate-report',
      { reportId: 'report-1' },
      { jobId: 'report-1' }
    );
  });

  it('reuses an in-flight generating report for the same scan and user', async () => {
    const prisma = {
      scan: {
        findFirst: jest.fn().mockResolvedValue({
          id: 'scan-1',
          status: 'DONE',
          connectedRepo: {
            userId: 'user-1'
          }
        })
      },
      report: {
        findFirst: jest.fn().mockResolvedValue({
          id: 'report-1',
          status: 'GENERATING'
        }),
        create: jest.fn(),
        update: jest.fn()
      }
    };

    const service = new ReportService(
      prisma as never,
      { add: jest.fn() } as never,
      { exists: jest.fn() } as never
    );

    await expect(
      service.requestReport({
        userId: 'user-1',
        scanId: 'scan-1'
      })
    ).resolves.toEqual({
      reportId: 'report-1',
      status: 'GENERATING',
      message: 'A PDF report is already being generated.'
    });
  });

  it('reuses a ready report when it is not expired and the file still exists', async () => {
    const prisma = {
      scan: {
        findFirst: jest.fn().mockResolvedValue({
          id: 'scan-1',
          status: 'DONE',
          connectedRepo: {
            userId: 'user-1'
          }
        })
      },
      report: {
        findFirst: jest.fn().mockResolvedValue({
          id: 'report-1',
          status: 'READY',
          expiresAt: new Date(Date.now() + 60_000),
          filePath: './tmp/reports/report-1.pdf'
        }),
        create: jest.fn(),
        update: jest.fn()
      }
    };
    const storage = {
      exists: jest.fn().mockResolvedValue(true)
    };

    const service = new ReportService(
      prisma as never,
      { add: jest.fn() } as never,
      storage as never
    );

    await expect(
      service.requestReport({
        userId: 'user-1',
        scanId: 'scan-1'
      })
    ).resolves.toEqual({
      reportId: 'report-1',
      status: 'READY',
      message: 'An existing PDF report is still available.'
    });
  });

  it('rejects report generation when the scan is not done', async () => {
    const prisma = {
      scan: {
        findFirst: jest.fn().mockResolvedValue({
          id: 'scan-1',
          status: 'RUNNING',
          connectedRepo: {
            userId: 'user-1'
          }
        })
      }
    };

    const service = new ReportService(
      prisma as never,
      { add: jest.fn() } as never,
      { exists: jest.fn() } as never
    );

    await expect(
      service.requestReport({
        userId: 'user-1',
        scanId: 'scan-1'
      })
    ).rejects.toBeInstanceOf(BadRequestException);
  });

  it('rejects report generation when the scan does not belong to the user', async () => {
    const prisma = {
      scan: {
        findFirst: jest.fn().mockResolvedValue(null)
      }
    };

    const service = new ReportService(
      prisma as never,
      { add: jest.fn() } as never,
      { exists: jest.fn() } as never
    );

    await expect(
      service.requestReport({
        userId: 'user-1',
        scanId: 'scan-1'
      })
    ).rejects.toBeInstanceOf(NotFoundException);
  });

  it('marks a report failed when queue enqueue fails after row creation', async () => {
    const reportDelegate = {
      findFirst: jest.fn().mockResolvedValue(null),
      create: jest.fn().mockResolvedValue({
        id: 'report-1',
        status: 'GENERATING'
      }),
      update: jest.fn().mockResolvedValue({
        id: 'report-1',
        status: 'FAILED'
      })
    };
    const prisma = {
      scan: {
        findFirst: jest.fn().mockResolvedValue({
          id: 'scan-1',
          status: 'DONE',
          connectedRepo: {
            userId: 'user-1'
          }
        })
      },
      report: reportDelegate
    };
    const queue = {
      add: jest.fn().mockRejectedValue(new Error('Redis unavailable'))
    };

    const service = new ReportService(
      prisma as never,
      queue as never,
      { exists: jest.fn() } as never
    );

    await expect(
      service.requestReport({
        userId: 'user-1',
        scanId: 'scan-1'
      })
    ).rejects.toBeInstanceOf(ServiceUnavailableException);

    expect(reportDelegate.update).toHaveBeenCalledWith({
      where: { id: 'report-1' },
      data: {
        status: 'FAILED',
        errorMessage: 'Redis unavailable'
      }
    });
  });
});
