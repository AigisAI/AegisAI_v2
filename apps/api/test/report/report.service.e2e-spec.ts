import {
  BadRequestException,
  ConflictException,
  GoneException,
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
    const queue = {
      add: jest.fn()
    };
    const storage = {
      exists: jest.fn()
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
      report: {
        findFirst: jest.fn().mockResolvedValue({
          id: 'report-1',
          status: 'GENERATING'
        }),
        create: jest.fn(),
        update: jest.fn()
      }
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
      message: 'A PDF report is already being generated.'
    });

    expect(prisma.report.create).not.toHaveBeenCalled();
    expect(prisma.report.update).not.toHaveBeenCalled();
    expect(storage.exists).not.toHaveBeenCalled();
    expect(queue.add).not.toHaveBeenCalled();
  });

  it('reuses a ready report when it is not expired and the file still exists', async () => {
    const queue = {
      add: jest.fn()
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
      report: {
        findFirst: jest.fn().mockResolvedValue({
          id: 'report-1',
          status: 'READY',
          expiresAt: new Date(Date.now() + 60_000),
          filePath: './tmp/reports/report-1.pdf'
        }),
        findUnique: jest.fn().mockResolvedValue({
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

    const service = new ReportService(prisma as never, queue as never, storage as never);

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

    expect(storage.exists).toHaveBeenCalledTimes(2);
    expect(storage.exists).toHaveBeenNthCalledWith(1, './tmp/reports/report-1.pdf');
    expect(storage.exists).toHaveBeenNthCalledWith(2, './tmp/reports/report-1.pdf');
    expect(prisma.report.create).not.toHaveBeenCalled();
    expect(prisma.report.update).not.toHaveBeenCalled();
    expect(queue.add).not.toHaveBeenCalled();
  });

  it('returns the existing generating report when create hits a uniqueness conflict', async () => {
    const duplicateError = Object.assign(new Error('duplicate report'), {
      code: 'P2002'
    });
    const reportDelegate = {
      findFirst: jest
        .fn()
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce({
          id: 'report-existing',
          status: 'GENERATING'
        }),
      create: jest.fn().mockRejectedValue(duplicateError),
      update: jest.fn()
    };
    const queue = {
      add: jest.fn()
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
    ).resolves.toEqual({
      reportId: 'report-existing',
      status: 'GENERATING',
      message: 'A PDF report is already being generated.'
    });

    expect(reportDelegate.create).toHaveBeenCalledTimes(1);
    expect(reportDelegate.update).not.toHaveBeenCalled();
    expect(queue.add).not.toHaveBeenCalled();
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

  it('returns a downloadable PDF for an owned ready report with an existing file', async () => {
    const prisma = {
      report: {
        findFirst: jest.fn().mockResolvedValue({
          id: 'report-1',
          scanId: 'scan-1',
          userId: 'user-1',
          status: 'READY',
          filePath: './tmp/reports/report-1.pdf',
          expiresAt: new Date(Date.now() + 60_000)
        }),
        update: jest.fn()
      }
    };
    const storage = {
      exists: jest.fn().mockResolvedValue(true),
      read: jest.fn().mockResolvedValue(Buffer.from('%PDF-1.4\n'))
    };

    const service = new ReportService(prisma as never, { add: jest.fn() } as never, storage as never);

    await expect(service.getReportDownload('user-1', 'report-1')).resolves.toEqual({
      fileName: 'report-1.pdf',
      mimeType: 'application/pdf',
      buffer: Buffer.from('%PDF-1.4\n')
    });

    expect(storage.exists).toHaveBeenCalledWith('./tmp/reports/report-1.pdf');
    expect(storage.read).toHaveBeenCalledWith('./tmp/reports/report-1.pdf');
    expect(prisma.report.update).not.toHaveBeenCalled();
  });

  it('rejects report download while generation is still in progress', async () => {
    const prisma = {
      report: {
        findFirst: jest.fn().mockResolvedValue({
          id: 'report-1',
          scanId: 'scan-1',
          userId: 'user-1',
          status: 'GENERATING',
          filePath: null,
          expiresAt: null
        })
      }
    };

    const service = new ReportService(
      prisma as never,
      { add: jest.fn() } as never,
      { exists: jest.fn(), read: jest.fn() } as never
    );

    await expect(service.getReportDownload('user-1', 'report-1')).rejects.toBeInstanceOf(
      ConflictException
    );
  });

  it('expires a stale ready report and rejects download when the file is missing', async () => {
    const prisma = {
      report: {
        findFirst: jest.fn().mockResolvedValue({
          id: 'report-1',
          scanId: 'scan-1',
          userId: 'user-1',
          status: 'READY',
          filePath: './tmp/reports/report-1.pdf',
          expiresAt: new Date(Date.now() + 60_000)
        }),
        update: jest.fn().mockResolvedValue({
          id: 'report-1',
          status: 'EXPIRED'
        })
      }
    };
    const storage = {
      exists: jest.fn().mockResolvedValue(false),
      read: jest.fn()
    };

    const service = new ReportService(prisma as never, { add: jest.fn() } as never, storage as never);

    await expect(service.getReportDownload('user-1', 'report-1')).rejects.toBeInstanceOf(
      GoneException
    );

    expect(prisma.report.update).toHaveBeenCalledWith({
      where: {
        id: 'report-1'
      },
      data: {
        status: 'EXPIRED',
        downloadUrl: null,
        errorMessage: 'Report expired.'
      }
    });
    expect(storage.read).not.toHaveBeenCalled();
  });

  it('rejects report download when generation failed', async () => {
    const prisma = {
      report: {
        findFirst: jest.fn().mockResolvedValue({
          id: 'report-1',
          scanId: 'scan-1',
          userId: 'user-1',
          status: 'FAILED',
          filePath: null,
          expiresAt: null,
          errorMessage: 'Renderer crashed'
        })
      }
    };

    const service = new ReportService(
      prisma as never,
      { add: jest.fn() } as never,
      { exists: jest.fn(), read: jest.fn() } as never
    );

    await expect(service.getReportDownload('user-1', 'report-1')).rejects.toBeInstanceOf(
      ConflictException
    );
  });

  it('rejects report download when the report is already expired', async () => {
    const prisma = {
      report: {
        findFirst: jest.fn().mockResolvedValue({
          id: 'report-1',
          scanId: 'scan-1',
          userId: 'user-1',
          status: 'EXPIRED',
          filePath: './tmp/reports/report-1.pdf',
          expiresAt: new Date(Date.now() - 60_000)
        })
      }
    };

    const service = new ReportService(
      prisma as never,
      { add: jest.fn() } as never,
      { exists: jest.fn(), read: jest.fn() } as never
    );

    await expect(service.getReportDownload('user-1', 'report-1')).rejects.toBeInstanceOf(
      GoneException
    );
  });
});
