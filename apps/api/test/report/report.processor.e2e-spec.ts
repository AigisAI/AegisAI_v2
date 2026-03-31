import { ReportProcessor } from '../../src/report/report.processor';

describe('ReportProcessor', () => {
  it('generates a PDF, stores it, and marks the report ready', async () => {
    const prisma = {
      report: {
        findUnique: jest.fn().mockResolvedValue({
          id: 'report-1',
          scanId: 'scan-1',
          status: 'GENERATING',
          scan: {
            id: 'scan-1',
            branch: 'main',
            commitSha: 'commit-123',
            totalFiles: 12,
            totalLines: 420,
            vulnCritical: 1,
            vulnHigh: 2,
            vulnMedium: 3,
            vulnLow: 1,
            vulnInfo: 0,
            connectedRepo: {
              fullName: 'acme/service'
            },
            vulnerabilities: [
              {
                id: 'vuln-1',
                title: 'SQL Injection',
                severity: 'HIGH',
                filePath: 'src/App.java',
                lineStart: 42,
                fixSuggestion: 'Use prepared statements.'
              }
            ]
          }
        }),
        update: jest.fn().mockResolvedValue({
          id: 'report-1',
          status: 'READY'
        })
      }
    };
    const generator = {
      generateScanReport: jest.fn().mockResolvedValue(Buffer.from('%PDF-1.4\n'))
    };
    const storage = {
      write: jest.fn().mockResolvedValue('./tmp/reports/report-1.pdf')
    };
    const config = {
      get: jest.fn().mockImplementation((key: string) => {
        if (key === 'REPORT_EXPIRY_HOURS') {
          return 24;
        }

        return undefined;
      })
    };

    const processor = new ReportProcessor(
      prisma as never,
      generator as never,
      storage as never,
      config as never
    );

    await processor.process({ data: { reportId: 'report-1' } } as never);

    expect(generator.generateScanReport).toHaveBeenCalled();
    expect(storage.write).toHaveBeenCalledWith({
      reportId: 'report-1',
      scanId: 'scan-1',
      pdf: Buffer.from('%PDF-1.4\n')
    });
    expect(prisma.report.update).toHaveBeenCalledWith({
      where: { id: 'report-1' },
      data: {
        status: 'READY',
        filePath: './tmp/reports/report-1.pdf',
        downloadUrl: '/api/reports/report-1/download',
        errorMessage: null,
        expiresAt: expect.any(Date)
      }
    });
  });

  it('marks the report failed when generation raises an error', async () => {
    const prisma = {
      report: {
        findUnique: jest.fn().mockResolvedValue({
          id: 'report-1',
          scanId: 'scan-1',
          status: 'GENERATING',
          scan: {
            id: 'scan-1',
            branch: 'main',
            connectedRepo: {
              fullName: 'acme/service'
            },
            vulnerabilities: []
          }
        }),
        update: jest.fn().mockResolvedValue({
          id: 'report-1',
          status: 'FAILED'
        })
      }
    };

    const processor = new ReportProcessor(
      prisma as never,
      {
        generateScanReport: jest.fn().mockRejectedValue(new Error('pdf failure'))
      } as never,
      { write: jest.fn() } as never,
      { get: jest.fn().mockReturnValue(24) } as never
    );

    await expect(processor.process({ data: { reportId: 'report-1' } } as never)).rejects.toThrow(
      'pdf failure'
    );

    expect(prisma.report.update).toHaveBeenCalledWith({
      where: { id: 'report-1' },
      data: {
        status: 'FAILED',
        errorMessage: 'pdf failure'
      }
    });
  });

  it('deletes the generated pdf when persistence fails after writing the file', async () => {
    const readyFailure = new Error('ready update failed');
    const prisma = {
      report: {
        findUnique: jest.fn().mockResolvedValue({
          id: 'report-1',
          scanId: 'scan-1',
          status: 'GENERATING',
          scan: {
            id: 'scan-1',
            branch: 'main',
            commitSha: 'commit-123',
            totalFiles: 2,
            totalLines: 20,
            vulnCritical: 0,
            vulnHigh: 1,
            vulnMedium: 0,
            vulnLow: 0,
            vulnInfo: 0,
            connectedRepo: {
              fullName: 'acme/service'
            },
            vulnerabilities: []
          }
        }),
        update: jest
          .fn()
          .mockRejectedValueOnce(readyFailure)
          .mockResolvedValueOnce({
            id: 'report-1',
            status: 'FAILED'
          })
      }
    };
    const storage = {
      write: jest.fn().mockResolvedValue('./tmp/reports/report-1.pdf'),
      delete: jest.fn().mockResolvedValue(undefined)
    };

    const processor = new ReportProcessor(
      prisma as never,
      {
        generateScanReport: jest.fn().mockResolvedValue(Buffer.from('%PDF-1.4\n'))
      } as never,
      storage as never,
      { get: jest.fn().mockReturnValue(24) } as never
    );

    await expect(processor.process({ data: { reportId: 'report-1' } } as never)).rejects.toThrow(
      'ready update failed'
    );

    expect(storage.delete).toHaveBeenCalledWith('./tmp/reports/report-1.pdf');
    expect(prisma.report.update).toHaveBeenNthCalledWith(2, {
      where: { id: 'report-1' },
      data: {
        status: 'FAILED',
        errorMessage: 'ready update failed'
      }
    });
  });
});
