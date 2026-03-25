import { ScanProcessor } from '../../src/scan/scan.processor';

describe('ScanProcessor', () => {
  it('marks the scan done and persists findings on successful analysis', async () => {
    const prisma = {
      scan: {
        findUnique: jest.fn().mockResolvedValue({
          id: 'scan-1',
          branch: 'main',
          language: 'java',
          connectedRepo: {
            id: 'repo-1',
            userId: 'user-1',
            provider: 'GITHUB',
            fullName: 'acme/service'
          }
        }),
        update: jest
          .fn()
          .mockResolvedValueOnce({ id: 'scan-1', status: 'RUNNING' })
          .mockResolvedValueOnce({ id: 'scan-1', status: 'DONE' })
      },
      oAuthToken: {
        findFirst: jest.fn().mockResolvedValue({
          accessToken: 'enc(access-token)'
        })
      },
      vulnerability: {
        deleteMany: jest.fn().mockResolvedValue({ count: 0 }),
        createMany: jest.fn().mockResolvedValue({ count: 1 })
      }
    };
    const tokenCrypto = {
      decrypt: jest.fn().mockReturnValue('access-token')
    };
    const collector = {
      collect: jest.fn().mockResolvedValue({
        analysisRequest: {
          scanId: 'scan-1',
          language: 'java',
          files: [{ path: 'src/App.java', content: 'class App {}' }]
        },
        commitSha: 'commit-123',
        totalFiles: 1,
        totalLines: 1,
        skippedFiles: []
      })
    };
    const analysisClient = {
      analyze: jest.fn().mockResolvedValue({
        scanId: 'scan-1',
        success: true,
        totalFiles: 1,
        totalLines: 1,
        vulnerabilities: [
          {
            title: 'SQL Injection',
            description: 'Unsanitized query usage.',
            severity: 'HIGH',
            filePath: 'src/App.java',
            lineStart: 42,
            lineEnd: 45,
            codeSnippet: 'statement.execute(query)',
            fixSuggestion: 'Use a prepared statement.',
            fixExplanation: 'Parameterized queries neutralize user input.',
            cweId: 'CWE-89',
            cveId: undefined,
            owaspCategory: 'A03:2021-Injection',
            referenceLinks: [{ title: 'OWASP Injection', url: 'https://owasp.org' }],
            consensusScore: 0.92,
            modelResults: [
              {
                model: 'mock-primary',
                detected: true,
                severity: 'HIGH',
                reasoning: 'String interpolation reaches SQL execution.'
              }
            ]
          }
        ]
      })
    };

    const processor = new ScanProcessor(
      prisma as never,
      tokenCrypto as never,
      collector as never,
      analysisClient as never
    );

    await processor.process({ data: { scanId: 'scan-1' } } as never);

    expect(prisma.scan.update).toHaveBeenNthCalledWith(1, {
      where: { id: 'scan-1' },
      data: {
        status: 'RUNNING',
        startedAt: expect.any(Date),
        errorMessage: null
      }
    });
    expect(prisma.vulnerability.deleteMany).toHaveBeenCalledWith({
      where: { scanId: 'scan-1' }
    });
    expect(prisma.vulnerability.createMany).toHaveBeenCalledWith({
      data: [
        {
          scanId: 'scan-1',
          title: 'SQL Injection',
          description: 'Unsanitized query usage.',
          severity: 'HIGH',
          filePath: 'src/App.java',
          lineStart: 42,
          lineEnd: 45,
          codeSnippet: 'statement.execute(query)',
          fixSuggestion: 'Use a prepared statement.',
          fixExplanation: 'Parameterized queries neutralize user input.',
          cweId: 'CWE-89',
          cveId: null,
          owaspCategory: 'A03:2021-Injection',
          referenceLinks: [{ title: 'OWASP Injection', url: 'https://owasp.org' }],
          consensusScore: 0.92,
          modelResults: [
            {
              model: 'mock-primary',
              detected: true,
              severity: 'HIGH',
              reasoning: 'String interpolation reaches SQL execution.'
            }
          ]
        }
      ]
    });
    expect(prisma.scan.update).toHaveBeenNthCalledWith(2, {
      where: { id: 'scan-1' },
      data: {
        status: 'DONE',
        commitSha: 'commit-123',
        totalFiles: 1,
        totalLines: 1,
        vulnCritical: 0,
        vulnHigh: 1,
        vulnMedium: 0,
        vulnLow: 0,
        vulnInfo: 0,
        errorMessage: null,
        completedAt: expect.any(Date)
      }
    });
  });

  it('marks the scan failed when collection or analysis raises an error', async () => {
    const prisma = {
      scan: {
        findUnique: jest.fn().mockResolvedValue({
          id: 'scan-1',
          branch: 'main',
          language: 'java',
          connectedRepo: {
            id: 'repo-1',
            userId: 'user-1',
            provider: 'GITHUB',
            fullName: 'acme/service'
          }
        }),
        update: jest
          .fn()
          .mockResolvedValueOnce({ id: 'scan-1', status: 'RUNNING' })
          .mockResolvedValueOnce({ id: 'scan-1', status: 'FAILED' })
      },
      oAuthToken: {
        findFirst: jest.fn().mockResolvedValue({
          accessToken: 'enc(access-token)'
        })
      },
      vulnerability: {
        deleteMany: jest.fn(),
        createMany: jest.fn()
      }
    };
    const tokenCrypto = {
      decrypt: jest.fn().mockReturnValue('access-token')
    };
    const collector = {
      collect: jest.fn().mockRejectedValue(new Error('Provider rate limit'))
    };

    const processor = new ScanProcessor(
      prisma as never,
      tokenCrypto as never,
      collector as never,
      { analyze: jest.fn() } as never
    );

    await expect(processor.process({ data: { scanId: 'scan-1' } } as never)).rejects.toThrow(
      'Provider rate limit'
    );

    expect(prisma.scan.update).toHaveBeenNthCalledWith(2, {
      where: { id: 'scan-1' },
      data: {
        status: 'FAILED',
        errorMessage: 'Provider rate limit',
        completedAt: expect.any(Date)
      }
    });
    expect(prisma.vulnerability.deleteMany).not.toHaveBeenCalled();
    expect(prisma.vulnerability.createMany).not.toHaveBeenCalled();
  });

  it('marks the scan failed when the analysis payload is malformed', async () => {
    const prisma = {
      scan: {
        findUnique: jest.fn().mockResolvedValue({
          id: 'scan-1',
          branch: 'main',
          commitSha: 'commit-123',
          language: 'java',
          connectedRepo: {
            id: 'repo-1',
            userId: 'user-1',
            provider: 'GITHUB',
            fullName: 'acme/service'
          }
        }),
        update: jest
          .fn()
          .mockResolvedValueOnce({ id: 'scan-1', status: 'RUNNING' })
          .mockResolvedValueOnce({ id: 'scan-1', status: 'FAILED' })
      },
      oAuthToken: {
        findFirst: jest.fn().mockResolvedValue({
          accessToken: 'enc(access-token)'
        })
      },
      vulnerability: {
        deleteMany: jest.fn(),
        createMany: jest.fn()
      }
    };
    const processor = new ScanProcessor(
      prisma as never,
      { decrypt: jest.fn().mockReturnValue('access-token') } as never,
      {
        collect: jest.fn().mockResolvedValue({
          analysisRequest: {
            scanId: 'scan-1',
            language: 'java',
            files: [{ path: 'src/App.java', content: 'class App {}' }]
          },
          commitSha: 'commit-123',
          totalFiles: 1,
          totalLines: 1,
          skippedFiles: []
        })
      } as never,
      {
        analyze: jest.fn().mockResolvedValue({
          scanId: 'scan-1',
          success: true,
          totalFiles: 1,
          totalLines: 1,
          vulnerabilities: [
            {
              title: 'Invalid score',
              description: 'Malformed provider payload.',
              severity: 'HIGH',
              filePath: 'src/App.java',
              lineStart: 10,
              consensusScore: 1.5,
              modelResults: []
            }
          ]
        })
      } as never
    );

    await expect(processor.process({ data: { scanId: 'scan-1' } } as never)).rejects.toThrow(
      'consensusScore'
    );

    expect(prisma.scan.update).toHaveBeenNthCalledWith(2, {
      where: { id: 'scan-1' },
      data: {
        status: 'FAILED',
        errorMessage: expect.stringContaining('consensusScore'),
        completedAt: expect.any(Date)
      }
    });
  });
});
