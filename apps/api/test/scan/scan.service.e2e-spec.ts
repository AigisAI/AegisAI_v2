import { BadRequestException, ConflictException, NotFoundException } from '@nestjs/common';
import { GitProviderNotFoundError } from '../../src/client/git/git-provider-client.errors';

import { SCAN_PROCESS_JOB } from '../../src/scan/scan.constants';
import { ScanService } from '../../src/scan/scan.service';

describe('ScanService', () => {
  it('creates a pending scan and enqueues the processor job', async () => {
    const prisma = {
      connectedRepo: {
        findFirst: jest.fn().mockResolvedValue({
          id: 'repo-1',
          userId: 'user-1',
          fullName: 'acme/service',
          provider: 'GITHUB'
        })
      },
      oAuthToken: {
        findFirst: jest.fn().mockResolvedValue({
          accessToken: 'enc(access-token)'
        })
      },
      scan: {
        findFirst: jest.fn().mockResolvedValue(null),
        create: jest.fn().mockResolvedValue({
          id: 'scan-1',
          status: 'PENDING'
        })
      }
    };
    const queue = {
      add: jest.fn().mockResolvedValue({ id: 'scan-1' })
    };
    const gitClients = {
      get: jest.fn().mockReturnValue({
        getLatestCommitSha: jest.fn().mockResolvedValue('commit-123')
      })
    };
    const tokenCrypto = {
      decrypt: jest.fn().mockReturnValue('access-token')
    };

    const service = new ScanService(
      prisma as never,
      queue as never,
      gitClients as never,
      tokenCrypto as never
    );

    await expect(
      service.createScan({
        userId: 'user-1',
        connectedRepoId: 'repo-1',
        branch: 'main'
      })
    ).resolves.toEqual({
      scanId: 'scan-1',
      status: 'PENDING',
      message: 'Scan queued successfully.'
    });

    expect(prisma.connectedRepo.findFirst).toHaveBeenCalledWith({
      where: {
        id: 'repo-1',
        userId: 'user-1'
      }
    });
    expect(prisma.scan.findFirst).toHaveBeenCalledWith({
      where: {
        connectedRepoId: 'repo-1',
        branch: 'main',
        status: { in: ['PENDING', 'RUNNING'] }
      }
    });
    expect(prisma.scan.create).toHaveBeenCalledWith({
      data: {
        connectedRepoId: 'repo-1',
        branch: 'main',
        language: 'java',
        status: 'PENDING'
      }
    });
    expect(queue.add).toHaveBeenCalledWith(
      SCAN_PROCESS_JOB,
      { scanId: 'scan-1' },
      { jobId: 'scan-1' }
    );
    expect(gitClients.get).toHaveBeenCalledWith('github');
  });

  it('rejects duplicate active scans for the same repository branch', async () => {
    const prisma = {
      connectedRepo: {
        findFirst: jest.fn().mockResolvedValue({
          id: 'repo-1',
          userId: 'user-1',
          fullName: 'acme/service',
          provider: 'GITHUB'
        })
      },
      oAuthToken: {
        findFirst: jest.fn().mockResolvedValue({
          accessToken: 'enc(access-token)'
        })
      },
      scan: {
        findFirst: jest.fn().mockResolvedValue({
          id: 'scan-existing',
          status: 'RUNNING'
        })
      }
    };
    const gitClients = {
      get: jest.fn().mockReturnValue({
        getLatestCommitSha: jest.fn().mockResolvedValue('commit-123')
      })
    };
    const tokenCrypto = {
      decrypt: jest.fn().mockReturnValue('access-token')
    };

    const service = new ScanService(
      prisma as never,
      { add: jest.fn() } as never,
      gitClients as never,
      tokenCrypto as never
    );

    await expect(
      service.createScan({
        userId: 'user-1',
        connectedRepoId: 'repo-1',
        branch: 'main'
      })
    ).rejects.toBeInstanceOf(ConflictException);
  });

  it('throws when the connected repository does not belong to the user', async () => {
    const prisma = {
      connectedRepo: {
        findFirst: jest.fn().mockResolvedValue(null)
      }
    };

    const service = new ScanService(
      prisma as never,
      { add: jest.fn() } as never,
      { get: jest.fn() } as never,
      { decrypt: jest.fn() } as never
    );

    await expect(
      service.createScan({
        userId: 'user-1',
        connectedRepoId: 'missing-repo',
        branch: 'main'
      })
    ).rejects.toBeInstanceOf(NotFoundException);
  });

  it('rejects scan creation when the requested branch does not exist', async () => {
    const prisma = {
      connectedRepo: {
        findFirst: jest.fn().mockResolvedValue({
          id: 'repo-1',
          userId: 'user-1',
          fullName: 'acme/service',
          provider: 'GITHUB'
        })
      },
      oAuthToken: {
        findFirst: jest.fn().mockResolvedValue({
          accessToken: 'enc(access-token)'
        })
      },
      scan: {
        findFirst: jest.fn()
      }
    };
    const gitClients = {
      get: jest.fn().mockReturnValue({
        getLatestCommitSha: jest
          .fn()
          .mockRejectedValue(new GitProviderNotFoundError('Branch not found', 'github'))
      })
    };
    const tokenCrypto = {
      decrypt: jest.fn().mockReturnValue('access-token')
    };

    const service = new ScanService(
      prisma as never,
      { add: jest.fn() } as never,
      gitClients as never,
      tokenCrypto as never
    );

    await expect(
      service.createScan({
        userId: 'user-1',
        connectedRepoId: 'repo-1',
        branch: 'missing'
      })
    ).rejects.toBeInstanceOf(BadRequestException);
  });

  it('returns scan detail scoped to the authenticated user', async () => {
    const prisma = {
      scan: {
        findFirst: jest.fn().mockResolvedValue({
          id: 'scan-1',
          branch: 'main',
          commitSha: 'commit-123',
          status: 'DONE',
          language: 'java',
          totalFiles: 12,
          totalLines: 1200,
          vulnCritical: 1,
          vulnHigh: 2,
          vulnMedium: 3,
          vulnLow: 4,
          vulnInfo: 5,
          errorMessage: null,
          startedAt: new Date('2026-03-25T10:00:00.000Z'),
          completedAt: new Date('2026-03-25T10:05:00.000Z'),
          createdAt: new Date('2026-03-25T09:59:00.000Z'),
          connectedRepo: {
            fullName: 'acme/service'
          }
        })
      }
    };

    const service = new ScanService(
      prisma as never,
      { add: jest.fn() } as never,
      { get: jest.fn() } as never,
      { decrypt: jest.fn() } as never
    );

    await expect(service.getScanDetail('user-1', 'scan-1')).resolves.toEqual({
      id: 'scan-1',
      repoFullName: 'acme/service',
      branch: 'main',
      commitSha: 'commit-123',
      status: 'DONE',
      language: 'java',
      totalFiles: 12,
      totalLines: 1200,
      summary: {
        critical: 1,
        high: 2,
        medium: 3,
        low: 4,
        info: 5
      },
      startedAt: '2026-03-25T10:00:00.000Z',
      completedAt: '2026-03-25T10:05:00.000Z',
      errorMessage: null,
      createdAt: '2026-03-25T09:59:00.000Z'
    });
  });

  it('returns paginated scan history for a connected repository', async () => {
    const prisma = {
      connectedRepo: {
        findFirst: jest.fn().mockResolvedValue({
          id: 'repo-1',
          userId: 'user-1'
        })
      },
      scan: {
        count: jest.fn().mockResolvedValue(3),
        findMany: jest.fn().mockResolvedValue([
          {
            id: 'scan-3',
            branch: 'main',
            commitSha: 'commit-333',
            status: 'DONE',
            language: 'java',
            totalFiles: 10,
            totalLines: 100,
            vulnCritical: 0,
            vulnHigh: 1,
            vulnMedium: 0,
            vulnLow: 0,
            vulnInfo: 0,
            errorMessage: null,
            startedAt: null,
            completedAt: null,
            createdAt: new Date('2026-03-25T12:00:00.000Z'),
            connectedRepo: {
              fullName: 'acme/service'
            }
          },
          {
            id: 'scan-2',
            branch: 'release',
            commitSha: null,
            status: 'FAILED',
            language: 'java',
            totalFiles: null,
            totalLines: null,
            vulnCritical: 0,
            vulnHigh: 0,
            vulnMedium: 0,
            vulnLow: 0,
            vulnInfo: 0,
            errorMessage: 'Provider unavailable',
            startedAt: null,
            completedAt: null,
            createdAt: new Date('2026-03-24T12:00:00.000Z'),
            connectedRepo: {
              fullName: 'acme/service'
            }
          }
        ])
      }
    };

    const service = new ScanService(
      prisma as never,
      { add: jest.fn() } as never,
      { get: jest.fn() } as never,
      { decrypt: jest.fn() } as never
    );

    await expect(service.listRepoScans({ userId: 'user-1', repoId: 'repo-1', page: 1, size: 2 }))
      .resolves.toEqual({
        items: [
          {
            id: 'scan-3',
            repoFullName: 'acme/service',
            branch: 'main',
            commitSha: 'commit-333',
            status: 'DONE',
            language: 'java',
            totalFiles: 10,
            totalLines: 100,
            summary: {
              critical: 0,
              high: 1,
              medium: 0,
              low: 0,
              info: 0
            },
            startedAt: null,
            completedAt: null,
            errorMessage: null,
            createdAt: '2026-03-25T12:00:00.000Z'
          },
          {
            id: 'scan-2',
            repoFullName: 'acme/service',
            branch: 'release',
            commitSha: null,
            status: 'FAILED',
            language: 'java',
            totalFiles: null,
            totalLines: null,
            summary: {
              critical: 0,
              high: 0,
              medium: 0,
              low: 0,
              info: 0
            },
            startedAt: null,
            completedAt: null,
            errorMessage: 'Provider unavailable',
            createdAt: '2026-03-24T12:00:00.000Z'
          }
        ],
        totalCount: 3,
        page: 1,
        totalPages: 2
      });
  });
});
