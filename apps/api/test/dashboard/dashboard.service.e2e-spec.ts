import { DashboardService } from '../../src/dashboard/dashboard.service';

describe('DashboardService', () => {
  it('aggregates connected repositories, recent scans, and trend data for the authenticated user', async () => {
    const prisma = {
      connectedRepo: {
        findMany: jest.fn().mockResolvedValue([
          {
            id: 'repo-1',
            provider: 'GITHUB',
            fullName: 'acme/payments-service',
            cloneUrl: 'https://github.com/acme/payments-service.git',
            defaultBranch: 'main',
            isPrivate: true,
            connectedAt: new Date('2026-03-30T08:00:00.000Z'),
            scans: [
              {
                createdAt: new Date('2026-03-31T08:00:00.000Z'),
                status: 'DONE'
              }
            ]
          },
          {
            id: 'repo-2',
            provider: 'GITLAB',
            fullName: 'ops/compliance-service',
            cloneUrl: 'https://gitlab.com/ops/compliance-service.git',
            defaultBranch: 'trunk',
            isPrivate: true,
            connectedAt: new Date('2026-03-29T08:00:00.000Z'),
            scans: [
              {
                createdAt: new Date('2026-03-31T07:00:00.000Z'),
                status: 'RUNNING'
              }
            ]
          }
        ])
      },
      scan: {
        count: jest.fn().mockResolvedValue(7),
        findMany: jest
          .fn()
          .mockResolvedValueOnce([
            {
              id: 'scan-2',
              branch: 'release/2026',
              commitSha: 'def5678',
              status: 'RUNNING',
              language: 'java',
              totalFiles: 12,
              totalLines: 1900,
              vulnCritical: 0,
              vulnHigh: 1,
              vulnMedium: 2,
              vulnLow: 1,
              vulnInfo: 0,
              errorMessage: null,
              startedAt: new Date('2026-03-31T09:00:00.000Z'),
              completedAt: null,
              createdAt: new Date('2026-03-31T08:55:00.000Z'),
              connectedRepo: {
                fullName: 'ops/compliance-service'
              }
            },
            {
              id: 'scan-1',
              branch: 'main',
              commitSha: 'abc1234',
              status: 'DONE',
              language: 'java',
              totalFiles: 40,
              totalLines: 8100,
              vulnCritical: 1,
              vulnHigh: 2,
              vulnMedium: 1,
              vulnLow: 0,
              vulnInfo: 0,
              errorMessage: null,
              startedAt: new Date('2026-03-31T08:00:00.000Z'),
              completedAt: new Date('2026-03-31T08:06:00.000Z'),
              createdAt: new Date('2026-03-31T07:58:00.000Z'),
              connectedRepo: {
                fullName: 'acme/payments-service'
              }
            }
          ])
          .mockResolvedValueOnce([
            {
              id: 'scan-3',
              branch: 'main',
              commitSha: 'ghi9012',
              status: 'DONE',
              language: 'java',
              totalFiles: 18,
              totalLines: 2300,
              vulnCritical: 0,
              vulnHigh: 1,
              vulnMedium: 1,
              vulnLow: 0,
              vulnInfo: 0,
              errorMessage: null,
              startedAt: new Date('2026-03-30T12:00:00.000Z'),
              completedAt: new Date('2026-03-30T12:07:00.000Z'),
              createdAt: new Date('2026-03-30T11:58:00.000Z'),
              connectedRepo: {
                fullName: 'acme/payments-service'
              }
            },
            {
              id: 'scan-1',
              branch: 'main',
              commitSha: 'abc1234',
              status: 'DONE',
              language: 'java',
              totalFiles: 40,
              totalLines: 8100,
              vulnCritical: 1,
              vulnHigh: 2,
              vulnMedium: 1,
              vulnLow: 0,
              vulnInfo: 0,
              errorMessage: null,
              startedAt: new Date('2026-03-31T08:00:00.000Z'),
              completedAt: new Date('2026-03-31T08:06:00.000Z'),
              createdAt: new Date('2026-03-31T07:58:00.000Z'),
              connectedRepo: {
                fullName: 'acme/payments-service'
              }
            }
          ])
      }
    };

    const service = new DashboardService(prisma as never);

    await expect(service.getDashboardWorkspaceData('user-1')).resolves.toEqual({
      totalRepos: 2,
      totalScans: 7,
      openVulnerabilities: {
        critical: 1,
        high: 3,
        medium: 3,
        low: 1,
        info: 0
      },
      recentScans: [
        expect.objectContaining({
          id: 'scan-2',
          repoFullName: 'ops/compliance-service',
          status: 'RUNNING'
        }),
        expect.objectContaining({
          id: 'scan-1',
          repoFullName: 'acme/payments-service',
          status: 'DONE'
        })
      ],
      trend: [
        {
          date: 'Mar 30',
          critical: 0,
          high: 1,
          medium: 1
        },
        {
          date: 'Mar 31',
          critical: 1,
          high: 2,
          medium: 1
        }
      ],
      connectedRepos: [
        expect.objectContaining({
          id: 'repo-1',
          provider: 'github',
          fullName: 'acme/payments-service',
          lastScanStatus: 'DONE'
        }),
        expect.objectContaining({
          id: 'repo-2',
          provider: 'gitlab',
          fullName: 'ops/compliance-service',
          lastScanStatus: 'RUNNING'
        })
      ],
      completedScans: [
        expect.objectContaining({
          id: 'scan-1',
          status: 'DONE'
        })
      ],
      severitySummary: {
        critical: 1,
        high: 3,
        medium: 3,
        low: 1,
        info: 0
      },
      degraded: false
    });

    expect(prisma.connectedRepo.findMany).toHaveBeenCalledWith({
      where: {
        userId: 'user-1'
      },
      include: {
        scans: {
          orderBy: {
            createdAt: 'desc'
          },
          take: 1,
          select: {
            createdAt: true,
            status: true
          }
        }
      },
      orderBy: {
        connectedAt: 'desc'
      }
    });
    expect(prisma.scan.count).toHaveBeenCalledWith({
      where: {
        connectedRepo: {
          userId: 'user-1'
        }
      }
    });
    expect(prisma.scan.findMany).toHaveBeenNthCalledWith(1, {
      where: {
        connectedRepo: {
          userId: 'user-1'
        }
      },
      include: {
        connectedRepo: {
          select: {
            fullName: true
          }
        }
      },
      orderBy: {
        createdAt: 'desc'
      },
      take: 8
    });
    expect(prisma.scan.findMany).toHaveBeenNthCalledWith(2, {
      where: {
        connectedRepo: {
          userId: 'user-1'
        },
        status: 'DONE'
      },
      include: {
        connectedRepo: {
          select: {
            fullName: true
          }
        }
      },
      orderBy: [
        {
          completedAt: 'desc'
        },
        {
          createdAt: 'desc'
        }
      ],
      take: 32
    });
  });

  it('returns an empty dashboard snapshot when the user has no connected repositories', async () => {
    const prisma = {
      connectedRepo: {
        findMany: jest.fn().mockResolvedValue([])
      },
      scan: {
        count: jest.fn(),
        findMany: jest.fn()
      }
    };

    const service = new DashboardService(prisma as never);

    await expect(service.getDashboardWorkspaceData('user-1')).resolves.toEqual({
      totalRepos: 0,
      totalScans: 0,
      openVulnerabilities: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0
      },
      recentScans: [],
      trend: [],
      connectedRepos: [],
      completedScans: [],
      severitySummary: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0
      },
      degraded: false
    });

    expect(prisma.scan.count).not.toHaveBeenCalled();
    expect(prisma.scan.findMany).not.toHaveBeenCalled();
  });
});
