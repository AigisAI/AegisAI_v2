import type { Provider } from '@aegisai/shared';
import { ConflictException, ForbiddenException, NotFoundException } from '@nestjs/common';

import { GitProviderRateLimitError } from '../../src/client/git/git-provider-client.errors';
import type { IGitProviderClient } from '../../src/client/git/git-provider-client.interface';
import { RepoService } from '../../src/repo/repo.service';

describe('RepoService', () => {
  it('lists connected repositories with latest scan metadata', async () => {
    const lastScanAt = new Date('2026-03-23T01:02:03.000Z');
    const prisma = {
      connectedRepo: {
        findMany: jest.fn().mockResolvedValue([
          {
            id: 'repo-1',
            provider: 'GITHUB',
            fullName: 'acme/service',
            cloneUrl: 'https://github.com/acme/service.git',
            defaultBranch: 'main',
            isPrivate: true,
            scans: [{ createdAt: lastScanAt, status: 'DONE' }]
          }
        ])
      }
    };
    const service = new RepoService(prisma as never, {} as never, {} as never);

    await expect(service.listConnectedRepos('user-1')).resolves.toEqual([
      {
        id: 'repo-1',
        provider: 'github',
        fullName: 'acme/service',
        cloneUrl: 'https://github.com/acme/service.git',
        defaultBranch: 'main',
        isPrivate: true,
        lastScanAt: lastScanAt.toISOString(),
        lastScanStatus: 'DONE'
      }
    ]);

    expect(prisma.connectedRepo.findMany).toHaveBeenCalledWith({
      where: { userId: 'user-1' },
      include: {
        scans: {
          orderBy: { createdAt: 'desc' },
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
  });

  it('lists available repositories for a connected provider and marks already connected repos', async () => {
    const prisma = {
      oAuthToken: {
        findFirst: jest.fn().mockResolvedValue({
          accessToken: 'encrypted-token'
        })
      },
      connectedRepo: {
        findMany: jest.fn().mockResolvedValue([{ providerRepoId: '101' }])
      }
    };
    const client = createGitProviderClient({
      getRepositories: jest.fn().mockResolvedValue({
        items: [
          {
            providerRepoId: '101',
            fullName: 'acme/service',
            cloneUrl: 'https://github.com/acme/service.git',
            defaultBranch: 'main',
            isPrivate: true
          },
          {
            providerRepoId: '102',
            fullName: 'acme/platform',
            cloneUrl: 'https://github.com/acme/platform.git',
            defaultBranch: 'develop',
            isPrivate: false
          }
        ],
        hasNextPage: true
      })
    });
    const registry = {
      get: jest.fn().mockReturnValue(client)
    };
    const tokenCrypto = {
      decrypt: jest.fn().mockReturnValue('github-token')
    };
    const service = new RepoService(prisma as never, registry as never, tokenCrypto as never);

    await expect(
      service.listAvailableRepos({
        userId: 'user-1',
        provider: 'github',
        page: 2,
        size: 10
      })
    ).resolves.toEqual({
      items: [
        {
          providerRepoId: '101',
          fullName: 'acme/service',
          cloneUrl: 'https://github.com/acme/service.git',
          defaultBranch: 'main',
          isPrivate: true,
          alreadyConnected: true
        },
        {
          providerRepoId: '102',
          fullName: 'acme/platform',
          cloneUrl: 'https://github.com/acme/platform.git',
          defaultBranch: 'develop',
          isPrivate: false,
          alreadyConnected: false
        }
      ],
      page: 2,
      size: 10,
      hasNextPage: true,
      nextPage: 3
    });

    expect(registry.get).toHaveBeenCalledWith('github');
    expect(client.getRepositories).toHaveBeenCalledWith('github-token', 2, 10);
  });

  it('connects a repository by provider repo id after loading provider metadata', async () => {
    const connectedAt = new Date('2026-03-23T09:00:00.000Z');
    const prisma = {
      oAuthToken: {
        findFirst: jest.fn().mockResolvedValue({
          accessToken: 'encrypted-token'
        })
      },
      connectedRepo: {
        findUnique: jest.fn().mockResolvedValue(null),
        create: jest.fn().mockResolvedValue({
          id: 'connected-1',
          fullName: 'acme/service',
          connectedAt
        })
      }
    };
    const client = createGitProviderClient({
      getRepository: jest.fn().mockResolvedValue({
        providerRepoId: '101',
        fullName: 'acme/service',
        cloneUrl: 'https://github.com/acme/service.git',
        defaultBranch: 'main',
        isPrivate: true
      })
    });
    const registry = {
      get: jest.fn().mockReturnValue(client)
    };
    const tokenCrypto = {
      decrypt: jest.fn().mockReturnValue('github-token')
    };
    const service = new RepoService(prisma as never, registry as never, tokenCrypto as never);

    await expect(
      service.connectRepo({
        userId: 'user-1',
        provider: 'github',
        providerRepoId: '101'
      })
    ).resolves.toEqual({
      id: 'connected-1',
      fullName: 'acme/service',
      connectedAt: connectedAt.toISOString()
    });

    expect(client.getRepository).toHaveBeenCalledWith('101', 'github-token');
    expect(prisma.connectedRepo.findUnique).toHaveBeenCalledWith({
      where: {
        userId_provider_providerRepoId: {
          userId: 'user-1',
          provider: 'GITHUB',
          providerRepoId: '101'
        }
      }
    });
    expect(prisma.connectedRepo.create).toHaveBeenCalledWith({
      data: {
        userId: 'user-1',
        provider: 'GITHUB',
        providerRepoId: '101',
        fullName: 'acme/service',
        cloneUrl: 'https://github.com/acme/service.git',
        defaultBranch: 'main',
        isPrivate: true
      }
    });
  });

  it('rejects duplicate repository connections after canonical provider repo lookup', async () => {
    const prisma = {
      oAuthToken: {
        findFirst: jest.fn().mockResolvedValue({
          accessToken: 'encrypted-token'
        })
      },
      connectedRepo: {
        findUnique: jest.fn().mockResolvedValue({
          id: 'connected-1'
        })
      }
    };
    const client = createGitProviderClient({
      getRepository: jest.fn().mockResolvedValue({
        providerRepoId: '101',
        fullName: 'acme/service',
        cloneUrl: 'https://github.com/acme/service.git',
        defaultBranch: 'main',
        isPrivate: true
      })
    });
    const service = new RepoService(
      prisma as never,
      { get: jest.fn().mockReturnValue(client) } as never,
      { decrypt: jest.fn().mockReturnValue('github-token') } as never
    );

    await expect(
      service.connectRepo({
        userId: 'user-1',
        provider: 'github',
        providerRepoId: 'acme/service'
      })
    ).rejects.toBeInstanceOf(ConflictException);
  });

  it('lists branches for a connected repository owned by the user', async () => {
    const prisma = {
      connectedRepo: {
        findFirst: jest.fn().mockResolvedValue({
          id: 'repo-1',
          userId: 'user-1',
          provider: 'GITHUB',
          fullName: 'acme/service'
        })
      },
      oAuthToken: {
        findFirst: jest.fn().mockResolvedValue({
          accessToken: 'encrypted-token'
        })
      }
    };
    const client = createGitProviderClient({
      getBranches: jest.fn().mockResolvedValue({
        items: [
          { name: 'main', isDefault: true, lastCommitSha: 'sha-main' },
          { name: 'feature/repo', isDefault: false, lastCommitSha: 'sha-feature' }
        ],
        hasNextPage: false
      })
    });
    const registry = {
      get: jest.fn().mockReturnValue(client)
    };
    const tokenCrypto = {
      decrypt: jest.fn().mockReturnValue('github-token')
    };
    const service = new RepoService(prisma as never, registry as never, tokenCrypto as never);

    await expect(
      service.listBranches({
        userId: 'user-1',
        repoId: 'repo-1',
        page: 1,
        size: 30
      })
    ).resolves.toEqual({
      items: [
        { name: 'main', isDefault: true, lastCommitSha: 'sha-main' },
        { name: 'feature/repo', isDefault: false, lastCommitSha: 'sha-feature' }
      ],
      page: 1,
      size: 30,
      hasNextPage: false,
      nextPage: null
    });
  });

  it('throws when the requested provider is not connected for the user', async () => {
    const prisma = {
      oAuthToken: {
        findFirst: jest.fn().mockResolvedValue(null)
      }
    };
    const service = new RepoService(
      prisma as never,
      { get: jest.fn() } as never,
      { decrypt: jest.fn() } as never
    );

    await expect(
      service.listAvailableRepos({
        userId: 'user-1',
        provider: 'gitlab',
        page: 1,
        size: 30
      })
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it('maps provider rate limits into API throttling errors', async () => {
    const prisma = {
      connectedRepo: {
        findFirst: jest.fn().mockResolvedValue({
          id: 'repo-1',
          userId: 'user-1',
          provider: 'GITHUB',
          fullName: 'acme/service'
        })
      },
      oAuthToken: {
        findFirst: jest.fn().mockResolvedValue({
          accessToken: 'encrypted-token'
        })
      }
    };
    const client = createGitProviderClient({
      getBranches: jest.fn().mockRejectedValue(
        new GitProviderRateLimitError('Rate limited', 'github', 429, 1711111111)
      )
    });
    const service = new RepoService(
      prisma as never,
      { get: jest.fn().mockReturnValue(client) } as never,
      { decrypt: jest.fn().mockReturnValue('github-token') } as never
    );

    await expect(
      service
        .listBranches({
          userId: 'user-1',
          repoId: 'repo-1',
          page: 1,
          size: 30
        })
        .catch((error: { getStatus: () => number }) => error.getStatus())
    ).resolves.toBe(429);
  });

  it('deletes a connected repository owned by the user', async () => {
    const prisma = {
      connectedRepo: {
        findFirst: jest.fn().mockResolvedValue({
          id: 'repo-1',
          userId: 'user-1'
        }),
        delete: jest.fn().mockResolvedValue(undefined)
      }
    };
    const service = new RepoService(prisma as never, {} as never, {} as never);

    await expect(
      service.disconnectRepo({
        userId: 'user-1',
        repoId: 'repo-1'
      })
    ).resolves.toBeUndefined();

    expect(prisma.connectedRepo.delete).toHaveBeenCalledWith({
      where: { id: 'repo-1' }
    });
  });

  it('throws when disconnecting an unknown connected repository', async () => {
    const prisma = {
      connectedRepo: {
        findFirst: jest.fn().mockResolvedValue(null)
      }
    };
    const service = new RepoService(prisma as never, {} as never, {} as never);

    await expect(
      service.disconnectRepo({
        userId: 'user-1',
        repoId: 'missing-repo'
      })
    ).rejects.toBeInstanceOf(NotFoundException);
  });
});

function createGitProviderClient(
  overrides: Partial<jest.Mocked<IGitProviderClient>> = {}
): jest.Mocked<IGitProviderClient> {
  return {
    provider: 'github' as Provider,
    getRepositories: jest.fn(),
    getRepository: jest.fn(),
    getBranches: jest.fn(),
    getLatestCommitSha: jest.fn(),
    getFileTree: jest.fn(),
    getFileContent: jest.fn(),
    collectByTarball: jest.fn(),
    ...overrides
  };
}
