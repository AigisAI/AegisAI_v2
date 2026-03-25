import type {
  AvailableRepoListResponse,
  ConnectRepoRequest,
  ConnectRepoResponse,
  ConnectedRepoListResponse,
  Provider,
  RepoBranchListResponse
} from '@aegisai/shared';
import {
  ConflictException,
  ForbiddenException,
  HttpException,
  Injectable,
  NotFoundException,
  ServiceUnavailableException
} from '@nestjs/common';
import { RepoProvider } from '@prisma/client';

import {
  GitProviderNotFoundError,
  GitProviderRateLimitError,
  GitProviderUnauthorizedError,
  GitProviderUnavailableError
} from '../client/git/git-provider-client.errors';
import { GitClientRegistry } from '../client/git/git-client.registry';
import { PrismaService } from '../prisma/prisma.service';
import { TokenCryptoUtil } from '../auth/utils/token-crypto.util';

interface ListAvailableReposInput {
  userId: string;
  provider: Provider;
  page: number;
  size: number;
}

interface ListBranchesInput {
  userId: string;
  repoId: string;
  page: number;
  size: number;
}

interface DisconnectRepoInput {
  userId: string;
  repoId: string;
}

@Injectable()
export class RepoService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly gitClients: GitClientRegistry,
    private readonly tokenCrypto: TokenCryptoUtil
  ) {}

  async listConnectedRepos(userId: string): Promise<ConnectedRepoListResponse> {
    const connectedRepos = await this.prisma.connectedRepo.findMany({
      where: { userId },
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

    return connectedRepos.map((connectedRepo) => {
      const [latestScan] = connectedRepo.scans;

      return {
        id: connectedRepo.id,
        provider: this.fromRepoProvider(connectedRepo.provider),
        fullName: connectedRepo.fullName,
        cloneUrl: connectedRepo.cloneUrl,
        defaultBranch: connectedRepo.defaultBranch,
        isPrivate: connectedRepo.isPrivate,
        lastScanAt: latestScan?.createdAt.toISOString() ?? null,
        lastScanStatus: latestScan?.status ?? null
      };
    });
  }

  async listAvailableRepos(input: ListAvailableReposInput): Promise<AvailableRepoListResponse> {
    const { client, accessToken, providerEnum } = await this.resolveProviderClient(input.userId, input.provider);

    try {
      const [providerRepos, connectedRepos] = await Promise.all([
        client.getRepositories(accessToken, input.page, input.size),
        this.prisma.connectedRepo.findMany({
          where: {
            userId: input.userId,
            provider: providerEnum
          },
          select: {
            providerRepoId: true
          }
        })
      ]);

      const connectedRepoIds = new Set(connectedRepos.map((repo) => repo.providerRepoId));

      return {
        items: providerRepos.items.map((repo) => ({
          ...repo,
          alreadyConnected: connectedRepoIds.has(repo.providerRepoId)
        })),
        page: input.page,
        size: input.size,
        hasNextPage: providerRepos.hasNextPage,
        nextPage: providerRepos.hasNextPage ? input.page + 1 : null
      };
    } catch (error) {
      this.throwProviderError(error, input.provider);
    }
  }

  async connectRepo(input: { userId: string } & ConnectRepoRequest): Promise<ConnectRepoResponse> {
    const { client, accessToken, providerEnum } = await this.resolveProviderClient(input.userId, input.provider);

    try {
      const repository = await client.getRepository(input.providerRepoId, accessToken);
      const existingRepo = await this.prisma.connectedRepo.findUnique({
        where: {
          userId_provider_providerRepoId: {
            userId: input.userId,
            provider: providerEnum,
            providerRepoId: repository.providerRepoId
          }
        }
      });

      if (existingRepo) {
        throw new ConflictException({
          message: 'Repository is already connected.',
          errorCode: 'REPO_ALREADY_CONNECTED'
        });
      }

      const connectedRepo = await this.prisma.connectedRepo.create({
        data: {
          userId: input.userId,
          provider: providerEnum,
          providerRepoId: repository.providerRepoId,
          fullName: repository.fullName,
          cloneUrl: repository.cloneUrl,
          defaultBranch: repository.defaultBranch,
          isPrivate: repository.isPrivate
        }
      });

      return {
        id: connectedRepo.id,
        fullName: connectedRepo.fullName,
        connectedAt: connectedRepo.connectedAt.toISOString()
      };
    } catch (error) {
      this.throwProviderError(error, input.provider);
    }
  }

  async listBranches(input: ListBranchesInput): Promise<RepoBranchListResponse> {
    const connectedRepo = await this.prisma.connectedRepo.findFirst({
      where: {
        id: input.repoId,
        userId: input.userId
      }
    });

    if (!connectedRepo) {
      throw new NotFoundException({
        message: 'Connected repository not found.',
        errorCode: 'REPO_NOT_FOUND'
      });
    }

    const provider = this.fromRepoProvider(connectedRepo.provider);
    const { client, accessToken } = await this.resolveProviderClient(input.userId, provider);

    try {
      const branches = await client.getBranches(
        connectedRepo.fullName,
        input.page,
        input.size,
        accessToken
      );

      return {
        items: branches.items,
        page: input.page,
        size: input.size,
        hasNextPage: branches.hasNextPage,
        nextPage: branches.hasNextPage ? input.page + 1 : null
      };
    } catch (error) {
      this.throwProviderError(error, provider);
    }
  }

  async disconnectRepo(input: DisconnectRepoInput): Promise<void> {
    const connectedRepo = await this.prisma.connectedRepo.findFirst({
      where: {
        id: input.repoId,
        userId: input.userId
      }
    });

    if (!connectedRepo) {
      throw new NotFoundException({
        message: 'Connected repository not found.',
        errorCode: 'REPO_NOT_FOUND'
      });
    }

    await this.prisma.connectedRepo.delete({
      where: { id: input.repoId }
    });
  }

  private async resolveProviderClient(userId: string, provider: Provider) {
    const providerEnum = this.toRepoProvider(provider);
    const persistedToken = await this.prisma.oAuthToken.findFirst({
      where: {
        userId,
        provider: providerEnum
      }
    });

    if (!persistedToken) {
      throw new ForbiddenException({
        message: 'Provider account is not connected.',
        errorCode: 'PROVIDER_NOT_CONNECTED'
      });
    }

    return {
      providerEnum,
      client: this.gitClients.get(provider),
      accessToken: this.tokenCrypto.decrypt(persistedToken.accessToken)
    };
  }

  private toRepoProvider(provider: Provider): RepoProvider {
    return provider === 'github' ? RepoProvider.GITHUB : RepoProvider.GITLAB;
  }

  private fromRepoProvider(provider: RepoProvider): Provider {
    return provider.toLowerCase() as Provider;
  }

  private throwProviderError(error: unknown, provider: Provider): never {
    if (error instanceof GitProviderUnauthorizedError) {
      throw new ForbiddenException({
        message: `${provider} provider token is invalid or expired.`,
        errorCode: 'PROVIDER_TOKEN_INVALID'
      });
    }

    if (error instanceof GitProviderNotFoundError) {
      throw new NotFoundException({
        message: `${provider} repository resource was not found.`,
        errorCode: 'PROVIDER_RESOURCE_NOT_FOUND'
      });
    }

    if (error instanceof GitProviderRateLimitError) {
      throw new HttpException(
        {
          message: `${provider} provider rate limit exceeded.`,
          errorCode: 'PROVIDER_RATE_LIMITED'
        },
        429
      );
    }

    if (error instanceof GitProviderUnavailableError) {
      throw new ServiceUnavailableException({
        message: `${provider} provider is unavailable.`,
        errorCode: 'PROVIDER_UNAVAILABLE'
      });
    }

    throw error;
  }
}
