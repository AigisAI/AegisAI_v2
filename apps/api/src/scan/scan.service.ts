import type {
  Provider,
  RepoScanListResponse,
  ScanDetail,
  ScanRequestResponse,
  ScanSummary
} from '@aegisai/shared';
import { InjectQueue } from '@nestjs/bullmq';
import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  HttpException,
  Injectable,
  NotFoundException,
  ServiceUnavailableException
} from '@nestjs/common';
import { Prisma, RepoProvider, ScanStatus } from '@prisma/client';
import type { Queue } from 'bullmq';

import {
  GitProviderNotFoundError,
  GitProviderRateLimitError,
  GitProviderUnauthorizedError,
  GitProviderUnavailableError
} from '../client/git/git-provider-client.errors';
import { GitClientRegistry } from '../client/git/git-client.registry';
import { TokenCryptoUtil } from '../auth/utils/token-crypto.util';
import { PrismaService } from '../prisma/prisma.service';
import { SCAN_PROCESS_JOB, SCAN_QUEUE } from './scan.constants';

interface CreateScanInput {
  userId: string;
  connectedRepoId: string;
  branch: string;
  language?: string;
}

interface ListRepoScansInput {
  userId: string;
  repoId: string;
  page: number;
  size: number;
}

@Injectable()
export class ScanService {
  constructor(
    private readonly prisma: PrismaService,
    @InjectQueue(SCAN_QUEUE) private readonly scanQueue: Queue,
    private readonly gitClients: GitClientRegistry,
    private readonly tokenCrypto: TokenCryptoUtil
  ) {}

  async createScan(input: CreateScanInput): Promise<ScanRequestResponse> {
    const branch = input.branch.trim();
    if (!branch) {
      throw new BadRequestException({
        message: 'branch is required.',
        errorCode: 'BAD_REQUEST'
      });
    }

    const connectedRepo = await this.getOwnedRepo(input.userId, input.connectedRepoId);
    const commitSha = await this.assertBranchExists(
      input.userId,
      connectedRepo.provider,
      connectedRepo.fullName,
      branch
    );

    let scan;

    try {
      scan = await this.prisma.$transaction(
        async (tx) => {
          const existingScan = await tx.scan.findFirst({
            where: {
              connectedRepoId: input.connectedRepoId,
              branch,
              status: { in: [ScanStatus.PENDING, ScanStatus.RUNNING] }
            }
          });

          if (existingScan) {
            throw this.createActiveScanConflict();
          }

          return tx.scan.create({
            data: {
              connectedRepoId: input.connectedRepoId,
              branch,
              commitSha,
              language: input.language ?? 'java',
              status: ScanStatus.PENDING
            }
          });
        },
        {
          isolationLevel: Prisma.TransactionIsolationLevel.Serializable
        }
      );
    } catch (error) {
      if (error instanceof ConflictException || isActiveScanTransactionConflict(error)) {
        throw this.createActiveScanConflict();
      }

      throw error;
    }

    try {
      await this.scanQueue.add(SCAN_PROCESS_JOB, { scanId: scan.id }, { jobId: scan.id });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to enqueue scan.';

      await this.prisma.scan.update({
        where: { id: scan.id },
        data: {
          status: ScanStatus.FAILED,
          errorMessage: message,
          completedAt: new Date()
        }
      });

      throw new ServiceUnavailableException({
        message: 'Scan queue is unavailable.',
        errorCode: 'SCAN_QUEUE_UNAVAILABLE'
      });
    }

    return {
      scanId: scan.id,
      status: 'PENDING',
      message: 'Scan queued successfully.'
    };
  }

  async getScanDetail(userId: string, scanId: string): Promise<ScanDetail> {
    const scan = await this.prisma.scan.findFirst({
      where: {
        id: scanId,
        connectedRepo: {
          userId
        }
      },
      include: {
        connectedRepo: {
          select: {
            fullName: true
          }
        }
      }
    });

    if (!scan) {
      throw new NotFoundException({
        message: 'Scan not found.',
        errorCode: 'SCAN_NOT_FOUND'
      });
    }

    return this.toScanSummary(scan);
  }

  async listRepoScans(input: ListRepoScansInput): Promise<RepoScanListResponse> {
    await this.getOwnedRepo(input.userId, input.repoId);

    const skip = (input.page - 1) * input.size;
    const [totalCount, scans] = await Promise.all([
      this.prisma.scan.count({
        where: {
          connectedRepoId: input.repoId
        }
      }),
      this.prisma.scan.findMany({
        where: {
          connectedRepoId: input.repoId
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
        skip,
        take: input.size
      })
    ]);

    return {
      items: scans.map((scan) => this.toScanSummary(scan)),
      totalCount,
      page: input.page,
      totalPages: Math.max(1, Math.ceil(totalCount / input.size))
    };
  }

  private async getOwnedRepo(userId: string, repoId: string) {
    const connectedRepo = await this.prisma.connectedRepo.findFirst({
      where: {
        id: repoId,
        userId
      }
    });

    if (!connectedRepo) {
      throw new NotFoundException({
        message: 'Connected repository not found.',
        errorCode: 'REPO_NOT_FOUND'
      });
    }

    return connectedRepo;
  }

  private async assertBranchExists(
    userId: string,
    providerEnum: RepoProvider,
    fullName: string,
    branch: string
  ): Promise<string> {
    const provider = providerEnum.toLowerCase() as Provider;
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

    const accessToken = this.tokenCrypto.decrypt(persistedToken.accessToken);

    try {
      return await this.gitClients.get(provider).getLatestCommitSha(fullName, branch, accessToken);
    } catch (error) {
      if (error instanceof GitProviderNotFoundError) {
        throw new BadRequestException({
          message: 'Requested branch was not found for the connected repository.',
          errorCode: 'BRANCH_NOT_FOUND'
        });
      }

      if (error instanceof GitProviderUnauthorizedError) {
        throw new ForbiddenException({
          message: `${provider} provider token is invalid or expired.`,
          errorCode: 'PROVIDER_TOKEN_INVALID'
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

  private createActiveScanConflict(): ConflictException {
    return new ConflictException({
      message: 'An active scan already exists for this repository branch.',
      errorCode: 'SCAN_ALREADY_ACTIVE'
    });
  }

  private toScanSummary(scan: {
    id: string;
    branch: string;
    commitSha: string | null;
    status: ScanStatus;
    language: string;
    totalFiles: number | null;
    totalLines: number | null;
    vulnCritical: number;
    vulnHigh: number;
    vulnMedium: number;
    vulnLow: number;
    vulnInfo: number;
    errorMessage: string | null;
    startedAt: Date | null;
    completedAt: Date | null;
    createdAt: Date;
    connectedRepo: {
      fullName: string;
    };
  }): ScanSummary {
    return {
      id: scan.id,
      repoFullName: scan.connectedRepo.fullName,
      branch: scan.branch,
      commitSha: scan.commitSha,
      status: scan.status,
      language: scan.language,
      totalFiles: scan.totalFiles,
      totalLines: scan.totalLines,
      summary: {
        critical: scan.vulnCritical,
        high: scan.vulnHigh,
        medium: scan.vulnMedium,
        low: scan.vulnLow,
        info: scan.vulnInfo
      },
      startedAt: scan.startedAt?.toISOString() ?? null,
      completedAt: scan.completedAt?.toISOString() ?? null,
      errorMessage: scan.errorMessage,
      createdAt: scan.createdAt.toISOString()
    };
  }
}

function isActiveScanTransactionConflict(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    ['P2002', 'P2034'].includes((error as { code?: string }).code ?? '')
  );
}
