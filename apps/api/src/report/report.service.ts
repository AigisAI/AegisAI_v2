import type { ReportDetail, ReportRequestResponse } from '@aegisai/shared';
import {
  BadRequestException,
  Injectable,
  NotFoundException,
  ServiceUnavailableException
} from '@nestjs/common';
import { ReportStatus, ScanStatus } from '@prisma/client';

import { PrismaService } from '../prisma/prisma.service';
import { InjectQueue } from '@nestjs/bullmq';
import type { Queue } from 'bullmq';
import { REPORT_GENERATE_JOB, REPORT_QUEUE } from './report.constants';
import { ReportStorageService } from './services/report-storage.service';

interface RequestReportInput {
  userId: string;
  scanId: string;
}

interface CreateGeneratingReportResult {
  report: {
    id: string;
    status: ReportStatus;
  };
  reused: boolean;
}

@Injectable()
export class ReportService {
  constructor(
    private readonly prisma: PrismaService,
    @InjectQueue(REPORT_QUEUE) private readonly reportQueue: Queue,
    private readonly storage: ReportStorageService
  ) {}

  async requestReport(input: RequestReportInput): Promise<ReportRequestResponse> {
    const scan = await this.prisma.scan.findFirst({
      where: {
        id: input.scanId,
        connectedRepo: {
          userId: input.userId
        }
      }
    });

    if (!scan) {
      throw new NotFoundException({
        message: 'Scan not found.',
        errorCode: 'SCAN_NOT_FOUND'
      });
    }

    if (scan.status !== ScanStatus.DONE) {
      throw new BadRequestException({
        message: 'Reports are only available for completed scans.',
        errorCode: 'SCAN_NOT_DONE'
      });
    }

    const existing = await this.findReusableReport(input.userId, input.scanId);

    if (existing?.status === ReportStatus.GENERATING) {
      return {
        reportId: existing.id,
        status: 'GENERATING',
        message: 'A PDF report is already being generated.'
      };
    }

    if (existing?.status === ReportStatus.READY) {
      if (await this.canReuseReadyReport(existing.id, existing.expiresAt, existing.filePath)) {
        return {
          reportId: existing.id,
          status: 'READY',
          message: 'An existing PDF report is still available.'
        };
      }

      await this.prisma.report.update({
        where: {
          id: existing.id
        },
        data: {
          status: ReportStatus.EXPIRED,
          downloadUrl: null,
          errorMessage: 'Report expired.'
        }
      });
    }

    const { report, reused } = await this.createGeneratingReport(input.userId, input.scanId);

    if (reused && report.status === ReportStatus.GENERATING) {
      return {
        reportId: report.id,
        status: 'GENERATING',
        message: 'A PDF report is already being generated.'
      };
    }

    if (reused && report.status === ReportStatus.READY) {
      return {
        reportId: report.id,
        status: 'READY',
        message: 'An existing PDF report is still available.'
      };
    }

    try {
      await this.reportQueue.add(
        REPORT_GENERATE_JOB,
        { reportId: report.id },
        {
          jobId: report.id
        }
      );
    } catch (error) {
      const message = this.toErrorMessage(error);

      await this.prisma.report.update({
        where: {
          id: report.id
        },
        data: {
          status: ReportStatus.FAILED,
          errorMessage: message
        }
      });

      throw new ServiceUnavailableException({
        message: 'Failed to queue report generation.',
        errorCode: 'REPORT_QUEUE_UNAVAILABLE'
      });
    }

    return {
      reportId: report.id,
      status: 'GENERATING',
      message: 'PDF report generation has started.'
    };
  }

  async getReportDetail(userId: string, reportId: string): Promise<ReportDetail> {
    const report = await this.prisma.report.findFirst({
      where: {
        id: reportId,
        userId,
        scan: {
          connectedRepo: {
            userId
          }
        }
      }
    });

    if (!report) {
      throw new NotFoundException({
        message: 'Report not found.',
        errorCode: 'REPORT_NOT_FOUND'
      });
    }

    return {
      id: report.id,
      scanId: report.scanId,
      status: report.status,
      downloadUrl: report.downloadUrl,
      errorMessage: report.errorMessage,
      createdAt: report.createdAt.toISOString(),
      expiresAt: report.expiresAt?.toISOString() ?? null
    };
  }

  private toErrorMessage(error: unknown): string {
    if (error instanceof Error && error.message) {
      return error.message;
    }

    return 'Unknown report queue failure';
  }

  private async findReusableReport(userId: string, scanId: string) {
    return this.prisma.report.findFirst({
      where: {
        scanId,
        userId,
        status: {
          in: [ReportStatus.GENERATING, ReportStatus.READY]
        }
      },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }]
    });
  }

  private async canReuseReadyReport(
    reportId: string,
    expiresAt: Date | null,
    filePath: string | null
  ): Promise<boolean> {
    const isExpired = expiresAt !== null && expiresAt.getTime() <= Date.now();
    const hasFile = filePath ? await this.storage.exists(filePath) : false;

    if (isExpired || !hasFile) {
      return false;
    }

    const refreshed = await this.prisma.report.findUnique({
      where: {
        id: reportId
      }
    });

    if (!refreshed || refreshed.status !== ReportStatus.READY) {
      return false;
    }

    const refreshedExpired =
      refreshed.expiresAt !== null && refreshed.expiresAt.getTime() <= Date.now();
    const refreshedHasFile = refreshed.filePath
      ? await this.storage.exists(refreshed.filePath)
      : false;

    return !refreshedExpired && refreshedHasFile;
  }

  private async createGeneratingReport(
    userId: string,
    scanId: string
  ): Promise<CreateGeneratingReportResult> {
    try {
      return {
        report: await this.prisma.report.create({
          data: {
            scanId,
            userId,
            status: ReportStatus.GENERATING
          }
        }),
        reused: false
      };
    } catch (error) {
      if (!this.isReusableReportConflict(error)) {
        throw error;
      }

      const existing = await this.findReusableReport(userId, scanId);

      if (!existing) {
        throw error;
      }

      if (existing.status === ReportStatus.READY) {
        const isReusable = await this.canReuseReadyReport(
          existing.id,
          existing.expiresAt,
          existing.filePath
        );

        if (!isReusable) {
          await this.prisma.report.update({
            where: { id: existing.id },
            data: {
              status: ReportStatus.EXPIRED,
              downloadUrl: null,
              errorMessage: 'Report expired.'
            }
          });
          throw error;
        }
      }

      return {
        report: existing,
        reused: true
      };
    }
  }

  private isReusableReportConflict(error: unknown): boolean {
    return (
      typeof error === 'object' &&
      error !== null &&
      'code' in error &&
      (error as { code?: string }).code === 'P2002'
    );
  }
}
