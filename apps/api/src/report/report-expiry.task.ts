import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ReportStatus } from '@prisma/client';

import { PrismaService } from '../prisma/prisma.service';
import { REPORT_EXPIRY_INTERVAL_MS } from './report.constants';
import { ReportStorageService } from './services/report-storage.service';

@Injectable()
export class ReportExpiryTask implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(ReportExpiryTask.name);
  private timer: NodeJS.Timeout | null = null;

  constructor(
    private readonly prisma: PrismaService,
    private readonly storage: ReportStorageService
  ) {}

  onModuleInit(): void {
    if (process.env.NODE_ENV === 'test') {
      return;
    }

    this.timer = setInterval(() => {
      void this.expireReadyReports().catch((error: unknown) => {
        this.logger.error('Failed to expire report files.', error as Error);
      });
    }, REPORT_EXPIRY_INTERVAL_MS);
    this.timer.unref?.();
  }

  onModuleDestroy(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  async expireReadyReports(referenceTime = new Date()): Promise<void> {
    const expiredReports = await this.prisma.report.findMany({
      where: {
        status: ReportStatus.READY,
        expiresAt: {
          lte: referenceTime
        }
      }
    });

    for (const report of expiredReports) {
      if (report.filePath) {
        await this.storage.delete(report.filePath);
      }
    }

    if (expiredReports.length > 0) {
      await this.prisma.report.updateMany({
        where: {
          id: {
            in: expiredReports.map((report) => report.id)
          }
        },
        data: {
          status: ReportStatus.EXPIRED,
          downloadUrl: null,
          errorMessage: 'Report expired.'
        }
      });
    }
  }
}
