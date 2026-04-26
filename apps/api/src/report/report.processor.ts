import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Injectable, Logger } from '@nestjs/common';
import type { Job } from 'bullmq';
import { ReportStatus } from '@prisma/client';

import { ConfigService } from '../config/config.service';
import { PrismaService } from '../prisma/prisma.service';
import { REPORT_QUEUE } from './report.constants';
import { PdfGeneratorService } from './services/pdf-generator.service';
import { ReportStorageService } from './services/report-storage.service';

@Injectable()
@Processor(REPORT_QUEUE, { concurrency: 2 })
export class ReportProcessor extends WorkerHost {
  private readonly logger = new Logger(ReportProcessor.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly pdfGenerator: PdfGeneratorService,
    private readonly storage: ReportStorageService,
    private readonly config: ConfigService
  ) {
    super();
  }

  async process(job: Job<{ reportId: string }>): Promise<void> {
    const report = await this.prisma.report.findUnique({
      where: {
        id: job.data.reportId
      },
      include: {
        scan: {
          include: {
            connectedRepo: {
              select: {
                fullName: true
              }
            },
            vulnerabilities: {
              select: {
                id: true,
                title: true,
                severity: true,
                filePath: true,
                lineStart: true,
                fixSuggestion: true
              },
              orderBy: [{ severity: 'desc' }, { createdAt: 'asc' }]
            }
          }
        }
      }
    });

    if (!report) {
      throw new Error(`Report not found: ${job.data.reportId}`);
    }

    let filePath: string | undefined;

    try {
      const pdf = await this.pdfGenerator.generateScanReport(report.scan);
      filePath = await this.storage.write({
        reportId: report.id,
        scanId: report.scanId,
        pdf
      });
      const expiresAt = new Date(
        Date.now() + this.config.get('REPORT_EXPIRY_HOURS') * 60 * 60 * 1000
      );

      await this.prisma.report.update({
        where: {
          id: report.id
        },
        data: {
          status: ReportStatus.READY,
          filePath,
          downloadUrl: `/api/reports/${report.id}/download`,
          errorMessage: null,
          expiresAt
        }
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Report generation failed';

      if (filePath) {
        try {
          await this.storage.delete(filePath);
        } catch (cleanupError) {
          this.logger.error(
            `Failed to clean up generated report file for ${report.id}.`,
            cleanupError as Error
          );
        }
      }

      try {
        await this.prisma.report.update({
          where: {
            id: report.id
          },
          data: {
            status: ReportStatus.FAILED,
            errorMessage: message
          }
        });
      } catch (updateError) {
        this.logger.error(
          `Failed to persist report failure state: ${report.id}`,
          updateError as Error
        );
      }

      this.logger.error(`Report generation failed: ${report.id}`, error as Error);
      throw error;
    }
  }
}
