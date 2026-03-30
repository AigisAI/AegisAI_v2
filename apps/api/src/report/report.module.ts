import { BullModule, getQueueToken } from '@nestjs/bullmq';
import { Module } from '@nestjs/common';

import { ConfigModule } from '../config/config.module';
import { PrismaModule } from '../prisma/prisma.module';
import { REPORT_QUEUE } from './report.constants';
import { ReportExpiryTask } from './report-expiry.task';
import { ReportProcessor } from './report.processor';
import { ReportService } from './report.service';
import { PdfGeneratorService } from './services/pdf-generator.service';
import { ReportStorageService } from './services/report-storage.service';

const runtimeProviders =
  process.env.NODE_ENV === 'test' ? [] : [ReportProcessor, ReportExpiryTask];
const queueImports =
  process.env.NODE_ENV === 'test'
    ? []
    : [
        BullModule.registerQueue({
          name: REPORT_QUEUE
        })
      ];
const queueProviders =
  process.env.NODE_ENV === 'test'
    ? [
        {
          provide: getQueueToken(REPORT_QUEUE),
          useValue: {
            add: async () => undefined
          }
        }
      ]
    : [];

@Module({
  imports: [...queueImports, PrismaModule, ConfigModule],
  providers: [
    ReportService,
    PdfGeneratorService,
    ReportStorageService,
    ...runtimeProviders,
    ...queueProviders
  ],
  exports: [ReportService]
})
export class ReportModule {}
