import { BullModule, getQueueToken } from '@nestjs/bullmq';
import { Module } from '@nestjs/common';

import { AuthModule } from '../auth/auth.module';
import { AnalysisApiModule } from '../client/analysis/analysis-api.module';
import { GitClientModule } from '../client/git/git-client.module';
import { ConfigModule } from '../config/config.module';
import { LanguageModule } from '../language/language.module';
import { PrismaModule } from '../prisma/prisma.module';
import { SCAN_QUEUE } from './scan.constants';
import { ScanController } from './scan.controller';
import { ScanProcessor } from './scan.processor';
import { ScanService } from './scan.service';
import { CodeCollectorService } from './services/code-collector.service';
import { StuckScanRecoveryTask } from './stuck-scan-recovery.task';

const runtimeProviders =
  process.env.NODE_ENV === 'test' ? [] : [ScanProcessor, StuckScanRecoveryTask];
const queueImports =
  process.env.NODE_ENV === 'test'
    ? []
    : [
        BullModule.registerQueue({
          name: SCAN_QUEUE
        })
      ];
const queueProviders =
  process.env.NODE_ENV === 'test'
    ? [
        {
          provide: getQueueToken(SCAN_QUEUE),
          useValue: {
            add: async () => undefined
          }
        }
      ]
    : [];

@Module({
  imports: [
    ...queueImports,
    PrismaModule,
    AuthModule,
    ConfigModule,
    GitClientModule,
    LanguageModule,
    AnalysisApiModule
  ],
  controllers: [ScanController],
  providers: [ScanService, CodeCollectorService, ...runtimeProviders, ...queueProviders],
  exports: [ScanService]
})
export class ScanModule {}
