import { BullModule } from '@nestjs/bullmq';
import { Module } from '@nestjs/common';

import { AuthModule } from '../auth/auth.module';
import { AnalysisApiModule } from '../client/analysis/analysis-api.module';
import { GitClientModule } from '../client/git/git-client.module';
import { LanguageModule } from '../language/language.module';
import { PrismaModule } from '../prisma/prisma.module';
import { SCAN_QUEUE } from './scan.constants';
import { ScanProcessor } from './scan.processor';
import { ScanService } from './scan.service';
import { CodeCollectorService } from './services/code-collector.service';
import { StuckScanRecoveryTask } from './stuck-scan-recovery.task';

@Module({
  imports: [
    BullModule.registerQueue({
      name: SCAN_QUEUE
    }),
    PrismaModule,
    AuthModule,
    GitClientModule,
    LanguageModule,
    AnalysisApiModule
  ],
  providers: [ScanService, ScanProcessor, CodeCollectorService, StuckScanRecoveryTask],
  exports: [ScanService]
})
export class ScanModule {}
