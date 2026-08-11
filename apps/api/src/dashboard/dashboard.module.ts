import { Module } from '@nestjs/common';

import { AuthModule } from '../auth/auth.module';
import { ConfigModule } from '../config/config.module';
import { PrismaModule } from '../prisma/prisma.module';
import { ScanPlaneModule } from '../scan-plane/scan-plane.module';
import { DashboardEvidenceController } from './dashboard-evidence.controller';
import { DashboardController } from './dashboard.controller';
import { DashboardService } from './dashboard.service';

@Module({
  imports: [AuthModule, ConfigModule, PrismaModule, ScanPlaneModule],
  controllers: [DashboardController, DashboardEvidenceController],
  providers: [DashboardService],
  exports: [DashboardService]
})
export class DashboardModule {}
