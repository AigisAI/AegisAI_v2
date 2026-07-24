import { Body, Controller, Get, Post, Query, UseGuards } from '@nestjs/common';

import { CurrentTenant } from '../auth/decorators/current-tenant.decorator';
import { SessionAuthGuard } from '../auth/guards/session-auth.guard';
import { InternalServiceGuard } from '../common/security/internal-service.guard';
import { RunSandboxScannersDto, ScanArtifactsQueryDto } from './scan-plane.dto';
import { ScanPlaneService } from "./scan-plane.service";

@Controller("scan-plane")
export class ScanPlaneController {
  constructor(private readonly scanPlaneService: ScanPlaneService) {}

  @Post("scanner-runs/execute")
  @UseGuards(InternalServiceGuard)
  runSandboxScanners(@Body() body: RunSandboxScannersDto) {
    return this.scanPlaneService.runSandboxScanners(body);
  }

  @Get("scanner-runs")
  @UseGuards(SessionAuthGuard)
  listScannerRuns(@CurrentTenant() tenantId: string, @Query() query: ScanArtifactsQueryDto) {
    return this.scanPlaneService.listScannerRuns(tenantId, query.scanRequestId);
  }
}
