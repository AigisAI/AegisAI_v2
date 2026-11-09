import { Body, Controller, Get, Post, Query, UseGuards } from "@nestjs/common";

import { CurrentTenant } from "../common/security/current-tenant.decorator";
import { InternalServiceGuard } from "../common/security/internal-service.guard";
import { SessionAuthGuard } from "../common/security/session-auth.guard";
import { PendingRuntimeGuard } from "../common/security/pending-runtime.guard";
import { RunMockScanPlaneDto, ScanArtifactsQueryDto } from "./scan-plane.dto";
import { ScanPlaneService } from "./scan-plane.service";

@Controller("scan-plane")
export class ScanPlaneController {
  constructor(private readonly scanPlaneService: ScanPlaneService) {}

  @Post("mock-runs")
  @UseGuards(InternalServiceGuard, PendingRuntimeGuard)
  runMockPipeline(@Body() body: RunMockScanPlaneDto) {
    return this.scanPlaneService.runMockPipeline(body);
  }

  @Get("scanner-runs")
  @UseGuards(SessionAuthGuard)
  listScannerRuns(
    @CurrentTenant() tenantId: string,
    @Query() query: ScanArtifactsQueryDto
  ) {
    return this.scanPlaneService.listScannerRuns(tenantId, query.scanRequestId);
  }
}
