import { Body, Controller, Get, Post, Query } from "@nestjs/common";

import { ScanPlaneService } from "./scan-plane.service";
import type { RunMockScanPlaneInput, RunSandboxScannersInput } from "./scan-plane.types";

@Controller("scan-plane")
export class ScanPlaneController {
  constructor(private readonly scanPlaneService: ScanPlaneService) {}

  @Post("mock-runs")
  runMockPipeline(@Body() body: RunMockScanPlaneInput) {
    return this.scanPlaneService.runMockPipeline(body);
  }

  @Post("scanner-runs/execute")
  runSandboxScanners(@Body() body: RunSandboxScannersInput) {
    return this.scanPlaneService.runSandboxScanners(body);
  }

  @Get("scanner-runs")
  listScannerRuns(@Query("tenantId") tenantId: string, @Query("scanRequestId") scanRequestId: string) {
    return this.scanPlaneService.listScannerRuns(tenantId, scanRequestId);
  }
}
