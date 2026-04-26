import { Body, Controller, Get, Param, Post } from "@nestjs/common";

import { ControlPlaneService } from "./control-plane.service";
import type { CreateScanRequestInput } from "./control-plane.types";

@Controller("scan-requests")
export class ScanRequestsController {
  constructor(private readonly controlPlaneService: ControlPlaneService) {}

  @Post()
  create(@Body() body: CreateScanRequestInput) {
    return this.controlPlaneService.createScanRequest(body);
  }

  @Get(":scanRequestId")
  get(@Param("scanRequestId") scanRequestId: string) {
    return this.controlPlaneService.getScanRequest(scanRequestId);
  }
}
