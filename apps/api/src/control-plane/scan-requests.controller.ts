import { Body, Controller, Get, Param, Post, UseGuards } from "@nestjs/common";

import { CurrentTenant } from "../common/security/current-tenant.decorator";
import { SessionAuthGuard } from "../common/security/session-auth.guard";
import { PendingRuntimeGuard } from "../common/security/pending-runtime.guard";
import { CreateScanRequestDto, ScanRequestIdParamDto } from "./control-plane.dto";
import { ControlPlaneService } from "./control-plane.service";

@Controller("scan-requests")
@UseGuards(SessionAuthGuard)
export class ScanRequestsController {
  constructor(private readonly controlPlaneService: ControlPlaneService) {}

  @Post()
  @UseGuards(PendingRuntimeGuard)
  create(@CurrentTenant() tenantId: string, @Body() body: CreateScanRequestDto) {
    return this.controlPlaneService.createScanRequest({ ...body, tenantId });
  }

  @Get(":scanRequestId")
  get(@CurrentTenant() tenantId: string, @Param() params: ScanRequestIdParamDto) {
    return this.controlPlaneService.getScanRequest(tenantId, params.scanRequestId);
  }
}
