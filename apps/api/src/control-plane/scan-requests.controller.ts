import { Body, Controller, Get, Param, Post, UseGuards } from '@nestjs/common';

import { CurrentTenant } from '../auth/decorators/current-tenant.decorator';
import { SessionAuthGuard } from '../auth/guards/session-auth.guard';
import { CreateScanRequestDto } from './control-plane.dto';
import { ControlPlaneService } from "./control-plane.service";

@Controller("scan-requests")
@UseGuards(SessionAuthGuard)
export class ScanRequestsController {
  constructor(private readonly controlPlaneService: ControlPlaneService) {}

  @Post()
  create(@CurrentTenant() tenantId: string, @Body() body: CreateScanRequestDto) {
    return this.controlPlaneService.createScanRequest({ ...body, tenantId });
  }

  @Get(":scanRequestId")
  get(@CurrentTenant() tenantId: string, @Param("scanRequestId") scanRequestId: string) {
    return this.controlPlaneService.getScanRequest(tenantId, scanRequestId);
  }
}
