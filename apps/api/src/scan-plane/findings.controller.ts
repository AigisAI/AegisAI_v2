import { Controller, Get, Query, UseGuards } from '@nestjs/common';

import { CurrentTenant } from '../auth/decorators/current-tenant.decorator';
import { SessionAuthGuard } from '../auth/guards/session-auth.guard';
import { ScanArtifactsQueryDto } from './scan-plane.dto';
import { ScanPlaneService } from "./scan-plane.service";

@Controller("findings")
@UseGuards(SessionAuthGuard)
export class FindingsController {
  constructor(private readonly scanPlaneService: ScanPlaneService) {}

  @Get()
  list(@CurrentTenant() tenantId: string, @Query() query: ScanArtifactsQueryDto) {
    return this.scanPlaneService.listFindings(tenantId, query.scanRequestId);
  }
}
