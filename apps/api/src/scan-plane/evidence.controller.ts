import { Body, Controller, Get, Param, Post, Query, UseGuards } from '@nestjs/common';

import { CurrentTenant } from '../auth/decorators/current-tenant.decorator';
import { SessionAuthGuard } from '../auth/guards/session-auth.guard';
import { EvidenceAccessRequestDto, ScanArtifactsQueryDto } from './scan-plane.dto';
import { ScanPlaneService } from "./scan-plane.service";

@Controller("evidence")
@UseGuards(SessionAuthGuard)
export class EvidenceController {
  constructor(private readonly scanPlaneService: ScanPlaneService) {}

  @Get()
  list(@CurrentTenant() tenantId: string, @Query() query: ScanArtifactsQueryDto) {
    return this.scanPlaneService.listEvidencePacks(tenantId, query.scanRequestId);
  }

  @Post(":evidencePackId/access-requests")
  requestAccess(
    @CurrentTenant() tenantId: string,
    @Param("evidencePackId") evidencePackId: string,
    @Body() body: EvidenceAccessRequestDto
  ) {
    return this.scanPlaneService.requestEvidenceAccess({
      evidencePackId,
      tenantId,
      scanRequestId: body.scanRequestId
    });
  }
}
