import { Controller, Get, Query, UseGuards } from "@nestjs/common";

import { CurrentTenant } from "../common/security/current-tenant.decorator";
import { SessionAuthGuard } from "../common/security/session-auth.guard";
import { ScanArtifactsQueryDto } from "./scan-plane.dto";
import { ScanPlaneService } from "./scan-plane.service";

@Controller("evidence")
@UseGuards(SessionAuthGuard)
export class EvidenceController {
  constructor(private readonly scanPlaneService: ScanPlaneService) {}

  @Get()
  list(@CurrentTenant() tenantId: string, @Query() query: ScanArtifactsQueryDto) {
    return this.scanPlaneService.listEvidencePacks(tenantId, query.scanRequestId);
  }
}
