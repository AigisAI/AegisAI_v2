import { Body, Controller, Get, Param, Post, Query } from "@nestjs/common";

import { ScanPlaneService } from "./scan-plane.service";

@Controller("evidence")
export class EvidenceController {
  constructor(private readonly scanPlaneService: ScanPlaneService) {}

  @Get()
  list(@Query("tenantId") tenantId: string, @Query("scanRequestId") scanRequestId: string) {
    return this.scanPlaneService.listEvidencePacks(tenantId, scanRequestId);
  }

  @Post(":evidencePackId/access-requests")
  requestAccess(
    @Param("evidencePackId") evidencePackId: string,
    @Body() body: { tenantId: string; scanRequestId: string }
  ) {
    return this.scanPlaneService.requestEvidenceAccess({
      evidencePackId,
      tenantId: body.tenantId,
      scanRequestId: body.scanRequestId
    });
  }
}
