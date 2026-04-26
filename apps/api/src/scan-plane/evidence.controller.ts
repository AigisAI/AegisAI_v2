import { Controller, Get, Query } from "@nestjs/common";

import { ScanPlaneService } from "./scan-plane.service";

@Controller("evidence")
export class EvidenceController {
  constructor(private readonly scanPlaneService: ScanPlaneService) {}

  @Get()
  list(@Query("tenantId") tenantId: string, @Query("scanRequestId") scanRequestId: string) {
    return this.scanPlaneService.listEvidencePacks(tenantId, scanRequestId);
  }
}
