import { Body, Controller, Get, Param, Post, Query } from "@nestjs/common";

import type { AiAdvisoryRequest } from "../../../../packages/shared/src";
import { AiAdvisoryService } from "./ai-advisory.service";

@Controller("ai-advisories")
export class AiAdvisoryController {
  constructor(private readonly aiAdvisoryService: AiAdvisoryService) {}

  @Post()
  create(@Body() body: AiAdvisoryRequest) {
    return this.aiAdvisoryService.createAdvisory(body);
  }

  @Get(":advisoryId")
  read(@Param("advisoryId") advisoryId: string, @Query("tenantId") tenantId: string) {
    return this.aiAdvisoryService.getAdvisory(tenantId, advisoryId);
  }
}
