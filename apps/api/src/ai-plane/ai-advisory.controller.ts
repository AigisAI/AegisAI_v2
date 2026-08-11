import { Body, Controller, Get, Param, Post, UseGuards } from '@nestjs/common';

import type { SastAiAdvisoryIntent } from '@aegisai/shared';
import { CurrentTenant } from '../auth/decorators/current-tenant.decorator';
import { SessionAuthGuard } from '../auth/guards/session-auth.guard';
import { InternalServiceGuard } from '../common/security/internal-service.guard';
import { AiAdvisoryService } from "./ai-advisory.service";

@Controller("ai-advisories")
export class AiAdvisoryController {
  constructor(private readonly aiAdvisoryService: AiAdvisoryService) {}

  @Post()
  @UseGuards(InternalServiceGuard)
  create(@Body() body: SastAiAdvisoryIntent) {
    return this.aiAdvisoryService.createAdvisory(body);
  }

  @Get(":advisoryId")
  @UseGuards(SessionAuthGuard)
  read(@Param("advisoryId") advisoryId: string, @CurrentTenant() tenantId: string) {
    return this.aiAdvisoryService.getAdvisory(tenantId, advisoryId);
  }
}
