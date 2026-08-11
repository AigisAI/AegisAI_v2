import { Body, Controller, Get, Param, Post, UseGuards } from '@nestjs/common';

import type {
  SastAiAdvisoryAuthorityProofIntent,
  SastAiAdvisoryIntent
} from '@aegisai/shared';
import { CurrentTenant } from '../auth/decorators/current-tenant.decorator';
import { SessionAuthGuard } from '../auth/guards/session-auth.guard';
import { InternalServiceGuard } from '../common/security/internal-service.guard';
import { AiAdvisoryAuthorityService } from './ai-advisory-authority.service';
import { AiAdvisoryService } from "./ai-advisory.service";

@Controller("ai-advisories")
export class AiAdvisoryController {
  constructor(
    private readonly aiAdvisoryService: AiAdvisoryService,
    private readonly authorityService: AiAdvisoryAuthorityService
  ) {}

  @Post()
  @UseGuards(InternalServiceGuard)
  create(@Body() body: SastAiAdvisoryIntent) {
    return this.aiAdvisoryService.createAdvisory(body);
  }

  @Post('authority-proofs')
  @UseGuards(InternalServiceGuard)
  createAuthorityProof(
    @Body() body: SastAiAdvisoryAuthorityProofIntent
  ) {
    return this.authorityService.createProof(body);
  }

  @Get(":advisoryId")
  @UseGuards(SessionAuthGuard)
  read(@Param("advisoryId") advisoryId: string, @CurrentTenant() tenantId: string) {
    return this.aiAdvisoryService.getAdvisory(tenantId, advisoryId);
  }
}
