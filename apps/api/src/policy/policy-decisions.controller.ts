import { Body, Controller, Get, Param, Post, UseGuards } from '@nestjs/common';

import type { PolicyEvaluationInput } from '@aegisai/shared';
import { CurrentTenant } from '../auth/decorators/current-tenant.decorator';
import { SessionAuthGuard } from '../auth/guards/session-auth.guard';
import { InternalServiceGuard } from '../common/security/internal-service.guard';
import { PolicyEngineService } from "./policy-engine.service";

@Controller("policy-decisions")
export class PolicyDecisionsController {
  constructor(private readonly policyEngineService: PolicyEngineService) {}

  @Post("evaluate")
  @UseGuards(InternalServiceGuard)
  evaluate(@Body() body: PolicyEvaluationInput) {
    return this.policyEngineService.evaluate(body);
  }

  @Get(":policyDecisionId")
  @UseGuards(SessionAuthGuard)
  read(@Param("policyDecisionId") policyDecisionId: string, @CurrentTenant() tenantId: string) {
    return this.policyEngineService.getPolicyDecision(tenantId, policyDecisionId);
  }
}
