import { Body, Controller, Get, Param, Post, Query } from "@nestjs/common";

import type { PolicyEvaluationInput } from "../../../../packages/shared/src";
import { PolicyEngineService } from "./policy-engine.service";

@Controller("policy-decisions")
export class PolicyDecisionsController {
  constructor(private readonly policyEngineService: PolicyEngineService) {}

  @Post("evaluate")
  evaluate(@Body() body: PolicyEvaluationInput) {
    return this.policyEngineService.evaluate(body);
  }

  @Get(":policyDecisionId")
  read(@Param("policyDecisionId") policyDecisionId: string, @Query("tenantId") tenantId: string) {
    return this.policyEngineService.getPolicyDecision(tenantId, policyDecisionId);
  }
}
