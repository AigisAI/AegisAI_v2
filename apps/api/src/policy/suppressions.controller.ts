import { Body, Controller, Post, UseGuards } from '@nestjs/common';

import type { SuppressionCreateInput } from '@aegisai/shared';
import { CurrentTenant } from '../auth/decorators/current-tenant.decorator';
import { SessionAuthGuard } from '../auth/guards/session-auth.guard';
import { PolicyLifecycleService } from "./policy-lifecycle.service";

@Controller("suppressions")
@UseGuards(SessionAuthGuard)
export class SuppressionsController {
  constructor(private readonly policyLifecycleService: PolicyLifecycleService) {}

  @Post()
  create(@CurrentTenant() tenantId: string, @Body() body: SuppressionCreateInput) {
    return this.policyLifecycleService.createSuppression({ ...body, tenantId });
  }
}
