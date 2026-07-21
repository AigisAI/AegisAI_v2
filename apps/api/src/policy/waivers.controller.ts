import { Body, Controller, Param, Patch, Post, UseGuards } from '@nestjs/common';

import type { WaiverCreateInput, WaiverUpdateInput } from '@aegisai/shared';
import { CurrentTenant } from '../auth/decorators/current-tenant.decorator';
import { SessionAuthGuard } from '../auth/guards/session-auth.guard';
import { PolicyLifecycleService } from "./policy-lifecycle.service";

@Controller("waivers")
@UseGuards(SessionAuthGuard)
export class WaiversController {
  constructor(private readonly policyLifecycleService: PolicyLifecycleService) {}

  @Post()
  create(@CurrentTenant() tenantId: string, @Body() body: WaiverCreateInput) {
    return this.policyLifecycleService.createWaiver({ ...body, tenantId });
  }

  @Patch(":waiverId")
  update(
    @CurrentTenant() tenantId: string,
    @Param("waiverId") waiverId: string,
    @Body() body: WaiverUpdateInput
  ) {
    return this.policyLifecycleService.updateWaiver(waiverId, { ...body, tenantId });
  }
}
