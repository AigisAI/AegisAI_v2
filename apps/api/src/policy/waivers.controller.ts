import { Body, Controller, Param, Patch, Post } from "@nestjs/common";

import type { WaiverCreateInput, WaiverUpdateInput } from "../../../../packages/shared/src";
import { PolicyLifecycleService } from "./policy-lifecycle.service";

@Controller("waivers")
export class WaiversController {
  constructor(private readonly policyLifecycleService: PolicyLifecycleService) {}

  @Post()
  create(@Body() body: WaiverCreateInput) {
    return this.policyLifecycleService.createWaiver(body);
  }

  @Patch(":waiverId")
  update(@Param("waiverId") waiverId: string, @Body() body: WaiverUpdateInput) {
    return this.policyLifecycleService.updateWaiver(waiverId, body);
  }
}
