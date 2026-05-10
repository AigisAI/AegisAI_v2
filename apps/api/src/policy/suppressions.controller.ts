import { Body, Controller, Post } from "@nestjs/common";

import type { SuppressionCreateInput } from "../../../../packages/shared/src";
import { PolicyLifecycleService } from "./policy-lifecycle.service";

@Controller("suppressions")
export class SuppressionsController {
  constructor(private readonly policyLifecycleService: PolicyLifecycleService) {}

  @Post()
  create(@Body() body: SuppressionCreateInput) {
    return this.policyLifecycleService.createSuppression(body);
  }
}
