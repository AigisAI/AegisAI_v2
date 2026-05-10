import { Module } from "@nestjs/common";

import { PolicyDecisionsController } from "./policy-decisions.controller";
import { PolicyEngineService } from "./policy-engine.service";
import { PolicyLifecycleService } from "./policy-lifecycle.service";
import { SuppressionsController } from "./suppressions.controller";
import { WaiversController } from "./waivers.controller";

@Module({
  controllers: [PolicyDecisionsController, WaiversController, SuppressionsController],
  providers: [PolicyEngineService, PolicyLifecycleService],
  exports: [PolicyEngineService, PolicyLifecycleService]
})
export class PolicyModule {}
