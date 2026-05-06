import { Module } from "@nestjs/common";

import { PolicyDecisionsController } from "./policy-decisions.controller";
import { PolicyEngineService } from "./policy-engine.service";

@Module({
  controllers: [PolicyDecisionsController],
  providers: [PolicyEngineService],
  exports: [PolicyEngineService]
})
export class PolicyModule {}
