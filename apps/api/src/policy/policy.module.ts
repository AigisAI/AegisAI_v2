import { Module } from "@nestjs/common";

import { AiPlaneModule } from '../ai-plane/ai-plane.module';
import { PrismaModule } from '../prisma/prisma.module';
import { PolicyDecisionStore } from './policy-decision.store';
import { PolicyDecisionsController } from "./policy-decisions.controller";
import { PolicyEngineService } from "./policy-engine.service";
import { PolicyLifecycleStore } from './policy-lifecycle.store';
import { PolicyLifecycleService } from "./policy-lifecycle.service";
import { PrismaPolicyDecisionStore } from './prisma-policy-decision.store';
import { PrismaPolicyLifecycleStore } from './prisma-policy-lifecycle.store';
import { SuppressionsController } from "./suppressions.controller";
import { WaiversController } from "./waivers.controller";

@Module({
  imports: [AiPlaneModule, PrismaModule],
  controllers: [PolicyDecisionsController, WaiversController, SuppressionsController],
  providers: [
    PolicyEngineService,
    PolicyLifecycleService,
    PrismaPolicyDecisionStore,
    PrismaPolicyLifecycleStore,
    {
      provide: PolicyDecisionStore,
      useExisting: PrismaPolicyDecisionStore
    },
    {
      provide: PolicyLifecycleStore,
      useExisting: PrismaPolicyLifecycleStore
    }
  ],
  exports: [PolicyEngineService, PolicyLifecycleService]
})
export class PolicyModule {}
