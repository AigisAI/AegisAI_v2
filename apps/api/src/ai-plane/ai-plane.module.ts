import { Module } from "@nestjs/common";

import { AiAdvisoryController } from "./ai-advisory.controller";
import { AiAdvisoryAuthorityService } from './ai-advisory-authority.service';
import { AiAdvisoryRuntimeClient } from "./ai-advisory-runtime.client";
import { AiAdvisoryService } from "./ai-advisory.service";
import { ConfigModule } from "../config/config.module";
import { PrismaModule } from "../prisma/prisma.module";
import { ScanPlaneModule } from '../scan-plane/scan-plane.module';
import { RuleGovernanceModule } from '../rule-governance/rule-governance.module';
import { PrismaSastAiAdvisoryStore } from './prisma-sast-ai-advisory.store';
import { PrismaSastAiAdvisoryAuthorityStore } from './prisma-sast-ai-advisory-authority.store';
import { SastAiAdvisoryAuthorityStore } from './sast-ai-advisory-authority.store';
import { SastAiAdvisoryStore } from './sast-ai-advisory.store';

@Module({
  imports: [
    ConfigModule,
    PrismaModule,
    RuleGovernanceModule,
    ScanPlaneModule
  ],
  controllers: [AiAdvisoryController],
  providers: [
    AiAdvisoryService,
    AiAdvisoryAuthorityService,
    AiAdvisoryRuntimeClient,
    PrismaSastAiAdvisoryStore,
    PrismaSastAiAdvisoryAuthorityStore,
    {
      provide: SastAiAdvisoryStore,
      useExisting: PrismaSastAiAdvisoryStore
    },
    {
      provide: SastAiAdvisoryAuthorityStore,
      useExisting: PrismaSastAiAdvisoryAuthorityStore
    }
  ],
  exports: [AiAdvisoryService, AiAdvisoryAuthorityService]
})
export class AiPlaneModule {}
