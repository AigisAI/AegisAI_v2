import { Module } from "@nestjs/common";

import { AiAdvisoryController } from "./ai-advisory.controller";
import { AiAdvisoryRuntimeClient } from "./ai-advisory-runtime.client";
import { AiAdvisoryService } from "./ai-advisory.service";
import { ConfigModule } from "../config/config.module";
import { PrismaModule } from "../prisma/prisma.module";
import { ScanPlaneModule } from '../scan-plane/scan-plane.module';
import { PrismaSastAiAdvisoryStore } from './prisma-sast-ai-advisory.store';
import { SastAiAdvisoryStore } from './sast-ai-advisory.store';

@Module({
  imports: [ConfigModule, PrismaModule, ScanPlaneModule],
  controllers: [AiAdvisoryController],
  providers: [
    AiAdvisoryService,
    AiAdvisoryRuntimeClient,
    PrismaSastAiAdvisoryStore,
    {
      provide: SastAiAdvisoryStore,
      useExisting: PrismaSastAiAdvisoryStore
    }
  ],
  exports: [AiAdvisoryService]
})
export class AiPlaneModule {}
