import { Module } from "@nestjs/common";

import { AiAdvisoryController } from "./ai-advisory.controller";
import { AiAdvisoryRuntimeClient } from "./ai-advisory-runtime.client";
import { AiAdvisoryService } from "./ai-advisory.service";
import { ConfigModule } from "../config/config.module";
import { PrismaModule } from "../prisma/prisma.module";

@Module({
  imports: [ConfigModule, PrismaModule],
  controllers: [AiAdvisoryController],
  providers: [AiAdvisoryService, AiAdvisoryRuntimeClient],
  exports: [AiAdvisoryService]
})
export class AiPlaneModule {}
