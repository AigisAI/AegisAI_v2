import { Module } from "@nestjs/common";

import { AiAdvisoryController } from "./ai-advisory.controller";
import { AiAdvisoryService } from "./ai-advisory.service";

@Module({
  controllers: [AiAdvisoryController],
  providers: [AiAdvisoryService],
  exports: [AiAdvisoryService]
})
export class AiPlaneModule {}
