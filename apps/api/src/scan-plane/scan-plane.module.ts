import { Module } from "@nestjs/common";

import { EvidenceController } from "./evidence.controller";
import { FindingsController } from "./findings.controller";
import { ScanPlaneController } from "./scan-plane.controller";
import { ScanPlaneService } from "./scan-plane.service";

@Module({
  controllers: [ScanPlaneController, FindingsController, EvidenceController],
  providers: [ScanPlaneService]
})
export class ScanPlaneModule {}
