import { Module } from "@nestjs/common";

import { ControlPlaneModule } from "../control-plane/control-plane.module";
import { EvidenceController } from "./evidence.controller";
import { FindingsController } from "./findings.controller";
import { ScanPlaneController } from "./scan-plane.controller";
import { ScanPlaneService } from "./scan-plane.service";

@Module({
  imports: [ControlPlaneModule],
  controllers: [ScanPlaneController, FindingsController, EvidenceController],
  providers: [ScanPlaneService]
})
export class ScanPlaneModule {}
