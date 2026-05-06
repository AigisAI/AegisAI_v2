import { Module } from "@nestjs/common";

import { EvidenceController } from "./evidence.controller";
import { EvidenceExpiryTask } from "./evidence-expiry.task";
import { EvidenceObjectStorageService } from "./evidence-object-storage.service";
import { FindingsController } from "./findings.controller";
import { ScanPlaneController } from "./scan-plane.controller";
import { ScanPlaneService } from "./scan-plane.service";
import { ScannerSandboxAdapterService } from "./scanner-sandbox-adapter.service";
import { ConfigModule } from "../config/config.module";

@Module({
  imports: [ConfigModule],
  controllers: [ScanPlaneController, FindingsController, EvidenceController],
  providers: [
    ScanPlaneService,
    ScannerSandboxAdapterService,
    EvidenceObjectStorageService,
    EvidenceExpiryTask
  ]
})
export class ScanPlaneModule {}
