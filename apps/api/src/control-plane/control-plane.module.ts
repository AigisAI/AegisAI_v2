import { Module } from "@nestjs/common";

import { ControlPlaneService } from "./control-plane.service";
import { IntegrationsController } from "./integrations.controller";
import { RepositoryBindingsController } from "./repository-bindings.controller";
import { ScanRequestsController } from "./scan-requests.controller";

@Module({
  controllers: [IntegrationsController, RepositoryBindingsController, ScanRequestsController],
  providers: [ControlPlaneService]
})
export class ControlPlaneModule {}
