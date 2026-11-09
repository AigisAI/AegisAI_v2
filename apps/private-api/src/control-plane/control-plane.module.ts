import { Module } from "@nestjs/common";

import { ControlPlaneService } from "./control-plane.service";
import { IntegrationsController } from "./integrations.controller";
import { RepositoryBindingsController } from "./repository-bindings.controller";
import { ScanRequestsController } from "./scan-requests.controller";
import { GithubAppClient } from "./github-app.client";
import { GithubInstallationController } from "./github-installation.controller";
import { GithubInstallationService } from "./github-installation.service";
import { RuntimeController } from "../runtime/runtime.controller";
import { RuntimeApiService } from "../runtime/runtime-api.service";
import { RuntimeCatalogService } from "../runtime/runtime-catalog.service";
import { EvidenceAccessService } from "../data-security/evidence-access.service";

@Module({
  controllers: [IntegrationsController, RepositoryBindingsController, ScanRequestsController, GithubInstallationController, RuntimeController],
  providers: [ControlPlaneService, GithubAppClient, GithubInstallationService, RuntimeApiService, RuntimeCatalogService, EvidenceAccessService],
  exports: [ControlPlaneService]
})
export class ControlPlaneModule {}
