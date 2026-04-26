import { HttpModule } from "@nestjs/axios";
import { Module } from "@nestjs/common";

import { ConfigModule } from "../config/config.module";
import { ControlPlaneService } from "./control-plane.service";
import { GithubAppInstallationClient } from "./github-app-installation.client";
import { IntegrationsController } from "./integrations.controller";
import { RepositoryBindingsController } from "./repository-bindings.controller";
import { ScanRequestsController } from "./scan-requests.controller";

@Module({
  imports: [ConfigModule, HttpModule],
  controllers: [IntegrationsController, RepositoryBindingsController, ScanRequestsController],
  providers: [ControlPlaneService, GithubAppInstallationClient],
  exports: [ControlPlaneService, GithubAppInstallationClient]
})
export class ControlPlaneModule {}
