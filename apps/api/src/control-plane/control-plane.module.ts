import { HttpModule } from "@nestjs/axios";
import { Module } from "@nestjs/common";

import { ConfigModule } from "../config/config.module";
import { ControlPlaneService } from "./control-plane.service";
import { GithubAppInstallationClient } from "./github-app-installation.client";
import { GithubAppInstallationStateService } from "./github-app-installation-state.service";
import { GithubWebhooksController } from "./github-webhooks.controller";
import { IntegrationsController } from "./integrations.controller";
import { RepositoryBindingsController } from "./repository-bindings.controller";
import { ScanRequestsController } from "./scan-requests.controller";

@Module({
  imports: [ConfigModule, HttpModule],
  controllers: [
    IntegrationsController,
    RepositoryBindingsController,
    ScanRequestsController,
    GithubWebhooksController
  ],
  providers: [
    ControlPlaneService,
    GithubAppInstallationClient,
    GithubAppInstallationStateService
  ],
  exports: [
    ControlPlaneService,
    GithubAppInstallationClient,
    GithubAppInstallationStateService
  ]
})
export class ControlPlaneModule {}
