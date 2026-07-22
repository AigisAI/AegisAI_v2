import { HttpModule } from "@nestjs/axios";
import { Module } from "@nestjs/common";

import { CommentDispatchesController } from "./comment-dispatches.controller";
import { ConfigModule } from "../config/config.module";
import { ControlPlaneService } from "./control-plane.service";
import { GithubAppInstallationClient } from "./github-app-installation.client";
import { GithubAppInstallationStateService } from "./github-app-installation-state.service";
import { GithubWebhooksController } from "./github-webhooks.controller";
import { GitlabCloudIntegrationClient } from "./gitlab-cloud-integration.client";
import { IntegrationsController } from "./integrations.controller";
import { RepositoryBindingsController } from "./repository-bindings.controller";
import { ScanRequestsController } from "./scan-requests.controller";
import { SastQueueAdmissionService } from './sast-queue-admission.service';
import { SastScanPlannerService } from './sast-scan-planner.service';

@Module({
  imports: [ConfigModule, HttpModule],
  controllers: [
    IntegrationsController,
    RepositoryBindingsController,
    ScanRequestsController,
    GithubWebhooksController,
    CommentDispatchesController
  ],
  providers: [
    ControlPlaneService,
    SastQueueAdmissionService,
    SastScanPlannerService,
    GithubAppInstallationClient,
    GithubAppInstallationStateService,
    GitlabCloudIntegrationClient
  ],
  exports: [
    ControlPlaneService,
    SastQueueAdmissionService,
    SastScanPlannerService,
    GithubAppInstallationClient,
    GithubAppInstallationStateService,
    GitlabCloudIntegrationClient
  ]
})
export class ControlPlaneModule {}
