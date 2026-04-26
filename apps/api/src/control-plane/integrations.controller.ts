import { Body, Controller, Delete, Get, Param, Post, Query } from "@nestjs/common";

import { ControlPlaneService } from "./control-plane.service";
import type { InstallIntegrationInput } from "./control-plane.types";

@Controller("integrations")
export class IntegrationsController {
  constructor(private readonly controlPlaneService: ControlPlaneService) {}

  @Post("github/install")
  installGithub(@Body() body: InstallIntegrationInput) {
    return this.controlPlaneService.installGithubAppIntegration(body);
  }

  @Post("gitlab/install")
  installGitlab(@Body() body: InstallIntegrationInput) {
    return this.controlPlaneService.installIntegration(body, {
      provider: "GITLAB",
      integrationType: "GITLAB_CLOUD_INTEGRATION"
    });
  }

  @Get()
  list(@Query("tenantId") tenantId: string) {
    return this.controlPlaneService.listIntegrations(tenantId);
  }

  @Delete(":integrationId")
  remove(@Param("integrationId") integrationId: string) {
    return this.controlPlaneService.removeIntegration(integrationId);
  }
}
