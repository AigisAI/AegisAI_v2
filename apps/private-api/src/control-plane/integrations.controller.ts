import { Body, Controller, Delete, Get, Param, Post, UseGuards } from "@nestjs/common";

import { CurrentTenant } from "../common/security/current-tenant.decorator";
import { SessionAuthGuard } from "../common/security/session-auth.guard";
import { PendingRuntimeGuard } from "../common/security/pending-runtime.guard";
import { InstallIntegrationDto, IntegrationIdParamDto } from "./control-plane.dto";
import { ControlPlaneService } from "./control-plane.service";

@Controller("integrations")
@UseGuards(SessionAuthGuard)
export class IntegrationsController {
  constructor(private readonly controlPlaneService: ControlPlaneService) {}

  @Post("github/install")
  @UseGuards(PendingRuntimeGuard)
  installGithub(@CurrentTenant() tenantId: string, @Body() body: InstallIntegrationDto) {
    return this.controlPlaneService.installIntegration({ ...body, tenantId }, {
      provider: "GITHUB",
      integrationType: "GITHUB_APP"
    });
  }

  @Post("gitlab/install")
  @UseGuards(PendingRuntimeGuard)
  installGitlab(@CurrentTenant() tenantId: string, @Body() body: InstallIntegrationDto) {
    return this.controlPlaneService.installIntegration({ ...body, tenantId }, {
      provider: "GITLAB",
      integrationType: "GITLAB_CLOUD_INTEGRATION"
    });
  }

  @Get()
  list(@CurrentTenant() tenantId: string) {
    return this.controlPlaneService.listIntegrations(tenantId);
  }

  @Delete(":integrationId")
  remove(@CurrentTenant() tenantId: string, @Param() params: IntegrationIdParamDto) {
    return this.controlPlaneService.removeIntegration(tenantId, params.integrationId);
  }
}
