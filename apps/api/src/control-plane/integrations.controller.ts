import { Body, Controller, Delete, Get, Param, Post, UseGuards } from '@nestjs/common';

import { CurrentTenant } from '../auth/decorators/current-tenant.decorator';
import { SessionAuthGuard } from '../auth/guards/session-auth.guard';
import { InstallIntegrationDto } from './control-plane.dto';
import { ControlPlaneService } from "./control-plane.service";

@Controller("integrations")
@UseGuards(SessionAuthGuard)
export class IntegrationsController {
  constructor(private readonly controlPlaneService: ControlPlaneService) {}

  @Post("github/install")
  installGithub(@CurrentTenant() tenantId: string, @Body() body: InstallIntegrationDto) {
    return this.controlPlaneService.installGithubAppIntegration({ ...body, tenantId });
  }

  @Post("gitlab/install")
  installGitlab(@CurrentTenant() tenantId: string, @Body() body: InstallIntegrationDto) {
    return this.controlPlaneService.installGitlabCloudIntegration({ ...body, tenantId });
  }

  @Get()
  list(@CurrentTenant() tenantId: string) {
    return this.controlPlaneService.listIntegrations(tenantId);
  }

  @Delete(":integrationId")
  remove(@CurrentTenant() tenantId: string, @Param("integrationId") integrationId: string) {
    return this.controlPlaneService.removeIntegration(tenantId, integrationId);
  }
}
