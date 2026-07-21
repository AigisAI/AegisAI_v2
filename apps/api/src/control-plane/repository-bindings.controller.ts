import { Controller, Get, UseGuards } from '@nestjs/common';

import { CurrentTenant } from '../auth/decorators/current-tenant.decorator';
import { SessionAuthGuard } from '../auth/guards/session-auth.guard';
import { ControlPlaneService } from "./control-plane.service";

@Controller("repository-bindings")
@UseGuards(SessionAuthGuard)
export class RepositoryBindingsController {
  constructor(private readonly controlPlaneService: ControlPlaneService) {}

  @Get()
  list(@CurrentTenant() tenantId: string) {
    return this.controlPlaneService.listRepositoryBindings(tenantId);
  }
}
