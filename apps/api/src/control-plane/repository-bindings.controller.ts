import { Controller, Get, Query } from "@nestjs/common";

import { ControlPlaneService } from "./control-plane.service";

@Controller("repository-bindings")
export class RepositoryBindingsController {
  constructor(private readonly controlPlaneService: ControlPlaneService) {}

  @Get()
  list(@Query("tenantId") tenantId: string) {
    return this.controlPlaneService.listRepositoryBindings(tenantId);
  }
}
