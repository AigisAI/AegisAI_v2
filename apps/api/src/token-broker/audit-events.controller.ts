import { Controller, Get, UseGuards } from "@nestjs/common";

import { CurrentTenant } from "../common/security/current-tenant.decorator";
import { SessionAuthGuard } from "../common/security/session-auth.guard";
import { TokenBrokerService } from "./token-broker.service";

@Controller("audit-events")
@UseGuards(SessionAuthGuard)
export class AuditEventsController {
  constructor(private readonly tokenBrokerService: TokenBrokerService) {}

  @Get()
  list(@CurrentTenant() tenantId: string) {
    return this.tokenBrokerService.listAuditEvents(tenantId);
  }
}
