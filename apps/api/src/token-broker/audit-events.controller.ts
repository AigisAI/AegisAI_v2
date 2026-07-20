import { Controller, Get, UseGuards } from '@nestjs/common';

import { CurrentTenant } from '../auth/decorators/current-tenant.decorator';
import { SessionAuthGuard } from '../auth/guards/session-auth.guard';
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
