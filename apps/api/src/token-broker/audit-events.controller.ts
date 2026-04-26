import { Controller, Get, Query } from "@nestjs/common";

import { TokenBrokerService } from "./token-broker.service";

@Controller("audit-events")
export class AuditEventsController {
  constructor(private readonly tokenBrokerService: TokenBrokerService) {}

  @Get()
  list(@Query("tenantId") tenantId: string) {
    return this.tokenBrokerService.listAuditEvents(tenantId);
  }
}
