import { Module } from "@nestjs/common";

import { AuditEventsController } from "./audit-events.controller";
import { TokenBrokerController } from "./token-broker.controller";
import { TokenBrokerService } from "./token-broker.service";

@Module({
  controllers: [TokenBrokerController, AuditEventsController],
  providers: [TokenBrokerService]
})
export class TokenBrokerModule {}
