import { Module } from "@nestjs/common";

import { AuditEventsController } from "./audit-events.controller";
import { TokenCredentialIssuerService } from "./token-credential-issuer.service";
import { TokenBrokerController } from "./token-broker.controller";
import { TokenBrokerService } from "./token-broker.service";

@Module({
  controllers: [TokenBrokerController, AuditEventsController],
  providers: [TokenBrokerService, TokenCredentialIssuerService]
})
export class TokenBrokerModule {}
