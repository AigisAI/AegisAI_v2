import { Body, Controller, Post, UseGuards } from "@nestjs/common";

import { InternalServiceGuard } from "../common/security/internal-service.guard";
import { PendingRuntimeGuard } from "../common/security/pending-runtime.guard";
import { TokenBrokerIssueDto } from "./token-broker.dto";
import { TokenBrokerService } from "./token-broker.service";

@Controller("token-broker")
@UseGuards(InternalServiceGuard)
export class TokenBrokerController {
  constructor(private readonly tokenBrokerService: TokenBrokerService) {}

  @Post("issue")
  @UseGuards(PendingRuntimeGuard)
  issue(@Body() body: TokenBrokerIssueDto) {
    return this.tokenBrokerService.issue(body);
  }
}
