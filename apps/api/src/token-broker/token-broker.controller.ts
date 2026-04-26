import { Body, Controller, Post } from "@nestjs/common";
import type { TokenBrokerIssueRequest } from "../../../../packages/shared/src";

import { TokenBrokerService } from "./token-broker.service";

@Controller("token-broker")
export class TokenBrokerController {
  constructor(private readonly tokenBrokerService: TokenBrokerService) {}

  @Post("issue")
  issue(@Body() body: TokenBrokerIssueRequest) {
    return this.tokenBrokerService.issue(body);
  }
}
