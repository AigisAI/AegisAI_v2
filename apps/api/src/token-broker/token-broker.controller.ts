import { Body, Controller, Post, UseGuards } from '@nestjs/common';

import { InternalServiceGuard } from '../common/security/internal-service.guard';
import { TokenBrokerService } from "./token-broker.service";
import { TokenBrokerIssueDto } from './token-broker.dto';

@Controller("token-broker")
export class TokenBrokerController {
  constructor(private readonly tokenBrokerService: TokenBrokerService) {}

  @Post("issue")
  @UseGuards(InternalServiceGuard)
  issue(@Body() body: TokenBrokerIssueDto) {
    return this.tokenBrokerService.issue(body);
  }
}
