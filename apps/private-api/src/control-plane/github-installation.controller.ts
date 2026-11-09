import { Body, Controller, Post, Req, UseGuards } from "@nestjs/common";
import { Throttle } from "@nestjs/throttler";

import type { AuthenticatedRequest } from "../auth/auth.types";
import { SessionAuthGuard } from "../common/security/session-auth.guard";
import { LinkGithubInstallationDto } from "./github-installation.dto";
import { GithubInstallationService } from "./github-installation.service";

@Controller("integrations/github-app")
@UseGuards(SessionAuthGuard)
@Throttle({ default: { limit: 10, ttl: 60_000 } })
export class GithubInstallationController {
  constructor(private readonly installations: GithubInstallationService) {}

  @Post("install")
  link(@Req() request: AuthenticatedRequest, @Body() body: LinkGithubInstallationDto) {
    return this.installations.link(request.auth!, body);
  }
}
