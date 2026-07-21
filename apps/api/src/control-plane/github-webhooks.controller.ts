import { Body, Controller, Headers, HttpCode, Post, UseGuards } from '@nestjs/common';

import { GithubWebhookSignatureGuard } from '../common/security/github-webhook-signature.guard';
import { ControlPlaneService } from "./control-plane.service";
import type { GithubInstallationWebhookInput } from "./control-plane.types";

@Controller("webhooks/github")
export class GithubWebhooksController {
  constructor(private readonly controlPlaneService: ControlPlaneService) {}

  @Post()
  @HttpCode(202)
  @UseGuards(GithubWebhookSignatureGuard)
  reconcileInstallationRepositories(
    @Headers("x-github-event") githubEvent: string | undefined,
    @Body() body: GithubInstallationWebhookInput
  ) {
    return this.controlPlaneService.reconcileGithubInstallationWebhook(
      githubEvent ?? "unknown",
      body
    );
  }
}
