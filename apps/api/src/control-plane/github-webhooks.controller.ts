import { Body, Controller, Headers, HttpCode, Post } from "@nestjs/common";

import { ControlPlaneService } from "./control-plane.service";
import type { GithubInstallationWebhookInput } from "./control-plane.types";

@Controller("webhooks/github")
export class GithubWebhooksController {
  constructor(private readonly controlPlaneService: ControlPlaneService) {}

  @Post()
  @HttpCode(202)
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
