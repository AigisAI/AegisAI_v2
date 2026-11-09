import { ForbiddenException, Injectable } from "@nestjs/common";
import type { LinkGithubInstallationRequest } from "@aegisai/shared";

import type { AuthenticatedPrincipal } from "../auth/auth.types";
import { PrismaService } from "../prisma/prisma.service";
import { ControlPlaneService } from "./control-plane.service";
import { GithubAppClient } from "./github-app.client";

@Injectable()
export class GithubInstallationService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly client: GithubAppClient,
    private readonly controlPlane: ControlPlaneService
  ) {}

  async link(principal: AuthenticatedPrincipal, input: LinkGithubInstallationRequest) {
    const tenant = await this.prisma.tenant.findFirst({
      where: { id: principal.tenantId, status: "ACTIVE" }, select: { id: true }
    });
    if (!tenant || principal.provider !== "GITHUB") throw new ForbiddenException("Active GitHub tenant required");
    const repositories = await this.client.discoverInstallation(
      input.installationId, input.repositoryIds, principal.providerUserId
    );
    return this.controlPlane.installIntegration({
      tenantId: principal.tenantId, externalInstallationId: String(input.installationId),
      repoReadPrincipalId: `github-app:${input.installationId}:contents-read`, repositories
    }, { provider: "GITHUB", integrationType: "GITHUB_APP" });
  }
}
