import { CanActivate, ExecutionContext, ForbiddenException, Injectable, UnauthorizedException } from "@nestjs/common";

import type { AuthenticatedRequest } from "../../auth/auth.types";
import { ConfigService } from "../../config/config.service";
@Injectable()
export class SessionAuthGuard implements CanActivate {
  constructor(private readonly config: ConfigService) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    const principal = request.session?.auth;

    if (!principal) {
      throw new UnauthorizedException({
        errorCode: "AUTHENTICATION_REQUIRED",
        message: "Authentication is required."
      });
    }

    if (!this.config.isGithubIdentityAllowed(principal.providerUserId)) {
      throw new ForbiddenException({
        errorCode: "DEPLOYMENT_ACCOUNT_NOT_ALLOWED",
        message: "This private deployment does not admit this GitHub account."
      });
    }

    request.auth = principal;
    return true;
  }
}
