import { Controller, Get, Post, Query, Req, Res } from "@nestjs/common";
import { Throttle } from "@nestjs/throttler";
import type { Request, Response } from "express";

import { generateCsrfToken, revokeCsrfToken } from "../common/security/csrf";
import { ConfigService } from "../config/config.service";
import { AuthService } from "./auth.service";
import { GithubCallbackQueryDto } from "./github-callback-query.dto";

function saveSession(request: Request): Promise<void> {
  return new Promise((resolve, reject) => {
    request.session.save((error) => (error ? reject(error) : resolve()));
  });
}

function regenerateSession(request: Request): Promise<void> {
  return new Promise((resolve, reject) => {
    request.session.regenerate((error) => (error ? reject(error) : resolve()));
  });
}

@Controller("auth")
@Throttle({ default: { limit: 20, ttl: 60_000 } })
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly config: ConfigService
  ) {}

  @Get("github")
  async beginGithub(@Req() request: Request, @Res() response: Response): Promise<void> {
    const authorizationUrl = this.authService.beginGithubAuthentication(request.session);
    await saveSession(request);
    response.redirect(302, authorizationUrl);
  }

  @Get("github/callback")
  async completeGithub(
    @Query() query: GithubCallbackQueryDto,
    @Req() request: Request,
    @Res() response: Response
  ): Promise<void> {
    const principal = await this.authService.completeGithubAuthentication(
      request.session,
      query.code,
      query.state
    );

    await regenerateSession(request);
    request.session.auth = principal;
    await saveSession(request);
    response.redirect(302, this.authService.frontendUrl());
  }

  @Get("me")
  getSession(@Req() request: Request) {
    const candidate = request.session.auth;
    const principal = candidate && this.config.isGithubIdentityAllowed(candidate.providerUserId) ? candidate : undefined;
    if (candidate && !principal) delete request.session.auth;
    const csrfToken = generateCsrfToken(request);

    return {
      authenticated: Boolean(principal),
      csrfToken,
      user: principal
        ? {
            id: principal.userId,
            email: principal.email,
            name: principal.name,
            avatarUrl: principal.avatarUrl
          }
        : null
    };
  }

  @Post("logout")
  async logout(@Req() request: Request, @Res() response: Response): Promise<void> {
    revokeCsrfToken(request);
    await new Promise<void>((resolve, reject) => {
      request.session.destroy((error) => (error ? reject(error) : resolve()));
    });
    response.clearCookie(this.config.get("SESSION_COOKIE_NAME"), {
      domain: this.config.getOptional("COOKIE_DOMAIN") || undefined,
      httpOnly: true,
      sameSite: "lax",
      secure: this.config.get("COOKIE_SECURE") === "true"
    });
    response.status(204).send();
  }
}
