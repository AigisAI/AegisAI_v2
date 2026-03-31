import type { AuthMeResponse, AuthUser } from '@aegisai/shared';
import {
  Controller,
  Get,
  HttpCode,
  Post,
  Req,
  Res,
  UseGuards
} from '@nestjs/common';
import type { Request, Response } from 'express';
import type session from 'express-session';

import { ConfigService } from '../config/config.service';
import { CurrentUser } from './decorators/current-user.decorator';
import { AuthService } from './auth.service';
import { buildFrontendRedirectUrl, shouldUseSecureCookies } from './auth-runtime.util';
import { GithubAuthGuard } from './guards/github-auth.guard';
import { GitlabAuthGuard } from './guards/gitlab-auth.guard';
import { SessionAuthGuard } from './guards/session-auth.guard';

type RequestWithSession = Request & {
  session?: session.Session & Partial<session.SessionData>;
  logout?: (callback: (error?: Error | null) => void) => void;
};

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly config: ConfigService
  ) {}

  @Get('github')
  @UseGuards(GithubAuthGuard)
  githubLogin(): void {}

  @Get('github/callback')
  @UseGuards(GithubAuthGuard)
  githubCallback(@Req() request: Request, @Res() response: Response): void {
    this.issueCsrfCookie(request, response);
    response.redirect(buildFrontendRedirectUrl(request, this.config.get('FRONTEND_URL'), '/dashboard'));
  }

  @Get('gitlab')
  @UseGuards(GitlabAuthGuard)
  gitlabLogin(): void {}

  @Get('gitlab/callback')
  @UseGuards(GitlabAuthGuard)
  gitlabCallback(@Req() request: Request, @Res() response: Response): void {
    this.issueCsrfCookie(request, response);
    response.redirect(buildFrontendRedirectUrl(request, this.config.get('FRONTEND_URL'), '/dashboard'));
  }

  @Get('me')
  @UseGuards(SessionAuthGuard)
  getMe(
    @Req() request: Request,
    @CurrentUser() user: AuthUser,
    @Res({ passthrough: true }) response: Response
  ): AuthMeResponse {
    this.issueCsrfCookie(request, response);
    return user;
  }

  @Post('logout')
  @HttpCode(200)
  @UseGuards(SessionAuthGuard)
  async logout(
    @Req() request: RequestWithSession,
    @Res() response: Response
  ): Promise<void> {
    await this.logoutRequest(request);

    response.clearCookie(this.config.get('SESSION_COOKIE_NAME'), {
      httpOnly: true,
      sameSite: 'lax',
      secure: shouldUseSecureCookies(request, this.config.get('APP_URL')),
      domain: this.config.getOptional('COOKIE_DOMAIN') || undefined
    });
    response.clearCookie(this.config.get('CSRF_COOKIE_NAME'), {
      httpOnly: false,
      sameSite: 'lax',
      secure: shouldUseSecureCookies(request, this.config.get('APP_URL')),
      domain: this.config.getOptional('COOKIE_DOMAIN') || undefined
    });

    response.status(200).json(null);
  }

  private issueCsrfCookie(request: Request, response: Response): void {
    response.cookie(this.config.get('CSRF_COOKIE_NAME'), this.authService.createCsrfToken(), {
      httpOnly: false,
      sameSite: 'lax',
      secure: shouldUseSecureCookies(request, this.config.get('APP_URL')),
      domain: this.config.getOptional('COOKIE_DOMAIN') || undefined
    });
  }

  private async logoutRequest(request: RequestWithSession): Promise<void> {
    if (typeof request.logout === 'function') {
      await new Promise<void>((resolve, reject) => {
        request.logout?.((error?: Error | null) => {
          if (error) {
            reject(error);
            return;
          }

          resolve();
        });
      });
    }

    if (request.session) {
      await new Promise<void>((resolve, reject) => {
        request.session?.destroy((error) => {
          if (error) {
            reject(error);
            return;
          }

          resolve();
        });
      });
    }
  }
}
