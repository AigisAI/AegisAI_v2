import type { AuthUser } from '@aegisai/shared';
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy as GitHubPassportStrategy } from 'passport-github2';

import { ConfigService } from '../../config/config.service';
import { AuthService } from '../auth.service';
import type { GithubOAuthProfile } from '../oauth-profile.types';

@Injectable()
export class GithubStrategy extends PassportStrategy(GitHubPassportStrategy, 'github') {
  constructor(
    private readonly config: ConfigService,
    private readonly authService: AuthService
  ) {
    super(
      {
        clientID: config.get('GITHUB_CLIENT_ID'),
        clientSecret: config.get('GITHUB_CLIENT_SECRET'),
        callbackURL: new URL('/api/auth/github/callback', config.get('APP_URL')).toString(),
        scope: ['read:user', 'user:email', 'repo'],
        state: true,
        userAgent: new URL(config.get('APP_URL')).host
      } as never
    );
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: GithubOAuthProfile
  ): Promise<AuthUser> {
    return this.authService.findOrCreateUser('github', profile, accessToken, refreshToken);
  }
}
