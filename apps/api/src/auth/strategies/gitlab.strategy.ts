import type { AuthUser } from '@aegisai/shared';
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';

import { ConfigService } from '../../config/config.service';
import { AuthService } from '../auth.service';
import type { GitlabOAuthProfile } from '../oauth-profile.types';

// eslint-disable-next-line @typescript-eslint/no-require-imports
const GitLabPassportStrategy = require('passport-gitlab2');

@Injectable()
export class GitlabStrategy extends PassportStrategy(GitLabPassportStrategy, 'gitlab') {
  constructor(
    private readonly config: ConfigService,
    private readonly authService: AuthService
  ) {
    super({
      clientID: config.get('GITLAB_CLIENT_ID'),
      clientSecret: config.get('GITLAB_CLIENT_SECRET'),
      callbackURL: new URL('/api/auth/gitlab/callback', config.get('APP_URL')).toString(),
      scope: ['read_user', 'read_api'],
      state: true
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string | undefined,
    profile: GitlabOAuthProfile
  ): Promise<AuthUser> {
    return this.authService.findOrCreateUser('gitlab', profile, accessToken, refreshToken);
  }
}
