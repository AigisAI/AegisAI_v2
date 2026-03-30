import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import type { ExecutionContext } from '@nestjs/common';

import { ConfigService } from '../../config/config.service';
import { buildProviderCallbackUrl } from '../auth-runtime.util';

@Injectable()
export class GithubAuthGuard extends AuthGuard('github') {
  constructor(private readonly config: ConfigService) {
    super();
  }

  getAuthenticateOptions(context: ExecutionContext): Record<string, string> {
    const request = context.switchToHttp().getRequest();

    return {
      callbackURL: buildProviderCallbackUrl(request, this.config.get('APP_URL'), 'github')
    };
  }
}
