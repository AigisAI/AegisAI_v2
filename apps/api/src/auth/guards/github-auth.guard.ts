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

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const activated = await super.canActivate(context);
    const request = context.switchToHttp().getRequest<RequestWithSessionUser>();

    if (request.user) {
      await super.logIn(request);
    }

    return Boolean(activated);
  }

  getAuthenticateOptions(context: ExecutionContext): Record<string, string> {
    const request = context.switchToHttp().getRequest();

    return {
      callbackURL: buildProviderCallbackUrl(request, this.config.get('APP_URL'), 'github')
    };
  }
}

type RequestWithSessionUser = {
  user?: unknown;
  logIn: (user: unknown, callback: (error?: Error | null) => void) => void;
};
