import { CanActivate, ExecutionContext, ForbiddenException, Injectable, UnauthorizedException } from '@nestjs/common';

import { ConfigService } from '../../config/config.service';

type RequestWithSession = {
  method?: string;
  cookies?: Record<string, string | undefined>;
  headers?: Record<string, string | string[] | undefined>;
  isAuthenticated?: () => boolean;
  user?: unknown;
};

@Injectable()
export class SessionAuthGuard implements CanActivate {
  constructor(private readonly config: ConfigService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<RequestWithSession>();

    if (!this.isAuthenticated(request)) {
      throw new UnauthorizedException({ message: '인증이 필요합니다.', errorCode: 'UNAUTHORIZED' });
    }

    if (this.isSafeMethod(request.method)) {
      return true;
    }

    const csrfCookieName = this.config.get('CSRF_COOKIE_NAME');
    const csrfCookie = request.cookies?.[csrfCookieName];
    const csrfHeader = this.getHeaderValue(request.headers?.['x-csrf-token']);

    if (!csrfCookie || !csrfHeader || csrfCookie !== csrfHeader) {
      throw new ForbiddenException({
        message: 'CSRF 검증에 실패했습니다.',
        errorCode: 'CSRF_TOKEN_INVALID'
      });
    }

    return true;
  }

  private isAuthenticated(request: RequestWithSession): boolean {
    if (typeof request.isAuthenticated === 'function') {
      return request.isAuthenticated();
    }

    return request.user !== undefined;
  }

  private isSafeMethod(method?: string): boolean {
    return ['GET', 'HEAD', 'OPTIONS'].includes((method ?? 'GET').toUpperCase());
  }

  private getHeaderValue(value: string | string[] | undefined): string | undefined {
    if (Array.isArray(value)) {
      return value[0];
    }

    return value;
  }
}
