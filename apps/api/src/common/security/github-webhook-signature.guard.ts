import { createHmac, timingSafeEqual } from 'node:crypto';

import {
  CanActivate,
  ExecutionContext,
  Injectable,
  ServiceUnavailableException,
  UnauthorizedException
} from '@nestjs/common';
import type { Request } from 'express';

import { ConfigService } from '../../config/config.service';

type RawBodyRequest = Request & { rawBody?: Buffer };

@Injectable()
export class GithubWebhookSignatureGuard implements CanActivate {
  constructor(private readonly config: ConfigService) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<RawBodyRequest>();
    const secret = this.config.get('GITHUB_APP_WEBHOOK_SECRET');

    if (!secret) {
      throw new ServiceUnavailableException({
        errorCode: 'GITHUB_WEBHOOK_NOT_CONFIGURED',
        message: 'GitHub webhook verification is not configured.'
      });
    }

    const signature = request.header('x-hub-signature-256') ?? '';
    const payload = request.rawBody ?? Buffer.from(JSON.stringify(request.body ?? {}));
    const expected = `sha256=${createHmac('sha256', secret).update(payload).digest('hex')}`;

    if (!this.safeEqual(signature, expected)) {
      throw new UnauthorizedException({
        errorCode: 'GITHUB_WEBHOOK_SIGNATURE_INVALID',
        message: 'GitHub webhook signature validation failed.'
      });
    }

    return true;
  }

  private safeEqual(actual: string, expected: string): boolean {
    const actualBuffer = Buffer.from(actual);
    const expectedBuffer = Buffer.from(expected);

    return (
      actualBuffer.length === expectedBuffer.length &&
      timingSafeEqual(actualBuffer, expectedBuffer)
    );
  }
}
