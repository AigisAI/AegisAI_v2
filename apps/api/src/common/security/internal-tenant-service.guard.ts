import { createHmac, timingSafeEqual } from 'node:crypto';

import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException
} from '@nestjs/common';
import type { Request } from 'express';

import { ConfigService } from '../../config/config.service';

const TENANT_HEADER = 'x-aegis-internal-tenant-id';
const CREDENTIAL_CONTEXT = 'aegis-internal-tenant-credential-v1';

export interface InternalTenantRequest extends Request {
  internalTenantId?: string;
}

@Injectable()
export class InternalTenantServiceGuard implements CanActivate {
  constructor(private readonly config: ConfigService) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context
      .switchToHttp()
      .getRequest<InternalTenantRequest>();
    const tenantId = request.header(TENANT_HEADER) ?? '';
    const authorization = request.header('authorization');
    const token = authorization?.startsWith('Bearer ')
      ? authorization.slice(7)
      : '';
    const secret = this.config.get('INTERNAL_API_SECRET');
    const expected = deriveTenantBoundInternalCredential(
      secret,
      tenantId
    );

    if (!expected || !safeEqual(token, expected)) {
      throw new UnauthorizedException({
        errorCode: 'INTERNAL_TENANT_AUTHENTICATION_REQUIRED',
        message:
          'A valid tenant-bound internal service credential is required.'
      });
    }

    request.internalTenantId = tenantId;
    return true;
  }
}

export function deriveTenantBoundInternalCredential(
  secret: string,
  tenantId: string
): string | null {
  if (
    secret.length === 0 ||
    !isBoundedTenantId(tenantId)
  ) {
    return null;
  }
  const mac = createHmac('sha256', secret)
    .update(CREDENTIAL_CONTEXT, 'utf8')
    .update('\0', 'utf8')
    .update(tenantId, 'utf8')
    .digest('hex');
  return `v1.${mac}`;
}

function isBoundedTenantId(value: string): boolean {
  return value.length > 0 &&
    value.trim() === value &&
    !hasAsciiControl(value) &&
    new TextEncoder().encode(value).length <= 512;
}

function hasAsciiControl(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function safeEqual(actual: string, expected: string): boolean {
  const actualBuffer = Buffer.from(actual);
  const expectedBuffer = Buffer.from(expected);
  return actualBuffer.length === expectedBuffer.length &&
    timingSafeEqual(actualBuffer, expectedBuffer);
}
