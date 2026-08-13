import {
  createParamDecorator,
  type ExecutionContext,
  UnauthorizedException
} from '@nestjs/common';

import type { InternalTenantRequest } from './internal-tenant-service.guard';

export const CurrentInternalTenant = createParamDecorator(
  (_data: unknown, context: ExecutionContext) => {
    const request = context
      .switchToHttp()
      .getRequest<InternalTenantRequest>();
    if (!request.internalTenantId) {
      throw new UnauthorizedException({
        errorCode: 'INTERNAL_TENANT_CONTEXT_REQUIRED',
        message: 'An authenticated internal tenant context is required.'
      });
    }
    return request.internalTenantId;
  }
);
