import type { AuthUser } from '@aegisai/shared';
import { createParamDecorator, type ExecutionContext, UnauthorizedException } from '@nestjs/common';

type RequestWithUser = {
  user?: AuthUser;
};

export const CurrentTenant = createParamDecorator((_data: unknown, context: ExecutionContext) => {
  const request = context.switchToHttp().getRequest<RequestWithUser>();
  const tenantId = request.user?.tenantId;

  if (!tenantId) {
    throw new UnauthorizedException({
      errorCode: 'TENANT_CONTEXT_REQUIRED',
      message: 'An authenticated tenant context is required.'
    });
  }

  return tenantId;
});
