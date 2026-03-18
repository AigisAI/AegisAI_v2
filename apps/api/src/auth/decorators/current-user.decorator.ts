import type { AuthUser } from '@aegisai/shared';
import { createParamDecorator, type ExecutionContext } from '@nestjs/common';

type RequestWithUser = {
  user?: AuthUser;
};

export function getCurrentUserFromRequest(request: RequestWithUser): AuthUser | undefined {
  return request.user;
}

export const CurrentUser = createParamDecorator((_data: unknown, ctx: ExecutionContext) => {
  const request = ctx.switchToHttp().getRequest<RequestWithUser>();
  return getCurrentUserFromRequest(request);
});
