import { createParamDecorator, ExecutionContext, UnauthorizedException } from "@nestjs/common";

import type { AuthenticatedRequest } from "../../auth/auth.types";

export const CurrentTenant = createParamDecorator((_data: unknown, context: ExecutionContext) => {
  const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
  const tenantId = request.auth?.tenantId;

  if (!tenantId) {
    throw new UnauthorizedException({
      errorCode: "TENANT_CONTEXT_REQUIRED",
      message: "An authenticated tenant context is required."
    });
  }

  return tenantId;
});
