import type { AuthUser } from '@aegisai/shared';
import type { CanActivate, ExecutionContext } from '@nestjs/common';

type TestRequest = {
  body?: { tenantId?: unknown };
  query?: { tenantId?: unknown };
  headers?: Record<string, string | string[] | undefined>;
  user?: AuthUser;
};

export class TestSessionAuthGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<TestRequest>();
    const headerTenant = request.headers?.['x-test-tenant-id'];
    const tenantId = String(
      (Array.isArray(headerTenant) ? headerTenant[0] : headerTenant) ??
        request.body?.tenantId ??
        request.query?.tenantId ??
        'tenant_test'
    );

    request.user = {
      id: 'test-user',
      tenantId,
      email: 'test@example.com',
      name: 'Test User',
      avatarUrl: null,
      connectedProviders: ['github']
    };

    return true;
  }
}

export class TestInternalServiceGuard implements CanActivate {
  canActivate(): boolean {
    return true;
  }
}

export class TestGithubWebhookSignatureGuard implements CanActivate {
  canActivate(): boolean {
    return true;
  }
}
