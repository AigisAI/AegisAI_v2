import type { ExecutionContext } from '@nestjs/common';

import {
  deriveTenantBoundInternalCredential,
  InternalTenantServiceGuard,
  type InternalTenantRequest
} from '../../src/common/security/internal-tenant-service.guard';

describe('InternalTenantServiceGuard', () => {
  const secret = 'test-internal-secret-value-at-least-32-characters';

  it('authenticates and attaches only the tenant bound into the credential', () => {
    const tenantId = 'tenant-bound';
    const credential = deriveTenantBoundInternalCredential(
      secret,
      tenantId
    );
    const { context, request } = requestContext({
      authorization: `Bearer ${credential}`,
      'x-aegis-internal-tenant-id': tenantId
    });
    const guard = new InternalTenantServiceGuard({
      get: jest.fn().mockReturnValue(secret)
    } as never);

    expect(guard.canActivate(context)).toBe(true);
    expect(request.internalTenantId).toBe(tenantId);
  });

  it('rejects replaying one tenant credential under another tenant header', () => {
    const credential = deriveTenantBoundInternalCredential(
      secret,
      'tenant-a'
    );
    const { context, request } = requestContext({
      authorization: `Bearer ${credential}`,
      'x-aegis-internal-tenant-id': 'tenant-b'
    });
    const guard = new InternalTenantServiceGuard({
      get: jest.fn().mockReturnValue(secret)
    } as never);

    expect(() => guard.canActivate(context)).toThrow(
      'A valid tenant-bound internal service credential is required.'
    );
    expect(request.internalTenantId).toBeUndefined();
  });
});

function requestContext(headers: Record<string, string>) {
  const request = {
    header: (name: string) => headers[name.toLowerCase()]
  } as InternalTenantRequest;
  return {
    request,
    context: {
      switchToHttp: () => ({ getRequest: () => request })
    } as ExecutionContext
  };
}
