import { ForbiddenException, UnauthorizedException, type ExecutionContext } from '@nestjs/common';

import { SessionAuthGuard } from '../../src/auth/guards/session-auth.guard';

function createHttpContext(request: Record<string, unknown>): ExecutionContext {
  return {
    switchToHttp: () => ({
      getRequest: () => request,
      getResponse: () => undefined,
      getNext: () => undefined
    })
  } as ExecutionContext;
}

describe('SessionAuthGuard', () => {
  const guard = new SessionAuthGuard({
    get: (key: string) => {
      if (key === 'CSRF_COOKIE_NAME') {
        return 'csrf_token';
      }

      throw new Error(`Unexpected key: ${key}`);
    }
  } as never);

  it('rejects unauthenticated requests', async () => {
    const context = createHttpContext({
      method: 'GET',
      isAuthenticated: () => false,
      cookies: {},
      headers: {}
    });

    await expect(guard.canActivate(context)).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('allows authenticated safe requests without csrf validation', async () => {
    const context = createHttpContext({
      method: 'GET',
      isAuthenticated: () => true,
      cookies: {},
      headers: {}
    });

    await expect(guard.canActivate(context)).resolves.toBe(true);
  });

  it('rejects mutating requests when csrf data is missing', async () => {
    const context = createHttpContext({
      method: 'POST',
      isAuthenticated: () => true,
      cookies: {},
      headers: {}
    });

    await expect(guard.canActivate(context)).rejects.toBeInstanceOf(ForbiddenException);
  });

  it('rejects mutating requests when csrf values differ', async () => {
    const context = createHttpContext({
      method: 'PATCH',
      isAuthenticated: () => true,
      cookies: { csrf_token: 'cookie-token' },
      headers: { 'x-csrf-token': 'header-token' }
    });

    try {
      await guard.canActivate(context);
      fail('Expected guard to reject mismatched CSRF values');
    } catch (error) {
      expect(error).toBeInstanceOf(ForbiddenException);
      expect((error as ForbiddenException).getResponse()).toMatchObject({
        message: 'CSRF 검증에 실패했습니다.',
        errorCode: 'CSRF_TOKEN_INVALID'
      });
    }
  });

  it('allows authenticated mutating requests when csrf values match', async () => {
    const context = createHttpContext({
      method: 'DELETE',
      isAuthenticated: () => true,
      cookies: { csrf_token: 'same-token' },
      headers: { 'x-csrf-token': 'same-token' }
    });

    await expect(guard.canActivate(context)).resolves.toBe(true);
  });
});
