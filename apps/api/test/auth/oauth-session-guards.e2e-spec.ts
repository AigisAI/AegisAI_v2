import type { ExecutionContext } from '@nestjs/common';

import { ConfigService } from '../../src/config/config.service';
import { GithubAuthGuard } from '../../src/auth/guards/github-auth.guard';
import { GitlabAuthGuard } from '../../src/auth/guards/gitlab-auth.guard';

type ParentAuthGuard = {
  canActivate: (context: ExecutionContext) => Promise<boolean>;
  logIn: (request: RequestWithLogin) => Promise<void>;
};

type RequestWithLogin = {
  user?: { id: string };
  logIn: (user: unknown, callback: (error?: Error | null) => void) => void;
};

describe('OAuth session guards', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  it.each([
    ['github', GithubAuthGuard],
    ['gitlab', GitlabAuthGuard]
  ])(
    'logs the authenticated %s user into the session after callback authentication',
    async (_provider, GuardClass) => {
      const guard = new GuardClass(createConfigService()) as GithubAuthGuard | GitlabAuthGuard;
      const request: RequestWithLogin = {
        logIn: jest.fn((_user, callback) => callback())
      };
      const context = createExecutionContext(request);
      const parentGuard = Object.getPrototypeOf(GuardClass.prototype) as ParentAuthGuard;

      const canActivateSpy = jest
        .spyOn(parentGuard, 'canActivate')
        .mockImplementation(async (innerContext: ExecutionContext) => {
          innerContext
            .switchToHttp()
            .getRequest<RequestWithLogin>().user = { id: 'user-1' };
          return true;
        });
      const logInSpy = jest
        .spyOn(parentGuard, 'logIn')
        .mockImplementation(async (innerRequest: RequestWithLogin) => {
          await new Promise<void>((resolve, reject) => {
            innerRequest.logIn(innerRequest.user, (error?: Error | null) => {
              if (error) {
                reject(error);
                return;
              }

              resolve();
            });
          });
        });

      await expect(guard.canActivate(context)).resolves.toBe(true);

      expect(canActivateSpy).toHaveBeenCalledWith(context);
      expect(logInSpy).toHaveBeenCalledWith(request);
      expect(request.logIn).toHaveBeenCalledWith({ id: 'user-1' }, expect.any(Function));
    }
  );
});

function createConfigService(): ConfigService {
  return {
    get: jest.fn().mockReturnValue('http://localhost:3000')
  } as unknown as ConfigService;
}

function createExecutionContext(request: RequestWithLogin): ExecutionContext {
  return {
    switchToHttp: () => ({
      getRequest: <T>() => request as T
    })
  } as ExecutionContext;
}
