import type { AuthUser } from '@aegisai/shared';
import type { CanActivate, ExecutionContext, INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { createHmac } from 'node:crypto';
import request from 'supertest';

import { SessionAuthGuard } from '../../src/auth/guards/session-auth.guard';
import { csrfProtectionMiddleware, generateCsrfToken } from '../../src/common/security/csrf';
import { GithubWebhookSignatureGuard } from '../../src/common/security/github-webhook-signature.guard';
import { InternalServiceGuard } from '../../src/common/security/internal-service.guard';
import { IntegrationsController } from '../../src/control-plane/integrations.controller';
import { ControlPlaneService } from '../../src/control-plane/control-plane.service';

describe('production architecture security boundaries', () => {
  it('accepts only the configured internal bearer credential', () => {
    const guard = new InternalServiceGuard({
      get: jest.fn().mockReturnValue('internal-secret-at-least-32-characters')
    } as never);

    expect(
      guard.canActivate(
        contextWithRequest({
          header: (name: string) =>
            name === 'authorization'
              ? 'Bearer internal-secret-at-least-32-characters'
              : undefined
        })
      )
    ).toBe(true);
    expect(() =>
      guard.canActivate(contextWithRequest({ header: () => 'Bearer wrong-secret' }))
    ).toThrow('A valid internal service credential is required.');
  });

  it('verifies the GitHub webhook HMAC against the raw request body', () => {
    const secret = 'github-webhook-secret-at-least-32-characters';
    const rawBody = Buffer.from('{"installation":{"id":123}}');
    const signature = `sha256=${createHmac('sha256', secret).update(rawBody).digest('hex')}`;
    const guard = new GithubWebhookSignatureGuard({
      get: jest.fn().mockReturnValue(secret)
    } as never);

    expect(
      guard.canActivate(
        contextWithRequest({
          rawBody,
          body: { installation: { id: 123 } },
          header: (name: string) => (name === 'x-hub-signature-256' ? signature : undefined)
        })
      )
    ).toBe(true);
    expect(() =>
      guard.canActivate(
        contextWithRequest({ rawBody, body: {}, header: () => 'sha256=invalid' })
      )
    ).toThrow('GitHub webhook signature validation failed.');
  });

  it('binds CSRF tokens to one server-side session', () => {
    const firstSession: Record<string, unknown> = {};
    const secondSession: Record<string, unknown> = {};
    const token = generateCsrfToken({ session: firstSession } as never);
    const accepted = jest.fn();
    const rejected = jest.fn();

    csrfProtectionMiddleware(
      {
        method: 'POST',
        session: firstSession,
        headers: { 'x-csrf-token': token }
      } as never,
      {} as never,
      accepted
    );
    csrfProtectionMiddleware(
      {
        method: 'POST',
        session: secondSession,
        headers: { 'x-csrf-token': token }
      } as never,
      {} as never,
      rejected
    );

    expect(accepted).toHaveBeenCalledWith();
    expect(rejected).toHaveBeenCalledWith(expect.objectContaining({ status: 403 }));
  });
});

describe('session tenant authority', () => {
  let app: INestApplication;
  const installGithubAppIntegration = jest.fn((input: unknown) => input);

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      controllers: [IntegrationsController],
      providers: [
        {
          provide: ControlPlaneService,
          useValue: {
            installGithubAppIntegration,
            installGitlabCloudIntegration: jest.fn(),
            listIntegrations: jest.fn(),
            removeIntegration: jest.fn()
          }
        }
      ]
    })
      .overrideGuard(SessionAuthGuard)
      .useClass(FixedTenantSessionGuard)
      .compile();

    app = moduleRef.createNestApplication();
    app.setGlobalPrefix('api');
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  it('ignores a client-supplied tenant id in favor of the authenticated session tenant', async () => {
    const response = await request(app.getHttpServer())
      .post('/api/integrations/github/install')
      .send({
        tenantId: 'attacker-tenant',
        externalInstallationId: 'installation-1',
        repoReadPrincipalId: 'repo-read-1',
        repositories: []
      })
      .expect(201);

    expect(response.body.tenantId).toBe('session-tenant');
    expect(installGithubAppIntegration).toHaveBeenCalledWith(
      expect.objectContaining({ tenantId: 'session-tenant' })
    );
  });
});

class FixedTenantSessionGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<{ user?: AuthUser }>();
    request.user = {
      id: 'user-1',
      tenantId: 'session-tenant',
      email: 'user@example.com',
      name: 'Session User',
      avatarUrl: null,
      connectedProviders: ['github']
    };
    return true;
  }
}

function contextWithRequest(request: unknown): ExecutionContext {
  return {
    switchToHttp: () => ({ getRequest: () => request })
  } as never;
}
