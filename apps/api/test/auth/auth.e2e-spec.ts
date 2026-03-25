import { CanActivate, ExecutionContext, INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';

jest.setTimeout(15000);

class MockGithubAuthGuard implements CanActivate {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context
      .switchToHttp()
      .getRequest<
        Express.Request & {
          logIn: (
            user: unknown,
            callback: (error?: Error | null) => void
          ) => void;
        }
      >();

    await new Promise<void>((resolve, reject) => {
      request.logIn(
        {
          id: 'user-1',
          email: 'user@example.com',
          name: 'Aegis User',
          avatarUrl: 'https://example.com/avatar.png',
          connectedProviders: ['github']
        },
        (error?: Error | null) => {
          if (error) {
            reject(error);
            return;
          }

          resolve();
        }
      );
    });

    return true;
  }
}

describe('AuthController (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    process.env.NODE_ENV = 'test';
    process.env.PORT = '3000';
    process.env.DATABASE_URL = 'postgresql://postgres:postgres@localhost:5432/aegisai';
    process.env.REDIS_URL = 'redis://localhost:6379';
    process.env.SESSION_SECRET = 'test-session-secret-value';
    process.env.CSRF_SECRET = 'test-csrf-secret-value';
    process.env.GITHUB_CLIENT_ID = 'github-client-id';
    process.env.GITHUB_CLIENT_SECRET = 'github-client-secret';
    process.env.GITLAB_CLIENT_ID = 'gitlab-client-id';
    process.env.GITLAB_CLIENT_SECRET = 'gitlab-client-secret';
    process.env.APP_URL = 'http://localhost:3000';
    process.env.FRONTEND_URL = 'http://localhost:5173';
    process.env.SESSION_COOKIE_NAME = 'connect.sid';
    process.env.CSRF_COOKIE_NAME = 'csrf_token';
    process.env.COOKIE_DOMAIN = '';
    process.env.TOKEN_ENCRYPTION_KEY =
      '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    process.env.ANALYSIS_CLIENT_MODE = 'mock';
    process.env.AI_SERVER_URL = 'http://localhost:8000';
    process.env.USE_INTERNAL_AI = 'false';
    process.env.INTERNAL_API_SECRET = '';
    process.env.GITHUB_APP_WEBHOOK_SECRET = '';
    process.env.GITLAB_WEBHOOK_SECRET = '';
    process.env.REPORT_STORAGE_PATH = './tmp/reports';
    process.env.REPORT_EXPIRY_HOURS = '24';

    const [{ AppModule }, { configureApp }, { GithubAuthGuard }, { PrismaService }] =
      await Promise.all([
      import('../../src/app.module'),
      import('../../src/bootstrap/configure-app'),
      import('../../src/auth/guards/github-auth.guard'),
      import('../../src/prisma/prisma.service')
    ]);

    const moduleRef = await Test.createTestingModule({
      imports: [AppModule]
    })
      .overrideProvider(PrismaService)
      .useValue({
        user: {
          findUnique: jest.fn().mockResolvedValue({
            id: 'user-1',
            email: 'user@example.com',
            name: 'Aegis User',
            avatarUrl: 'https://example.com/avatar.png',
            oauthTokens: [{ provider: 'GITHUB' }]
          })
        }
      })
      .overrideGuard(GithubAuthGuard)
      .useClass(MockGithubAuthGuard)
      .compile();

    app = moduleRef.createNestApplication();
    await configureApp(app);
    await app.init();
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
  });

  it('returns the shared error envelope from GET /api/auth/me when no session is present', async () => {
    await request(app.getHttpServer())
      .get('/api/auth/me')
      .expect(401)
      .expect(({ body }) => {
        expect(body).toMatchObject({
          success: false,
          data: null,
          errorCode: 'UNAUTHORIZED'
        });
        expect(body.message).toEqual(expect.any(String));
        expect(body.timestamp).toEqual(expect.any(String));
      });
  });

  it('creates a session on github callback, returns the current user, and logs out with csrf', async () => {
    const agent = request.agent(app.getHttpServer());

    const callbackResponse = await agent.get('/api/auth/github/callback').expect(302);

    expect(callbackResponse.headers.location).toBe('http://localhost:5173/dashboard');
    expect(findCookie(callbackResponse.headers['set-cookie'], 'csrf_token')).toBeDefined();

    const meResponse = await agent.get('/api/auth/me').expect(200);
    const csrfToken = findCookie(meResponse.headers['set-cookie'], 'csrf_token');

    expect(meResponse.body).toMatchObject({
      success: true,
      data: {
        id: 'user-1',
        email: 'user@example.com',
        name: 'Aegis User',
        avatarUrl: 'https://example.com/avatar.png',
        connectedProviders: ['github']
      },
      message: null
    });
    expect(meResponse.body.timestamp).toEqual(expect.any(String));
    expect(csrfToken).toMatch(/[A-Fa-f0-9]{64}/);

    const logoutResponse = await agent
      .post('/api/auth/logout')
      .set('X-CSRF-Token', csrfToken ?? '')
      .expect(200);

    expect(logoutResponse.body).toBeNull();
    expect(findCookie(logoutResponse.headers['set-cookie'], 'connect.sid')).toBe('');
    expect(findCookie(logoutResponse.headers['set-cookie'], 'csrf_token')).toBe('');

    await agent.get('/api/auth/me').expect(401);
  });
});

function findCookie(
  setCookieHeader: string | string[] | undefined,
  cookieName: string
): string | undefined {
  const cookieValues = Array.isArray(setCookieHeader)
    ? setCookieHeader
    : setCookieHeader
      ? [setCookieHeader]
      : [];
  const cookie = cookieValues.find((value) => value.startsWith(`${cookieName}=`));

  if (!cookie) {
    return undefined;
  }

  const [value] = cookie.split(';');

  return value?.slice(cookieName.length + 1);
}
