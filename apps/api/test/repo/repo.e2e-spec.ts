import type { AuthUser } from '@aegisai/shared';
import {
  CanActivate,
  ExecutionContext,
  INestApplication
} from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';

class MockSessionAuthGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<{ user?: AuthUser }>();

    request.user = {
      id: 'user-1',
      email: 'user@example.com',
      name: 'Aegis User',
      avatarUrl: null,
      connectedProviders: ['github', 'gitlab']
    };

    return true;
  }
}

describe('RepoController (e2e)', () => {
  let app: INestApplication;
  const repoService = {
    listConnectedRepos: jest.fn(),
    listAvailableRepos: jest.fn(),
    connectRepo: jest.fn(),
    disconnectRepo: jest.fn(),
    listBranches: jest.fn()
  };

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

    const [{ AppModule }, { configureApp }, { PrismaService }, { SessionAuthGuard }, { RepoService }] =
      await Promise.all([
        import('../../src/app.module'),
        import('../../src/bootstrap/configure-app'),
        import('../../src/prisma/prisma.service'),
        import('../../src/auth/guards/session-auth.guard'),
        import('../../src/repo/repo.service')
      ]);

    const moduleRef = await Test.createTestingModule({
      imports: [AppModule]
    })
      .overrideProvider(PrismaService)
      .useValue({
        $connect: jest.fn().mockResolvedValue(undefined),
        $disconnect: jest.fn().mockResolvedValue(undefined),
        onModuleInit: jest.fn().mockResolvedValue(undefined),
        onModuleDestroy: jest.fn().mockResolvedValue(undefined),
        $queryRawUnsafe: jest.fn().mockResolvedValue([{ result: 1 }])
      })
      .overrideGuard(SessionAuthGuard)
      .useClass(MockSessionAuthGuard)
      .overrideProvider(RepoService)
      .useValue(repoService)
      .compile();

    app = moduleRef.createNestApplication();
    await configureApp(app);
    await app.init();
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
  });

  it('returns wrapped connected repositories from GET /api/repos', async () => {
    repoService.listConnectedRepos.mockResolvedValue([
      {
        id: 'repo-1',
        provider: 'github',
        fullName: 'acme/service',
        cloneUrl: 'https://github.com/acme/service.git',
        defaultBranch: 'main',
        isPrivate: true,
        lastScanAt: null,
        lastScanStatus: null
      }
    ]);

    await request(app.getHttpServer())
      .get('/api/repos')
      .expect(200)
      .expect(({ body }) => {
        expect(body).toMatchObject({
          success: true,
          data: [
            {
              id: 'repo-1',
              provider: 'github',
              fullName: 'acme/service'
            }
          ],
          message: null
        });
        expect(body.timestamp).toEqual(expect.any(String));
      });

    expect(repoService.listConnectedRepos).toHaveBeenCalledWith('user-1');
  });

  it('returns wrapped available repositories from GET /api/repos/available', async () => {
    repoService.listAvailableRepos.mockResolvedValue({
      items: [
        {
          providerRepoId: '101',
          fullName: 'acme/service',
          cloneUrl: 'https://github.com/acme/service.git',
          defaultBranch: 'main',
          isPrivate: true,
          alreadyConnected: false
        }
      ],
      page: 2,
      size: 10,
      hasNextPage: true,
      nextPage: 3
    });

    await request(app.getHttpServer())
      .get('/api/repos/available')
      .query({ provider: 'github', page: 2, size: 10 })
      .expect(200)
      .expect(({ body }) => {
        expect(body).toMatchObject({
          success: true,
          data: {
            items: [
              {
                providerRepoId: '101',
                fullName: 'acme/service'
              }
            ],
            page: 2,
            size: 10,
            hasNextPage: true,
            nextPage: 3
          },
          message: null
        });
      });

    expect(repoService.listAvailableRepos).toHaveBeenCalledWith({
      userId: 'user-1',
      provider: 'github',
      page: 2,
      size: 10
    });
  });

  it('returns 201 from POST /api/repos and wraps the connected repo summary', async () => {
    repoService.connectRepo.mockResolvedValue({
      id: 'repo-1',
      fullName: 'acme/service',
      connectedAt: '2026-03-23T09:00:00.000Z'
    });

    await request(app.getHttpServer())
      .post('/api/repos')
      .send({
        provider: 'github',
        providerRepoId: '101'
      })
      .expect(201)
      .expect(({ body }) => {
        expect(body).toMatchObject({
          success: true,
          data: {
            id: 'repo-1',
            fullName: 'acme/service',
            connectedAt: '2026-03-23T09:00:00.000Z'
          },
          message: null
        });
      });

    expect(repoService.connectRepo).toHaveBeenCalledWith({
      userId: 'user-1',
      provider: 'github',
      providerRepoId: '101'
    });
  });

  it('returns 400 from POST /api/repos when providerRepoId is not a string', async () => {
    await request(app.getHttpServer())
      .post('/api/repos')
      .send({
        provider: 'github',
        providerRepoId: 101
      })
      .expect(400)
      .expect(({ body }) => {
        expect(body.success).toBe(false);
        expect(body.errorCode).toBe('BAD_REQUEST');
      });

    expect(repoService.connectRepo).not.toHaveBeenCalled();
  });

  it('returns raw 204 from DELETE /api/repos/:repoId', async () => {
    repoService.disconnectRepo.mockResolvedValue(undefined);

    await request(app.getHttpServer()).delete('/api/repos/repo-1').expect(204).expect('');

    expect(repoService.disconnectRepo).toHaveBeenCalledWith({
      userId: 'user-1',
      repoId: 'repo-1'
    });
  });

  it('returns wrapped branch pages from GET /api/repos/:repoId/branches', async () => {
    repoService.listBranches.mockResolvedValue({
      items: [{ name: 'main', isDefault: true, lastCommitSha: 'sha-main' }],
      page: 1,
      size: 30,
      hasNextPage: false,
      nextPage: null
    });

    await request(app.getHttpServer())
      .get('/api/repos/repo-1/branches')
      .query({ page: 1, size: 30 })
      .expect(200)
      .expect(({ body }) => {
        expect(body).toMatchObject({
          success: true,
          data: {
            items: [{ name: 'main', isDefault: true, lastCommitSha: 'sha-main' }],
            page: 1,
            size: 30,
            hasNextPage: false,
            nextPage: null
          },
          message: null
        });
      });

    expect(repoService.listBranches).toHaveBeenCalledWith({
      userId: 'user-1',
      repoId: 'repo-1',
      page: 1,
      size: 30
    });
  });
});
