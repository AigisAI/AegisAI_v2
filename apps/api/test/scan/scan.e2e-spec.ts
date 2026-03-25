import type { AuthUser } from '@aegisai/shared';
import { CanActivate, ExecutionContext, INestApplication } from '@nestjs/common';
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
      connectedProviders: ['github']
    };

    return true;
  }
}

describe('ScanController (e2e)', () => {
  let app: INestApplication;
  const scanService = {
    createScan: jest.fn(),
    getScanDetail: jest.fn(),
    listRepoScans: jest.fn()
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

    const [{ AppModule }, { configureApp }, { PrismaService }, { SessionAuthGuard }, { ScanService }] =
      await Promise.all([
        import('../../src/app.module'),
        import('../../src/bootstrap/configure-app'),
        import('../../src/prisma/prisma.service'),
        import('../../src/auth/guards/session-auth.guard'),
        import('../../src/scan/scan.service')
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
      .overrideProvider(ScanService)
      .useValue(scanService)
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

  it('returns HTTP 202 from POST /api/scans with the wrapped request payload', async () => {
    scanService.createScan.mockResolvedValue({
      scanId: 'scan-1',
      status: 'PENDING',
      message: 'Scan queued successfully.'
    });

    await request(app.getHttpServer())
      .post('/api/scans')
      .send({
        repoId: 'repo-1',
        branch: 'main'
      })
      .expect(202)
      .expect(({ body }) => {
        expect(body).toMatchObject({
          success: true,
          data: {
            scanId: 'scan-1',
            status: 'PENDING',
            message: 'Scan queued successfully.'
          },
          message: null
        });
      });

    expect(scanService.createScan).toHaveBeenCalledWith({
      userId: 'user-1',
      connectedRepoId: 'repo-1',
      branch: 'main'
    });
  });

  it('returns wrapped scan detail from GET /api/scans/:scanId', async () => {
    scanService.getScanDetail.mockResolvedValue({
      id: 'scan-1',
      repoFullName: 'acme/service',
      branch: 'main',
      commitSha: 'commit-123',
      status: 'DONE',
      language: 'java',
      totalFiles: 10,
      totalLines: 200,
      summary: {
        critical: 0,
        high: 1,
        medium: 0,
        low: 0,
        info: 0
      },
      startedAt: null,
      completedAt: null,
      errorMessage: null,
      createdAt: '2026-03-25T12:00:00.000Z'
    });

    await request(app.getHttpServer())
      .get('/api/scans/scan-1')
      .expect(200)
      .expect(({ body }) => {
        expect(body).toMatchObject({
          success: true,
          data: {
            id: 'scan-1',
            repoFullName: 'acme/service',
            status: 'DONE'
          },
          message: null
        });
      });

    expect(scanService.getScanDetail).toHaveBeenCalledWith('user-1', 'scan-1');
  });

  it('returns wrapped scan history from GET /api/repos/:repoId/scans', async () => {
    scanService.listRepoScans.mockResolvedValue({
      items: [
        {
          id: 'scan-1',
          repoFullName: 'acme/service',
          branch: 'main',
          commitSha: 'commit-123',
          status: 'DONE',
          language: 'java',
          totalFiles: 10,
          totalLines: 200,
          summary: {
            critical: 0,
            high: 1,
            medium: 0,
            low: 0,
            info: 0
          },
          startedAt: null,
          completedAt: null,
          errorMessage: null,
          createdAt: '2026-03-25T12:00:00.000Z'
        }
      ],
      totalCount: 1,
      page: 1,
      totalPages: 1
    });

    await request(app.getHttpServer())
      .get('/api/repos/repo-1/scans')
      .query({ page: 1, size: 10 })
      .expect(200)
      .expect(({ body }) => {
        expect(body).toMatchObject({
          success: true,
          data: {
            items: [
              {
                id: 'scan-1',
                repoFullName: 'acme/service'
              }
            ],
            totalCount: 1,
            page: 1,
            totalPages: 1
          },
          message: null
        });
      });

    expect(scanService.listRepoScans).toHaveBeenCalledWith({
      userId: 'user-1',
      repoId: 'repo-1',
      page: 1,
      size: 10
    });
  });
});
