import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';

describe('App bootstrap (e2e)', () => {
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

    const [{ AppModule }, { configureApp }, { PrismaService }] = await Promise.all([
      import('../src/app.module'),
      import('../src/bootstrap/configure-app'),
      import('../src/prisma/prisma.service')
    ]);

    const moduleRef = await Test.createTestingModule({
      imports: [AppModule]
    })
      .overrideProvider(PrismaService)
      .useValue({
        $connect: jest.fn().mockResolvedValue(undefined),
        $disconnect: jest.fn().mockResolvedValue(undefined),
        onModuleInit: jest.fn().mockResolvedValue(undefined),
        onModuleDestroy: jest.fn().mockResolvedValue(undefined)
      })
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

  it('returns bootstrap metadata from GET /api', async () => {
    await request(app.getHttpServer())
      .get('/api')
      .expect(200)
      .expect(({ body }) => {
        expect(body).toMatchObject({
          docs: 'specs/001-aegisai-mvp-foundation/quickstart.md',
          service: 'api',
          status: 'bootstrapped'
        });
      });
  });
});
