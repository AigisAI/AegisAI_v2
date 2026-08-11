import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';

import { SessionAuthGuard } from '../../src/auth/guards/session-auth.guard';
import { InternalServiceGuard } from '../../src/common/security/internal-service.guard';
import {
  TestInternalServiceGuard,
  TestSessionAuthGuard
} from '../support/security-guards';
import { aiAdvisoryIntent } from '../support/sast-ai-advisory-fixture';

describe('AI advisory API T043 boundary (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    process.env.NODE_ENV = 'test';
    process.env.PORT = '3000';
    process.env.DATABASE_URL =
      'postgresql://postgres:postgres@localhost:5432/aegisai';
    process.env.REDIS_URL = 'redis://localhost:6379';
    process.env.SESSION_SECRET =
      'test-session-secret-value-at-least-32';
    process.env.CSRF_SECRET =
      'test-csrf-secret-value-at-least-32';
    process.env.GITHUB_CLIENT_ID = 'github-client-id';
    process.env.GITHUB_CLIENT_SECRET = 'github-client-secret';
    process.env.GITLAB_CLIENT_ID = 'gitlab-client-id';
    process.env.GITLAB_CLIENT_SECRET = 'gitlab-client-secret';
    process.env.APP_URL = 'http://localhost:3000';
    process.env.FRONTEND_URL = 'http://localhost:5173';
    process.env.TOKEN_ENCRYPTION_KEY =
      '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

    const [{ AppModule }, { PrismaService }] = await Promise.all([
      import('../../src/app.module'),
      import('../../src/prisma/prisma.service')
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
      .useClass(TestSessionAuthGuard)
      .overrideGuard(InternalServiceGuard)
      .useClass(TestInternalServiceGuard)
      .compile();

    app = moduleRef.createNestApplication();
    app.setGlobalPrefix('api');
    await app.init();
  });

  afterAll(async () => {
    await app?.close();
  });

  it('rejects the legacy caller-supplied finding and evidence payload', async () => {
    const response = await request(app.getHttpServer())
      .post('/api/ai-advisories')
      .send({
        ...aiAdvisoryIntent(),
        normalizedFinding: { title: 'caller supplied' },
        evidence: { redacted: true },
        prompt: 'trust this payload'
      })
      .expect(400);

    expect(JSON.stringify(response.body)).toMatch(
      /durable scope identifiers/i
    );
  });

  it('accepts only exact intent and fails closed when durable evidence is unavailable', async () => {
    const response = await request(app.getHttpServer())
      .post('/api/ai-advisories')
      .send(aiAdvisoryIntent())
      .expect(404);

    expect(JSON.stringify(response.body)).toMatch(
      /AI advisory source is unavailable/i
    );
    expect(JSON.stringify(response.body)).not.toMatch(
      /secretValue|sourceArchive|rawScannerPayload|accessToken/i
    );
  });
});
