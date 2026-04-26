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

describe('ReportController (e2e)', () => {
  let app: INestApplication;
  const reportService = {
    requestReport: jest.fn(),
    getReportDetail: jest.fn(),
    getReportDownload: jest.fn()
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

    const [{ AppModule }, { configureApp }, { PrismaService }, { SessionAuthGuard }] =
      await Promise.all([
        import('../../src/app.module'),
        import('../../src/bootstrap/configure-app'),
        import('../../src/prisma/prisma.service'),
        import('../../src/auth/guards/session-auth.guard')
      ]);

    let ReportService: object | null = null;

    try {
      ({ ReportService } = await import('../../src/report/report.service'));
    } catch {
      ReportService = null;
    }

    const builder = Test.createTestingModule({
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
      .useClass(MockSessionAuthGuard);

    if (ReportService) {
      builder.overrideProvider(ReportService).useValue(reportService);
    }

    const moduleRef = await builder.compile();

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

  it('returns wrapped report request data from POST /api/reports/scans/:scanId/pdf', async () => {
    reportService.requestReport.mockResolvedValue({
      reportId: 'report-1',
      status: 'GENERATING',
      message: 'PDF report generation has started.'
    });

    await request(app.getHttpServer())
      .post('/api/reports/scans/scan-1/pdf')
      .expect(202)
      .expect(({ body }) => {
        expect(body).toMatchObject({
          success: true,
          data: {
            reportId: 'report-1',
            status: 'GENERATING'
          },
          message: null
        });
      });

    expect(reportService.requestReport).toHaveBeenCalledWith({
      userId: 'user-1',
      scanId: 'scan-1'
    });
  });

  it('returns wrapped report detail from GET /api/reports/:reportId', async () => {
    reportService.getReportDetail.mockResolvedValue({
      id: 'report-1',
      scanId: 'scan-1',
      status: 'READY',
      downloadUrl: '/api/reports/report-1/download',
      errorMessage: null,
      createdAt: '2026-03-31T00:00:00.000Z',
      expiresAt: '2026-04-01T00:00:00.000Z'
    });

    await request(app.getHttpServer())
      .get('/api/reports/report-1')
      .expect(200)
      .expect(({ body }) => {
        expect(body).toMatchObject({
          success: true,
          data: {
            id: 'report-1',
            status: 'READY',
            downloadUrl: '/api/reports/report-1/download'
          },
          message: null
        });
      });

    expect(reportService.getReportDetail).toHaveBeenCalledWith('user-1', 'report-1');
  });

  it('returns a raw PDF stream from GET /api/reports/:reportId/download', async () => {
    reportService.getReportDownload.mockResolvedValue({
      fileName: 'aegisai-scan-report-scan-1-report-1.pdf',
      mimeType: 'application/pdf',
      buffer: Buffer.from('%PDF-1.4\n')
    });

    const response = await request(app.getHttpServer())
      .get('/api/reports/report-1/download')
      .buffer()
      .parse((res, callback) => {
        const chunks: Buffer[] = [];

        res.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
        res.on('end', () => callback(null, Buffer.concat(chunks)));
      })
      .expect(200);

    expect(response.headers['content-type']).toMatch(/application\/pdf/);
    expect(response.headers['content-disposition']).toContain(
      'attachment; filename="aegisai-scan-report-scan-1-report-1.pdf"'
    );
    expect(Buffer.isBuffer(response.body)).toBe(true);
    expect(response.body.subarray(0, 5).toString('utf8')).toBe('%PDF-');
    expect(reportService.getReportDownload).toHaveBeenCalledWith('user-1', 'report-1');
  });
});
