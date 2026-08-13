import { INestApplication } from "@nestjs/common";
import { Test } from "@nestjs/testing";
import request from "supertest";
import { SessionAuthGuard } from '../../src/auth/guards/session-auth.guard';
import { InternalServiceGuard } from '../../src/common/security/internal-service.guard';
import { PolicyDecisionStore } from '../../src/policy/policy-decision.store';
import { TestInternalServiceGuard, TestSessionAuthGuard } from '../support/security-guards';

describe("Policy decision API (e2e)", () => {
  let app: INestApplication;

  beforeAll(async () => {
    process.env.NODE_ENV = "test";
    process.env.PORT = "3000";
    process.env.DATABASE_URL = "postgresql://postgres:postgres@localhost:5432/aegisai";
    process.env.REDIS_URL = "redis://localhost:6379";
    process.env.SESSION_SECRET = "test-session-secret-value-at-least-32";
    process.env.CSRF_SECRET = "test-csrf-secret-value-at-least-32";
    process.env.GITHUB_CLIENT_ID = "github-client-id";
    process.env.GITHUB_CLIENT_SECRET = "github-client-secret";
    process.env.GITLAB_CLIENT_ID = "gitlab-client-id";
    process.env.GITLAB_CLIENT_SECRET = "gitlab-client-secret";
    process.env.APP_URL = "http://localhost:3000";
    process.env.FRONTEND_URL = "http://localhost:5173";
    process.env.TOKEN_ENCRYPTION_KEY =
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    const [{ AppModule }, { PrismaService }] = await Promise.all([
      import("../../src/app.module"),
      import("../../src/prisma/prisma.service")
    ]);
    let decisionSequence = 0;
    const decisions = new Map<string, Record<string, unknown>>();
    const policyDecisionStore = {
      create: jest.fn(async (input: Record<string, unknown>) => {
        const decision = {
          id: `policy_decision_${++decisionSequence}`,
          ...input
        };
        decisions.set(String(decision.id), decision);
        return decision;
      }),
      findByTenantAndId: jest.fn(
        async (tenantId: string, id: string) => {
          const decision = decisions.get(id);
          return decision?.tenantId === tenantId ? decision : null;
        }
      )
    };

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
      .overrideProvider(PolicyDecisionStore)
      .useValue(policyDecisionStore)
      .overrideGuard(SessionAuthGuard)
      .useClass(TestSessionAuthGuard)
      .overrideGuard(InternalServiceGuard)
      .useClass(TestInternalServiceGuard)
      .compile();

    app = moduleRef.createNestApplication();
    app.setGlobalPrefix("api");

    await app.init();
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
  });

  const dataOf = <T>(body: { data?: T } | T): T => {
    if (body && typeof body === "object" && "data" in body) {
      return (body as { data: T }).data;
    }

    return body as T;
  };

  it("evaluates and reads tenant-scoped policy decisions without credential or AI override leakage", async () => {
    const evaluate = await request(app.getHttpServer())
      .post("/api/policy-decisions/evaluate")
      .send({
        tenantId: "tenant_policy_api",
        scanRequestId: "scan_request_api_1",
        scanLane: "DEEP",
        scannerCoverage: ["OPENGREP"],
        finding: {
          id: "finding_api_1",
          tenantId: "tenant_policy_api",
          scanRequestId: "scan_request_api_1",
          scannerRunId: "scanner_run_api_1",
          title: "Unsafe deserialization",
          severity: "HIGH",
          scannerProvenance: "OPENGREP",
          filePath: "src/App.java",
          lineStart: 42,
          status: "OPEN"
        }
      })
      .expect(201);

    const decision = dataOf<Record<string, unknown>>(evaluate.body);

    expect(decision).toEqual(
      expect.objectContaining({
        tenantId: "tenant_policy_api",
        scanRequestId: "scan_request_api_1",
        findingId: "finding_api_1",
        enforcementAction: "WARN",
        aiAdvisoryVisible: false
      })
    );

    const read = await request(app.getHttpServer())
      .get(`/api/policy-decisions/${decision.id}`)
      .query({ tenantId: "tenant_policy_api" })
      .expect(200);

    expect(dataOf<Record<string, unknown>>(read.body)).toEqual(decision);
    expect(JSON.stringify({ decision, read: read.body })).not.toMatch(
      /accessToken|refreshToken|tokenValue|secretValue|sourceArchive|fullRepository|aiOverride|policyOverride/i
    );
  });

  it('rejects legacy AI suggested actions at the policy boundary', async () => {
    await request(app.getHttpServer())
      .post('/api/policy-decisions/evaluate')
      .send({
        tenantId: 'tenant_policy_api',
        scanRequestId: 'scan_request_api_2',
        scanLane: 'FAST',
        scannerCoverage: ['OPENGREP', 'TRIVY', 'SYFT'],
        finding: {
          id: 'finding_api_2',
          tenantId: 'tenant_policy_api',
          scanRequestId: 'scan_request_api_2',
          scannerRunId: 'scanner_run_api_2',
          title: 'Critical finding',
          severity: 'CRITICAL',
          scannerProvenance: 'OPENGREP',
          filePath: 'src/App.java',
          lineStart: 42,
          status: 'OPEN'
        },
        aiAdvisory: {
          visible: true,
          suggestedAction: 'DASHBOARD_ONLY'
        }
      })
      .expect(400);
  });
});
