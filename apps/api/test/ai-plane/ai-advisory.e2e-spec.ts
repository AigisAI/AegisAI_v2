import { INestApplication } from "@nestjs/common";
import { Test } from "@nestjs/testing";
import request from "supertest";

describe("AI advisory API (e2e)", () => {
  let app: INestApplication;

  beforeAll(async () => {
    process.env.NODE_ENV = "test";
    process.env.PORT = "3000";
    process.env.DATABASE_URL = "postgresql://postgres:postgres@localhost:5432/aegisai";
    process.env.REDIS_URL = "redis://localhost:6379";
    process.env.SESSION_SECRET = "test-session-secret-value";
    process.env.CSRF_SECRET = "test-csrf-secret-value";
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

  it("creates and reads advisory-only AI output without source, credential, finding, or policy authority", async () => {
    const create = await request(app.getHttpServer())
      .post("/api/ai-advisories")
      .send({
        tenantId: "tenant_ai_api",
        scanRequestId: "scan_request_ai_1",
        findingId: "finding_ai_1",
        normalizedFinding: {
          id: "finding_ai_1",
          tenantId: "tenant_ai_api",
          scanRequestId: "scan_request_ai_1",
          scannerRunId: "scanner_run_ai_1",
          title: "Unsafe deserialization",
          severity: "HIGH",
          scannerProvenance: "OPENGREP",
          filePath: "src/App.java",
          lineStart: 42,
          status: "OPEN"
        },
        evidence: {
          id: "evidence_ai_1",
          tenantId: "tenant_ai_api",
          scanRequestId: "scan_request_ai_1",
          classification: "SHORT_LIVED_EVIDENCE",
          objectKey: "tenant_ai_api/scan_request_ai_1/evidence/evidence_ai_1.json",
          expiresAt: "2026-04-19T00:00:00.000Z",
          byteSize: 512,
          redacted: true
        },
        modelVersion: "detector-planner-mock-v1"
      })
      .expect(201);

    const advisory = dataOf<Record<string, unknown>>(create.body);

    expect(advisory).toEqual(
      expect.objectContaining({
        tenantId: "tenant_ai_api",
        scanRequestId: "scan_request_ai_1",
        findingId: "finding_ai_1",
        advisoryOnly: true,
        redactedEvidenceOnly: true
      })
    );

    const read = await request(app.getHttpServer())
      .get(`/api/ai-advisories/${advisory.id}`)
      .query({ tenantId: "tenant_ai_api" })
      .expect(200);

    expect(dataOf<Record<string, unknown>>(read.body)).toEqual(advisory);
    expect(JSON.stringify({ advisory, read: read.body })).not.toMatch(
      /enforcementAction|blockRequested|policyOverride|findingOverride|accessToken|refreshToken|tokenValue|secretValue|sourceArchive|fullRepository|rawScannerPayload/i
    );
  });
});
