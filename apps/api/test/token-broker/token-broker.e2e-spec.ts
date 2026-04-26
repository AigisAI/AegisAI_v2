import { INestApplication } from "@nestjs/common";
import { Test } from "@nestjs/testing";
import request from "supertest";

describe("Token Broker and audit skeleton (e2e)", () => {
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

  it("issues scan-scoped credential metadata without returning token values", async () => {
    const response = await request(app.getHttpServer())
      .post("/api/token-broker/issue")
      .send({
        tenantId: "tenant_gamma",
        repositoryBindingId: "repository_binding_1",
        scanRequestId: "scan_request_1",
        principal: "REPO_READ",
        commitSha: "abc123",
        ttlSeconds: 600,
        auditReason: "scan-fetch"
      })
      .expect(201);

    const responseData = dataOf<Record<string, unknown>>(response.body);

    expect(responseData).toMatchObject({
      tenantId: "tenant_gamma",
      repositoryBindingId: "repository_binding_1",
      scanRequestId: "scan_request_1",
      principal: "REPO_READ",
      commitSha: "abc123",
      ttlSeconds: 600,
      expiresInSeconds: 600,
      auditEventType: "token.issued"
    });
    expect(responseData.credentialId).toMatch(/^credential_/);
    expect(JSON.stringify(responseData)).not.toMatch(/tokenValue|secretValue|accessToken|refreshToken/i);
  });

  it("records tenant-scoped audit events for token issuance", async () => {
    await request(app.getHttpServer())
      .post("/api/token-broker/issue")
      .send({
        tenantId: "tenant_delta",
        repositoryBindingId: "repository_binding_2",
        scanRequestId: "scan_request_2",
        principal: "REPO_READ",
        commitSha: "def456",
        ttlSeconds: 300,
        auditReason: "scan-fetch"
      })
      .expect(201);

    const audit = await request(app.getHttpServer())
      .get("/api/audit-events")
      .query({ tenantId: "tenant_delta" })
      .expect(200);

    const auditData = dataOf<Array<Record<string, unknown>>>(audit.body);

    expect(auditData).toEqual([
      expect.objectContaining({
        tenantId: "tenant_delta",
        eventType: "token.issued",
        actor: "token-broker",
        targetType: "scan_request",
        targetId: "scan_request_2",
        metadata: expect.objectContaining({
          repositoryBindingId: "repository_binding_2",
          principal: "REPO_READ",
          commitSha: "def456",
          ttlSeconds: 300,
          auditReason: "scan-fetch"
        })
      })
    ]);
    expect(JSON.stringify(auditData)).not.toMatch(/tokenValue|secretValue|accessToken|refreshToken/i);
  });
});
