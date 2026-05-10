import { INestApplication } from "@nestjs/common";
import { Test } from "@nestjs/testing";
import request from "supertest";

describe("Waiver and suppression lifecycle API (e2e)", () => {
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

  it("creates and updates tenant-scoped waivers without credential or policy override leakage", async () => {
    const create = await request(app.getHttpServer())
      .post("/api/waivers")
      .send({
        tenantId: "tenant_waiver_api",
        owner: "security-reviewer@example.com",
        reason: "Compensating control approved for one sprint.",
        scope: "finding:finding_waiver_1",
        expiresAt: "2026-06-01T00:00:00.000Z"
      })
      .expect(201);

    const waiver = dataOf<Record<string, unknown>>(create.body);

    expect(waiver).toEqual(
      expect.objectContaining({
        id: "waiver_1",
        tenantId: "tenant_waiver_api",
        owner: "security-reviewer@example.com",
        reason: "Compensating control approved for one sprint.",
        scope: "finding:finding_waiver_1",
        expiresAt: "2026-06-01T00:00:00.000Z"
      })
    );

    const update = await request(app.getHttpServer())
      .patch(`/api/waivers/${waiver.id}`)
      .send({
        tenantId: "tenant_waiver_api",
        reason: "Compensating control reviewed and extended.",
        expiresAt: "2026-06-15T00:00:00.000Z",
        lastReviewedAt: "2026-05-10T00:00:00.000Z"
      })
      .expect(200);

    expect(dataOf<Record<string, unknown>>(update.body)).toEqual(
      expect.objectContaining({
        id: waiver.id,
        tenantId: "tenant_waiver_api",
        reason: "Compensating control reviewed and extended.",
        expiresAt: "2026-06-15T00:00:00.000Z",
        lastReviewedAt: "2026-05-10T00:00:00.000Z"
      })
    );
    expect(JSON.stringify({ create: create.body, update: update.body })).not.toMatch(
      /accessToken|refreshToken|tokenValue|secretValue|sourceArchive|fullRepository|rawScannerPayload|aiOverride|policyOverride/i
    );
  });

  it("creates tenant-scoped suppressions without accepting source or credential material", async () => {
    const create = await request(app.getHttpServer())
      .post("/api/suppressions")
      .send({
        tenantId: "tenant_suppression_api",
        scanRequestId: "scan_request_suppression_1",
        findingId: "finding_suppression_1",
        reason: "STALE_RESULT"
      })
      .expect(201);

    expect(dataOf<Record<string, unknown>>(create.body)).toEqual({
      id: "suppression_1",
      tenantId: "tenant_suppression_api",
      scanRequestId: "scan_request_suppression_1",
      findingId: "finding_suppression_1",
      reason: "STALE_RESULT"
    });
    expect(JSON.stringify(create.body)).not.toMatch(
      /accessToken|refreshToken|tokenValue|secretValue|sourceArchive|fullRepository|rawScannerPayload|policyOverride|findingOverride/i
    );
  });

  it("rejects lifecycle payloads that include credentials, full repository content, or policy authority", async () => {
    await request(app.getHttpServer())
      .post("/api/waivers")
      .send({
        tenantId: "tenant_waiver_api",
        owner: "security-reviewer@example.com",
        reason: "Do not accept this payload.",
        scope: "finding:finding_waiver_2",
        expiresAt: "2026-06-01T00:00:00.000Z",
        accessToken: "ghs_secret"
      })
      .expect(400);

    await request(app.getHttpServer())
      .post("/api/suppressions")
      .send({
        tenantId: "tenant_suppression_api",
        scanRequestId: "scan_request_suppression_2",
        reason: "POLICY",
        fullRepository: "all source"
      })
      .expect(400);
  });
});
