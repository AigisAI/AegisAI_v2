import { INestApplication } from "@nestjs/common";
import { Test } from "@nestjs/testing";
import request from "supertest";
import { SessionAuthGuard } from '../../src/auth/guards/session-auth.guard';
import { InternalServiceGuard } from '../../src/common/security/internal-service.guard';
import { ControlPlaneService } from '../../src/control-plane/control-plane.service';
import { TestInternalServiceGuard, TestSessionAuthGuard } from '../support/security-guards';

describe("Scan Plane mock pipeline skeleton (e2e)", () => {
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
      .overrideProvider(ControlPlaneService)
      .useValue({
        getScanRequest: jest.fn((tenantId: string, scanRequestId: string) => ({
          id: scanRequestId,
          tenantId,
          scannerSetVersion: ['scan_request_3', 'scan_request_4'].includes(scanRequestId)
            ? 'scanner-set-v2'
            : 'scanner-set-v1'
        }))
      })
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

  it("creates deterministic scanner run, finding, and evidence metadata without leaking credentials or source", async () => {
    const response = await request(app.getHttpServer())
      .post("/api/scan-plane/mock-runs")
      .send({
        tenantId: "tenant_scan",
        scanRequestId: "scan_request_1",
        scannerSetVersion: "scanner-set-v1"
      })
      .expect(201);

    const responseData = dataOf<{
      scannerRuns: unknown[];
      findings: unknown[];
      evidencePacks: unknown[];
    }>(response.body);

    expect(responseData.scannerRuns).toEqual([
      expect.objectContaining({ tenantId: "tenant_scan", scanRequestId: "scan_request_1", scanner: "OPENGREP", status: "COMPLETED" }),
      expect.objectContaining({ tenantId: "tenant_scan", scanRequestId: "scan_request_1", scanner: "TRIVY", status: "COMPLETED" }),
      expect.objectContaining({ tenantId: "tenant_scan", scanRequestId: "scan_request_1", scanner: "SYFT", status: "COMPLETED" })
    ]);
    expect(responseData.findings).toEqual([
      expect.objectContaining({
        tenantId: "tenant_scan",
        scanRequestId: "scan_request_1",
        scannerProvenance: "OPENGREP",
        severity: "HIGH",
        status: "OPEN"
      })
    ]);
    expect(responseData.evidencePacks).toEqual([
      expect.objectContaining({
        tenantId: "tenant_scan",
        scanRequestId: "scan_request_1",
        classification: "SHORT_LIVED_EVIDENCE",
        objectKey: expect.stringMatching(/^tenant_scan\/scan_request_1\/evidence\/evidence_/),
        redacted: true
      })
    ]);
    expect(JSON.stringify(responseData)).not.toMatch(/accessToken|refreshToken|tokenValue|secretValue|fullRepository|sourceArchive/i);
  });

  it("reads generated scanner runs, findings, and evidence through tenant-scoped endpoints", async () => {
    await request(app.getHttpServer())
      .post("/api/scan-plane/mock-runs")
      .send({
        tenantId: "tenant_reads",
        scanRequestId: "scan_request_2",
        scannerSetVersion: "scanner-set-v1"
      })
      .expect(201);

    const scannerRuns = await request(app.getHttpServer())
      .get("/api/scan-plane/scanner-runs")
      .query({ tenantId: "tenant_reads", scanRequestId: "scan_request_2" })
      .expect(200);
    expect(dataOf<unknown[]>(scannerRuns.body)).toHaveLength(3);

    const findings = await request(app.getHttpServer())
      .get("/api/findings")
      .query({ tenantId: "tenant_reads", scanRequestId: "scan_request_2" })
      .expect(200);
    const findingsData = dataOf<Array<{ tenantId: string }>>(findings.body);
    expect(findingsData).toHaveLength(1);
    expect(findingsData[0].tenantId).toBe("tenant_reads");

    const evidence = await request(app.getHttpServer())
      .get("/api/evidence")
      .query({ tenantId: "tenant_reads", scanRequestId: "scan_request_2" })
      .expect(200);
    const evidenceData = dataOf<Array<{ objectKey: string }>>(evidence.body);
    expect(evidenceData).toHaveLength(1);
    expect(evidenceData[0].objectKey).toContain("tenant_reads/scan_request_2/evidence/");
  });

  it("rejects the legacy caller-controlled workspace, timeout, and isolation execution shape", async () => {
    const response = await request(app.getHttpServer())
      .post("/api/scan-plane/scanner-runs/execute")
      .send({
        tenantId: "tenant_exec",
        scanRequestId: "scan_request_3",
        scannerSetVersion: "scanner-set-v2",
        workspaceRef: "sandbox://tenant_exec/scan_request_3/workspace",
        isolationClass: "HARDENED",
        timeoutSeconds: 120
      })
      .expect(403);

    expect(JSON.stringify(response.body)).not.toMatch(
      /accessToken|refreshToken|tokenValue|secretValue/i
    );
  });

  it("creates metadata-only evidence access requests without leaking repository content or credentials", async () => {
    const scanRun = await request(app.getHttpServer())
      .post("/api/scan-plane/mock-runs")
      .send({
        tenantId: "tenant_evidence",
        scanRequestId: "scan_request_4",
        scannerSetVersion: "scanner-set-v2"
      })
      .expect(201);

    const scanRunData = dataOf<{
      evidencePacks: Array<{ id: string; objectKey: string }>;
    }>(scanRun.body);
    const evidencePack = scanRunData.evidencePacks[0];

    const access = await request(app.getHttpServer())
      .post(`/api/evidence/${evidencePack.id}/access-requests`)
      .send({
        tenantId: "tenant_evidence",
        scanRequestId: "scan_request_4"
      })
      .expect(201);

    const accessData = dataOf<Record<string, unknown>>(access.body);

    expect(accessData).toEqual(
      expect.objectContaining({
        evidencePackId: evidencePack.id,
        objectKey: evidencePack.objectKey,
        tenantId: "tenant_evidence",
        scanRequestId: "scan_request_4",
        accessMode: "METADATA_ONLY",
        redacted: true
      })
    );
    expect(JSON.stringify(accessData)).not.toMatch(
      /accessToken|refreshToken|tokenValue|secretValue|sourceArchive|fullRepository|workspaceRef|rawContent/i
    );
  });
});
