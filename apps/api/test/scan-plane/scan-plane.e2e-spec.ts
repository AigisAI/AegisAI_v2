import { INestApplication } from "@nestjs/common";
import { Test } from "@nestjs/testing";
import request from "supertest";

import { AppModule } from "../../src/app.module";

describe("Scan Plane mock pipeline skeleton (e2e)", () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule]
    }).compile();

    app = moduleRef.createNestApplication();
    app.setGlobalPrefix("api");

    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  it("creates deterministic scanner run, finding, and evidence metadata without leaking credentials or source", async () => {
    const response = await request(app.getHttpServer())
      .post("/api/scan-plane/mock-runs")
      .send({
        tenantId: "tenant_scan",
        scanRequestId: "scan_request_1",
        scannerSetVersion: "scanner-set-v1"
      })
      .expect(201);

    expect(response.body.scannerRuns).toEqual([
      expect.objectContaining({ tenantId: "tenant_scan", scanRequestId: "scan_request_1", scanner: "OPENGREP", status: "COMPLETED" }),
      expect.objectContaining({ tenantId: "tenant_scan", scanRequestId: "scan_request_1", scanner: "TRIVY", status: "COMPLETED" }),
      expect.objectContaining({ tenantId: "tenant_scan", scanRequestId: "scan_request_1", scanner: "SYFT", status: "COMPLETED" })
    ]);
    expect(response.body.findings).toEqual([
      expect.objectContaining({
        tenantId: "tenant_scan",
        scanRequestId: "scan_request_1",
        scannerProvenance: "OPENGREP",
        severity: "HIGH",
        status: "OPEN"
      })
    ]);
    expect(response.body.evidencePacks).toEqual([
      expect.objectContaining({
        tenantId: "tenant_scan",
        scanRequestId: "scan_request_1",
        classification: "SHORT_LIVED_EVIDENCE",
        objectKey: expect.stringMatching(/^tenant_scan\/scan_request_1\/evidence\/evidence_/),
        redacted: true
      })
    ]);
    expect(JSON.stringify(response.body)).not.toMatch(/accessToken|refreshToken|tokenValue|secretValue|fullRepository|sourceArchive/i);
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
    expect(scannerRuns.body).toHaveLength(3);

    const findings = await request(app.getHttpServer())
      .get("/api/findings")
      .query({ tenantId: "tenant_reads", scanRequestId: "scan_request_2" })
      .expect(200);
    expect(findings.body).toHaveLength(1);
    expect(findings.body[0].tenantId).toBe("tenant_reads");

    const evidence = await request(app.getHttpServer())
      .get("/api/evidence")
      .query({ tenantId: "tenant_reads", scanRequestId: "scan_request_2" })
      .expect(200);
    expect(evidence.body).toHaveLength(1);
    expect(evidence.body[0].objectKey).toContain("tenant_reads/scan_request_2/evidence/");
  });
});
