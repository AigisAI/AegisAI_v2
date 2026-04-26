import { INestApplication } from "@nestjs/common";
import { Test } from "@nestjs/testing";
import request from "supertest";

import { AppModule } from "../../src/app.module";

describe("Token Broker and audit skeleton (e2e)", () => {
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

    expect(response.body).toMatchObject({
      tenantId: "tenant_gamma",
      repositoryBindingId: "repository_binding_1",
      scanRequestId: "scan_request_1",
      principal: "REPO_READ",
      commitSha: "abc123",
      ttlSeconds: 600,
      expiresInSeconds: 600,
      auditEventType: "token.issued"
    });
    expect(response.body.credentialId).toMatch(/^credential_/);
    expect(JSON.stringify(response.body)).not.toMatch(/tokenValue|secretValue|accessToken|refreshToken/i);
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

    expect(audit.body).toEqual([
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
    expect(JSON.stringify(audit.body)).not.toMatch(/tokenValue|secretValue|accessToken|refreshToken/i);
  });
});
