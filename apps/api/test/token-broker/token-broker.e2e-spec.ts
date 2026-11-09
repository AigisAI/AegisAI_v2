import type { NestExpressApplication } from "@nestjs/platform-express";
import request from "supertest";

import {
  createTestApplication,
  loginTestAgent,
  TEST_INTERNAL_API_SECRET
} from "../support/test-app";

describe("Token Broker and audit boundaries (e2e)", () => {
  let app: NestExpressApplication;
  let tenantAgent: request.Agent;
  let csrfToken: string;
  let repositoryBindingId: string;
  let scanRequestId: string;

  beforeAll(async () => {
    app = await createTestApplication();
    tenantAgent = request.agent(app.getHttpServer());
    csrfToken = await loginTestAgent(tenantAgent, "tenant_gamma");

    await tenantAgent
      .post("/api/integrations/github/install")
      .set("X-CSRF-Token", csrfToken)
      .send({
        externalInstallationId: "gh-token-test",
        repoReadPrincipalId: "repo-read-principal",
        repositories: [
          {
            providerRepoId: "3003",
            fullName: "acme/token-test",
            defaultBranch: "main",
            isPrivate: true
          }
        ]
      })
      .expect(201);
    const repositories = await tenantAgent.get("/api/repository-bindings").expect(200);
    repositoryBindingId = repositories.body[0].id as string;
    const scan = await tenantAgent
      .post("/api/scan-requests")
      .set("X-CSRF-Token", csrfToken)
      .send({
        repositoryBindingId,
        lane: "FAST",
        targetRef: "refs/heads/main",
        commitSha: "abcdef123",
        policyVersion: "policy-v1",
        scannerSetVersion: "scanner-set-v1"
      })
      .expect(201);
    scanRequestId = scan.body.id as string;
  });

  afterAll(async () => {
    await app.close();
  });

  it("requires internal authentication and returns only short-lived credential metadata", async () => {
    const payload = {
      tenantId: "tenant_gamma",
      repositoryBindingId,
      scanRequestId,
      principal: "REPO_READ",
      commitSha: "abcdef123",
      ttlSeconds: 600,
      auditReason: "scan-fetch"
    };

    await request(app.getHttpServer()).post("/api/token-broker/issue").send(payload).expect(401);

    const issuedAt = Date.now();
    const response = await request(app.getHttpServer())
      .post("/api/token-broker/issue")
      .set("Authorization", `Bearer ${TEST_INTERNAL_API_SECRET}`)
      .send(payload)
      .expect(201);

    expect(response.body).toMatchObject({
      repositoryBindingId,
      scanRequestId,
      principal: "REPO_READ",
      expiresInSeconds: 600,
      auditEventType: "token.issued"
    });
    expect(response.body.credentialId).toMatch(/^credential_[0-9a-f-]{36}$/);
    expect(Date.parse(response.body.expiresAt)).toBeGreaterThanOrEqual(issuedAt + 599_000);
    expect(JSON.stringify(response.body)).not.toMatch(
      /tokenValue|secretValue|accessToken|refreshToken|auditReason|tenantId|commitSha/i
    );

    const audit = await tenantAgent.get("/api/audit-events").expect(200);
    expect(audit.body).toEqual([
      expect.objectContaining({
        tenantId: "tenant_gamma",
        eventType: "token.issued",
        actor: "token-broker",
        targetId: scanRequestId,
        occurredAt: expect.any(String),
        metadata: expect.objectContaining({
          repositoryBindingId,
          principal: "REPO_READ",
          commitSha: "abcdef123",
          ttlSeconds: 600,
          auditReason: "scan-fetch"
        })
      })
    ]);
    expect(Date.parse(audit.body[0].occurredAt)).toBeGreaterThan(0);
  });

  it("rejects overlong TTLs and scope that does not match the scan request", async () => {
    const base = {
      tenantId: "tenant_gamma",
      repositoryBindingId,
      scanRequestId,
      principal: "REPO_READ",
      commitSha: "abcdef123",
      ttlSeconds: 300,
      auditReason: "scan-fetch"
    };

    await request(app.getHttpServer())
      .post("/api/token-broker/issue")
      .set("Authorization", `Bearer ${TEST_INTERNAL_API_SECRET}`)
      .send({ ...base, ttlSeconds: 601 })
      .expect(400);

    await request(app.getHttpServer())
      .post("/api/token-broker/issue")
      .set("Authorization", `Bearer ${TEST_INTERNAL_API_SECRET}`)
      .send({ ...base, commitSha: "deadbee" })
      .expect(400);

    await request(app.getHttpServer())
      .post("/api/token-broker/issue")
      .set("Authorization", `Bearer ${TEST_INTERNAL_API_SECRET}`)
      .send({ ...base, principal: "COMMENT_WRITE" })
      .expect(400);
  });

  it("does not expose one tenant's audit log to another session", async () => {
    const otherTenant = request.agent(app.getHttpServer());
    await loginTestAgent(otherTenant, "tenant_other");
    await otherTenant.get("/api/audit-events").expect(200, []);
  });
});
