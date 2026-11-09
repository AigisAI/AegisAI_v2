import type { NestExpressApplication } from "@nestjs/platform-express";
import { buildCanonicalScanKey } from "@aegisai/shared";
import request from "supertest";

import { createTestApplication, loginTestAgent } from "../support/test-app";

describe("Control Plane skeleton security boundaries (e2e)", () => {
  let app: NestExpressApplication;

  beforeAll(async () => {
    app = await createTestApplication();
  });

  afterAll(async () => {
    await app.close();
  });

  it("derives the tenant from the session and validates integration input", async () => {
    await request(app.getHttpServer()).get("/api/integrations").expect(401);

    const agent = request.agent(app.getHttpServer());
    const csrfToken = await loginTestAgent(agent, "tenant_alpha");
    const payload = {
      externalInstallationId: "gh-installation-1",
      repoReadPrincipalId: "repo-read-principal",
      commentWritePrincipalId: "comment-write-principal",
      integrationAdminPrincipalId: "integration-admin-principal",
      repositories: [
        {
          providerRepoId: "1001",
          fullName: "acme/payments",
          defaultBranch: "main",
          isPrivate: true
        }
      ]
    };

    await agent
      .post("/api/integrations/github/install")
      .set("X-CSRF-Token", csrfToken)
      .send({ ...payload, tenantId: "tenant_attacker" })
      .expect(400);

    const install = await agent
      .post("/api/integrations/github/install")
      .set("X-CSRF-Token", csrfToken)
      .send(payload)
      .expect(201);

    expect(install.body).toMatchObject({
      provider: "GITHUB",
      integrationType: "GITHUB_APP",
      tenantId: "tenant_alpha",
      status: "ACTIVE"
    });
    expect(JSON.stringify(install.body)).not.toMatch(/token|secret/i);

    const retry = await agent
      .post("/api/integrations/github/install")
      .set("X-CSRF-Token", csrfToken)
      .send(payload)
      .expect(201);
    expect(retry.body.id).toBe(install.body.id);

    const integrations = await agent
      .get("/api/integrations")
      .query({ tenantId: "tenant_attacker" })
      .expect(200);
    expect(integrations.body).toHaveLength(1);
    expect(integrations.body[0].tenantId).toBe("tenant_alpha");

    const repositories = await agent.get("/api/repository-bindings").expect(200);
    expect(repositories.body).toEqual([
      expect.objectContaining({
        tenantId: "tenant_alpha",
        scmIntegrationId: install.body.id,
        providerRepoId: "1001",
        fullName: "acme/payments",
        defaultBranch: "main",
        isPrivate: true
      })
    ]);
  });

  it("creates idempotent scan requests and blocks cross-tenant reads", async () => {
    const beta = request.agent(app.getHttpServer());
    const betaCsrf = await loginTestAgent(beta, "tenant_beta");
    await beta
      .post("/api/integrations/gitlab/install")
      .set("X-CSRF-Token", betaCsrf)
      .send({
        externalInstallationId: "gl-group-1",
        repoReadPrincipalId: "repo-read-principal",
        repositories: [
          {
            providerRepoId: "2002",
            fullName: "acme/orders",
            defaultBranch: "main",
            isPrivate: false
          }
        ]
      })
      .expect(201);

    const repositories = await beta.get("/api/repository-bindings").expect(200);
    const repositoryBindingId = repositories.body[0].id as string;
    const payload = {
      repositoryBindingId,
      lane: "FAST",
      targetRef: "refs/merge-requests/7/head",
      commitSha: "abcdef123",
      policyVersion: "policy-2026-04-12",
      scannerSetVersion: "scanner-set-v1",
      isolationSignals: {
        tenantAgeDays: 3,
        repositorySizeMb: 64,
        hasParserFaultHistory: false,
        hasAbuseSignal: false,
        hasSuspiciousPathLayout: false,
        hasRepeatedTimeout: false,
        manuallyEscalated: false
      }
    } as const;

    const scan = await beta
      .post("/api/scan-requests")
      .set("X-CSRF-Token", betaCsrf)
      .send(payload)
      .expect(201);
    const expectedCanonicalKey = buildCanonicalScanKey({
      ...payload,
      tenantId: "tenant_beta"
    });

    expect(scan.body).toMatchObject({
      tenantId: "tenant_beta",
      repositoryBindingId,
      canonicalKey: expectedCanonicalKey,
      isolationClass: "HARDENED",
      status: "QUEUED"
    });

    const retry = await beta
      .post("/api/scan-requests")
      .set("X-CSRF-Token", betaCsrf)
      .send(payload)
      .expect(201);
    expect(retry.body.id).toBe(scan.body.id);

    await beta.get(`/api/scan-requests/${scan.body.id}`).expect(200);

    const alpha = request.agent(app.getHttpServer());
    await loginTestAgent(alpha, "tenant_alpha");
    await alpha.get(`/api/scan-requests/${scan.body.id}`).expect(404);
  });
});
