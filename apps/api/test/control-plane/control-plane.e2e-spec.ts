import { INestApplication } from "@nestjs/common";
import { Test } from "@nestjs/testing";
import request from "supertest";

import { AppModule } from "../../src/app.module";

describe("Control Plane skeleton (e2e)", () => {
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

  it("installs a GitHub App integration and exposes tenant-scoped repository bindings", async () => {
    const install = await request(app.getHttpServer())
      .post("/api/integrations/github/install")
      .send({
        tenantId: "tenant_alpha",
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
      })
      .expect(201);

    expect(install.body).toMatchObject({
      provider: "GITHUB",
      integrationType: "GITHUB_APP",
      tenantId: "tenant_alpha",
      status: "ACTIVE"
    });
    expect(JSON.stringify(install.body)).not.toMatch(/token|secret/i);

    const integrations = await request(app.getHttpServer())
      .get("/api/integrations")
      .query({ tenantId: "tenant_alpha" })
      .expect(200);

    expect(integrations.body).toHaveLength(1);
    expect(integrations.body[0].id).toBe(install.body.id);

    const repositories = await request(app.getHttpServer())
      .get("/api/repository-bindings")
      .query({ tenantId: "tenant_alpha" })
      .expect(200);

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

  it("creates scan requests with canonical keys and risk-based isolation escalation", async () => {
    const install = await request(app.getHttpServer())
      .post("/api/integrations/gitlab/install")
      .send({
        tenantId: "tenant_beta",
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

    const repositories = await request(app.getHttpServer())
      .get("/api/repository-bindings")
      .query({ tenantId: "tenant_beta" })
      .expect(200);

    const repositoryBindingId = repositories.body[0].id;

    const scan = await request(app.getHttpServer())
      .post("/api/scan-requests")
      .send({
        tenantId: "tenant_beta",
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
      })
      .expect(201);

    expect(scan.body).toMatchObject({
      tenantId: "tenant_beta",
      repositoryBindingId,
      lane: "FAST",
      targetRef: "refs/merge-requests/7/head",
      commitSha: "abcdef123",
      policyVersion: "policy-2026-04-12",
      scannerSetVersion: "scanner-set-v1",
      canonicalKey: `tenant_beta:${repositoryBindingId}:FAST:refs/merge-requests/7/head:abcdef123:policy-2026-04-12:scanner-set-v1`,
      isolationClass: "HARDENED",
      status: "QUEUED"
    });

    const status = await request(app.getHttpServer())
      .get(`/api/scan-requests/${scan.body.id}`)
      .expect(200);

    expect(status.body.id).toBe(scan.body.id);
    expect(status.body.canonicalKey).toBe(scan.body.canonicalKey);
    expect(install.body.provider).toBe("GITLAB");
  });
});
