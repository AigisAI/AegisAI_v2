import { INestApplication } from "@nestjs/common";
import { Test } from "@nestjs/testing";
import request from "supertest";

describe("Control Plane skeleton (e2e)", () => {
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

    const [{ AppModule }, { GithubAppInstallationClient }, { PrismaService }] = await Promise.all([
      import("../../src/app.module"),
      import("../../src/control-plane/github-app-installation.client"),
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
      .overrideProvider(GithubAppInstallationClient)
      .useValue({
        listInstallationRepositories: jest.fn().mockResolvedValue([
          {
            providerRepoId: "3003",
            fullName: "acme/runtime-bound",
            defaultBranch: "main",
            isPrivate: true
          }
        ])
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

    const installData = dataOf<Record<string, unknown>>(install.body);

    expect(installData).toMatchObject({
      provider: "GITHUB",
      integrationType: "GITHUB_APP",
      tenantId: "tenant_alpha",
      status: "ACTIVE"
    });
    expect(JSON.stringify(installData)).not.toMatch(/token|secret/i);

    const integrations = await request(app.getHttpServer())
      .get("/api/integrations")
      .query({ tenantId: "tenant_alpha" })
      .expect(200);

    const integrationsData = dataOf<Array<Record<string, unknown>>>(integrations.body);

    expect(integrationsData).toHaveLength(1);
    expect(integrationsData[0].id).toBe(installData.id);

    const repositories = await request(app.getHttpServer())
      .get("/api/repository-bindings")
      .query({ tenantId: "tenant_alpha" })
      .expect(200);

    const repositoriesData = dataOf<Array<Record<string, unknown>>>(repositories.body);

    expect(repositoriesData).toEqual([
      expect.objectContaining({
        tenantId: "tenant_alpha",
        scmIntegrationId: installData.id,
        providerRepoId: "1001",
        fullName: "acme/payments",
        defaultBranch: "main",
        isPrivate: true
      })
    ]);
  });

  it("loads GitHub App installation repositories when install payload omits repository bindings", async () => {
    const install = await request(app.getHttpServer())
      .post("/api/integrations/github/install")
      .send({
        tenantId: "tenant_github_app",
        externalInstallationId: "98765",
        repoReadPrincipalId: "github-app-installation:98765:repo-read",
        commentWritePrincipalId: "github-app-installation:98765:comment-write"
      })
      .expect(201);

    const installData = dataOf<Record<string, unknown>>(install.body);
    expect(installData).toMatchObject({
      provider: "GITHUB",
      integrationType: "GITHUB_APP",
      tenantId: "tenant_github_app",
      externalInstallationId: "98765",
      status: "ACTIVE"
    });
    expect(JSON.stringify(installData)).not.toMatch(/accessToken|tokenValue|secretValue/i);

    const repositories = await request(app.getHttpServer())
      .get("/api/repository-bindings")
      .query({ tenantId: "tenant_github_app" })
      .expect(200);

    expect(dataOf<Array<Record<string, unknown>>>(repositories.body)).toEqual([
      expect.objectContaining({
        tenantId: "tenant_github_app",
        scmIntegrationId: installData.id,
        providerRepoId: "3003",
        fullName: "acme/runtime-bound",
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

    const repositoryBindingId = dataOf<Array<{ id: string }>>(repositories.body)[0].id;

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

    const scanData = dataOf<Record<string, unknown>>(scan.body);

    expect(scanData).toMatchObject({
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
      .get(`/api/scan-requests/${scanData.id}`)
      .expect(200);

    const statusData = dataOf<Record<string, unknown>>(status.body);

    expect(statusData.id).toBe(scanData.id);
    expect(statusData.canonicalKey).toBe(scanData.canonicalKey);
    expect(dataOf<Record<string, unknown>>(install.body).provider).toBe("GITLAB");
  });
});
