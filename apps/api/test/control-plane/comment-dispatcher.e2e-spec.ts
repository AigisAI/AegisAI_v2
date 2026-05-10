import { INestApplication } from "@nestjs/common";
import { Test } from "@nestjs/testing";
import request from "supertest";

describe("Comment dispatcher boundary API (e2e)", () => {
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

    const [
      { AppModule },
      { GithubAppInstallationClient },
      { GitlabCloudIntegrationClient },
      { PrismaService }
    ] = await Promise.all([
      import("../../src/app.module"),
      import("../../src/control-plane/github-app-installation.client"),
      import("../../src/control-plane/gitlab-cloud-integration.client"),
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
        $queryRawUnsafe: jest.fn().mockResolvedValue([{ result: 1 }]),
        tenant: { upsert: jest.fn().mockResolvedValue({}) },
        scmIntegration: { upsert: jest.fn().mockResolvedValue({}) },
        repositoryBinding: {
          upsert: jest.fn().mockResolvedValue({}),
          deleteMany: jest.fn().mockResolvedValue({ count: 1 })
        },
        auditEvent: { create: jest.fn().mockResolvedValue({}) }
      })
      .overrideProvider(GithubAppInstallationClient)
      .useValue({
        listInstallationRepositories: jest.fn().mockResolvedValue([])
      })
      .overrideProvider(GitlabCloudIntegrationClient)
      .useValue({
        listIntegrationRepositories: jest.fn().mockResolvedValue([])
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

  async function installRepositoryBinding(input: {
    tenantId: string;
    provider: "github" | "gitlab";
    commentWritePrincipalId?: string;
  }): Promise<Record<string, unknown>> {
    await request(app.getHttpServer())
      .post(`/api/integrations/${input.provider}/install`)
      .send({
        tenantId: input.tenantId,
        externalInstallationId: `${input.provider}-comment-installation`,
        repoReadPrincipalId: `${input.provider}:repo-read`,
        commentWritePrincipalId: input.commentWritePrincipalId,
        repositories: [
          {
            providerRepoId: `${input.provider}-repo-1`,
            fullName: `acme/${input.provider}-comment-target`,
            defaultBranch: "main",
            isPrivate: true
          }
        ]
      })
      .expect(201);

    const repositories = await request(app.getHttpServer())
      .get("/api/repository-bindings")
      .query({ tenantId: input.tenantId })
      .expect(200);

    return dataOf<Array<Record<string, unknown>>>(repositories.body)[0];
  }

  function dispatchRequest(input: {
    tenantId: string;
    repositoryBindingId: unknown;
    policyCommentAllowed: boolean;
  }) {
    return {
      tenantId: input.tenantId,
      repositoryBindingId: input.repositoryBindingId,
      targetRef: "refs/pull/42/head",
      commitSha: "abc123comment",
      policyDecision: {
        id: "policy_decision_comment_1",
        tenantId: input.tenantId,
        scanRequestId: "scan_request_comment_1",
        findingId: "finding_comment_1",
        enforcementAction: input.policyCommentAllowed ? "WARN" : "DASHBOARD_ONLY",
        commentAllowed: input.policyCommentAllowed,
        dashboardVisible: true,
        ticketRequested: false,
        blockRequested: false,
        reasonCodes: ["SEVERITY_HIGH"],
        requiredCoverage: ["OPENGREP", "TRIVY", "SYFT"],
        waiverApplied: false,
        staleSuppressed: false,
        aiAdvisoryVisible: false
      },
      finding: {
        id: "finding_comment_1",
        tenantId: input.tenantId,
        scanRequestId: "scan_request_comment_1",
        scannerRunId: "scanner_run_comment_1",
        title: "Unsafe template injection",
        severity: "HIGH",
        scannerProvenance: "OPENGREP",
        filePath: "src/template.ts",
        lineStart: 42,
        status: "OPEN"
      }
    };
  }

  it("creates a metadata-only dispatch plan through the Control Plane comment-write principal", async () => {
    const repositoryBinding = await installRepositoryBinding({
      tenantId: "tenant_comment_dispatch",
      provider: "github",
      commentWritePrincipalId: "github-app-installation:comment-write"
    });

    const response = await request(app.getHttpServer())
      .post("/api/comment-dispatches/plan")
      .send(
        dispatchRequest({
          tenantId: "tenant_comment_dispatch",
          repositoryBindingId: repositoryBinding.id,
          policyCommentAllowed: true
        })
      )
      .expect(201);

    expect(dataOf<Record<string, unknown>>(response.body)).toEqual({
      id: "comment_dispatch_plan_1",
      tenantId: "tenant_comment_dispatch",
      repositoryBindingId: repositoryBinding.id,
      provider: "GITHUB",
      providerRepoId: "github-repo-1",
      commentWritePrincipalId: "github-app-installation:comment-write",
      policyDecisionId: "policy_decision_comment_1",
      findingId: "finding_comment_1",
      targetRef: "refs/pull/42/head",
      commitSha: "abc123comment",
      dispatchAllowed: true
    });
    expect(JSON.stringify(response.body)).not.toMatch(
      /accessToken|refreshToken|tokenValue|secretValue|sourceArchive|fullRepository|rawScannerPayload|repoReadPrincipalId|integrationAdminPrincipalId/i
    );
  });

  it("records tenant-scoped audit events for dispatch planning without exposing source or credential fields", async () => {
    const repositoryBinding = await installRepositoryBinding({
      tenantId: "tenant_comment_audit",
      provider: "github",
      commentWritePrincipalId: "github-app-installation:comment-write-audit"
    });

    const response = await request(app.getHttpServer())
      .post("/api/comment-dispatches/plan")
      .send(
        dispatchRequest({
          tenantId: "tenant_comment_audit",
          repositoryBindingId: repositoryBinding.id,
          policyCommentAllowed: true
        })
      )
      .expect(201);
    const plan = dataOf<Record<string, unknown>>(response.body);

    const auditEventsResponse = await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({ tenantId: "tenant_comment_audit" })
      .expect(200);

    expect(dataOf<Array<Record<string, unknown>>>(auditEventsResponse.body)).toEqual([
      expect.objectContaining({
        id: expect.stringMatching(/^audit_event_\d+$/),
        tenantId: "tenant_comment_audit",
        eventType: "comment_dispatch.planned",
        actor: "comment-dispatcher",
        targetType: "comment_dispatch_plan",
        targetId: plan.id,
        occurredAt: "1970-01-01T00:00:00.000Z",
        metadata: {
          repositoryBindingId: repositoryBinding.id,
          provider: "GITHUB",
          providerRepoId: "github-repo-1",
          policyDecisionId: "policy_decision_comment_1",
          findingId: "finding_comment_1",
          targetRef: "refs/pull/42/head",
          commitSha: "abc123comment",
          commentWritePrincipalId: "github-app-installation:comment-write-audit"
        }
      })
    ]);
    expect(JSON.stringify(auditEventsResponse.body)).not.toMatch(
      /accessToken|refreshToken|tokenValue|secretValue|sourceArchive|fullRepository|rawScannerPayload|repoReadPrincipalId|integrationAdminPrincipalId/i
    );

    const otherTenantResponse = await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({ tenantId: "tenant_comment_audit_other" })
      .expect(200);

    expect(dataOf<Array<Record<string, unknown>>>(otherTenantResponse.body)).toEqual([]);
  });

  it("rejects dispatch when policy forbids comments or no comment-write principal exists", async () => {
    const allowedBinding = await installRepositoryBinding({
      tenantId: "tenant_comment_policy_denied",
      provider: "github",
      commentWritePrincipalId: "github-app-installation:comment-write-denied"
    });

    await request(app.getHttpServer())
      .post("/api/comment-dispatches/plan")
      .send(
        dispatchRequest({
          tenantId: "tenant_comment_policy_denied",
          repositoryBindingId: allowedBinding.id,
          policyCommentAllowed: false
        })
      )
      .expect(400);

    const missingPrincipalBinding = await installRepositoryBinding({
      tenantId: "tenant_comment_missing_principal",
      provider: "gitlab"
    });

    await request(app.getHttpServer())
      .post("/api/comment-dispatches/plan")
      .send(
        dispatchRequest({
          tenantId: "tenant_comment_missing_principal",
          repositoryBindingId: missingPrincipalBinding.id,
          policyCommentAllowed: true
        })
      )
      .expect(400);
  });

  it("rejects dispatch payloads that include source, credentials, or policy override authority", async () => {
    const repositoryBinding = await installRepositoryBinding({
      tenantId: "tenant_comment_sensitive",
      provider: "github",
      commentWritePrincipalId: "github-app-installation:comment-write-sensitive"
    });

    await request(app.getHttpServer())
      .post("/api/comment-dispatches/plan")
      .send({
        ...dispatchRequest({
          tenantId: "tenant_comment_sensitive",
          repositoryBindingId: repositoryBinding.id,
          policyCommentAllowed: true
        }),
        accessToken: "ghs_secret"
      })
      .expect(400);

    await request(app.getHttpServer())
      .post("/api/comment-dispatches/plan")
      .send({
        ...dispatchRequest({
          tenantId: "tenant_comment_sensitive",
          repositoryBindingId: repositoryBinding.id,
          policyCommentAllowed: true
        }),
        fullRepository: "all source"
      })
      .expect(400);
  });
});
