import { INestApplication } from "@nestjs/common";
import { Test } from "@nestjs/testing";
import request from "supertest";
import { SessionAuthGuard } from '../../src/auth/guards/session-auth.guard';
import { InternalServiceGuard } from '../../src/common/security/internal-service.guard';
import { TestInternalServiceGuard, TestSessionAuthGuard } from '../support/security-guards';

describe("Comment dispatcher boundary API (e2e)", () => {
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
      idempotencyKey: [
        "tenant_comment_dispatch",
        repositoryBinding.id,
        "policy_decision_comment_1",
        "finding_comment_1",
        "refs/pull/42/head",
        "abc123comment"
      ].join(":"),
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

  it("returns the existing dispatch plan and avoids duplicate audit events for idempotent retries", async () => {
    const repositoryBinding = await installRepositoryBinding({
      tenantId: "tenant_comment_idempotent",
      provider: "github",
      commentWritePrincipalId: "github-app-installation:comment-write-idempotent"
    });
    const body = dispatchRequest({
      tenantId: "tenant_comment_idempotent",
      repositoryBindingId: repositoryBinding.id,
      policyCommentAllowed: true
    });

    const firstResponse = await request(app.getHttpServer())
      .post("/api/comment-dispatches/plan")
      .send(body)
      .expect(201);
    const secondResponse = await request(app.getHttpServer())
      .post("/api/comment-dispatches/plan")
      .send(body)
      .expect(201);

    expect(dataOf<Record<string, unknown>>(secondResponse.body)).toEqual(
      dataOf<Record<string, unknown>>(firstResponse.body)
    );
    expect(dataOf<Record<string, unknown>>(firstResponse.body)).toMatchObject({
      idempotencyKey: [
        "tenant_comment_idempotent",
        repositoryBinding.id,
        "policy_decision_comment_1",
        "finding_comment_1",
        "refs/pull/42/head",
        "abc123comment"
      ].join(":")
    });

    const auditEventsResponse = await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({ tenantId: "tenant_comment_idempotent" })
      .expect(200);

    expect(dataOf<Array<Record<string, unknown>>>(auditEventsResponse.body)).toHaveLength(1);
  });

  it("enqueues dispatch plans into a tenant-scoped metadata outbox without publishing external comments", async () => {
    const repositoryBinding = await installRepositoryBinding({
      tenantId: "tenant_comment_outbox",
      provider: "github",
      commentWritePrincipalId: "github-app-installation:comment-write-outbox"
    });

    const planResponse = await request(app.getHttpServer())
      .post("/api/comment-dispatches/plan")
      .send(
        dispatchRequest({
          tenantId: "tenant_comment_outbox",
          repositoryBindingId: repositoryBinding.id,
          policyCommentAllowed: true
        })
      )
      .expect(201);
    const plan = dataOf<Record<string, unknown>>(planResponse.body);

    const firstEnqueueResponse = await request(app.getHttpServer())
      .post("/api/comment-dispatches/enqueue")
      .send({ tenantId: "tenant_comment_outbox", planId: plan.id })
      .expect(201);
    const secondEnqueueResponse = await request(app.getHttpServer())
      .post("/api/comment-dispatches/enqueue")
      .send({ tenantId: "tenant_comment_outbox", planId: plan.id })
      .expect(201);

    expect(dataOf<Record<string, unknown>>(secondEnqueueResponse.body)).toEqual(
      dataOf<Record<string, unknown>>(firstEnqueueResponse.body)
    );
    expect(dataOf<Record<string, unknown>>(firstEnqueueResponse.body)).toEqual(
      expect.objectContaining({
        id: expect.stringMatching(/^comment_dispatch_outbox_\d+$/),
        tenantId: "tenant_comment_outbox",
        planId: plan.id,
        idempotencyKey: plan.idempotencyKey,
        repositoryBindingId: repositoryBinding.id,
        provider: "GITHUB",
        providerRepoId: "github-repo-1",
        commentWritePrincipalId: "github-app-installation:comment-write-outbox",
        policyDecisionId: "policy_decision_comment_1",
        findingId: "finding_comment_1",
        targetRef: "refs/pull/42/head",
        commitSha: "abc123comment",
        status: "PENDING",
        enqueuedAt: "1970-01-01T00:00:00.000Z"
      })
    );
    expect(JSON.stringify(firstEnqueueResponse.body)).not.toMatch(
      /accessToken|refreshToken|tokenValue|secretValue|sourceArchive|fullRepository|rawScannerPayload|repoReadPrincipalId|integrationAdminPrincipalId|externalCommentId/i
    );

    const outboxResponse = await request(app.getHttpServer())
      .get("/api/comment-dispatches/outbox")
      .query({ tenantId: "tenant_comment_outbox" })
      .expect(200);

    expect(dataOf<Array<Record<string, unknown>>>(outboxResponse.body)).toEqual([
      dataOf<Record<string, unknown>>(firstEnqueueResponse.body)
    ]);

    const otherTenantResponse = await request(app.getHttpServer())
      .get("/api/comment-dispatches/outbox")
      .query({ tenantId: "tenant_comment_outbox_other" })
      .expect(200);

    expect(dataOf<Array<Record<string, unknown>>>(otherTenantResponse.body)).toEqual([]);

    await request(app.getHttpServer())
      .post("/api/comment-dispatches/enqueue")
      .send({ tenantId: "tenant_comment_outbox", planId: plan.id, accessToken: "ghs_secret" })
      .expect(400);
  });

  it("records one metadata-only audit event when a dispatch plan is enqueued", async () => {
    const repositoryBinding = await installRepositoryBinding({
      tenantId: "tenant_comment_outbox_audit",
      provider: "github",
      commentWritePrincipalId: "github-app-installation:comment-write-outbox-audit"
    });

    const planResponse = await request(app.getHttpServer())
      .post("/api/comment-dispatches/plan")
      .send(
        dispatchRequest({
          tenantId: "tenant_comment_outbox_audit",
          repositoryBindingId: repositoryBinding.id,
          policyCommentAllowed: true
        })
      )
      .expect(201);
    const plan = dataOf<Record<string, unknown>>(planResponse.body);

    const firstEnqueueResponse = await request(app.getHttpServer())
      .post("/api/comment-dispatches/enqueue")
      .send({ tenantId: "tenant_comment_outbox_audit", planId: plan.id })
      .expect(201);
    await request(app.getHttpServer())
      .post("/api/comment-dispatches/enqueue")
      .send({ tenantId: "tenant_comment_outbox_audit", planId: plan.id })
      .expect(201);
    const outboxItem = dataOf<Record<string, unknown>>(firstEnqueueResponse.body);

    const auditEventsResponse = await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({ tenantId: "tenant_comment_outbox_audit" })
      .expect(200);
    const auditEvents = dataOf<Array<Record<string, unknown>>>(auditEventsResponse.body);

    expect(auditEvents).toHaveLength(2);
    expect(auditEvents.map((event) => event.eventType)).toEqual([
      "comment_dispatch.planned",
      "comment_dispatch.enqueued"
    ]);
    expect(auditEvents[1]).toEqual(
      expect.objectContaining({
        id: expect.stringMatching(/^audit_event_\d+$/),
        tenantId: "tenant_comment_outbox_audit",
        eventType: "comment_dispatch.enqueued",
        actor: "comment-dispatcher",
        targetType: "comment_dispatch_outbox_item",
        targetId: outboxItem.id,
        occurredAt: "1970-01-01T00:00:00.000Z",
        metadata: {
          outboxItemId: outboxItem.id,
          planId: plan.id,
          idempotencyKey: plan.idempotencyKey,
          repositoryBindingId: repositoryBinding.id,
          provider: "GITHUB",
          providerRepoId: "github-repo-1",
          policyDecisionId: "policy_decision_comment_1",
          findingId: "finding_comment_1",
          targetRef: "refs/pull/42/head",
          commitSha: "abc123comment",
          commentWritePrincipalId: "github-app-installation:comment-write-outbox-audit"
        }
      })
    );
    expect(JSON.stringify(auditEventsResponse.body)).not.toMatch(
      /accessToken|refreshToken|tokenValue|secretValue|sourceArchive|fullRepository|rawScannerPayload|repoReadPrincipalId|integrationAdminPrincipalId|externalCommentId/i
    );
  });

  it("updates outbox items to failure states without accepting publish or external comment authority", async () => {
    const repositoryBinding = await installRepositoryBinding({
      tenantId: "tenant_comment_outbox_status",
      provider: "github",
      commentWritePrincipalId: "github-app-installation:comment-write-outbox-status"
    });

    const planResponse = await request(app.getHttpServer())
      .post("/api/comment-dispatches/plan")
      .send(
        dispatchRequest({
          tenantId: "tenant_comment_outbox_status",
          repositoryBindingId: repositoryBinding.id,
          policyCommentAllowed: true
        })
      )
      .expect(201);
    const plan = dataOf<Record<string, unknown>>(planResponse.body);

    const enqueueResponse = await request(app.getHttpServer())
      .post("/api/comment-dispatches/enqueue")
      .send({ tenantId: "tenant_comment_outbox_status", planId: plan.id })
      .expect(201);
    const outboxItem = dataOf<Record<string, unknown>>(enqueueResponse.body);
    const claimResponse = await request(app.getHttpServer())
      .post("/api/comment-dispatches/outbox/claim")
      .send({
        tenantId: "tenant_comment_outbox_status",
        workerId: "comment-dispatch-worker-status",
        leaseSeconds: 300
      })
      .expect(201);
    const claimedOutboxItem = dataOf<Record<string, unknown>>(claimResponse.body);

    const failedResponse = await request(app.getHttpServer())
      .patch(`/api/comment-dispatches/outbox/${outboxItem.id}/status`)
      .send({
        tenantId: "tenant_comment_outbox_status",
        workerId: "comment-dispatch-worker-status",
        status: "FAILED",
        statusReason: "SCM_RATE_LIMIT"
      })
      .expect(200);

    expect(dataOf<Record<string, unknown>>(failedResponse.body)).toEqual({
      ...claimedOutboxItem,
      status: "FAILED",
      statusReason: "SCM_RATE_LIMIT",
      statusUpdatedAt: "1970-01-01T00:00:00.000Z"
    });
    expect(JSON.stringify(failedResponse.body)).not.toMatch(
      /accessToken|refreshToken|tokenValue|secretValue|sourceArchive|fullRepository|rawScannerPayload|repoReadPrincipalId|integrationAdminPrincipalId|externalCommentId/i
    );

    const outboxResponse = await request(app.getHttpServer())
      .get("/api/comment-dispatches/outbox")
      .query({ tenantId: "tenant_comment_outbox_status" })
      .expect(200);

    expect(dataOf<Array<Record<string, unknown>>>(outboxResponse.body)).toEqual([
      dataOf<Record<string, unknown>>(failedResponse.body)
    ]);

    await request(app.getHttpServer())
      .patch(`/api/comment-dispatches/outbox/${outboxItem.id}/status`)
      .send({
        tenantId: "tenant_comment_outbox_status",
        workerId: "comment-dispatch-worker-status",
        status: "PUBLISHED",
        externalCommentId: "github-comment-1"
      })
      .expect(400);

    await request(app.getHttpServer())
      .patch(`/api/comment-dispatches/outbox/${outboxItem.id}/status`)
      .send({
        tenantId: "tenant_comment_outbox_other",
        workerId: "comment-dispatch-worker-status",
        status: "CANCELED",
        statusReason: "TENANT_MISMATCH"
      })
      .expect(404);
  });

  it("records one metadata-only audit event when an outbox item enters a failure state", async () => {
    const repositoryBinding = await installRepositoryBinding({
      tenantId: "tenant_comment_outbox_status_audit",
      provider: "github",
      commentWritePrincipalId: "github-app-installation:comment-write-outbox-status-audit"
    });

    const planResponse = await request(app.getHttpServer())
      .post("/api/comment-dispatches/plan")
      .send(
        dispatchRequest({
          tenantId: "tenant_comment_outbox_status_audit",
          repositoryBindingId: repositoryBinding.id,
          policyCommentAllowed: true
        })
      )
      .expect(201);
    const plan = dataOf<Record<string, unknown>>(planResponse.body);

    const enqueueResponse = await request(app.getHttpServer())
      .post("/api/comment-dispatches/enqueue")
      .send({ tenantId: "tenant_comment_outbox_status_audit", planId: plan.id })
      .expect(201);
    const outboxItem = dataOf<Record<string, unknown>>(enqueueResponse.body);
    await request(app.getHttpServer())
      .post("/api/comment-dispatches/outbox/claim")
      .send({
        tenantId: "tenant_comment_outbox_status_audit",
        workerId: "comment-dispatch-worker-status-audit",
        leaseSeconds: 300
      })
      .expect(201);

    const failedPayload = {
      tenantId: "tenant_comment_outbox_status_audit",
      workerId: "comment-dispatch-worker-status-audit",
      status: "FAILED",
      statusReason: "SCM_RATE_LIMIT"
    };
    const firstFailedResponse = await request(app.getHttpServer())
      .patch(`/api/comment-dispatches/outbox/${outboxItem.id}/status`)
      .send(failedPayload)
      .expect(200);
    await request(app.getHttpServer())
      .patch(`/api/comment-dispatches/outbox/${outboxItem.id}/status`)
      .send(failedPayload)
      .expect(200);
    const failedOutboxItem = dataOf<Record<string, unknown>>(firstFailedResponse.body);

    const auditEventsResponse = await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({ tenantId: "tenant_comment_outbox_status_audit" })
      .expect(200);
    const auditEvents = dataOf<Array<Record<string, unknown>>>(auditEventsResponse.body);

    expect(auditEvents).toHaveLength(4);
    expect(auditEvents.map((event) => event.eventType)).toEqual([
      "comment_dispatch.planned",
      "comment_dispatch.enqueued",
      "comment_dispatch.outbox_claimed",
      "comment_dispatch.outbox_status_updated"
    ]);
    expect(auditEvents[3]).toEqual(
      expect.objectContaining({
        id: expect.stringMatching(/^audit_event_\d+$/),
        tenantId: "tenant_comment_outbox_status_audit",
        eventType: "comment_dispatch.outbox_status_updated",
        actor: "comment-dispatcher",
        targetType: "comment_dispatch_outbox_item",
        targetId: outboxItem.id,
        occurredAt: "1970-01-01T00:00:00.000Z",
        metadata: {
          outboxItemId: outboxItem.id,
          planId: plan.id,
          previousStatus: "PENDING",
          nextStatus: "FAILED",
          statusReason: "SCM_RATE_LIMIT",
          statusUpdatedAt: failedOutboxItem.statusUpdatedAt,
          workerId: "comment-dispatch-worker-status-audit",
          repositoryBindingId: repositoryBinding.id,
          provider: "GITHUB",
          findingId: "finding_comment_1",
          commitSha: "abc123comment"
        }
      })
    );
    expect(JSON.stringify(auditEventsResponse.body)).not.toMatch(
      /accessToken|refreshToken|tokenValue|secretValue|sourceArchive|fullRepository|rawScannerPayload|repoReadPrincipalId|integrationAdminPrincipalId|externalCommentId/i
    );
  });

  it("claims one pending outbox item for a dispatcher worker without publishing external comments", async () => {
    const repositoryBinding = await installRepositoryBinding({
      tenantId: "tenant_comment_outbox_claim",
      provider: "github",
      commentWritePrincipalId: "github-app-installation:comment-write-outbox-claim"
    });

    const planResponse = await request(app.getHttpServer())
      .post("/api/comment-dispatches/plan")
      .send(
        dispatchRequest({
          tenantId: "tenant_comment_outbox_claim",
          repositoryBindingId: repositoryBinding.id,
          policyCommentAllowed: true
        })
      )
      .expect(201);
    const plan = dataOf<Record<string, unknown>>(planResponse.body);

    const enqueueResponse = await request(app.getHttpServer())
      .post("/api/comment-dispatches/enqueue")
      .send({ tenantId: "tenant_comment_outbox_claim", planId: plan.id })
      .expect(201);
    const outboxItem = dataOf<Record<string, unknown>>(enqueueResponse.body);

    const claimPayload = {
      tenantId: "tenant_comment_outbox_claim",
      workerId: "comment-dispatch-worker-1",
      leaseSeconds: 300
    };
    const firstClaimResponse = await request(app.getHttpServer())
      .post("/api/comment-dispatches/outbox/claim")
      .send(claimPayload)
      .expect(201);
    const secondClaimResponse = await request(app.getHttpServer())
      .post("/api/comment-dispatches/outbox/claim")
      .send(claimPayload)
      .expect(201);
    const otherWorkerClaimResponse = await request(app.getHttpServer())
      .post("/api/comment-dispatches/outbox/claim")
      .send({
        tenantId: "tenant_comment_outbox_claim",
        workerId: "comment-dispatch-worker-2",
        leaseSeconds: 300
      })
      .expect(201);
    const otherTenantClaimResponse = await request(app.getHttpServer())
      .post("/api/comment-dispatches/outbox/claim")
      .send({
        tenantId: "tenant_comment_outbox_claim_other",
        workerId: "comment-dispatch-worker-1",
        leaseSeconds: 300
      })
      .expect(201);

    expect(dataOf<Record<string, unknown>>(firstClaimResponse.body)).toEqual({
      ...outboxItem,
      claimedBy: "comment-dispatch-worker-1",
      claimedAt: "1970-01-01T00:00:00.000Z",
      leaseExpiresAt: "1970-01-01T00:05:00.000Z"
    });
    expect(dataOf<Record<string, unknown>>(secondClaimResponse.body)).toEqual(
      dataOf<Record<string, unknown>>(firstClaimResponse.body)
    );
    expect(dataOf<unknown>(otherWorkerClaimResponse.body)).toBeNull();
    expect(dataOf<unknown>(otherTenantClaimResponse.body)).toBeNull();
    expect(JSON.stringify(firstClaimResponse.body)).not.toMatch(
      /accessToken|refreshToken|tokenValue|secretValue|sourceArchive|fullRepository|rawScannerPayload|repoReadPrincipalId|integrationAdminPrincipalId|externalCommentId/i
    );

    const auditEventsResponse = await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({ tenantId: "tenant_comment_outbox_claim" })
      .expect(200);
    const auditEvents = dataOf<Array<Record<string, unknown>>>(auditEventsResponse.body);

    expect(auditEvents).toHaveLength(3);
    expect(auditEvents.map((event) => event.eventType)).toEqual([
      "comment_dispatch.planned",
      "comment_dispatch.enqueued",
      "comment_dispatch.outbox_claimed"
    ]);
    expect(auditEvents[2]).toEqual(
      expect.objectContaining({
        id: expect.stringMatching(/^audit_event_\d+$/),
        tenantId: "tenant_comment_outbox_claim",
        eventType: "comment_dispatch.outbox_claimed",
        actor: "comment-dispatcher",
        targetType: "comment_dispatch_outbox_item",
        targetId: outboxItem.id,
        occurredAt: "1970-01-01T00:00:00.000Z",
        metadata: {
          outboxItemId: outboxItem.id,
          planId: plan.id,
          workerId: "comment-dispatch-worker-1",
          claimedAt: "1970-01-01T00:00:00.000Z",
          leaseExpiresAt: "1970-01-01T00:05:00.000Z",
          repositoryBindingId: repositoryBinding.id,
          provider: "GITHUB",
          findingId: "finding_comment_1",
          commitSha: "abc123comment"
        }
      })
    );
    expect(JSON.stringify(auditEventsResponse.body)).not.toMatch(
      /accessToken|refreshToken|tokenValue|secretValue|sourceArchive|fullRepository|rawScannerPayload|repoReadPrincipalId|integrationAdminPrincipalId|externalCommentId/i
    );

    await request(app.getHttpServer())
      .post("/api/comment-dispatches/outbox/claim")
      .send({ ...claimPayload, accessToken: "ghs_secret" })
      .expect(400);
  });

  it("rejects invalid or excessive outbox claim lease durations", async () => {
    const repositoryBinding = await installRepositoryBinding({
      tenantId: "tenant_comment_outbox_claim_lease",
      provider: "github",
      commentWritePrincipalId: "github-app-installation:comment-write-outbox-claim-lease"
    });

    const planResponse = await request(app.getHttpServer())
      .post("/api/comment-dispatches/plan")
      .send(
        dispatchRequest({
          tenantId: "tenant_comment_outbox_claim_lease",
          repositoryBindingId: repositoryBinding.id,
          policyCommentAllowed: true
        })
      )
      .expect(201);
    const plan = dataOf<Record<string, unknown>>(planResponse.body);

    await request(app.getHttpServer())
      .post("/api/comment-dispatches/enqueue")
      .send({ tenantId: "tenant_comment_outbox_claim_lease", planId: plan.id })
      .expect(201);

    for (const leaseSeconds of [0, -1, 0.5, 901]) {
      await request(app.getHttpServer())
        .post("/api/comment-dispatches/outbox/claim")
        .send({
          tenantId: "tenant_comment_outbox_claim_lease",
          workerId: "comment-dispatch-worker-lease",
          leaseSeconds
        })
        .expect(400);
    }

    const claimResponse = await request(app.getHttpServer())
      .post("/api/comment-dispatches/outbox/claim")
      .send({
        tenantId: "tenant_comment_outbox_claim_lease",
        workerId: "comment-dispatch-worker-lease",
        leaseSeconds: 900
      })
      .expect(201);

    expect(dataOf<Record<string, unknown>>(claimResponse.body)).toEqual(
      expect.objectContaining({
        tenantId: "tenant_comment_outbox_claim_lease",
        claimedBy: "comment-dispatch-worker-lease",
        claimedAt: "1970-01-01T00:00:00.000Z",
        leaseExpiresAt: "1970-01-01T00:15:00.000Z"
      })
    );
    expect(JSON.stringify(claimResponse.body)).not.toMatch(
      /accessToken|refreshToken|tokenValue|secretValue|sourceArchive|fullRepository|rawScannerPayload|repoReadPrincipalId|integrationAdminPrincipalId|externalCommentId/i
    );
  });

  it("renews an active outbox claim lease only for the claiming dispatcher worker", async () => {
    const repositoryBinding = await installRepositoryBinding({
      tenantId: "tenant_comment_outbox_lease_renewal",
      provider: "github",
      commentWritePrincipalId: "github-app-installation:comment-write-lease-renewal"
    });

    const planResponse = await request(app.getHttpServer())
      .post("/api/comment-dispatches/plan")
      .send(
        dispatchRequest({
          tenantId: "tenant_comment_outbox_lease_renewal",
          repositoryBindingId: repositoryBinding.id,
          policyCommentAllowed: true
        })
      )
      .expect(201);
    const plan = dataOf<Record<string, unknown>>(planResponse.body);

    const enqueueResponse = await request(app.getHttpServer())
      .post("/api/comment-dispatches/enqueue")
      .send({ tenantId: "tenant_comment_outbox_lease_renewal", planId: plan.id })
      .expect(201);
    const outboxItem = dataOf<Record<string, unknown>>(enqueueResponse.body);

    await request(app.getHttpServer())
      .patch(`/api/comment-dispatches/outbox/${outboxItem.id}/lease`)
      .send({
        tenantId: "tenant_comment_outbox_lease_renewal",
        workerId: "comment-dispatch-worker-lease-renewal",
        leaseSeconds: 300
      })
      .expect(400);

    const claimResponse = await request(app.getHttpServer())
      .post("/api/comment-dispatches/outbox/claim")
      .send({
        tenantId: "tenant_comment_outbox_lease_renewal",
        workerId: "comment-dispatch-worker-lease-renewal",
        leaseSeconds: 300
      })
      .expect(201);
    const claimedOutboxItem = dataOf<Record<string, unknown>>(claimResponse.body);

    await request(app.getHttpServer())
      .patch(`/api/comment-dispatches/outbox/${outboxItem.id}/lease`)
      .send({
        tenantId: "tenant_comment_outbox_lease_renewal",
        workerId: "comment-dispatch-worker-other",
        leaseSeconds: 600
      })
      .expect(400);

    await request(app.getHttpServer())
      .patch(`/api/comment-dispatches/outbox/${outboxItem.id}/lease`)
      .send({
        tenantId: "tenant_comment_outbox_lease_renewal",
        workerId: "comment-dispatch-worker-lease-renewal",
        leaseSeconds: 901
      })
      .expect(400);

    const renewalResponse = await request(app.getHttpServer())
      .patch(`/api/comment-dispatches/outbox/${outboxItem.id}/lease`)
      .send({
        tenantId: "tenant_comment_outbox_lease_renewal",
        workerId: "comment-dispatch-worker-lease-renewal",
        leaseSeconds: 600
      })
      .expect(200);

    expect(dataOf<Record<string, unknown>>(renewalResponse.body)).toEqual({
      ...claimedOutboxItem,
      leaseExpiresAt: "1970-01-01T00:10:00.000Z"
    });
    expect(JSON.stringify(renewalResponse.body)).not.toMatch(
      /accessToken|refreshToken|tokenValue|secretValue|sourceArchive|fullRepository|rawScannerPayload|repoReadPrincipalId|integrationAdminPrincipalId|externalCommentId/i
    );

    const auditEventsResponse = await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({ tenantId: "tenant_comment_outbox_lease_renewal" })
      .expect(200);
    const auditEvents = dataOf<Array<Record<string, unknown>>>(auditEventsResponse.body);

    expect(auditEvents.map((event) => event.eventType)).toEqual([
      "comment_dispatch.planned",
      "comment_dispatch.enqueued",
      "comment_dispatch.outbox_claimed",
      "comment_dispatch.outbox_lease_renewed"
    ]);
    expect(auditEvents[3]).toEqual(
      expect.objectContaining({
        eventType: "comment_dispatch.outbox_lease_renewed",
        actor: "comment-dispatcher",
        targetType: "comment_dispatch_outbox_item",
        targetId: outboxItem.id,
        metadata: {
          outboxItemId: outboxItem.id,
          planId: plan.id,
          workerId: "comment-dispatch-worker-lease-renewal",
          claimedAt: "1970-01-01T00:00:00.000Z",
          leaseExpiresAt: "1970-01-01T00:10:00.000Z",
          repositoryBindingId: repositoryBinding.id,
          provider: "GITHUB",
          findingId: "finding_comment_1",
          commitSha: "abc123comment"
        }
      })
    );
    expect(JSON.stringify(auditEventsResponse.body)).not.toMatch(
      /accessToken|refreshToken|tokenValue|secretValue|sourceArchive|fullRepository|rawScannerPayload|repoReadPrincipalId|integrationAdminPrincipalId|externalCommentId/i
    );
  });

  it("requires the active claim owner when a dispatcher worker updates outbox status", async () => {
    const repositoryBinding = await installRepositoryBinding({
      tenantId: "tenant_comment_outbox_status_owner",
      provider: "github",
      commentWritePrincipalId: "github-app-installation:comment-write-status-owner"
    });

    const planResponse = await request(app.getHttpServer())
      .post("/api/comment-dispatches/plan")
      .send(
        dispatchRequest({
          tenantId: "tenant_comment_outbox_status_owner",
          repositoryBindingId: repositoryBinding.id,
          policyCommentAllowed: true
        })
      )
      .expect(201);
    const plan = dataOf<Record<string, unknown>>(planResponse.body);

    const enqueueResponse = await request(app.getHttpServer())
      .post("/api/comment-dispatches/enqueue")
      .send({ tenantId: "tenant_comment_outbox_status_owner", planId: plan.id })
      .expect(201);
    const outboxItem = dataOf<Record<string, unknown>>(enqueueResponse.body);

    await request(app.getHttpServer())
      .patch(`/api/comment-dispatches/outbox/${outboxItem.id}/status`)
      .send({
        tenantId: "tenant_comment_outbox_status_owner",
        workerId: "comment-dispatch-worker-1",
        status: "FAILED",
        statusReason: "UNCLAIMED_STATUS_UPDATE"
      })
      .expect(400);

    await request(app.getHttpServer())
      .post("/api/comment-dispatches/outbox/claim")
      .send({
        tenantId: "tenant_comment_outbox_status_owner",
        workerId: "comment-dispatch-worker-1",
        leaseSeconds: 300
      })
      .expect(201);

    await request(app.getHttpServer())
      .patch(`/api/comment-dispatches/outbox/${outboxItem.id}/status`)
      .send({
        tenantId: "tenant_comment_outbox_status_owner",
        workerId: "comment-dispatch-worker-2",
        status: "FAILED",
        statusReason: "WRONG_WORKER"
      })
      .expect(400);

    const failedResponse = await request(app.getHttpServer())
      .patch(`/api/comment-dispatches/outbox/${outboxItem.id}/status`)
      .send({
        tenantId: "tenant_comment_outbox_status_owner",
        workerId: "comment-dispatch-worker-1",
        status: "FAILED",
        statusReason: "SCM_RATE_LIMIT"
      })
      .expect(200);

    expect(dataOf<Record<string, unknown>>(failedResponse.body)).toEqual(
      expect.objectContaining({
        id: outboxItem.id,
        tenantId: "tenant_comment_outbox_status_owner",
        claimedBy: "comment-dispatch-worker-1",
        status: "FAILED",
        statusReason: "SCM_RATE_LIMIT",
        statusUpdatedAt: "1970-01-01T00:00:00.000Z"
      })
    );
    expect(JSON.stringify(failedResponse.body)).not.toMatch(
      /accessToken|refreshToken|tokenValue|secretValue|sourceArchive|fullRepository|rawScannerPayload|repoReadPrincipalId|integrationAdminPrincipalId|externalCommentId/i
    );

    const auditEventsResponse = await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({ tenantId: "tenant_comment_outbox_status_owner" })
      .expect(200);
    const auditEvents = dataOf<Array<Record<string, unknown>>>(auditEventsResponse.body);

    expect(auditEvents.map((event) => event.eventType)).toEqual([
      "comment_dispatch.planned",
      "comment_dispatch.enqueued",
      "comment_dispatch.outbox_claimed",
      "comment_dispatch.outbox_status_updated"
    ]);
    expect(auditEvents[3]).toEqual(
      expect.objectContaining({
        eventType: "comment_dispatch.outbox_status_updated",
        metadata: expect.objectContaining({
          outboxItemId: outboxItem.id,
          workerId: "comment-dispatch-worker-1",
          previousStatus: "PENDING",
          nextStatus: "FAILED",
          statusReason: "SCM_RATE_LIMIT"
        })
      })
    );
    expect(JSON.stringify(auditEventsResponse.body)).not.toMatch(
      /accessToken|refreshToken|tokenValue|secretValue|sourceArchive|fullRepository|rawScannerPayload|repoReadPrincipalId|integrationAdminPrincipalId|externalCommentId/i
    );
  });

  it("keeps terminal outbox failure states immutable except for exact idempotent retries", async () => {
    const repositoryBinding = await installRepositoryBinding({
      tenantId: "tenant_comment_outbox_status_finality",
      provider: "github",
      commentWritePrincipalId: "github-app-installation:comment-write-status-finality"
    });

    const planResponse = await request(app.getHttpServer())
      .post("/api/comment-dispatches/plan")
      .send(
        dispatchRequest({
          tenantId: "tenant_comment_outbox_status_finality",
          repositoryBindingId: repositoryBinding.id,
          policyCommentAllowed: true
        })
      )
      .expect(201);
    const plan = dataOf<Record<string, unknown>>(planResponse.body);

    const enqueueResponse = await request(app.getHttpServer())
      .post("/api/comment-dispatches/enqueue")
      .send({ tenantId: "tenant_comment_outbox_status_finality", planId: plan.id })
      .expect(201);
    const outboxItem = dataOf<Record<string, unknown>>(enqueueResponse.body);

    await request(app.getHttpServer())
      .post("/api/comment-dispatches/outbox/claim")
      .send({
        tenantId: "tenant_comment_outbox_status_finality",
        workerId: "comment-dispatch-worker-finality",
        leaseSeconds: 300
      })
      .expect(201);

    const failedPayload = {
      tenantId: "tenant_comment_outbox_status_finality",
      workerId: "comment-dispatch-worker-finality",
      status: "FAILED",
      statusReason: "SCM_RATE_LIMIT"
    };
    const firstFailedResponse = await request(app.getHttpServer())
      .patch(`/api/comment-dispatches/outbox/${outboxItem.id}/status`)
      .send(failedPayload)
      .expect(200);
    const retryFailedResponse = await request(app.getHttpServer())
      .patch(`/api/comment-dispatches/outbox/${outboxItem.id}/status`)
      .send(failedPayload)
      .expect(200);

    expect(dataOf<Record<string, unknown>>(retryFailedResponse.body)).toEqual(
      dataOf<Record<string, unknown>>(firstFailedResponse.body)
    );

    await request(app.getHttpServer())
      .patch(`/api/comment-dispatches/outbox/${outboxItem.id}/status`)
      .send({
        tenantId: "tenant_comment_outbox_status_finality",
        workerId: "comment-dispatch-worker-finality",
        status: "FAILED",
        statusReason: "DIFFERENT_FAILURE_REASON"
      })
      .expect(400);

    await request(app.getHttpServer())
      .patch(`/api/comment-dispatches/outbox/${outboxItem.id}/status`)
      .send({
        tenantId: "tenant_comment_outbox_status_finality",
        workerId: "comment-dispatch-worker-finality",
        status: "CANCELED",
        statusReason: "MANUAL_CANCEL_AFTER_FAILURE"
      })
      .expect(400);

    const outboxResponse = await request(app.getHttpServer())
      .get("/api/comment-dispatches/outbox")
      .query({ tenantId: "tenant_comment_outbox_status_finality" })
      .expect(200);

    expect(dataOf<Array<Record<string, unknown>>>(outboxResponse.body)).toEqual([
      dataOf<Record<string, unknown>>(firstFailedResponse.body)
    ]);

    const auditEventsResponse = await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({ tenantId: "tenant_comment_outbox_status_finality" })
      .expect(200);
    const auditEvents = dataOf<Array<Record<string, unknown>>>(auditEventsResponse.body);

    expect(auditEvents.map((event) => event.eventType)).toEqual([
      "comment_dispatch.planned",
      "comment_dispatch.enqueued",
      "comment_dispatch.outbox_claimed",
      "comment_dispatch.outbox_status_updated"
    ]);
    expect(JSON.stringify(auditEventsResponse.body)).not.toMatch(
      /accessToken|refreshToken|tokenValue|secretValue|sourceArchive|fullRepository|rawScannerPayload|repoReadPrincipalId|integrationAdminPrincipalId|externalCommentId/i
    );
  });

  it("filters outbox reads by status and claiming worker without crossing tenant or sensitive boundaries", async () => {
    const repositoryBinding = await installRepositoryBinding({
      tenantId: "tenant_comment_outbox_filters",
      provider: "github",
      commentWritePrincipalId: "github-app-installation:comment-write-outbox-filters"
    });

    const planResponse = await request(app.getHttpServer())
      .post("/api/comment-dispatches/plan")
      .send(
        dispatchRequest({
          tenantId: "tenant_comment_outbox_filters",
          repositoryBindingId: repositoryBinding.id,
          policyCommentAllowed: true
        })
      )
      .expect(201);
    const plan = dataOf<Record<string, unknown>>(planResponse.body);

    const enqueueResponse = await request(app.getHttpServer())
      .post("/api/comment-dispatches/enqueue")
      .send({ tenantId: "tenant_comment_outbox_filters", planId: plan.id })
      .expect(201);
    const outboxItem = dataOf<Record<string, unknown>>(enqueueResponse.body);

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/outbox")
      .query({ tenantId: "tenant_comment_outbox_filters", status: "FAILED" })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body)).toEqual([]);
      });

    const claimResponse = await request(app.getHttpServer())
      .post("/api/comment-dispatches/outbox/claim")
      .send({
        tenantId: "tenant_comment_outbox_filters",
        workerId: "comment-dispatch-worker-filter",
        leaseSeconds: 300
      })
      .expect(201);
    const claimedOutboxItem = dataOf<Record<string, unknown>>(claimResponse.body);

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/outbox")
      .query({ tenantId: "tenant_comment_outbox_filters", workerId: "comment-dispatch-worker-filter" })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body)).toEqual([claimedOutboxItem]);
      });

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/outbox")
      .query({ tenantId: "tenant_comment_outbox_filters", workerId: "comment-dispatch-worker-other" })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body)).toEqual([]);
      });

    const failedResponse = await request(app.getHttpServer())
      .patch(`/api/comment-dispatches/outbox/${outboxItem.id}/status`)
      .send({
        tenantId: "tenant_comment_outbox_filters",
        workerId: "comment-dispatch-worker-filter",
        status: "FAILED",
        statusReason: "SCM_RATE_LIMIT"
      })
      .expect(200);
    const failedOutboxItem = dataOf<Record<string, unknown>>(failedResponse.body);

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/outbox")
      .query({ tenantId: "tenant_comment_outbox_filters", status: "PENDING" })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body)).toEqual([]);
      });

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/outbox")
      .query({ tenantId: "tenant_comment_outbox_filters", status: "FAILED" })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body)).toEqual([failedOutboxItem]);
      });

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/outbox")
      .query({ tenantId: "tenant_comment_outbox_filters_other", status: "FAILED" })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body)).toEqual([]);
      });

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/outbox")
      .query({
        tenantId: "tenant_comment_outbox_filters",
        status: "FAILED",
        accessToken: "ghs_secret"
      })
      .expect(400);
  });

  it("limits outbox reads after tenant and metadata filters are applied", async () => {
    const repositoryBinding = await installRepositoryBinding({
      tenantId: "tenant_comment_outbox_limit",
      provider: "github",
      commentWritePrincipalId: "github-app-installation:comment-write-outbox-limit"
    });

    const createPlan = async (commitSha: string) => {
      const planResponse = await request(app.getHttpServer())
        .post("/api/comment-dispatches/plan")
        .send({
          ...dispatchRequest({
            tenantId: "tenant_comment_outbox_limit",
            repositoryBindingId: repositoryBinding.id,
            policyCommentAllowed: true
          }),
          commitSha
        })
        .expect(201);
      return dataOf<Record<string, unknown>>(planResponse.body);
    };

    const firstPlan = await createPlan("abc123limit1");
    const secondPlan = await createPlan("abc123limit2");
    const thirdPlan = await createPlan("abc123limit3");

    const firstOutboxResponse = await request(app.getHttpServer())
      .post("/api/comment-dispatches/enqueue")
      .send({ tenantId: "tenant_comment_outbox_limit", planId: firstPlan.id })
      .expect(201);
    const firstOutboxItem = dataOf<Record<string, unknown>>(firstOutboxResponse.body);
    const secondOutboxItem = dataOf<Record<string, unknown>>(
      (
        await request(app.getHttpServer())
          .post("/api/comment-dispatches/enqueue")
          .send({ tenantId: "tenant_comment_outbox_limit", planId: secondPlan.id })
          .expect(201)
      ).body.data
    );
    const thirdOutboxItem = dataOf<Record<string, unknown>>(
      (
        await request(app.getHttpServer())
          .post("/api/comment-dispatches/enqueue")
          .send({ tenantId: "tenant_comment_outbox_limit", planId: thirdPlan.id })
          .expect(201)
      ).body.data
    );

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/outbox")
      .query({ tenantId: "tenant_comment_outbox_limit", limit: 2 })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body)).toEqual([firstOutboxItem, secondOutboxItem]);
      });

    await request(app.getHttpServer())
      .post("/api/comment-dispatches/outbox/claim")
      .send({
        tenantId: "tenant_comment_outbox_limit",
        workerId: "comment-dispatch-worker-outbox-limit",
        leaseSeconds: 300
      })
      .expect(201);

    await request(app.getHttpServer())
      .patch(`/api/comment-dispatches/outbox/${firstOutboxItem.id}/status`)
      .send({
        tenantId: "tenant_comment_outbox_limit",
        workerId: "comment-dispatch-worker-outbox-limit",
        status: "FAILED",
        statusReason: "SCM_RATE_LIMIT"
      })
      .expect(200);

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/outbox")
      .query({ tenantId: "tenant_comment_outbox_limit", status: "PENDING", limit: 1 })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body)).toEqual([secondOutboxItem]);
      });

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/outbox")
      .query({ tenantId: "tenant_comment_outbox_limit", workerId: "comment-dispatch-worker-outbox-limit", limit: 1 })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body)[0]).toEqual(
          expect.objectContaining({ id: firstOutboxItem.id, status: "FAILED" })
        );
      });

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/outbox")
      .query({ tenantId: "tenant_comment_outbox_limit", limit: 0 })
      .expect(400);

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/outbox")
      .query({ tenantId: "tenant_comment_outbox_limit", limit: 101 })
      .expect(400);

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/outbox")
      .query({ tenantId: "tenant_comment_outbox_limit", limit: 1.5 })
      .expect(400);

    expect(thirdOutboxItem.id).toEqual(expect.stringMatching(/^comment_dispatch_outbox_\d+$/));
  });

  it("orders outbox reads after metadata filters and before limit is applied", async () => {
    const repositoryBinding = await installRepositoryBinding({
      tenantId: "tenant_comment_outbox_order",
      provider: "github",
      commentWritePrincipalId: "github-app-installation:comment-write-outbox-order"
    });

    const createPlan = async (commitSha: string) => {
      const planResponse = await request(app.getHttpServer())
        .post("/api/comment-dispatches/plan")
        .send({
          ...dispatchRequest({
            tenantId: "tenant_comment_outbox_order",
            repositoryBindingId: repositoryBinding.id,
            policyCommentAllowed: true
          }),
          commitSha
        })
        .expect(201);
      return dataOf<Record<string, unknown>>(planResponse.body);
    };

    const firstPlan = await createPlan("abc123order1");
    const secondPlan = await createPlan("abc123order2");
    const thirdPlan = await createPlan("abc123order3");

    const firstOutboxItem = dataOf<Record<string, unknown>>(
      (
        await request(app.getHttpServer())
          .post("/api/comment-dispatches/enqueue")
          .send({ tenantId: "tenant_comment_outbox_order", planId: firstPlan.id })
          .expect(201)
      ).body
    );
    const secondOutboxItem = dataOf<Record<string, unknown>>(
      (
        await request(app.getHttpServer())
          .post("/api/comment-dispatches/enqueue")
          .send({ tenantId: "tenant_comment_outbox_order", planId: secondPlan.id })
          .expect(201)
      ).body
    );
    const thirdOutboxItem = dataOf<Record<string, unknown>>(
      (
        await request(app.getHttpServer())
          .post("/api/comment-dispatches/enqueue")
          .send({ tenantId: "tenant_comment_outbox_order", planId: thirdPlan.id })
          .expect(201)
      ).body
    );

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/outbox")
      .query({ tenantId: "tenant_comment_outbox_order", order: "ASC" })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body).map((item) => item.id)).toEqual([
          firstOutboxItem.id,
          secondOutboxItem.id,
          thirdOutboxItem.id
        ]);
      });

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/outbox")
      .query({ tenantId: "tenant_comment_outbox_order", order: "DESC", limit: 2 })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body).map((item) => item.id)).toEqual([
          thirdOutboxItem.id,
          secondOutboxItem.id
        ]);
      });

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/outbox")
      .query({ tenantId: "tenant_comment_outbox_order", order: "SIDEWAYS" })
      .expect(400);
  });

  it("filters outbox reads by repository binding inside the tenant boundary", async () => {
    const firstRepositoryBinding = await installRepositoryBinding({
      tenantId: "tenant_comment_outbox_repository_filter",
      provider: "github",
      commentWritePrincipalId: "github-app-installation:comment-write-outbox-repo-filter-1"
    });
    await installRepositoryBinding({
      tenantId: "tenant_comment_outbox_repository_filter",
      provider: "gitlab",
      commentWritePrincipalId: "gitlab-project-integration:comment-write-outbox-repo-filter-2"
    });
    const repositoryBindingsResponse = await request(app.getHttpServer())
      .get("/api/repository-bindings")
      .query({ tenantId: "tenant_comment_outbox_repository_filter" })
      .expect(200);
    const secondRepositoryBinding = dataOf<Array<Record<string, unknown>>>(repositoryBindingsResponse.body).find(
      (binding) => binding.id !== firstRepositoryBinding.id
    );
    if (!secondRepositoryBinding) {
      throw new Error("Expected a second repository binding for outbox repository filter coverage.");
    }

    const createPlan = async (repositoryBindingId: unknown, commitSha: string) => {
      const planResponse = await request(app.getHttpServer())
        .post("/api/comment-dispatches/plan")
        .send({
          ...dispatchRequest({
            tenantId: "tenant_comment_outbox_repository_filter",
            repositoryBindingId,
            policyCommentAllowed: true
          }),
          commitSha
        })
        .expect(201);
      return dataOf<Record<string, unknown>>(planResponse.body);
    };

    const firstPlan = await createPlan(firstRepositoryBinding.id, "abc123repo-filter-1");
    const secondPlan = await createPlan(secondRepositoryBinding.id, "abc123repo-filter-2");
    const firstOutboxItem = dataOf<Record<string, unknown>>(
      (
        await request(app.getHttpServer())
          .post("/api/comment-dispatches/enqueue")
          .send({ tenantId: "tenant_comment_outbox_repository_filter", planId: firstPlan.id })
          .expect(201)
      ).body
    );
    const secondOutboxItem = dataOf<Record<string, unknown>>(
      (
        await request(app.getHttpServer())
          .post("/api/comment-dispatches/enqueue")
          .send({ tenantId: "tenant_comment_outbox_repository_filter", planId: secondPlan.id })
          .expect(201)
      ).body
    );

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/outbox")
      .query({
        tenantId: "tenant_comment_outbox_repository_filter",
        repositoryBindingId: secondRepositoryBinding.id
      })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body)).toEqual([secondOutboxItem]);
      });

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/outbox")
      .query({
        tenantId: "tenant_comment_outbox_repository_filter",
        repositoryBindingId: firstRepositoryBinding.id,
        order: "DESC",
        limit: 1
      })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body)).toEqual([firstOutboxItem]);
      });

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/outbox")
      .query({
        tenantId: "tenant_comment_outbox_repository_filter_other",
        repositoryBindingId: firstRepositoryBinding.id
      })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body)).toEqual([]);
      });
  });

  it("filters outbox reads by provider inside the tenant boundary", async () => {
    const githubRepositoryBinding = await installRepositoryBinding({
      tenantId: "tenant_comment_outbox_provider_filter",
      provider: "github",
      commentWritePrincipalId: "github-app-installation:comment-write-outbox-provider-filter-1"
    });
    await installRepositoryBinding({
      tenantId: "tenant_comment_outbox_provider_filter",
      provider: "gitlab",
      commentWritePrincipalId: "gitlab-project-integration:comment-write-outbox-provider-filter-2"
    });
    const repositoryBindingsResponse = await request(app.getHttpServer())
      .get("/api/repository-bindings")
      .query({ tenantId: "tenant_comment_outbox_provider_filter" })
      .expect(200);
    const gitlabRepositoryBinding = dataOf<Array<Record<string, unknown>>>(repositoryBindingsResponse.body).find(
      (binding) => binding.id !== githubRepositoryBinding.id
    );
    if (!gitlabRepositoryBinding) {
      throw new Error("Expected a GitLab repository binding for outbox provider filter coverage.");
    }

    const createPlan = async (repositoryBindingId: unknown, commitSha: string) => {
      const planResponse = await request(app.getHttpServer())
        .post("/api/comment-dispatches/plan")
        .send({
          ...dispatchRequest({
            tenantId: "tenant_comment_outbox_provider_filter",
            repositoryBindingId,
            policyCommentAllowed: true
          }),
          commitSha
        })
        .expect(201);
      return dataOf<Record<string, unknown>>(planResponse.body);
    };

    const githubPlan = await createPlan(githubRepositoryBinding.id, "abc123provider-filter-1");
    const gitlabPlan = await createPlan(gitlabRepositoryBinding.id, "abc123provider-filter-2");
    const githubOutboxItem = dataOf<Record<string, unknown>>(
      (
        await request(app.getHttpServer())
          .post("/api/comment-dispatches/enqueue")
          .send({ tenantId: "tenant_comment_outbox_provider_filter", planId: githubPlan.id })
          .expect(201)
      ).body
    );
    const gitlabOutboxItem = dataOf<Record<string, unknown>>(
      (
        await request(app.getHttpServer())
          .post("/api/comment-dispatches/enqueue")
          .send({ tenantId: "tenant_comment_outbox_provider_filter", planId: gitlabPlan.id })
          .expect(201)
      ).body
    );

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/outbox")
      .query({
        tenantId: "tenant_comment_outbox_provider_filter",
        provider: "GITLAB"
      })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body)).toEqual([gitlabOutboxItem]);
      });

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/outbox")
      .query({
        tenantId: "tenant_comment_outbox_provider_filter",
        provider: "GITHUB",
        repositoryBindingId: githubRepositoryBinding.id,
        order: "DESC",
        limit: 1
      })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body)).toEqual([githubOutboxItem]);
      });

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/outbox")
      .query({
        tenantId: "tenant_comment_outbox_provider_filter_other",
        provider: "GITHUB"
      })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body)).toEqual([]);
      });

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/outbox")
      .query({
        tenantId: "tenant_comment_outbox_provider_filter",
        provider: "BITBUCKET"
      })
      .expect(400);
  });

  it("filters outbox reads by provider repository id inside the tenant boundary", async () => {
    const githubRepositoryBinding = await installRepositoryBinding({
      tenantId: "tenant_comment_outbox_provider_repo_filter",
      provider: "github",
      commentWritePrincipalId: "github-app-installation:comment-write-outbox-provider-repo-filter-1"
    });
    await installRepositoryBinding({
      tenantId: "tenant_comment_outbox_provider_repo_filter",
      provider: "gitlab",
      commentWritePrincipalId: "gitlab-project-integration:comment-write-outbox-provider-repo-filter-2"
    });
    const repositoryBindingsResponse = await request(app.getHttpServer())
      .get("/api/repository-bindings")
      .query({ tenantId: "tenant_comment_outbox_provider_repo_filter" })
      .expect(200);
    const gitlabRepositoryBinding = dataOf<Array<Record<string, unknown>>>(repositoryBindingsResponse.body).find(
      (binding) => binding.id !== githubRepositoryBinding.id
    );
    if (!gitlabRepositoryBinding) {
      throw new Error("Expected a GitLab repository binding for outbox provider repository filter coverage.");
    }

    const createPlan = async (repositoryBindingId: unknown, commitSha: string) => {
      const planResponse = await request(app.getHttpServer())
        .post("/api/comment-dispatches/plan")
        .send({
          ...dispatchRequest({
            tenantId: "tenant_comment_outbox_provider_repo_filter",
            repositoryBindingId,
            policyCommentAllowed: true
          }),
          commitSha
        })
        .expect(201);
      return dataOf<Record<string, unknown>>(planResponse.body);
    };

    const githubPlan = await createPlan(githubRepositoryBinding.id, "abc123provider-repo-filter-1");
    const gitlabPlan = await createPlan(gitlabRepositoryBinding.id, "abc123provider-repo-filter-2");
    const githubOutboxItem = dataOf<Record<string, unknown>>(
      (
        await request(app.getHttpServer())
          .post("/api/comment-dispatches/enqueue")
          .send({ tenantId: "tenant_comment_outbox_provider_repo_filter", planId: githubPlan.id })
          .expect(201)
      ).body
    );
    const gitlabOutboxItem = dataOf<Record<string, unknown>>(
      (
        await request(app.getHttpServer())
          .post("/api/comment-dispatches/enqueue")
          .send({ tenantId: "tenant_comment_outbox_provider_repo_filter", planId: gitlabPlan.id })
          .expect(201)
      ).body
    );

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/outbox")
      .query({
        tenantId: "tenant_comment_outbox_provider_repo_filter",
        providerRepoId: "gitlab-repo-1"
      })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body)).toEqual([gitlabOutboxItem]);
      });

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/outbox")
      .query({
        tenantId: "tenant_comment_outbox_provider_repo_filter",
        provider: "GITHUB",
        providerRepoId: "github-repo-1",
        repositoryBindingId: githubRepositoryBinding.id,
        order: "DESC",
        limit: 1
      })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body)).toEqual([githubOutboxItem]);
      });

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/outbox")
      .query({
        tenantId: "tenant_comment_outbox_provider_repo_filter",
        provider: "GITHUB",
        providerRepoId: "gitlab-repo-1"
      })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body)).toEqual([]);
      });

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/outbox")
      .query({
        tenantId: "tenant_comment_outbox_provider_repo_filter_other",
        providerRepoId: "github-repo-1"
      })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body)).toEqual([]);
      });
  });

  it("filters outbox reads by idempotency key inside the tenant boundary", async () => {
    const repositoryBinding = await installRepositoryBinding({
      tenantId: "tenant_comment_outbox_idempotency_filter",
      provider: "github",
      commentWritePrincipalId: "github-app-installation:comment-write-outbox-idempotency-filter"
    });

    const createPlan = async (commitSha: string) => {
      const planResponse = await request(app.getHttpServer())
        .post("/api/comment-dispatches/plan")
        .send({
          ...dispatchRequest({
            tenantId: "tenant_comment_outbox_idempotency_filter",
            repositoryBindingId: repositoryBinding.id,
            policyCommentAllowed: true
          }),
          commitSha
        })
        .expect(201);
      return dataOf<Record<string, unknown>>(planResponse.body);
    };

    const firstPlan = await createPlan("abc123idempotency-filter-1");
    const secondPlan = await createPlan("abc123idempotency-filter-2");
    const firstOutboxItem = dataOf<Record<string, unknown>>(
      (
        await request(app.getHttpServer())
          .post("/api/comment-dispatches/enqueue")
          .send({ tenantId: "tenant_comment_outbox_idempotency_filter", planId: firstPlan.id })
          .expect(201)
      ).body
    );
    const secondOutboxItem = dataOf<Record<string, unknown>>(
      (
        await request(app.getHttpServer())
          .post("/api/comment-dispatches/enqueue")
          .send({ tenantId: "tenant_comment_outbox_idempotency_filter", planId: secondPlan.id })
          .expect(201)
      ).body
    );

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/outbox")
      .query({
        tenantId: "tenant_comment_outbox_idempotency_filter",
        idempotencyKey: secondOutboxItem.idempotencyKey
      })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body)).toEqual([secondOutboxItem]);
      });

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/outbox")
      .query({
        tenantId: "tenant_comment_outbox_idempotency_filter",
        idempotencyKey: firstOutboxItem.idempotencyKey,
        repositoryBindingId: repositoryBinding.id,
        provider: "GITHUB",
        providerRepoId: "github-repo-1",
        status: "PENDING",
        order: "DESC",
        limit: 1
      })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body)).toEqual([firstOutboxItem]);
      });

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/outbox")
      .query({
        tenantId: "tenant_comment_outbox_idempotency_filter_other",
        idempotencyKey: firstOutboxItem.idempotencyKey
      })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body)).toEqual([]);
      });
  });

  it("filters audit event reads by repository binding inside the tenant boundary", async () => {
    const firstRepositoryBinding = await installRepositoryBinding({
      tenantId: "tenant_comment_audit_repository_filter",
      provider: "github",
      commentWritePrincipalId: "github-app-installation:comment-write-audit-repo-filter-1"
    });
    await installRepositoryBinding({
      tenantId: "tenant_comment_audit_repository_filter",
      provider: "gitlab",
      commentWritePrincipalId: "gitlab-project-integration:comment-write-audit-repo-filter-2"
    });
    const repositoryBindingsResponse = await request(app.getHttpServer())
      .get("/api/repository-bindings")
      .query({ tenantId: "tenant_comment_audit_repository_filter" })
      .expect(200);
    const secondRepositoryBinding = dataOf<Array<Record<string, unknown>>>(repositoryBindingsResponse.body).find(
      (binding) => binding.id !== firstRepositoryBinding.id
    );
    if (!secondRepositoryBinding) {
      throw new Error("Expected a second repository binding for audit repository filter coverage.");
    }

    const createPlan = async (repositoryBindingId: unknown, commitSha: string) => {
      const planResponse = await request(app.getHttpServer())
        .post("/api/comment-dispatches/plan")
        .send({
          ...dispatchRequest({
            tenantId: "tenant_comment_audit_repository_filter",
            repositoryBindingId,
            policyCommentAllowed: true
          }),
          commitSha
        })
        .expect(201);
      return dataOf<Record<string, unknown>>(planResponse.body);
    };

    const firstPlan = await createPlan(firstRepositoryBinding.id, "abc123audit-repo-filter-1");
    const secondPlan = await createPlan(secondRepositoryBinding.id, "abc123audit-repo-filter-2");
    const firstOutboxItem = dataOf<Record<string, unknown>>(
      (
        await request(app.getHttpServer())
          .post("/api/comment-dispatches/enqueue")
          .send({ tenantId: "tenant_comment_audit_repository_filter", planId: firstPlan.id })
          .expect(201)
      ).body
    );
    await request(app.getHttpServer())
      .post("/api/comment-dispatches/enqueue")
      .send({ tenantId: "tenant_comment_audit_repository_filter", planId: secondPlan.id })
      .expect(201);

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({
        tenantId: "tenant_comment_audit_repository_filter",
        repositoryBindingId: secondRepositoryBinding.id
      })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body).map((event) => event.eventType)).toEqual([
          "comment_dispatch.planned",
          "comment_dispatch.enqueued"
        ]);
        expect(dataOf<Array<Record<string, unknown>>>(response.body)).toEqual([
          expect.objectContaining({
            metadata: expect.objectContaining({ repositoryBindingId: secondRepositoryBinding.id })
          }),
          expect.objectContaining({
            metadata: expect.objectContaining({ repositoryBindingId: secondRepositoryBinding.id })
          })
        ]);
      });

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({
        tenantId: "tenant_comment_audit_repository_filter",
        repositoryBindingId: firstRepositoryBinding.id,
        targetType: "comment_dispatch_outbox_item",
        order: "DESC",
        limit: 1
      })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body)).toEqual([
          expect.objectContaining({
            eventType: "comment_dispatch.enqueued",
            targetId: firstOutboxItem.id,
            metadata: expect.objectContaining({ repositoryBindingId: firstRepositoryBinding.id })
          })
        ]);
      });

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({
        tenantId: "tenant_comment_audit_repository_filter_other",
        repositoryBindingId: firstRepositoryBinding.id
      })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body)).toEqual([]);
      });

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({
        tenantId: "tenant_comment_audit_repository_filter",
        repositoryBindingId: secondRepositoryBinding.id,
        accessToken: "ghs_secret"
      })
      .expect(400);
  });

  it("filters audit event reads by provider inside the tenant boundary", async () => {
    const githubRepositoryBinding = await installRepositoryBinding({
      tenantId: "tenant_comment_audit_provider_filter",
      provider: "github",
      commentWritePrincipalId: "github-app-installation:comment-write-audit-provider-filter-1"
    });
    await installRepositoryBinding({
      tenantId: "tenant_comment_audit_provider_filter",
      provider: "gitlab",
      commentWritePrincipalId: "gitlab-project-integration:comment-write-audit-provider-filter-2"
    });
    const repositoryBindingsResponse = await request(app.getHttpServer())
      .get("/api/repository-bindings")
      .query({ tenantId: "tenant_comment_audit_provider_filter" })
      .expect(200);
    const gitlabRepositoryBinding = dataOf<Array<Record<string, unknown>>>(repositoryBindingsResponse.body).find(
      (binding) => binding.id !== githubRepositoryBinding.id
    );
    if (!gitlabRepositoryBinding) {
      throw new Error("Expected a GitLab repository binding for audit provider filter coverage.");
    }

    const createPlan = async (repositoryBindingId: unknown, commitSha: string) => {
      const planResponse = await request(app.getHttpServer())
        .post("/api/comment-dispatches/plan")
        .send({
          ...dispatchRequest({
            tenantId: "tenant_comment_audit_provider_filter",
            repositoryBindingId,
            policyCommentAllowed: true
          }),
          commitSha
        })
        .expect(201);
      return dataOf<Record<string, unknown>>(planResponse.body);
    };

    const githubPlan = await createPlan(githubRepositoryBinding.id, "abc123audit-provider-filter-1");
    const gitlabPlan = await createPlan(gitlabRepositoryBinding.id, "abc123audit-provider-filter-2");
    await request(app.getHttpServer())
      .post("/api/comment-dispatches/enqueue")
      .send({ tenantId: "tenant_comment_audit_provider_filter", planId: githubPlan.id })
      .expect(201);
    const gitlabOutboxItem = dataOf<Record<string, unknown>>(
      (
        await request(app.getHttpServer())
          .post("/api/comment-dispatches/enqueue")
          .send({ tenantId: "tenant_comment_audit_provider_filter", planId: gitlabPlan.id })
          .expect(201)
      ).body
    );

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({
        tenantId: "tenant_comment_audit_provider_filter",
        provider: "GITLAB"
      })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body).map((event) => event.eventType)).toEqual([
          "comment_dispatch.planned",
          "comment_dispatch.enqueued"
        ]);
        expect(dataOf<Array<Record<string, unknown>>>(response.body)).toEqual([
          expect.objectContaining({
            metadata: expect.objectContaining({ provider: "GITLAB" })
          }),
          expect.objectContaining({
            metadata: expect.objectContaining({ provider: "GITLAB" })
          })
        ]);
      });

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({
        tenantId: "tenant_comment_audit_provider_filter",
        provider: "GITLAB",
        repositoryBindingId: gitlabRepositoryBinding.id,
        targetType: "comment_dispatch_outbox_item",
        order: "DESC",
        limit: 1
      })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body)).toEqual([
          expect.objectContaining({
            eventType: "comment_dispatch.enqueued",
            targetId: gitlabOutboxItem.id,
            metadata: expect.objectContaining({
              provider: "GITLAB",
              repositoryBindingId: gitlabRepositoryBinding.id
            })
          })
        ]);
      });

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({
        tenantId: "tenant_comment_audit_provider_filter_other",
        provider: "GITHUB"
      })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body)).toEqual([]);
      });

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({
        tenantId: "tenant_comment_audit_provider_filter",
        provider: "BITBUCKET"
      })
      .expect(400);
  });

  it("filters audit event reads by provider repository id inside the tenant boundary", async () => {
    const githubRepositoryBinding = await installRepositoryBinding({
      tenantId: "tenant_comment_audit_provider_repo_filter",
      provider: "github",
      commentWritePrincipalId: "github-app-installation:comment-write-audit-provider-repo-filter-1"
    });
    await installRepositoryBinding({
      tenantId: "tenant_comment_audit_provider_repo_filter",
      provider: "gitlab",
      commentWritePrincipalId: "gitlab-project-integration:comment-write-audit-provider-repo-filter-2"
    });
    const repositoryBindingsResponse = await request(app.getHttpServer())
      .get("/api/repository-bindings")
      .query({ tenantId: "tenant_comment_audit_provider_repo_filter" })
      .expect(200);
    const gitlabRepositoryBinding = dataOf<Array<Record<string, unknown>>>(repositoryBindingsResponse.body).find(
      (binding) => binding.id !== githubRepositoryBinding.id
    );
    if (!gitlabRepositoryBinding) {
      throw new Error("Expected a GitLab repository binding for audit provider repository filter coverage.");
    }

    const createPlan = async (repositoryBindingId: unknown, commitSha: string) => {
      const planResponse = await request(app.getHttpServer())
        .post("/api/comment-dispatches/plan")
        .send({
          ...dispatchRequest({
            tenantId: "tenant_comment_audit_provider_repo_filter",
            repositoryBindingId,
            policyCommentAllowed: true
          }),
          commitSha
        })
        .expect(201);
      return dataOf<Record<string, unknown>>(planResponse.body);
    };

    const githubPlan = await createPlan(githubRepositoryBinding.id, "abc123audit-provider-repo-filter-1");
    const gitlabPlan = await createPlan(gitlabRepositoryBinding.id, "abc123audit-provider-repo-filter-2");
    await request(app.getHttpServer())
      .post("/api/comment-dispatches/enqueue")
      .send({ tenantId: "tenant_comment_audit_provider_repo_filter", planId: githubPlan.id })
      .expect(201);
    const gitlabOutboxItem = dataOf<Record<string, unknown>>(
      (
        await request(app.getHttpServer())
          .post("/api/comment-dispatches/enqueue")
          .send({ tenantId: "tenant_comment_audit_provider_repo_filter", planId: gitlabPlan.id })
          .expect(201)
      ).body
    );

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({
        tenantId: "tenant_comment_audit_provider_repo_filter",
        providerRepoId: "gitlab-repo-1"
      })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body).map((event) => event.eventType)).toEqual([
          "comment_dispatch.planned",
          "comment_dispatch.enqueued"
        ]);
        expect(dataOf<Array<Record<string, unknown>>>(response.body)).toEqual([
          expect.objectContaining({
            metadata: expect.objectContaining({ providerRepoId: "gitlab-repo-1" })
          }),
          expect.objectContaining({
            metadata: expect.objectContaining({ providerRepoId: "gitlab-repo-1" })
          })
        ]);
      });

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({
        tenantId: "tenant_comment_audit_provider_repo_filter",
        provider: "GITLAB",
        providerRepoId: "gitlab-repo-1",
        repositoryBindingId: gitlabRepositoryBinding.id,
        targetType: "comment_dispatch_outbox_item",
        order: "DESC",
        limit: 1
      })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body)).toEqual([
          expect.objectContaining({
            eventType: "comment_dispatch.enqueued",
            targetId: gitlabOutboxItem.id,
            metadata: expect.objectContaining({
              provider: "GITLAB",
              providerRepoId: "gitlab-repo-1",
              repositoryBindingId: gitlabRepositoryBinding.id
            })
          })
        ]);
      });

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({
        tenantId: "tenant_comment_audit_provider_repo_filter",
        provider: "GITHUB",
        providerRepoId: "gitlab-repo-1"
      })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body)).toEqual([]);
      });

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({
        tenantId: "tenant_comment_audit_provider_repo_filter_other",
        providerRepoId: "github-repo-1"
      })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body)).toEqual([]);
      });
  });

  it("filters audit event reads by idempotency key inside the tenant boundary", async () => {
    const repositoryBinding = await installRepositoryBinding({
      tenantId: "tenant_comment_audit_idempotency_filter",
      provider: "github",
      commentWritePrincipalId: "github-app-installation:comment-write-audit-idempotency-filter"
    });

    const createPlan = async (commitSha: string) => {
      const planResponse = await request(app.getHttpServer())
        .post("/api/comment-dispatches/plan")
        .send({
          ...dispatchRequest({
            tenantId: "tenant_comment_audit_idempotency_filter",
            repositoryBindingId: repositoryBinding.id,
            policyCommentAllowed: true
          }),
          commitSha
        })
        .expect(201);
      return dataOf<Record<string, unknown>>(planResponse.body);
    };

    const firstPlan = await createPlan("abc123audit-idempotency-filter-1");
    const secondPlan = await createPlan("abc123audit-idempotency-filter-2");
    const firstOutboxItem = dataOf<Record<string, unknown>>(
      (
        await request(app.getHttpServer())
          .post("/api/comment-dispatches/enqueue")
          .send({ tenantId: "tenant_comment_audit_idempotency_filter", planId: firstPlan.id })
          .expect(201)
      ).body
    );
    await request(app.getHttpServer())
      .post("/api/comment-dispatches/enqueue")
      .send({ tenantId: "tenant_comment_audit_idempotency_filter", planId: secondPlan.id })
      .expect(201);

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({
        tenantId: "tenant_comment_audit_idempotency_filter",
        idempotencyKey: secondPlan.idempotencyKey
      })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body).map((event) => event.eventType)).toEqual([
          "comment_dispatch.planned",
          "comment_dispatch.enqueued"
        ]);
        expect(dataOf<Array<Record<string, unknown>>>(response.body)).toEqual([
          expect.objectContaining({
            metadata: expect.objectContaining({ idempotencyKey: secondPlan.idempotencyKey })
          }),
          expect.objectContaining({
            metadata: expect.objectContaining({ idempotencyKey: secondPlan.idempotencyKey })
          })
        ]);
      });

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({
        tenantId: "tenant_comment_audit_idempotency_filter",
        idempotencyKey: firstPlan.idempotencyKey,
        repositoryBindingId: repositoryBinding.id,
        provider: "GITHUB",
        providerRepoId: "github-repo-1",
        eventType: "comment_dispatch.enqueued",
        targetType: "comment_dispatch_outbox_item",
        targetId: firstOutboxItem.id,
        order: "DESC",
        limit: 1
      })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body)).toEqual([
          expect.objectContaining({
            eventType: "comment_dispatch.enqueued",
            targetId: firstOutboxItem.id,
            metadata: expect.objectContaining({ idempotencyKey: firstPlan.idempotencyKey })
          })
        ]);
      });

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({
        tenantId: "tenant_comment_audit_idempotency_filter_other",
        idempotencyKey: firstPlan.idempotencyKey
      })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body)).toEqual([]);
      });

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({
        tenantId: "tenant_comment_audit_idempotency_filter",
        idempotencyKey: firstPlan.idempotencyKey,
        accessToken: "ghs_secret"
      })
      .expect(400);
  });

  it("filters audit event reads by event type and target without crossing tenant or sensitive boundaries", async () => {
    const repositoryBinding = await installRepositoryBinding({
      tenantId: "tenant_comment_audit_filters",
      provider: "github",
      commentWritePrincipalId: "github-app-installation:comment-write-audit-filters"
    });

    const planResponse = await request(app.getHttpServer())
      .post("/api/comment-dispatches/plan")
      .send(
        dispatchRequest({
          tenantId: "tenant_comment_audit_filters",
          repositoryBindingId: repositoryBinding.id,
          policyCommentAllowed: true
        })
      )
      .expect(201);
    const plan = dataOf<Record<string, unknown>>(planResponse.body);

    const enqueueResponse = await request(app.getHttpServer())
      .post("/api/comment-dispatches/enqueue")
      .send({ tenantId: "tenant_comment_audit_filters", planId: plan.id })
      .expect(201);
    const outboxItem = dataOf<Record<string, unknown>>(enqueueResponse.body);

    await request(app.getHttpServer())
      .post("/api/comment-dispatches/outbox/claim")
      .send({
        tenantId: "tenant_comment_audit_filters",
        workerId: "comment-dispatch-worker-audit-filter",
        leaseSeconds: 300
      })
      .expect(201);

    const plannedEventsResponse = await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({
        tenantId: "tenant_comment_audit_filters",
        eventType: "comment_dispatch.planned"
      })
      .expect(200);
    expect(dataOf<Array<Record<string, unknown>>>(plannedEventsResponse.body)).toEqual([
      expect.objectContaining({
        tenantId: "tenant_comment_audit_filters",
        eventType: "comment_dispatch.planned",
        targetType: "comment_dispatch_plan",
        targetId: plan.id
      })
    ]);

    const outboxTargetEventsResponse = await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({
        tenantId: "tenant_comment_audit_filters",
        targetType: "comment_dispatch_outbox_item",
        targetId: outboxItem.id
      })
      .expect(200);
    expect(dataOf<Array<Record<string, unknown>>>(outboxTargetEventsResponse.body).map((event) => event.eventType)).toEqual([
      "comment_dispatch.enqueued",
      "comment_dispatch.outbox_claimed"
    ]);

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({
        tenantId: "tenant_comment_audit_filters_other",
        targetType: "comment_dispatch_outbox_item",
        targetId: outboxItem.id
      })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body)).toEqual([]);
      });

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({
        tenantId: "tenant_comment_audit_filters",
        eventType: "comment_dispatch.unknown"
      })
      .expect(400);

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({
        tenantId: "tenant_comment_audit_filters",
        targetType: "comment_dispatch_outbox_item",
        accessToken: "ghs_secret"
      })
      .expect(400);
  });

  it("limits audit event reads after tenant and metadata filters are applied", async () => {
    const repositoryBinding = await installRepositoryBinding({
      tenantId: "tenant_comment_audit_limit",
      provider: "github",
      commentWritePrincipalId: "github-app-installation:comment-write-audit-limit"
    });

    const planResponse = await request(app.getHttpServer())
      .post("/api/comment-dispatches/plan")
      .send(
        dispatchRequest({
          tenantId: "tenant_comment_audit_limit",
          repositoryBindingId: repositoryBinding.id,
          policyCommentAllowed: true
        })
      )
      .expect(201);
    const plan = dataOf<Record<string, unknown>>(planResponse.body);

    await request(app.getHttpServer())
      .post("/api/comment-dispatches/enqueue")
      .send({ tenantId: "tenant_comment_audit_limit", planId: plan.id })
      .expect(201);

    await request(app.getHttpServer())
      .post("/api/comment-dispatches/outbox/claim")
      .send({
        tenantId: "tenant_comment_audit_limit",
        workerId: "comment-dispatch-worker-audit-limit",
        leaseSeconds: 300
      })
      .expect(201);

    const limitedEventsResponse = await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({ tenantId: "tenant_comment_audit_limit", limit: 2 })
      .expect(200);
    expect(dataOf<Array<Record<string, unknown>>>(limitedEventsResponse.body).map((event) => event.eventType)).toEqual([
      "comment_dispatch.planned",
      "comment_dispatch.enqueued"
    ]);

    const limitedOutboxEventsResponse = await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({
        tenantId: "tenant_comment_audit_limit",
        targetType: "comment_dispatch_outbox_item",
        limit: 1
      })
      .expect(200);
    expect(dataOf<Array<Record<string, unknown>>>(limitedOutboxEventsResponse.body).map((event) => event.eventType)).toEqual([
      "comment_dispatch.enqueued"
    ]);

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({ tenantId: "tenant_comment_audit_limit", limit: 0 })
      .expect(400);

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({ tenantId: "tenant_comment_audit_limit", limit: 101 })
      .expect(400);

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({ tenantId: "tenant_comment_audit_limit", limit: 1.5 })
      .expect(400);
  });

  it("orders audit event reads after metadata filters and before limit is applied", async () => {
    const repositoryBinding = await installRepositoryBinding({
      tenantId: "tenant_comment_audit_order",
      provider: "github",
      commentWritePrincipalId: "github-app-installation:comment-write-audit-order"
    });

    const planResponse = await request(app.getHttpServer())
      .post("/api/comment-dispatches/plan")
      .send(
        dispatchRequest({
          tenantId: "tenant_comment_audit_order",
          repositoryBindingId: repositoryBinding.id,
          policyCommentAllowed: true
        })
      )
      .expect(201);
    const plan = dataOf<Record<string, unknown>>(planResponse.body);

    const enqueueResponse = await request(app.getHttpServer())
      .post("/api/comment-dispatches/enqueue")
      .send({ tenantId: "tenant_comment_audit_order", planId: plan.id })
      .expect(201);
    const outboxItem = dataOf<Record<string, unknown>>(enqueueResponse.body);

    await request(app.getHttpServer())
      .post("/api/comment-dispatches/outbox/claim")
      .send({
        tenantId: "tenant_comment_audit_order",
        workerId: "comment-dispatch-worker-audit-order",
        leaseSeconds: 300
      })
      .expect(201);

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({ tenantId: "tenant_comment_audit_order", order: "ASC" })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body).map((event) => event.eventType)).toEqual([
          "comment_dispatch.planned",
          "comment_dispatch.enqueued",
          "comment_dispatch.outbox_claimed"
        ]);
      });

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({ tenantId: "tenant_comment_audit_order", order: "DESC", limit: 2 })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body).map((event) => event.eventType)).toEqual([
          "comment_dispatch.outbox_claimed",
          "comment_dispatch.enqueued"
        ]);
      });

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({
        tenantId: "tenant_comment_audit_order",
        targetType: "comment_dispatch_outbox_item",
        targetId: outboxItem.id,
        order: "DESC",
        limit: 1
      })
      .expect(200)
      .expect((response) => {
        expect(dataOf<Array<Record<string, unknown>>>(response.body).map((event) => event.eventType)).toEqual([
          "comment_dispatch.outbox_claimed"
        ]);
      });

    await request(app.getHttpServer())
      .get("/api/comment-dispatches/audit-events")
      .query({ tenantId: "tenant_comment_audit_order", order: "SIDEWAYS" })
      .expect(400);
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
          idempotencyKey: plan.idempotencyKey,
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
