import { INestApplication } from "@nestjs/common";
import { Test } from "@nestjs/testing";
import type { SastQueuePolicySet, ScannerSetDescriptor } from '@aegisai/shared';
import request from "supertest";
import { SessionAuthGuard } from '../../src/auth/guards/session-auth.guard';
import { GithubWebhookSignatureGuard } from '../../src/common/security/github-webhook-signature.guard';
import { InternalServiceGuard } from '../../src/common/security/internal-service.guard';
import { configureApp } from '../../src/bootstrap/configure-app';
import { ControlPlaneScanRequestStore } from '../../src/control-plane/control-plane-scan-request.store';
import { SastQueueAdmissionStore } from '../../src/control-plane/sast-queue-admission.store';
import { InMemoryControlPlaneScanRequestStore } from '../support/in-memory-control-plane-scan-request.store';
import { InMemorySastQueueAdmissionStore } from '../support/in-memory-sast-queue-admission.store';
import {
  TestGithubWebhookSignatureGuard,
  TestInternalServiceGuard,
  TestSessionAuthGuard
} from '../support/security-guards';

const digest = (character: string): `sha256:${string}` =>
  `sha256:${character.repeat(64)}`;

const signedArtifact = (character: string) => ({
  digest: digest(character),
  signatureRef: `signature://${character}`,
  provenanceRef: `provenance://${character}`
});

const scannerRuntime = (
  scanner: 'OPENGREP' | 'TRIVY' | 'SYFT',
  character: string,
  wrapperCharacter: string
) => ({
  ...signedArtifact(character),
  scanner,
  version: '1.0.0',
  sbomRef: `sbom://${scanner}`,
  wrapper: signedArtifact(wrapperCharacter)
});

const ruleBundle = (scanner: 'OPENGREP' | 'TRIVY', character: string) => ({
  bundleId: `${scanner.toLowerCase()}-rules`,
  version: '1.0.0',
  state: 'ACTIVE' as const,
  digest: digest(character),
  signatureRef: `signature://rules/${scanner}`,
  provenanceRef: `provenance://rules/${scanner}`,
  compatibilityRef: `compatibility://rules/${scanner}`,
  rolloutPolicyRef: `rollout://rules/${scanner}`,
  killSwitchRef: `kill-switch://rules/${scanner}`,
  scanner,
  source: 'PLATFORM_MANAGED' as const,
  immutable: true as const,
  customerExecutableConfigAllowed: false as const,
  rules: [
    {
      ruleId: `${scanner.toLowerCase()}.fixture`,
      ruleRevision: '1.0.0',
      ruleSemanticId: `${scanner.toLowerCase()}.fixture`,
      metadataDigest: digest(character)
    }
  ]
});

const buildScannerSet = (): ScannerSetDescriptor => ({
  scannerSetVersion: 'scanner-set-v1',
  scannerSetDigest: digest('1'),
  signatureRef: 'signature://scanner-set-v1',
  provenanceRef: 'provenance://scanner-set-v1',
  scanners: {
    OPENGREP: scannerRuntime('OPENGREP', 'a', 'd'),
    TRIVY: scannerRuntime('TRIVY', 'b', 'e'),
    SYFT: scannerRuntime('SYFT', 'c', 'f')
  },
  ruleBundles: [ruleBundle('OPENGREP', '7'), ruleBundle('TRIVY', '8')],
  vulnerabilityDatabase: {
    ...signedArtifact('9'),
    databaseVersion: '2026-07-22',
    publishedAt: '2026-07-22T00:00:00Z'
  },
  schemaBundle: signedArtifact('0'),
  normalizerBundle: signedArtifact('6'),
  sbomSchema: 'CYCLONEDX_JSON',
  rollbackRef: 'rollback://scanner-set-v0'
});

const queuePolicy: SastQueuePolicySet = {
  policyVersion: 'queue-policy-1',
  digest: digest('e'),
  signatureRef: 'signature://queue-policy-1',
  provenanceRef: 'provenance://queue-policy-1',
  fairnessStrategy: 'TENANT_ROUND_ROBIN',
  lanes: {
    FAST: {
      lane: 'FAST',
      queueName: 'scan.fast.v1',
      maxActivePerTenant: 2,
      maxQueuedPerTenant: 10,
      maxDailyAdmissionsPerTenant: 100,
      maxActivePerRepository: 1,
      minimumRepositoryIntervalSeconds: 60,
      maxQueuedInLane: 1000,
      capacityRetrySeconds: 30
    },
    DEEP: {
      lane: 'DEEP',
      queueName: 'scan.deep.v1',
      maxActivePerTenant: 1,
      maxQueuedPerTenant: 2,
      maxDailyAdmissionsPerTenant: 10,
      maxActivePerRepository: 1,
      minimumRepositoryIntervalSeconds: 3600,
      maxQueuedInLane: 100,
      capacityRetrySeconds: 300
    }
  }
};

describe("Control Plane skeleton (e2e)", () => {
  let app: INestApplication;
  let prismaMock: {
    $connect: jest.Mock;
    $disconnect: jest.Mock;
    onModuleInit: jest.Mock;
    onModuleDestroy: jest.Mock;
    $queryRawUnsafe: jest.Mock;
    tenant: { upsert: jest.Mock };
    scmIntegration: { upsert: jest.Mock };
    repositoryBinding: { upsert: jest.Mock; updateMany: jest.Mock };
    auditEvent: { create: jest.Mock };
  };
  let gitlabCloudIntegrationClientMock: {
    listIntegrationRepositories: jest.Mock;
  };

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

    prismaMock = {
      $connect: jest.fn().mockResolvedValue(undefined),
      $disconnect: jest.fn().mockResolvedValue(undefined),
      onModuleInit: jest.fn().mockResolvedValue(undefined),
      onModuleDestroy: jest.fn().mockResolvedValue(undefined),
      $queryRawUnsafe: jest.fn().mockResolvedValue([{ result: 1 }]),
      tenant: { upsert: jest.fn().mockResolvedValue({}) },
      scmIntegration: { upsert: jest.fn().mockResolvedValue({}) },
      repositoryBinding: {
        upsert: jest.fn().mockResolvedValue({}),
        updateMany: jest.fn().mockResolvedValue({ count: 1 })
      },
      auditEvent: { create: jest.fn().mockResolvedValue({}) }
    };
    gitlabCloudIntegrationClientMock = {
      listIntegrationRepositories: jest.fn().mockResolvedValue([
        {
          providerRepoId: "7007",
          fullName: "acme/gitlab-runtime",
          defaultBranch: "main",
          isPrivate: true
        }
      ])
    };

    const moduleRef = await Test.createTestingModule({
      imports: [AppModule]
    })
      .overrideProvider(PrismaService)
      .useValue(prismaMock)
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
      .overrideProvider(GitlabCloudIntegrationClient)
      .useValue(gitlabCloudIntegrationClientMock)
      .overrideProvider(ControlPlaneScanRequestStore)
      .useValue(new InMemoryControlPlaneScanRequestStore())
      .overrideProvider(SastQueueAdmissionStore)
      .useValue(new InMemorySastQueueAdmissionStore())
      .overrideGuard(SessionAuthGuard)
      .useClass(TestSessionAuthGuard)
      .overrideGuard(InternalServiceGuard)
      .useClass(TestInternalServiceGuard)
      .overrideGuard(GithubWebhookSignatureGuard)
      .useClass(TestGithubWebhookSignatureGuard)
      .compile();

    app = moduleRef.createNestApplication();
    await configureApp(app);
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

  beforeEach(() => {
    prismaMock.tenant.upsert.mockClear();
    prismaMock.scmIntegration.upsert.mockClear();
    prismaMock.repositoryBinding.upsert.mockClear();
    prismaMock.repositoryBinding.updateMany.mockClear();
    prismaMock.auditEvent.create.mockClear();
    gitlabCloudIntegrationClientMock.listIntegrationRepositories.mockClear();
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

  it("persists GitHub App installation state without storing runtime token values", async () => {
    const install = await request(app.getHttpServer())
      .post("/api/integrations/github/install")
      .send({
        tenantId: "tenant_persisted_github_app",
        externalInstallationId: "98766",
        repoReadPrincipalId: "github-app-installation:98766:repo-read",
        commentWritePrincipalId: "github-app-installation:98766:comment-write"
      })
      .expect(201);

    const installData = dataOf<Record<string, unknown>>(install.body);

    expect(prismaMock.tenant.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { id: "tenant_persisted_github_app" }
      })
    );
    expect(prismaMock.scmIntegration.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          tenantId_provider_externalInstallationId: {
            tenantId: "tenant_persisted_github_app",
            provider: "GITHUB",
            externalInstallationId: "98766"
          }
        }
      })
    );
    expect(prismaMock.repositoryBinding.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          tenantId_scmIntegrationId_providerRepoId: {
            tenantId: "tenant_persisted_github_app",
            scmIntegrationId: installData.id,
            providerRepoId: "3003"
          }
        }
      })
    );
    expect(prismaMock.auditEvent.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          tenantId: "tenant_persisted_github_app",
          eventType: "github_app.installation.persisted",
          targetType: "scm_integration",
          targetId: installData.id
        })
      })
    );
    expect(JSON.stringify(prismaMock.scmIntegration.upsert.mock.calls)).not.toMatch(
      /accessToken|installation-token|secretValue|tokenValue/i
    );
  });

  it("reconciles GitHub installation repository webhook changes into tenant bindings", async () => {
    const install = await request(app.getHttpServer())
      .post("/api/integrations/github/install")
      .send({
        tenantId: "tenant_webhook_github_app",
        externalInstallationId: "98767",
        repoReadPrincipalId: "github-app-installation:98767:repo-read",
        commentWritePrincipalId: "github-app-installation:98767:comment-write"
      })
      .expect(201);

    const installData = dataOf<Record<string, unknown>>(install.body);
    const bindingsBeforeRemoval = await request(app.getHttpServer())
      .get("/api/repository-bindings")
      .query({ tenantId: "tenant_webhook_github_app" })
      .expect(200);
    const removedBinding = dataOf<Array<Record<string, unknown>>>(
      bindingsBeforeRemoval.body
    )[0];

    const webhook = await request(app.getHttpServer())
      .post("/api/webhooks/github")
      .set("X-GitHub-Event", "installation_repositories")
      .send({
        tenantId: "tenant_webhook_github_app",
        action: "added",
        installation: { id: "98767" },
        repositories_added: [
          {
            id: 4004,
            full_name: "acme/new-service",
            default_branch: "trunk",
            private: false
          }
        ],
        repositories_removed: [
          {
            id: 3003,
            full_name: "acme/runtime-bound"
          }
        ]
      })
      .expect(202);

    expect(dataOf<Record<string, unknown>>(webhook.body)).toMatchObject({
      acknowledged: true,
      provider: "GITHUB",
      event: "installation_repositories",
      externalInstallationId: "98767",
      addedRepositoryCount: 1,
      removedRepositoryCount: 1
    });

    const repositories = await request(app.getHttpServer())
      .get("/api/repository-bindings")
      .query({ tenantId: "tenant_webhook_github_app" })
      .expect(200);

    expect(dataOf<Array<Record<string, unknown>>>(repositories.body)).toEqual([
      expect.objectContaining({
        tenantId: "tenant_webhook_github_app",
        scmIntegrationId: installData.id,
        providerRepoId: "4004",
        fullName: "acme/new-service",
        defaultBranch: "trunk",
        isPrivate: false
      })
    ]);
    expect(prismaMock.repositoryBinding.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          tenantId_scmIntegrationId_providerRepoId: {
            tenantId: "tenant_webhook_github_app",
            scmIntegrationId: installData.id,
            providerRepoId: "4004"
          }
        }
      })
    );
    expect(prismaMock.repositoryBinding.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          tenantId: "tenant_webhook_github_app",
          scmIntegrationId: installData.id,
          providerRepoId: { in: ["3003"] }
        },
        data: {
          status: 'REVOKED',
          revokedAt: expect.any(Date)
        }
      })
    );
    await request(app.getHttpServer())
      .post("/api/scan-requests")
      .send({
        tenantId: "tenant_webhook_github_app",
        repositoryBindingId: removedBinding.id,
        lane: "FAST",
        targetRef: "refs/heads/main",
        commitSha: "a".repeat(40),
        policyVersion: "policy-1",
        scannerSetVersion: "scanner-set-1"
      })
      .expect(404);
    expect(JSON.stringify(webhook.body)).not.toMatch(/accessToken|installation-token|secretValue|tokenValue/i);
  });

  it("loads GitLab Cloud integration repositories when install payload omits repository bindings", async () => {
    const install = await request(app.getHttpServer())
      .post("/api/integrations/gitlab/install")
      .send({
        tenantId: "tenant_gitlab_cloud",
        externalInstallationId: "group:acme",
        repoReadPrincipalId: "gitlab-cloud:group:acme:repo-read",
        commentWritePrincipalId: "gitlab-cloud:group:acme:comment-write",
        runtimeAccessToken: "gitlab-runtime-token"
      })
      .expect(201);

    const installData = dataOf<Record<string, unknown>>(install.body);

    expect(gitlabCloudIntegrationClientMock.listIntegrationRepositories).toHaveBeenCalledWith(
      "group:acme",
      "gitlab-runtime-token"
    );
    expect(installData).toMatchObject({
      provider: "GITLAB",
      integrationType: "GITLAB_CLOUD_INTEGRATION",
      tenantId: "tenant_gitlab_cloud",
      externalInstallationId: "group:acme",
      status: "ACTIVE"
    });
    expect(JSON.stringify(installData)).not.toMatch(/runtimeAccessToken|gitlab-runtime-token|tokenValue|secretValue/i);

    const repositories = await request(app.getHttpServer())
      .get("/api/repository-bindings")
      .query({ tenantId: "tenant_gitlab_cloud" })
      .expect(200);

    expect(dataOf<Array<Record<string, unknown>>>(repositories.body)).toEqual([
      expect.objectContaining({
        tenantId: "tenant_gitlab_cloud",
        scmIntegrationId: installData.id,
        providerRepoId: "7007",
        fullName: "acme/gitlab-runtime",
        defaultBranch: "main",
        isPrivate: true
      })
    ]);
    expect(JSON.stringify(repositories.body)).not.toMatch(/runtimeAccessToken|gitlab-runtime-token|tokenValue|secretValue/i);
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
    const fixedCommitSha = "a".repeat(40);

    const scan = await request(app.getHttpServer())
      .post("/api/scan-requests")
      .send({
        tenantId: "tenant_beta",
        repositoryBindingId,
        lane: "FAST",
        targetRef: "refs/merge-requests/7/head",
        commitSha: fixedCommitSha,
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
      commitSha: fixedCommitSha,
      policyVersion: "policy-2026-04-12",
      scannerSetVersion: "scanner-set-v1",
      canonicalKey: `v1:tenant_beta:${repositoryBindingId}:FAST:refs%2Fmerge-requests%2F7%2Fhead:${fixedCommitSha}:policy-2026-04-12:scanner-set-v1`,
      isolationClass: "RESTRICTED",
      status: "QUEUED"
    });

    const planningPayload = {
        tenantId: "tenant_beta",
        repositoryMetadata: {
          repositoryBindingId,
          fixedCommitSha,
          inventoryDigest: digest('2'),
          attestationRef: 'attestation://inventory-1',
          collectedAt: '2026-07-22T00:00:00Z',
          sourceLanguages: [
            { language: 'JAVA', sourceFileCount: 10, sourceBytes: 100_000 }
          ],
          manifestNames: ['pom.xml'],
          repositoryBytes: 1_000_000,
          selectedBytes: 500_000,
          fileCount: 100,
          maxSingleFileBytes: 100_000,
          maxPathDepth: 8
        },
        profilePolicy: {
          policyVersion: "policy-2026-04-12",
          allowedProfileIds: ['JAVA_FAST_V1', 'JAVA_DEEP_V1', 'COMMON_DEEP_V1'],
          requireLanguageSpecificSast: false
        },
        scannerSet: buildScannerSet(),
        queuePolicySet: queuePolicy,
        queueUsage: {
          snapshotVersion: 0,
          tenantId: "tenant_beta",
          repositoryBindingId,
          lane: 'FAST',
          dailyWindowStartedAt: '2026-07-22T00:00:00Z',
          activeForTenant: 0,
          queuedForTenant: 0,
          admittedTodayForTenant: 0,
          activeForRepository: 0,
          queuedInLane: 0
        },
        requestedAt: '2026-07-22T01:00:00Z'
      };
    await request(app.getHttpServer())
      .post(`/api/sast-planning/${scanData.id}`)
      .send({
        ...planningPayload,
        scannerSet: { ...planningPayload.scannerSet, command: 'curl attacker.invalid' }
      })
      .expect(400);

    const planning = await request(app.getHttpServer())
      .post(`/api/sast-planning/${scanData.id}`)
      .send(planningPayload)
      .expect(201);
    const planningData = dataOf<Record<string, unknown>>(planning.body);
    expect(planningData.planning).toMatchObject({
      state: 'ADMITTED',
      profileId: 'JAVA_FAST_V1',
      coverageClaim: 'LANGUAGE_SAST_COMPLETE',
      queueName: 'scan.fast.v1'
    });
    expect(planningData.plan).toMatchObject({
      scanRequestId: scanData.id,
      isolationClass: 'RESTRICTED'
    });

    const status = await request(app.getHttpServer())
      .get(`/api/scan-requests/${scanData.id}`)
      .set('x-test-tenant-id', 'tenant_beta')
      .expect(200);

    const statusData = dataOf<Record<string, unknown>>(status.body);

    expect(statusData.id).toBe(scanData.id);
    expect(statusData.canonicalKey).toBe(scanData.canonicalKey);
    expect(statusData.sastPlanning).toMatchObject({
      state: 'ADMITTED',
      profileId: 'JAVA_FAST_V1'
    });
    expect(JSON.stringify(statusData)).not.toMatch(
      /"(?:repositoryMetadata|scannerSet|queuePolicySet|queueUsage|sourceLanguages)"/
    );
    expect(dataOf<Record<string, unknown>>(install.body).provider).toBe("GITLAB");
  });
});
