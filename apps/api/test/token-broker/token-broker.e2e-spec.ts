import { INestApplication } from "@nestjs/common";
import { Test } from "@nestjs/testing";
import request from "supertest";
import type { TokenBrokerIssueRequest } from '@aegisai/shared';
import { SessionAuthGuard } from '../../src/auth/guards/session-auth.guard';
import { InternalServiceGuard } from '../../src/common/security/internal-service.guard';
import { ControlPlaneService } from '../../src/control-plane/control-plane.service';
import { RepositoryCredentialLeaseStore } from '../../src/token-broker/repository-credential-lease.store';
import { WorkloadIdentityAttestationService } from '../../src/token-broker/workload-identity-attestation.service';
import { TokenBrokerService } from '../../src/token-broker/token-broker.service';
import { InMemoryRepositoryCredentialLeaseStore } from '../support/in-memory-repository-credential-lease.store';
import { TestInternalServiceGuard, TestSessionAuthGuard } from '../support/security-guards';

describe("Token Broker and audit skeleton (e2e)", () => {
  let app: INestApplication;
  let workloadAttestation: WorkloadIdentityAttestationService;
  let tokenBroker: TokenBrokerService;
  let credentialLeases: InMemoryRepositoryCredentialLeaseStore;
  const auditRows: Array<{
    id: string;
    tenantId: string;
    eventType: string;
    actor: string;
    targetType: string;
    targetId: string;
    occurredAt: Date;
    metadata: Record<string, unknown>;
  }> = [];
  const commitOne = 'a'.repeat(40);
  const commitTwo = 'b'.repeat(40);

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

    credentialLeases = new InMemoryRepositoryCredentialLeaseStore();
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
        auditEvent: {
          create: jest.fn().mockImplementation(
            async ({ data }: { data: (typeof auditRows)[number] }) => {
              auditRows.push(data);
              return data;
            }
          ),
          findMany: jest.fn().mockImplementation(
            async ({
              where
            }: {
              where: { tenantId: string; eventType: string; actor: string };
            }) =>
              auditRows.filter(
                (row) =>
                  row.tenantId === where.tenantId &&
                  row.eventType === where.eventType &&
                  row.actor === where.actor
              )
          )
        }
      })
      .overrideProvider(ControlPlaneService)
      .useValue({
        getScanRequest: jest.fn((tenantId: string, scanRequestId: string) => ({
          id: scanRequestId,
          tenantId,
          repositoryBindingId:
            scanRequestId === 'scan_request_2' ? 'repository_binding_2' : 'repository_binding_1',
          commitSha: scanRequestId === 'scan_request_2' ? commitTwo : commitOne
        }))
      })
      .overrideProvider(RepositoryCredentialLeaseStore)
      .useValue(credentialLeases)
      .overrideGuard(SessionAuthGuard)
      .useClass(TestSessionAuthGuard)
      .overrideGuard(InternalServiceGuard)
      .useClass(TestInternalServiceGuard)
      .compile();

    app = moduleRef.createNestApplication();
    app.setGlobalPrefix("api");

    await app.init();
    workloadAttestation = app.get(WorkloadIdentityAttestationService);
    tokenBroker = app.get(TokenBrokerService);
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

  const issueBody = (
    attemptId: string,
    overrides: Partial<{
      tenantId: string;
      repositoryBindingId: string;
      scanRequestId: string;
      workloadIdentityRef: string;
      commitSha: string;
      ttlSeconds: number;
    }> = {}
  ): TokenBrokerIssueRequest => {
    const scope = {
      tenantId: overrides.tenantId ?? "tenant_gamma",
      repositoryBindingId: overrides.repositoryBindingId ?? "repository_binding_1",
      scanRequestId: overrides.scanRequestId ?? "scan_request_1",
      attemptId,
      workloadIdentityRef:
        overrides.workloadIdentityRef ?? `spiffe://aegisai/scan/${attemptId}`,
      commitSha: overrides.commitSha ?? commitOne
    };
    return {
      ...scope,
      workloadIdentityAttestation: workloadAttestation.issue(scope),
      principal: "REPO_READ" as const,
      ttlSeconds: overrides.ttlSeconds ?? 600,
      auditReason: "scan-fetch"
    };
  };

  it("issues scan-scoped short-lived credential values without persisting them", async () => {
    const response = await request(app.getHttpServer())
      .post("/api/token-broker/issue")
      .send(issueBody('attempt-1'))
      .expect(201);

    const responseData = dataOf<Record<string, unknown>>(response.body);

    expect(responseData).toMatchObject({
      tenantId: "tenant_gamma",
      repositoryBindingId: "repository_binding_1",
      scanRequestId: "scan_request_1",
      attemptId: "attempt-1",
      workloadIdentityRef: "spiffe://aegisai/scan/attempt-1",
      principal: "REPO_READ",
      commitSha: commitOne,
      ttlSeconds: 600,
      expiresInSeconds: 600,
      auditEventType: "token.issued",
      credentialType: "SCM_REPOSITORY_ACCESS"
    });
    expect(responseData.credentialId).toMatch(/^credential_/);
    expect(responseData.credentialValue).toMatch(/^aegis_tb_/);
    expect(new Date(responseData.issuedAt as string).toISOString()).toBe(responseData.issuedAt);
    expect(new Date(responseData.expiresAt as string).getTime()).toBeGreaterThan(
      new Date(responseData.issuedAt as string).getTime()
    );

    const secondResponse = await request(app.getHttpServer())
      .post("/api/token-broker/issue")
      .send(issueBody('attempt-2'))
      .expect(201);

    expect(dataOf<Record<string, unknown>>(secondResponse.body).credentialValue).not.toBe(
      responseData.credentialValue
    );
    expect(JSON.stringify(responseData)).not.toMatch(/workloadIdentityAttestation|signature/i);
    await expect(
      credentialLeases.findByAttempt('tenant_gamma', 'attempt-1')
    ).resolves.toMatchObject({
      status: 'ISSUED',
      credentialFingerprint: expect.stringMatching(/^sha256:[0-9a-f]{64}$/)
    });
    expect(
      JSON.stringify(
        await credentialLeases.findByAttempt('tenant_gamma', 'attempt-1')
      )
    ).not.toContain(responseData.credentialValue);

    const cleanupScope = issueBody('attempt-1');
    const cleanup = await request(app.getHttpServer())
      .post('/api/token-broker/leases/complete')
      .send({
        credentialId: responseData.credentialId,
        tenantId: cleanupScope.tenantId,
        repositoryBindingId: cleanupScope.repositoryBindingId,
        scanRequestId: cleanupScope.scanRequestId,
        attemptId: cleanupScope.attemptId,
        workloadIdentityRef: cleanupScope.workloadIdentityRef,
        workloadIdentityAttestation:
          cleanupScope.workloadIdentityAttestation,
        commitSha: cleanupScope.commitSha,
        disposition: 'WIPED'
      })
      .expect(201);

    expect(dataOf<Record<string, unknown>>(cleanup.body)).toMatchObject({
      credentialId: responseData.credentialId,
      attemptId: 'attempt-1',
      status: 'WIPED',
      wipedAt: expect.any(String)
    });
    await expect(
      credentialLeases.findByAttempt('tenant_gamma', 'attempt-1')
    ).resolves.toMatchObject({ status: 'WIPED' });
  });

  it('rejects attempt replay and tampered workload identity attestations', async () => {
    const body = issueBody('attempt-replay');
    await request(app.getHttpServer()).post('/api/token-broker/issue').send(body).expect(201);
    await request(app.getHttpServer()).post('/api/token-broker/issue').send(body).expect(409);

    const tampered = issueBody('attempt-tampered');
    tampered.workloadIdentityAttestation.claims.workloadIdentityRef =
      'spiffe://aegisai/scan/other-attempt';
    await request(app.getHttpServer())
      .post('/api/token-broker/issue')
      .send(tampered)
      .expect(401);

    const expired = issueBody('attempt-expired');
    expired.workloadIdentityAttestation = workloadAttestation.issue(
      {
        tenantId: expired.tenantId,
        repositoryBindingId: expired.repositoryBindingId,
        scanRequestId: expired.scanRequestId,
        attemptId: expired.attemptId,
        workloadIdentityRef: expired.workloadIdentityRef,
        commitSha: expired.commitSha
      },
      { now: new Date('2020-01-01T00:00:00.000Z'), ttlSeconds: 60 }
    );
    await request(app.getHttpServer())
      .post('/api/token-broker/issue')
      .send(expired)
      .expect(401);
  });

  it('scopes attempt replay protection to the tenant', async () => {
    await request(app.getHttpServer())
      .post('/api/token-broker/issue')
      .send(issueBody('attempt-shared'))
      .expect(201);
    await request(app.getHttpServer())
      .post('/api/token-broker/issue')
      .send(
        issueBody('attempt-shared', {
          tenantId: 'tenant_epsilon',
          repositoryBindingId: 'repository_binding_2',
          scanRequestId: 'scan_request_2',
          commitSha: commitTwo
        })
      )
      .expect(201);
  });

  it('zeroizes the in-memory handoff and records wiped lease evidence after fetch use', async () => {
    const body = issueBody('attempt-handoff');
    let observed: Uint8Array | undefined;
    const result = await tokenBroker.withCredential(body, async (credential) => {
      observed = credential;
      expect(Buffer.from(credential).toString('utf8')).toMatch(/^aegis_tb_/);
      return 'fetch-complete';
    });

    expect(result).toBe('fetch-complete');
    expect(observed && [...observed].every((value) => value === 0)).toBe(true);
    await expect(
      credentialLeases.findByAttempt('tenant_gamma', 'attempt-handoff')
    ).resolves.toMatchObject({
      status: 'WIPED',
      wipedAt: expect.any(String)
    });
  });

  it("records tenant-scoped audit events for token issuance", async () => {
    await request(app.getHttpServer())
      .post("/api/token-broker/issue")
      .send(
        issueBody('attempt-audit', {
          tenantId: 'tenant_delta',
          repositoryBindingId: 'repository_binding_2',
          scanRequestId: 'scan_request_2',
          workloadIdentityRef: 'spiffe://aegisai/scan/attempt-audit',
          commitSha: commitTwo,
          ttlSeconds: 300
        })
      )
      .expect(201);

    const audit = await request(app.getHttpServer())
      .get("/api/audit-events")
      .query({ tenantId: "tenant_delta" })
      .expect(200);

    const auditData = dataOf<Array<Record<string, unknown>>>(audit.body);

    expect(auditData).toEqual([
      expect.objectContaining({
        tenantId: "tenant_delta",
        eventType: "token.issued",
        actor: "token-broker",
        targetType: "scan_request",
        targetId: "scan_request_2",
        metadata: expect.objectContaining({
          repositoryBindingId: "repository_binding_2",
          attemptId: 'attempt-audit',
          workloadIdentityRef: 'spiffe://aegisai/scan/attempt-audit',
          credentialId: expect.stringMatching(/^credential_/),
          principal: "REPO_READ",
          commitSha: commitTwo,
          ttlSeconds: 300,
          auditReason: "scan-fetch"
        })
      })
    ]);
    expect(JSON.stringify(auditData)).not.toMatch(
      /credentialValue|aegis_tb_|tokenValue|secretValue|accessToken|refreshToken/i
    );
  });
});
