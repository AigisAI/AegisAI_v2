import {
  buildCanonicalScanKey,
  createEvidencePackMetadata,
  PRODUCTION_SCAN_ARCHITECTURE_FEATURE_ID,
  SCAN_LANES,
  shouldEscalateIsolation,
  type AiAdvisoryRequest,
  type TokenBrokerIssueRequest
} from '../../../../packages/shared/src';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

describe('production scan architecture contracts', () => {
  const schema = readFileSync(join(__dirname, '../../prisma/schema.prisma'), 'utf8');
  const aiAdvisoryMetadataMigration = readFileSync(
    join(__dirname, '../../prisma/migrations/20260603072000_ai_advisory_metadata/migration.sql'),
    'utf8'
  );
  const sastQueueStore = readFileSync(
    join(__dirname, '../../src/control-plane/prisma-sast-queue-admission.store.ts'),
    'utf8'
  );
  const sastDurabilityMigration = readFileSync(
    join(
      __dirname,
      '../../prisma/migrations/20260722141000_sast_durable_plan_lifecycle/migration.sql'
    ),
    'utf8'
  );
  const sastQueueMigration = readFileSync(
    join(
      __dirname,
      '../../prisma/migrations/20260722124500_sast_queue_atomic_ledger/migration.sql'
    ),
    'utf8'
  );
  const repositoryRevocationMigration = readFileSync(
    join(
      __dirname,
      '../../prisma/migrations/20260722152000_repository_binding_revocation/migration.sql'
    ),
    'utf8'
  );
  const credentialLeaseMigration = readFileSync(
    join(
      __dirname,
      '../../prisma/migrations/20260724120000_sast_repository_credential_lease/migration.sql'
    ),
    'utf8'
  );
  const credentialLeaseScopeIndexes = [
    readFileSync(
      join(
        __dirname,
        '../../prisma/migrations/20260724110000_repository_binding_lease_scope_index/migration.sql'
      ),
      'utf8'
    ),
    readFileSync(
      join(
        __dirname,
        '../../prisma/migrations/20260724111000_scan_request_lease_scope_index/migration.sql'
      ),
      'utf8'
    )
  ].join('\n');
  const tokenBrokerService = readFileSync(
    join(__dirname, '../../src/token-broker/token-broker.service.ts'),
    'utf8'
  );
  const repositoryFetchService = readFileSync(
    join(__dirname, '../../src/scan-plane/repository-fetch.service.ts'),
    'utf8'
  );
  const scanRequestStore = readFileSync(
    join(__dirname, '../../src/control-plane/prisma-control-plane-scan-request.store.ts'),
    'utf8'
  );
  const controlPlaneService = readFileSync(
    join(__dirname, '../../src/control-plane/control-plane.service.ts'),
    'utf8'
  );
  const modelBody = (model: string) => {
    const start = schema.indexOf(`model ${model} {`);
    if (start === -1) {
      return '';
    }

    const rest = schema.slice(start);
    const end = rest.indexOf('\n}');
    return end === -1 ? rest : rest.slice(0, end);
  };

  it('exports the active architecture constants and canonical scan key builder', () => {
    expect(PRODUCTION_SCAN_ARCHITECTURE_FEATURE_ID).toBe('002-production-scan-architecture');
    expect(SCAN_LANES).toEqual(['FAST', 'DEEP']);

    expect(
      buildCanonicalScanKey({
        tenantId: 'tenant_a',
        repositoryBindingId: 'repo_1',
        lane: 'FAST',
        targetRef: 'refs/pull/12/head',
        commitSha: 'abc123',
        policyVersion: 'policy-2026-04-12',
        scannerSetVersion: 'scanner-set-v1'
      })
    ).toBe('v1:tenant_a:repo_1:FAST:refs%2Fpull%2F12%2Fhead:abc123:policy-2026-04-12:scanner-set-v1');
  });

  it('keeps AI advisory input reduced and separate from SCM credentials', () => {
    const request: AiAdvisoryRequest = {
      tenantId: 'tenant_a',
      scanRequestId: 'scan_1',
      findingId: 'finding_1',
      normalizedFinding: {
        id: 'finding_1',
        tenantId: 'tenant_a',
        scanRequestId: 'scan_1',
        scannerRunId: 'scanner_1',
        title: 'Unsafe deserialization',
        severity: 'HIGH',
        scannerProvenance: 'OPENGREP',
        filePath: 'src/App.java',
        lineStart: 42,
        status: 'OPEN'
      },
      evidence: {
        id: 'evidence_1',
        tenantId: 'tenant_a',
        scanRequestId: 'scan_1',
        classification: 'SHORT_LIVED_EVIDENCE',
        objectKey: 'tenant_a/scan_1/evidence/evidence_1.json',
        expiresAt: '2026-04-19T00:00:00.000Z',
        byteSize: 512,
        redacted: true
      },
      modelVersion: 'detector-planner-v1'
    };

    expect(JSON.stringify(request)).not.toMatch(/accessToken|refreshToken|credential|fullRepository/i);
  });

  it('describes token broker issuance as scan-scoped and non-persisted', () => {
    const request: TokenBrokerIssueRequest = {
      tenantId: 'tenant_a',
      repositoryBindingId: 'repo_1',
      scanRequestId: 'scan_1',
      attemptId: 'attempt_1',
      workloadIdentityRef: 'spiffe://aegisai/scan/attempt_1',
      workloadIdentityAttestation: {
        claims: {
          version: '1',
          issuer: 'aegisai-sandbox-provisioner',
          audience: 'aegisai-token-broker',
          tenantId: 'tenant_a',
          repositoryBindingId: 'repo_1',
          scanRequestId: 'scan_1',
          attemptId: 'attempt_1',
          workloadIdentityRef: 'spiffe://aegisai/scan/attempt_1',
          commitSha: 'a'.repeat(40),
          nonce: 'nonce_1',
          issuedAt: '2026-07-24T00:00:00.000Z',
          expiresAt: '2026-07-24T00:02:00.000Z'
        },
        signature: `sha256:${'b'.repeat(64)}`
      },
      principal: 'REPO_READ',
      commitSha: 'a'.repeat(40),
      ttlSeconds: 600,
      auditReason: 'scan-fetch'
    };

    expect(request.ttlSeconds).toBeLessThanOrEqual(600);
    expect(request.principal).toBe('REPO_READ');
    expect(JSON.stringify(request)).not.toMatch(/tokenValue|secretValue/);
  });

  it('supports risk-based isolation escalation inputs', () => {
    expect(
      shouldEscalateIsolation({
        tenantAgeDays: 3,
        repositorySizeMb: 50,
        hasParserFaultHistory: false,
        hasAbuseSignal: false,
        hasSuspiciousPathLayout: false,
        hasRepeatedTimeout: false,
        manuallyEscalated: false
      })
    ).toBe(true);

    expect(
      shouldEscalateIsolation({
        tenantAgeDays: 120,
        repositorySizeMb: 50,
        hasParserFaultHistory: false,
        hasAbuseSignal: false,
        hasSuspiciousPathLayout: false,
        hasRepeatedTimeout: false,
        manuallyEscalated: false
      })
    ).toBe(false);
  });

  it('creates short-lived evidence metadata under tenant and scan scoped object keys', () => {
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();

    expect(
      createEvidencePackMetadata({
        id: 'evidence_1',
        tenantId: 'tenant_a',
        scanRequestId: 'scan_1',
        byteSize: 512,
        expiresAt,
        redacted: true
      })
    ).toEqual({
      id: 'evidence_1',
      tenantId: 'tenant_a',
      scanRequestId: 'scan_1',
      classification: 'SHORT_LIVED_EVIDENCE',
      objectKey: 'tenant_a/scan_1/evidence/evidence_1.json',
      expiresAt,
      byteSize: 512,
      redacted: true
    });
  });

  it('adds tenant-attributed production architecture models to Prisma', () => {
    for (const model of [
      'Tenant',
      'ScmIntegration',
      'RepositoryBinding',
      'ScanRequest',
      'ScannerRun',
      'NormalizedFinding',
      'EvidencePack',
      'PolicyDecision',
      'Waiver',
      'Suppression',
      'AuditEvent'
    ]) {
      expect(schema).toContain(`model ${model} {`);
    }

    for (const indexedModel of ['ScmIntegration', 'RepositoryBinding', 'ScanRequest', 'NormalizedFinding', 'EvidencePack', 'PolicyDecision', 'Waiver', 'Suppression', 'AuditEvent']) {
      const body = modelBody(indexedModel);
      expect(body).toContain('tenantId');
      expect(body).toContain('@@index([tenantId])');
    }
  });

  it('persists AI advisory metadata without policy or finding authority fields', () => {
    const body = modelBody('AiAdvisoryMetadata');

    expect(body).toContain('tenantId');
    expect(body).toContain('scanRequestId');
    expect(body).toContain('findingId');
    expect(body).toContain('detectorAdvisories');
    expect(body).toContain('plannerAdvisories');
    expect(body).toContain('modelMetadata');
    expect(body).toContain('fallback');
    expect(body).toContain('@@index([tenantId])');
    expect(body).toContain('@@index([scanRequestId])');
    expect(body).not.toMatch(/enforcementAction|blockRequested|policyOverride|findingOverride|waiverApplied|staleSuppressed/);
  });

  it('persists SAST admission and fair dispatch state in a shared serializable ledger', () => {
    for (const model of [
      'SastQueueLedger',
      'SastQueueTenantUsage',
      'SastQueueDailyTenantUsage',
      'SastQueueRepositoryUsage',
      'SastQueueReservation'
    ]) {
      expect(schema).toContain(`model ${model} {`);
      expect(sastQueueMigration).toContain(`CREATE TABLE "${model}"`);
    }

    expect(sastQueueMigration).toContain('"snapshotVersion" BIGINT NOT NULL');
    expect(sastQueueMigration).toContain('"dispatchLeaseExpiresAt" TIMESTAMP(3)');
    expect(sastQueueStore).toContain('Prisma.TransactionIsolationLevel.Serializable');
    expect(sastQueueStore).toContain('orderSastQueueCandidatesFairly');
    expect(sastQueueStore).toContain('oldestPending');
    expect(sastQueueStore).toContain('SAST_QUEUE_MAX_DISPATCH_ATTEMPTS');
    expect(sastQueueStore).toContain('expireExhaustedDispatches');
    expect(sastQueueStore).toContain('queuedInLane: { decrement: 1 }');
    expect(sastQueueStore).toContain('transaction.scanRequest.update');
    expect(sastQueueStore).toContain('completeDispatch');
    expect(sastQueueStore).not.toMatch(/new Map/);
    expect(scanRequestStore).toContain('Prisma.TransactionIsolationLevel.Serializable');
    expect(scanRequestStore).not.toMatch(/new Map/);
    expect(controlPlaneService).toContain('persistIntegrationContext');
    expect(controlPlaneService).toContain('findRepositoryContext');
    expect(controlPlaneService).not.toContain(
      'new Map<string, ControlPlaneIntegration>()'
    );
    expect(controlPlaneService).not.toContain(
      'new Map<string, ControlPlaneRepositoryBinding>()'
    );
    expect(sastDurabilityMigration).toContain('"sastPlanning" JSONB');
    expect(sastDurabilityMigration).toContain('"planning" JSONB NOT NULL');
    expect(sastDurabilityMigration).toContain('"immutablePlan" JSONB NOT NULL');
    expect(sastDurabilityMigration).toContain('"startedAt" TIMESTAMP(3)');
    expect(sastDurabilityMigration).toContain('"completedAt" TIMESTAMP(3)');
    expect(sastDurabilityMigration).toContain('BEGIN;');
    expect(sastDurabilityMigration).toContain(
      'LOCK TABLE "SastQueueReservation" IN ACCESS EXCLUSIVE MODE;'
    );
    expect(sastDurabilityMigration).toContain('COMMIT;');
    expect(sastDurabilityMigration).toContain(
      'FOREIGN KEY ("scanRequestId") REFERENCES "ScanRequest"("id")'
    );
    expect(modelBody('SastQueueLedger')).not.toContain('dailyWindowStartedAt');
    expect(modelBody('SastQueueTenantUsage')).not.toContain('admittedTodayForTenant');
    expect(modelBody('SastQueueDailyTenantUsage')).toContain('admittedTodayForTenant');
    expect(modelBody('RepositoryBinding')).toContain('status');
    expect(modelBody('RepositoryBinding')).toContain('revokedAt');
    expect(repositoryRevocationMigration).toContain('"RepositoryBindingStatus"');
    expect(repositoryRevocationMigration).toContain('"status"');
    expect(repositoryRevocationMigration).toContain('"revokedAt"');
  });

  it('ships a deployable Prisma migration for AI advisory metadata', () => {
    expect(aiAdvisoryMetadataMigration).toContain('CREATE TABLE "AiAdvisoryMetadata"');
    expect(aiAdvisoryMetadataMigration).toContain('CONSTRAINT "AiAdvisoryMetadata_pkey" PRIMARY KEY ("id")');
    expect(aiAdvisoryMetadataMigration).toContain('FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id")');
    expect(aiAdvisoryMetadataMigration).toContain('FOREIGN KEY ("scanRequestId") REFERENCES "ScanRequest"("id")');
    expect(aiAdvisoryMetadataMigration).not.toMatch(
      /enforcementAction|blockRequested|policyOverride|findingOverride|waiverApplied|staleSuppressed/
    );
  });

  it('persists only attempt-bound credential lease metadata and hardens fixed-SHA fetch', () => {
    const leaseModel = modelBody('SastRepositoryCredentialLease');
    expect(leaseModel).toContain('attemptId');
    expect(leaseModel).toContain('credentialFingerprint');
    expect(leaseModel).toContain('workloadIdentityRef');
    expect(leaseModel).toContain('@@unique([tenantId, attemptId])');
    expect(leaseModel).not.toMatch(/credentialValue|accessToken|refreshToken|secretValue/);
    expect(credentialLeaseMigration).toContain(
      'CREATE TABLE "SastRepositoryCredentialLease"'
    );
    expect(credentialLeaseMigration).toContain(
      'CREATE UNIQUE INDEX "SastRepositoryCredentialLease_tenantId_attemptId_key"'
    );
    expect(credentialLeaseMigration).toContain(
      'FOREIGN KEY ("scanRequestId", "tenantId", "repositoryBindingId")'
    );
    expect(credentialLeaseMigration).toContain(
      'REFERENCES "ScanRequest"("id", "tenantId", "repositoryBindingId")'
    );
    expect(credentialLeaseMigration).toContain(
      'FOREIGN KEY ("repositoryBindingId", "tenantId")'
    );
    expect(credentialLeaseMigration).toContain(
      'REFERENCES "RepositoryBinding"("id", "tenantId")'
    );
    expect(credentialLeaseMigration).toContain(
      'ADD CONSTRAINT "SastCredentialLease_scan_scope_fkey"'
    );
    expect(credentialLeaseMigration).toMatch(
      /REFERENCES "ScanRequest"\("id", "tenantId", "repositoryBindingId"\)\s+ON DELETE CASCADE/
    );
    expect(credentialLeaseMigration).toContain(
      'CONSTRAINT "SastRepositoryCredentialLease_lifecycle_check"'
    );
    expect(credentialLeaseScopeIndexes).toContain(
      'CREATE UNIQUE INDEX CONCURRENTLY "RepositoryBinding_id_tenantId_key"'
    );
    expect(credentialLeaseScopeIndexes).toContain(
      'CREATE UNIQUE INDEX CONCURRENTLY "ScanRequest_id_tenantId_repositoryBindingId_key"'
    );
    expect(credentialLeaseMigration).not.toMatch(
      /credentialValue|accessToken|refreshToken|secretValue/
    );
    expect(tokenBrokerService).toContain('workloadIdentityAttestation.verify');
    expect(tokenBrokerService).toContain('credentialLeaseStore.reserve');
    expect(tokenBrokerService).toContain('credentialLeaseStore.markWiped');
    expect(tokenBrokerService).not.toMatch(/private readonly auditEvents|new Map/);
    expect(repositoryFetchService).toContain("'--depth=1'");
    expect(repositoryFetchService).toContain("'--no-recurse-submodules'");
    expect(repositoryFetchService).toContain("GIT_LFS_SKIP_SMUDGE: '1'");
    expect(repositoryFetchService).toContain('credentialTmpfsVerifier.assertTmpfs');
    expect(repositoryFetchService).not.toMatch(/execSync|shell:\s*true/);
  });
});
