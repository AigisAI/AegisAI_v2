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
  const sastQueueMigration = readFileSync(
    join(__dirname, '../../prisma/migrations/20260722124500_sast_queue_atomic_ledger/migration.sql'),
    'utf8'
  );
  const sastQueueStore = readFileSync(
    join(__dirname, '../../src/control-plane/prisma-sast-queue-admission.store.ts'),
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
      principal: 'REPO_READ',
      commitSha: 'abc123',
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
    expect(sastQueueStore).not.toMatch(/new Map/);
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
});
