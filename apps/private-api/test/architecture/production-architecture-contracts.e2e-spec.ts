import {
  buildCanonicalScanKey,
  createEvidencePackMetadata,
  MAX_SCAN_CREDENTIAL_TTL_SECONDS,
  PRODUCTION_SCAN_ARCHITECTURE_FEATURE_ID,
  SCAN_LANES,
  shouldEscalateIsolation,
  type AiAdvisoryRequest,
  type TokenBrokerIssueRequest
} from '@aegisai/shared/private-runtime';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

describe('production scan architecture contracts', () => {
  const schema = readFileSync(join(__dirname, '../../../../packages/private-runtime-db/prisma/schema.prisma'), 'utf8');
  const hardeningMigration = readFileSync(
    join(
      __dirname,
      '../../../../packages/private-runtime-db/prisma/migrations/20260720000000_production_architecture_hardening/migration.sql'
    ),
    'utf8'
  );
  const futureEvidenceExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
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
        language: 'JAVA',
        scanProfile: 'JAVA_DETAILED',
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
        expiresAt: futureEvidenceExpiry,
        byteSize: 512,
        redacted: true
      },
      modelVersion: 'detector-planner-v1'
    };

    expect(JSON.stringify(request)).not.toMatch(
      /accessToken|refreshToken|credential|fullRepository|sourceContent|rawScannerOutput|policyOverride/i
    );
    // These assignments are checked by typecheck: AI accepts only the narrowed boundary.
    const commonFinding: AiAdvisoryRequest['normalizedFinding'] = {
      ...request.normalizedFinding,
      // @ts-expect-error Common coverage cannot enter the Java-only advisory contract.
      scanProfile: 'COMMON'
    };
    const unredactedEvidence: AiAdvisoryRequest['evidence'] = {
      ...request.evidence,
      // @ts-expect-error Unredacted evidence cannot enter the advisory contract.
      redacted: false
    };
    const sourceRequest: AiAdvisoryRequest = {
      ...request,
      // @ts-expect-error Source bodies are outside the advisory contract.
      fullRepository: 'forbidden'
    };
    expect(commonFinding.scanProfile).toBe('COMMON');
    expect(unredactedEvidence.redacted).toBe(false);
    expect(Object.keys(sourceRequest)).toContain('fullRepository');
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

    expect(request.ttlSeconds).toBeLessThanOrEqual(MAX_SCAN_CREDENTIAL_TTL_SECONDS);
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
    expect(
      createEvidencePackMetadata({
        id: 'evidence_1',
        tenantId: 'tenant_a',
        scanRequestId: 'scan_1',
        byteSize: 512,
        expiresAt: futureEvidenceExpiry,
        redacted: true
      })
    ).toEqual({
      id: 'evidence_1',
      tenantId: 'tenant_a',
      scanRequestId: 'scan_1',
      classification: 'SHORT_LIVED_EVIDENCE',
      objectKey: 'tenant_a/scan_1/evidence/evidence_1.json',
      expiresAt: futureEvidenceExpiry,
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

  it('stores OAuth identity metadata without long-lived user access tokens', () => {
    expect(schema).toContain('model UserOAuthIdentity {');
    expect(modelBody('UserOAuthIdentity')).not.toMatch(/accessToken|refreshToken/);
    expect(hardeningMigration).toContain('ALTER TABLE "OAuthToken" RENAME TO "UserOAuthIdentity"');
    expect(hardeningMigration).toContain('DROP COLUMN "accessToken"');
    expect(hardeningMigration).toContain('DROP COLUMN "refreshToken"');
  });

  it('ships migrations for every production architecture persistence model', () => {
    for (const table of [
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
      expect(hardeningMigration).toContain(`CREATE TABLE "${table}"`);
    }

    expect(hardeningMigration).toContain('NormalizedFinding_valid_line_range_check');
    expect(hardeningMigration).toContain('EvidencePack_valid_retention_check');
  });
});
