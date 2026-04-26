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
    ).toBe('tenant_a:repo_1:FAST:refs/pull/12/head:abc123:policy-2026-04-12:scanner-set-v1');
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
    expect(
      createEvidencePackMetadata({
        id: 'evidence_1',
        tenantId: 'tenant_a',
        scanRequestId: 'scan_1',
        byteSize: 512,
        expiresAt: '2026-04-19T00:00:00.000Z',
        redacted: true
      })
    ).toEqual({
      id: 'evidence_1',
      tenantId: 'tenant_a',
      scanRequestId: 'scan_1',
      classification: 'SHORT_LIVED_EVIDENCE',
      objectKey: 'tenant_a/scan_1/evidence/evidence_1.json',
      expiresAt: '2026-04-19T00:00:00.000Z',
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
});
