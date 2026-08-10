import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('SAST scan freshness and retry persistence contract', () => {
  const schema = read('prisma/schema.prisma');
  const migration = read(
    'prisma/migrations/20260810030000_sast_scan_freshness_retry/migration.sql'
  );
  const store = read(
    'src/scan-plane/prisma-sast-scan-freshness.store.ts'
  );
  const service = read('src/scan-plane/sast-scan-freshness.service.ts');
  const runtime = read('src/scan-plane/sast-scanner-runtime.service.ts');
  const attestation = read(
    'src/scan-plane/sandbox-runtime-attestation.service.ts'
  );
  const runtimeStore = read(
    'src/scan-plane/prisma-sast-scanner-runtime.store.ts'
  );
  const module = read('src/scan-plane/scan-plane.module.ts');

  it('persists independently scoped target observations, freshness, and retry decisions', () => {
    for (const model of [
      'SastLatestTargetObservation',
      'SastScanFreshnessDecision',
      'SastScanRetryDecision'
    ]) {
      expect(schema).toContain(`model ${model} {`);
      expect(migration).toContain(`CREATE TABLE "${model}"`);
    }
    expect(migration).toContain(
      'SastLatestTargetObservation_sequence_key'
    );
    expect(migration).toContain(
      'SastScanFreshnessDecision_coverage_scope_fkey'
    );
    expect(migration).toContain(
      'SastScanCoverageDecision_comparison_scope_key'
    );
    expect(migration).toMatch(
      /FOREIGN KEY \("previousCoverageDecisionId", "tenantId", "repositoryBindingId", "previousScanRequestId"\)/u
    );
    expect(migration).toContain(
      'SastScanRetryDecision_previous_attempt_fkey'
    );
    expect(migration).toContain(
      'SastScanRetryDecision_final_audit_fkey'
    );
    expect(migration).toContain(
      'SastScanAttempt_retryDecisionId_fkey'
    );
  });

  it('replaces the T039 permanent check while preserving its immutable source row', () => {
    expect(migration).toContain(
      'DROP CONSTRAINT "SastExternalPublicationDecision_contract_check"'
    );
    expect(migration).toContain(
      'SastExternalPublicationDecision_t039_source_check'
    );
    expect(migration).toContain(
      'VALIDATE CONSTRAINT "SastExternalPublicationDecision_t039_source_check"'
    );
    expect(
      migration.indexOf(
        'VALIDATE CONSTRAINT "SastExternalPublicationDecision_t039_source_check"'
      )
    ).toBeLessThan(
      migration.indexOf(
        'DROP CONSTRAINT "SastExternalPublicationDecision_contract_check"'
      )
    );
    expect(migration).toContain(
      'SastScanFreshnessDecision_contract_check'
    );
    expect(migration).toMatch(
      /"latestTargetAuthority" = 'VERIFIED'[\s\S]{0,200}"staleStatus" = 'FRESH'[\s\S]{0,200}"comparabilityStatus" = 'COMPARABLE'/
    );
    expect(migration).toContain('"aiAdvisoryAllowed" = false');
    expect(migration).toContain('"publicationAttempted" = false');
  });

  it('uses bounded serializable replay and re-verifies T037 lifecycle input', () => {
    expect(store).toContain(
      'Prisma.TransactionIsolationLevel.Serializable'
    );
    expect(store).toContain('SERIALIZABLE_ATTEMPTS = 3');
    expect(store).toContain(
      'SERIALIZABLE_TIMEOUT_MILLISECONDS = 120_000'
    );
    expect(store).toContain('sameFreshnessContext');
    expect(store).toContain('replayFreshness');
    expect(store).toContain('sameRetryPredecessor');
    expect(store).toContain('coverageRowMatchesDecision');
    expect(store).toContain('coverageLedgerMatchesDecision');
    expect(store).toContain('buildSastScanCoverageRecordsPreimage');
    expect(store).toContain('verifyLifecycleSource');
    expect(store).toContain("state: 'COMPLETE'");
    expect(store).toContain("staleStatus: 'FRESH'");
    expect(store).toContain("comparabilityStatus: 'COMPARABLE'");
  });

  it('requires a durable allowed retry row before attempt two starts', () => {
    expect(runtime).toContain('SastRetryAdmissionGate');
    expect(runtime).toContain("request.attemptNumber === 2");
    expect(runtime).toContain("'AUTHORIZED'");
    expect(runtimeStore).toContain(
      'isSastScanRetryDecisionShapeValid'
    );
    expect(runtimeStore).toContain(
      'sastScanRetryDecision.findUnique'
    );
    expect(runtimeStore).toContain('retryDecisionId: retryDecision?.id');
    expect(runtime).toContain('preflight: request.preflight');
    expect(runtime).toContain('verifyPreflight(request)');
    expect(attestation).toContain('effectivePreflight');
    expect(attestation).toContain('binding.attemptNumber === 1');
    expect(attestation).toMatch(
      /preflight\.attestationRef\s*!==\s*binding\.plan\.repositoryState\.attestationRef/u
    );
    expect(migration).toContain(
      '"previousFailureClass" = \'RETRYABLE_INFRASTRUCTURE\''
    );
    expect(migration).toMatch(
      /"retryAllowed" = true\s+AND "previousAttemptNumber" = 1/u
    );
    expect(migration).toContain(
      '"previousSandboxId" <> "requestedSandboxId"'
    );
  });

  it('exports only the T040 sequential handoff and opens no route or SCM writer', () => {
    const exportsBlock =
      module.match(/exports:\s*\[([\s\S]*?)\]\s*\n\}\)/)?.[1] ?? '';
    expect(exportsBlock).toContain('SastScanFreshnessService');
    expect(exportsBlock).not.toContain('SastScanCoverageService');
    expect(module).toMatch(
      /provide:\s*SastFindingLifecycleCoverageGate,[\s\S]{0,100}useExisting:\s*SastScanFreshnessService/
    );
    expect(module).toMatch(
      /provide:\s*SastRetryAdmissionGate,[\s\S]{0,100}useExisting:\s*SastScanFreshnessService/
    );
    expect(service).not.toMatch(/@Controller|@(Get|Post|Put|Patch|Delete)\(/u);
    expect(service).not.toMatch(/SCM_WRITE|commentWrite|statusWrite/u);
    expect(service).not.toMatch(/\bLogger\b|\bconsole\./u);
    expect(service).toContain('publicationAttempted: false');
    expect(service).toContain('aiPayloadCreated: false');
  });
});

function read(path: string): string {
  return readFileSync(resolve(__dirname, `../../${path}`), 'utf8');
}
