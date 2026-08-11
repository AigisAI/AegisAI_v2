import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('SAST scan coverage persistence contract', () => {
  const schema = read('prisma/schema.prisma');
  const migration = read(
    'prisma/migrations/20260802150000_sast_scan_coverage/migration.sql'
  );
  const onlineSchema = read(
    'scripts/apply-online-sast-runtime-schema.mjs'
  );
  const store = read(
    'src/scan-plane/prisma-sast-scan-coverage.store.ts'
  );
  const service = read('src/scan-plane/sast-scan-coverage.service.ts');
  const module = read('src/scan-plane/scan-plane.module.ts');

  it('persists tenant-scoped scanner, coverage, and publication decisions', () => {
    for (const model of [
      'SastScanCoverageDecision',
      'SastScannerCoverageRecord',
      'SastExternalPublicationDecision'
    ]) {
      expect(schema).toContain(`model ${model} {`);
      expect(migration).toContain(`CREATE TABLE "${model}"`);
    }
    expect(migration).toContain(
      'SastScanCoverageDecision_correlation_scope_fkey'
    );
    expect(onlineSchema).toContain(
      'SastScannerCoverageRecord_scanner_scope_fkey'
    );
    expect(onlineSchema).toContain(
      'SastScannerCoverageRecord_ingestion_scope_fkey'
    );
    expect(schema).toMatch(
      /artifactIngestion\s+SastArtifactIngestion\?[\s\S]{0,300}onDelete: Restrict[\s\S]{0,150}SastScannerCoverageRecord_ingestion_scope_fkey/
    );
    expect(onlineSchema).toMatch(
      /SastScannerCoverageRecord_ingestion_scope_fkey[\s\S]{0,500}ON DELETE RESTRICT ON UPDATE CASCADE/
    );
    expect(onlineSchema).toContain(
      'SastScannerCoverageRecord_disposition_scope_fkey'
    );
    expect(onlineSchema).toContain(
      'SastScannerCoverageRecord_source_scope_fkey'
    );
    expect(onlineSchema).toContain(
      'CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS "SastArtifactDispositionDecision_coverage_scope_key"'
    );
    expect(onlineSchema).toContain(
      'CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS "SastFindingCorrelationSource_coverage_scope_key"'
    );
    expect(migration).not.toContain(
      'CREATE UNIQUE INDEX "SastArtifactDispositionDecision_coverage_scope_key"'
    );
    expect(migration).not.toContain(
      'CREATE UNIQUE INDEX "SastFindingCorrelationSource_coverage_scope_key"'
    );
    expect(migration).not.toContain(
      'ADD CONSTRAINT "SastScannerCoverageRecord_scanner_scope_fkey"'
    );
    expect(migration).not.toContain(
      'ADD CONSTRAINT "SastScannerCoverageRecord_ingestion_scope_fkey"'
    );
    expect(migration).toContain(
      'SastScanCoverageDecision_attempt_key'
    );
    expect(migration).toContain(
      'SastScannerCoverageRecord_decision_scanner_key'
    );
  });

  it('makes zero external publication a database invariant before T040', () => {
    expect(migration).toMatch(/"externalCommentAllowed" = false/);
    expect(migration).toMatch(/"blockingStatusAllowed" = false/);
    expect(migration).toMatch(/"aiAdvisoryAllowed" = false/);
    expect(migration).toMatch(/"lifecycleMutationAllowed" = false/);
    expect(migration).toContain(
      '"latestTargetAuthority" = \'UNAVAILABLE\''
    );
    expect(migration).toContain('"staleStatus" = \'UNKNOWN\'');
    expect(migration).toContain(
      '"comparabilityStatus" = \'UNKNOWN\''
    );
    expect(migration).toContain(
      '"publicationAuthority": false'
    );
    expect(migration).toContain('"aiPayloadEligible": false');
  });

  it('re-reads exact durable state in a bounded serializable transaction', () => {
    expect(store).toContain(
      'Prisma.TransactionIsolationLevel.Serializable'
    );
    expect(store).toContain('SERIALIZABLE_ATTEMPTS = 3');
    expect(store).toContain(
      'SERIALIZABLE_TIMEOUT_MILLISECONDS = 120_000'
    );
    expect(store).toContain('sameDurableContext');
    expect(store).toContain('replayCoverage');
    expect(store).toContain('recordsMatchContext');
    expect(store).toContain("input.decision.state === 'PENDING'");
    expect(store).toContain(
      'buildSastFindingCorrelationSourceSetPreimage'
    );
    expect(store).toContain('isScannerArtifactEnvelopeBoundToPlan');
    expect(store).toContain(
      'canonicalizeSastArtifactDispositionDecision'
    );
    expect(store).toContain('verifyLifecycleSource');
    expect(store).toContain(
      'buildFailClosedSastExternalPublicationDecision'
    );
  });

  it('keeps T039 through T041 internal after exposing only the T042 handoff', () => {
    const exportsBlock =
      module.match(/exports:\s*\[([\s\S]*?)\]\s*\n\}\)/)?.[1] ?? '';
    expect(exportsBlock).toContain('SastEvidenceAccessService');
    expect(exportsBlock).not.toContain('SastAcceptedEvidenceService');
    expect(exportsBlock).not.toContain('SastScanFreshnessService');
    expect(exportsBlock).not.toContain('SastScanCoverageService');
    expect(exportsBlock).not.toContain(
      'SastFindingCorrelationService'
    );
    expect(exportsBlock).not.toContain('SastFindingLineageService');
    expect(exportsBlock).not.toContain('SastFindingIdentityService');
    expect(exportsBlock).not.toContain('SastSecretRedactionService');
    expect(exportsBlock).not.toContain('OpenGrepSarifNormalizer');
    expect(exportsBlock).not.toContain('TrivyJsonNormalizer');
    expect(exportsBlock).not.toContain('SyftCycloneDxInventoryIngestor');
    expect(module).toMatch(
      /provide:\s*SastFindingLifecycleCoverageGate,[\s\S]{0,100}useExisting:\s*SastScanFreshnessService/
    );
    expect(service).not.toMatch(/\bLogger\b|\bconsole\./u);
    expect(service).not.toMatch(
      /@Controller|@(Get|Post|Put|Patch|Delete)\(/u
    );
    expect(service).not.toMatch(/SCM_WRITE|commentWrite|statusWrite/u);
    expect(service).toContain('verifyLifecycleSource');
    expect(service).toContain('T040');
  });
});

function read(path: string): string {
  return readFileSync(resolve(__dirname, `../../${path}`), 'utf8');
}
