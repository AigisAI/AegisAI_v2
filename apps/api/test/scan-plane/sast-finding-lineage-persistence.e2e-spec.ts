import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('SAST finding lineage persistence contract', () => {
  const schema = read('prisma/schema.prisma');
  const migration = read(
    'prisma/migrations/20260730160000_sast_finding_lineage_lifecycle/migration.sql'
  );
  const onlineSchema = read(
    'scripts/apply-online-sast-runtime-schema.mjs'
  );
  const store = read(
    'src/scan-plane/prisma-sast-finding-lineage.store.ts'
  );
  const service = read(
    'src/scan-plane/sast-finding-lineage.service.ts'
  );
  const coverageGate = read(
    'src/scan-plane/sast-finding-lifecycle-coverage.gate.ts'
  );
  const module = read('src/scan-plane/scan-plane.module.ts');

  it('separates global identity, ordered occurrences, target lifecycle, and append-only events', () => {
    for (const model of [
      'SastFindingLineage',
      'SastFindingIdentityAlias',
      'SastFindingObservationBatch',
      'SastFindingOccurrence',
      'SastFindingLifecycleState',
      'SastFindingLifecycleReconciliation',
      'SastFindingLifecycleEvent'
    ]) {
      expect(schema).toContain(`model ${model} {`);
      expect(migration).toContain(`CREATE TABLE "${model}"`);
    }
    expect(schema).toContain(
      '@@unique([tenantId, repositoryBindingId, capability, fingerprintVersion, stableFingerprint], map: "SastFindingIdentityAlias_fingerprint_key")'
    );
    expect(schema).toContain(
      'SastFindingLineage_identity_scope_key'
    );
    expect(migration).toContain(
      'SastFindingLineage_identity_scope_key'
    );
    expect(schema).toContain(
      '@@unique([observationBatchId, ordinal], map: "SastFindingOccurrence_batch_ordinal_key")'
    );
    expect(schema).toContain(
      '@@unique([tenantId, repositoryBindingId, lifecycleContextKey, lineageId], map: "SastFindingLifecycleState_context_lineage_key")'
    );
    expect(schema).toContain(
      '@@unique([id, tenantId, repositoryBindingId, lineageId, lifecycleContextKey], map: "SastFindingLifecycleState_scope_key")'
    );
    expect(schema).toContain(
      '@@unique([id, tenantId, repositoryBindingId, lifecycleContextKey], map: "SastFindingObservationBatch_event_scope_key")'
    );
    expect(schema).toContain(
      '@@unique([id, tenantId, repositoryBindingId, lifecycleContextKey], map: "SastFindingLifecycleReconciliation_event_scope_key")'
    );
    expect(schema).toContain(
      '@@unique([lifecycleStateId, revision], map: "SastFindingLifecycleEvent_state_revision_key")'
    );
    expect(migration).toContain(
      '"kind" = \'FIXED\''
    );
    expect(migration).toContain(
      '"kind" = \'REOPENED\''
    );
    for (const sourceConstraint of [
      'SastFindingLifecycleEvent_observation_scope_fkey',
      'SastFindingLifecycleEvent_reconciliation_scope_fkey'
    ]) {
      expect(schema).toContain(sourceConstraint);
      expect(migration).toContain(sourceConstraint);
    }
    expect(schema).toMatch(/lastObservedAt\s+DateTime\?/u);
    expect(migration).toContain(
      '"lastObservedAt" TIMESTAMP(3)'
    );
  });

  it('keeps legacy policy status separate and rolls out nullable metadata online', () => {
    const normalizedFinding =
      schema.match(
        /model NormalizedFinding \{([\s\S]*?)\n\}/
      )?.[1] ?? '';
    expect(normalizedFinding).toContain(
      'status'
    );
    expect(normalizedFinding).not.toContain(
      'lifecycleStatus'
    );
    expect(migration).toContain(
      'ALTER COLUMN "lineStart" DROP NOT NULL'
    );
    expect(migration).toContain(
      'ADD COLUMN "sastLineageId" TEXT'
    );
    for (const onlineControl of [
      'NormalizedFinding_sast_occurrence_scope_key',
      'NormalizedFinding_sastLineageId_idx',
      'NormalizedFinding_sastObservationBatchId_idx',
      'NormalizedFinding_sast_metadata_check',
      'SastFindingOccurrence_normalized_scope_fkey',
      'SastFindingObservationBatch_scanner_scope_fkey'
    ]) {
      expect(onlineSchema).toContain(onlineControl);
    }
    expect(onlineSchema).toContain(
      'CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS "NormalizedFinding_sast_occurrence_scope_key"'
    );
  });

  it('serializes writes, retains duplicate observations, and rejects incomplete reconciliation', () => {
    expect(store).toContain(
      'Prisma.TransactionIsolationLevel.Serializable'
    );
    expect(store).toContain(
      'SERIALIZABLE_ATTEMPTS = 3'
    );
    expect(store).toContain(
      'SERIALIZABLE_TIMEOUT_MILLISECONDS = 120_000'
    );
    expect(store).toContain(
      'transaction.sastFindingOccurrence.createMany'
    );
    expect(store).toContain(
      'transaction.normalizedFinding.createMany'
    );
    expect(store).toContain(
      'SastFindingLineageObservationIncompleteError'
    );
    expect(store).toContain(
      'sameStringArray'
    );
    expect(store).toContain(
      'canonicalizeSastFingerprintedFinding'
    );
    expect(store).toContain(
      'SAST_SCANNER_RESPONSIBILITIES'
    );
    expect(service).toContain(
      'isSastFingerprintedFindingBatchShapeValid'
    );
    expect(service).toContain(
      'FINDING_LINEAGE_SCAN_STALE'
    );
    expect(service).toContain(
      'FINDING_LINEAGE_SCAN_NOT_COMPARABLE'
    );
  });

  it('keeps T037 internal after T038 and leaves rename/coverage authority unavailable by default', () => {
    expect(module).toContain(
      'UnavailableSastFindingRenameAttestationVerifier'
    );
    expect(module).toContain(
      'UnavailableSastFindingLifecycleCoverageGate'
    );
    expect(module).toMatch(
      /exports:\s*\[[\s\S]*SastFindingCorrelationService[\s\S]*\]/
    );
    const exportsBlock =
      module.match(/exports:\s*\[([\s\S]*?)\]\s*\n\}\)/)?.[1] ??
      '';
    expect(exportsBlock).not.toContain(
      'SastFindingIdentityService'
    );
    expect(exportsBlock).not.toContain(
      'SastFindingLineageService'
    );
    expect(coverageGate).toContain(
      'T039 owns coverage calculation'
    );
    expect(coverageGate).not.toMatch(
      /^\s*(?:(?:public|protected|private|static|async|override)\s+)*(?:calculate|publish|override)\s*\([^)]*\)\s*(?::[^{\n]+)?\s*\{|^\s*abstract\s+(?:calculate|publish|override)\s*\([^)]*\)\s*(?::[^;\n]+)?;/mu
    );
  });
});

function read(relativePath: string): string {
  return readFileSync(
    resolve(__dirname, `../../${relativePath}`),
    'utf8'
  );
}
