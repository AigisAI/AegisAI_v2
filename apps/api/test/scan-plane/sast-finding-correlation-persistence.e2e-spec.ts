import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('SAST finding correlation persistence contract', () => {
  const schema = read('prisma/schema.prisma');
  const migration = read(
    'prisma/migrations/20260802120000_sast_finding_correlation/migration.sql'
  );
  const onlineSchema = read(
    'scripts/apply-online-sast-runtime-schema.mjs'
  );
  const store = read(
    'src/scan-plane/prisma-sast-finding-correlation.store.ts'
  );
  const service = read(
    'src/scan-plane/sast-finding-correlation.service.ts'
  );
  const lineageStore = read(
    'src/scan-plane/prisma-sast-finding-lineage.store.ts'
  );
  const module = read('src/scan-plane/scan-plane.module.ts');

  it('persists a closed source set, non-collapsing edges, and two-sided provenance', () => {
    for (const model of [
      'SastFindingCorrelationBatch',
      'SastFindingCorrelationSource',
      'SastFindingCorrelationEdge',
      'SastFindingCorrelationProvenance'
    ]) {
      expect(schema).toContain(`model ${model} {`);
      expect(migration).toContain(`CREATE TABLE "${model}"`);
    }
    expect(schema).toContain(
      'SastFindingCorrelationBatch_attempt_context_key'
    );
    expect(schema).toContain(
      'SastFindingCorrelationSource_batch_observation_key'
    );
    expect(schema).toContain(
      'SastFindingCorrelationEdge_pair_key'
    );
    expect(schema).toContain(
      'SastFindingCorrelationProvenance_edge_side_key'
    );
    expect(migration).toContain(
      '"sourceOccurrenceId" < "targetOccurrenceId"'
    );
    expect(migration).toContain(
      '"severityInheritanceAllowed": false'
    );
    expect(migration).toContain(
      '"occurrenceProvenancePreserved": true'
    );
  });

  it('installs cross-tenant occurrence provenance fences through the blocking online step', () => {
    expect(schema).toContain(
      'SastFindingOccurrence_correlation_scope_key'
    );
    expect(onlineSchema).toContain(
      'CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS "SastFindingOccurrence_correlation_scope_key"'
    );
    for (const constraint of [
      'SastFindingCorrelationEdge_source_occurrence_scope_fkey',
      'SastFindingCorrelationEdge_target_occurrence_scope_fkey',
      'SastFindingCorrelationProvenance_occurrence_scope_fkey'
    ]) {
      expect(schema).toContain(constraint);
      expect(onlineSchema).toContain(constraint);
    }
  });

  it('revalidates the exact durable observation ledger in a bounded serializable transaction', () => {
    expect(store).toContain(
      'Prisma.TransactionIsolationLevel.Serializable'
    );
    expect(store).toContain('SERIALIZABLE_ATTEMPTS = 3');
    expect(store).toContain(
      'SERIALIZABLE_TIMEOUT_MILLISECONDS = 120_000'
    );
    expect(store).toContain('allBatches.length !== orderedIds.length');
    expect(store).toContain(
      'canonicalizeSastFingerprintedFinding'
    );
    expect(store).toContain('verifySourceCapabilities');
    expect(store).toContain('createManyInChunks');
    expect(store).toContain('replayCorrelation');
    expect(service).toContain(
      'SAST_FINDING_CORRELATION_LIMITS.maximumEdges'
    );
    expect(service).toContain(
      'yieldOccurrenceInterval'
    );
    expect(service).not.toMatch(
      /@Controller|@(Get|Post|Put|Patch|Delete)\(/u
    );
  });

  it('fences late T037 batches and exports only the T038 gate to T039', () => {
    expect(lineageStore).toContain(
      'transaction.sastFindingCorrelationBatch'
    );
    expect(lineageStore).toContain(
      'late scanner batch cannot be'
    );
    const exportsBlock =
      module.match(/exports:\s*\[([\s\S]*?)\]\s*\n\}\)/)?.[1] ?? '';
    expect(exportsBlock).toContain(
      'SastFindingCorrelationService'
    );
    expect(exportsBlock).not.toContain(
      'SastFindingLineageService'
    );
    expect(exportsBlock).not.toContain(
      'SastFindingIdentityService'
    );
  });
});

function read(relativePath: string): string {
  return readFileSync(
    resolve(__dirname, `../../${relativePath}`),
    'utf8'
  );
}
