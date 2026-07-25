import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('SAST artifact disposition persistence contract', () => {
  const schema = read('prisma/schema.prisma');
  const migration = read(
    'prisma/migrations/20260726120000_sast_artifact_disposition/migration.sql'
  );
  const onlineSchema = read(
    'scripts/apply-online-sast-runtime-schema.mjs'
  );
  const storagePort = read(
    'src/scan-plane/sast-artifact-disposition-storage.ts'
  );
  const module = read('src/scan-plane/scan-plane.module.ts');
  const configSchema = read('src/config/config.schema.ts');

  it('persists one immutable, scope-bound final decision without raw object or key material fields', () => {
    expect(schema).toMatch(
      /model SastArtifactDispositionDecision \{/
    );
    expect(schema).toMatch(
      /ingestionId\s+String\s+@unique/
    );
    expect(schema).toMatch(
      /normalizationEligible\s+Boolean\s+@default\(false\)/
    );
    expect(schema).toMatch(
      /@@unique\(\[ingestionId, tenantId, repositoryBindingId, scanRequestId, attemptId, scannerRunId\], map: "SastArtifactDispositionDecision_scope_key"\)/
    );
    expect(schema).toMatch(
      /@@unique\(\[auditEventId, attemptId, tenantId, scanRequestId\], map: "SastArtifactDispositionDecision_audit_scope_key"\)/
    );

    const decisionModel = schema.match(
      /model SastArtifactDispositionDecision \{([\s\S]*?)\n\}/
    )?.[1] ?? '';
    for (const forbiddenField of [
      'objectKey',
      'kmsKey',
      'encryptionKey',
      'rawArtifact',
      'plaintext'
    ]) {
      expect(decisionModel).not.toMatch(
        new RegExp(`\\b${forbiddenField}\\b`, 'i')
      );
    }
  });

  it('uses online indexes, a partial claim index, fencing, and validated lifecycle replacement', () => {
    for (const indexName of [
      'SastArtifactIngestion_dispositionLeaseToken_key',
      'SastArtifactIngestion_dispositionOperationId_key',
      'SastArtifactIngestion_disposition_scope_key',
      'SastArtifactIngestion_disposition_claim_idx'
    ]) {
      expect(onlineSchema).toContain(indexName);
    }
    expect(onlineSchema).toContain(
      'CREATE INDEX CONCURRENTLY IF NOT EXISTS "SastArtifactIngestion_disposition_claim_idx"'
    );
    expect(onlineSchema).toContain(
      `WHERE "status" = \\'PENDING_VALIDATION\\'`
    );
    expect(onlineSchema).toContain(
      'SastArtifactIngestion_lifecycle_v2_check'
    );
    expect(onlineSchema).toContain(
      'AuditEvent_artifact_disposition_scope_key'
    );
    expect(onlineSchema).toContain(
      'SastArtifactDispositionDecision_audit_scope_fkey'
    );
    expect(onlineSchema).toContain(
      "replacement: 'SastArtifactIngestion_lifecycle_v2_check'"
    );
    expect(migration).toContain(
      '"dispositionLeaseToken" TEXT'
    );
    expect(migration).toContain(
      '"dispositionIntent" JSONB'
    );
    expect(migration).toContain(
      '"dispositionOperationId" TEXT'
    );
    expect(migration).toContain(
      "'storageOperationId' = \"operationId\""
    );
    expect(migration).toContain(
      "'^storage-receipt://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]+$'"
    );
    expect(migration).toContain(
      '"retentionExpiresAt" > "decidedAt"'
    );
    expect(onlineSchema).toContain(
      '"retentionExpiresAt" > "dispositionDecidedAt"'
    );
  });

  it('keeps storage no-read and fail closed until explicit production adapters are installed', () => {
    expect(storagePort).toMatch(
      /abstract apply\([\s\S]*Promise<SastArtifactStorageDispositionReceipt>/
    );
    expect(storagePort).not.toMatch(/\b(read|get|download)\s*\(/);
    expect(storagePort).toContain(
      'server-side retain/delete/re-encrypt operations'
    );
    expect(module).toContain(
      'UnavailableSastArtifactDispositionStorage'
    );
    expect(module).toContain(
      'UnavailableSastArtifactAcceptanceGate'
    );
    expect(configSchema).toContain(
      'SAST_ARTIFACT_DISPOSITION_INTERVAL_MS'
    );
  });
});

function read(relativePath: string): string {
  return readFileSync(resolve(__dirname, `../../${relativePath}`), 'utf8');
}
