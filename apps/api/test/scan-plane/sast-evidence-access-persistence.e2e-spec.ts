import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('SAST evidence access and deletion persistence contract', () => {
  const schema = read('prisma/schema.prisma');
  const migration = read(
    'prisma/migrations/20260810070000_sast_evidence_access_deletion/migration.sql'
  );
  const store = read(
    'src/scan-plane/prisma-sast-evidence-access.store.ts'
  );
  const service = read(
    'src/scan-plane/sast-evidence-access.service.ts'
  );
  const deletion = read(
    'src/scan-plane/sast-evidence-deletion.service.ts'
  );
  const authority = read(
    'src/scan-plane/sast-evidence-deletion.authority.ts'
  );
  const controller = read(
    'src/dashboard/dashboard-evidence.controller.ts'
  );
  const module = read('src/scan-plane/scan-plane.module.ts');
  const shared = readShared('src/types/sast-evidence-access.ts');

  it('adds separate immutable access, schedule, claim, and proof ledgers', () => {
    for (const model of [
      'SastEvidenceAccessDecision',
      'SastEvidenceDeletionSchedule',
      'SastEvidenceDeletionClaim',
      'SastEvidenceDeletionProof'
    ]) {
      expect(schema).toContain(`model ${model} {`);
      expect(migration).toContain(`CREATE TABLE "${model}"`);
    }
    expect(migration).toContain(
      'SastEvidenceAccessDecision_build_scope_fkey'
    );
    expect(migration).toContain(
      'SastEvidenceAccessDecision_schedule_scope_fkey'
    );
    expect(migration).toContain(
      'SastEvidenceDeletionSchedule_build_scope_fkey'
    );
    expect(migration).toContain(
      'SastEvidenceDeletionProof_schedule_scope_fkey'
    );
    expect(migration).toContain(
      'SastEvidenceDeletionClaim_due_idx'
    );
    expect(migration).toContain(
      'SastEvidenceDeletionSchedule_deleteAfter_idx'
    );
    expect(migration).toContain(
      'SastEvidenceAccessDecision_aiPayloadExpiresAt_idx'
    );
    expect(migration).not.toContain('CONCURRENTLY');
  });

  it('pins seven-day evidence and 24-hour AI payload retention in code and SQL', () => {
    expect(shared).toContain(
      'SAST_EVIDENCE_MAX_RETENTION_SECONDS =\n  7 * 24 * 60 * 60'
    );
    expect(shared).toContain(
      'SAST_AI_PAYLOAD_MAX_RETENTION_SECONDS =\n  24 * 60 * 60'
    );
    expect(migration).toContain("INTERVAL '7 days'");
    expect(migration).toContain("INTERVAL '24 hours'");
    expect(migration).toContain(
      '"deleteAfter" <= "scheduledAt" + INTERVAL \'7 days\''
    );
    expect(service).toContain(
      'Date.parse(decidedAt) >= Date.parse(context.schedule.deleteAfter)'
    );
    expect(store).toContain(
      'Date.parse(context.result.pack.expiresAt) >'
    );
  });

  it('persists only bounded decisions and never persists access-time content or secret values', () => {
    expect(migration).toContain(
      "'{audit,rawSourceStored}')::boolean IS FALSE"
    );
    expect(migration).toContain(
      "'{audit,secretValueStored}')::boolean IS FALSE"
    );
    expect(migration).toContain(
      "'{audit,preRedactionPayloadStored}')::boolean IS FALSE"
    );
    expect(migration).toContain(
      "'{audit,matchedValueDigestStored}')::boolean IS FALSE"
    );
    expect(schema).not.toMatch(
      /model SastEvidenceAccessDecision \{[\s\S]*?redactedContent[\s\S]*?\n\}/
    );
    expect(store).toMatch(
      /redactedProjectionDigest:\s*decision\.redactedProjectionDigest/u
    );
    expect(store).not.toContain(
      'redactedContent: decision'
    );
    expect(service).toContain('KNOWN_SECRET_PATTERNS');
    expect(service).toContain('ENTROPY_TOKEN_PATTERN');
    expect(service).toContain('platformSecretValues');
  });

  it('keeps dashboard and AI authority independent and advisory-only', () => {
    expect(shared).toContain("'DASHBOARD'");
    expect(shared).toContain("'AI_ADVISORY'");
    expect(shared).toContain('dashboardReadAllowed: boolean');
    expect(shared).toContain(
      'reducedEvidenceReferenceAllowed: boolean'
    );
    for (const invariant of [
      'aiPayloadAllowed: false',
      'aiProviderCallAllowed: false',
      'retrievalAllowed: false',
      'toolsAllowed: false',
      'policyAuthority: false',
      'publicationAuthority: false',
      'lifecycleMutationAuthority: false',
      'scmWriteAuthority: false'
    ]) {
      expect(shared).toContain(invariant);
    }
    expect(controller).toContain(
      "@Controller('dashboard/evidence')"
    );
    expect(controller).toContain('@UseGuards(SessionAuthGuard)');
    expect(module).toContain('SastEvidenceAccessService');
    const exportsBlock = module.match(
      /exports:\s*\[([\s\S]*?)\]\s*\}\)\s*export class/
    )?.[1];
    expect(exportsBlock).toContain('SastEvidenceAccessService');
    expect(exportsBlock).not.toContain(
      'SastAcceptedEvidenceService'
    );
  });

  it('uses serializable replay, claim fencing, and default-unavailable authorities', () => {
    expect(store).toContain(
      'Prisma.TransactionIsolationLevel.Serializable'
    );
    expect(store).toContain('leaseToken = randomUUID()');
    expect(store).toContain("status: 'CLAIMED'");
    expect(store).toContain("status: 'COMPLETED'");
    expect(store).toContain(
      'transaction.sastAcceptedEvidencePack.delete'
    );
    expect(store).toContain(
      'transaction.sastEvidenceDeletionProof.create'
    );
    expect(store).toMatch(
      /input\.proof\.providerReceiptRef\s*!==\s*input\.receipt\.providerReceiptRef/u
    );
    expect(store).toMatch(
      /input\.proof\.completedAt\s*!==\s*input\.receipt\.completedAt/u
    );
    expect(store).toMatch(
      /Date\.parse\(input\.receipt\.completedAt\)\s*<\s*row\.deleteAfter\.getTime\(\)/u
    );
    expect(deletion).toContain(
      'buildSastEvidenceDeletionProof'
    );
    expect(deletion).toContain(
      "return finalized.replayed ? 'REPLAYED' : 'DELETED'"
    );
    expect(authority).toContain(
      'UnavailableSastEvidenceDeletionAuthority'
    );
    expect(module).toContain(
      'UnavailableSastEvidenceSecretRegistry'
    );
    expect(module).toContain(
      'UnavailableSastEvidenceDeletionAuthority'
    );
  });

  it('leaves immutable T041 downstream flags untouched while scheduling at write time', () => {
    const acceptedStore = read(
      'src/scan-plane/prisma-sast-accepted-evidence.store.ts'
    );
    expect(acceptedStore).toContain(
      'classificationDecisionRef: null'
    );
    expect(acceptedStore).toContain(
      'deletionScheduleRef: null'
    );
    expect(acceptedStore).toContain('dashboardSafe: false');
    expect(acceptedStore).toContain('aiSafe: false');
    expect(acceptedStore).toContain(
      'buildSastEvidenceDeletionSchedule'
    );
    expect(acceptedStore).toContain(
      'transaction.sastEvidenceDeletionSchedule.create'
    );
  });
});

function read(relativePath: string): string {
  return readFileSync(resolve(__dirname, '../..', relativePath), 'utf8');
}

function readShared(relativePath: string): string {
  return readFileSync(
    resolve(__dirname, '../../../../packages/shared', relativePath),
    'utf8'
  );
}
