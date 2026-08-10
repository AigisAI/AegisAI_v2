import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('SAST accepted-finding evidence persistence contract', () => {
  const schema = read('prisma/schema.prisma');
  const migration = read(
    'prisma/migrations/20260810043000_sast_accepted_evidence/migration.sql'
  );
  const store = read(
    'src/scan-plane/prisma-sast-accepted-evidence.store.ts'
  );
  const service = read(
    'src/scan-plane/sast-accepted-evidence.service.ts'
  );
  const authority = read(
    'src/scan-plane/sast-accepted-evidence-source.authority.ts'
  );
  const module = read('src/scan-plane/scan-plane.module.ts');
  const shared = readShared(
    'src/types/sast-accepted-evidence.ts'
  );

  it('persists tenant-scoped build, pack, and fragment ledgers', () => {
    for (const model of [
      'SastEvidenceBuildDecision',
      'SastAcceptedEvidencePack',
      'SastAcceptedEvidenceFragment'
    ]) {
      expect(schema).toContain('model ' + model + ' {');
      expect(migration).toContain(
        'CREATE TABLE "' + model + '"'
      );
    }
    expect(migration).toContain(
      'SastEvidenceBuildDecision_freshness_scope_fkey'
    );
    expect(migration).toContain(
      'SastEvidenceBuildDecision_occurrence_scope_fkey'
    );
    expect(migration).toContain(
      'SastAcceptedEvidencePack_decision_scope_fkey'
    );
    expect(migration).toContain(
      'SastAcceptedEvidenceFragment_pack_scope_fkey'
    );
    expect(migration).toContain(
      '"evidencePackId", "buildDecisionId", "tenantId", "repositoryBindingId", "scanRequestId", "attemptId"'
    );
    expect(migration).toContain(
      'SastEvidenceBuildDecision_replay_key'
    );
    expect(migration).toContain(
      'SastAcceptedEvidencePack_expiresAt_idx'
    );
    expect(migration).not.toContain('CONCURRENTLY');
  });

  it('enforces bounded redacted content and zero downstream authority in SQL', () => {
    expect(migration).toContain(
      '"totalBytes" BETWEEN 1 AND 32768'
    );
    expect(migration).toContain(
      '"fragmentCount" BETWEEN 1 AND 5'
    );
    expect(migration).toContain(
      '"byteSize" BETWEEN 1 AND 8192'
    );
    expect(migration).toContain(
      'NOT ("startLine" = 1 AND "endLine" = "sourceFileLineCount")'
    );
    expect(migration).toContain(
      '"secretRedactionApplied" = true'
    );
    expect(migration).toContain('"rawSourceStored" = false');
    expect(migration).toContain(
      '("authority"->>\'dashboardAccessAllowed\')::boolean IS FALSE'
    );
    expect(migration).toContain('"dashboardSafe" = false');
    expect(migration).toContain('"aiSafe" = false');
    expect(migration).toContain(
      '"classificationDecisionRef" IS NULL'
    );
    expect(migration).toContain(
      '"deletionScheduleRef" IS NULL'
    );
    expect(migration).toContain(
      '"expiresAt" <= "createdAt" + INTERVAL \'7 days\''
    );
  });

  it('rebinds the complete fresh T040 decision and accepted T037 occurrence', () => {
    expect(store).toContain(
      'isSastScanFreshnessDecisionShapeValid'
    );
    expect(store).toContain(
      'isSastScanCoverageDecisionShapeValid'
    );
    expect(store).toContain(
      'isSastFingerprintedFindingShapeValid'
    );
    expect(store).toContain(
      "freshnessRow.coverageDecision.state !== 'COMPLETE'"
    );
    expect(store).toContain(
      "freshness.latestTargetAuthority !== 'VERIFIED'"
    );
    expect(store).toContain(
      "freshness.staleStatus !== 'FRESH'"
    );
    expect(store).toContain(
      "freshness.comparabilityStatus !== 'COMPARABLE'"
    );
    expect(store).toContain('sourceBound');
    expect(store).toContain(
      'correlationBatch.sourceSetDigest ==='
    );
    expect(store).toContain(
      'source.observationBatchId ==='
    );
    expect(store).toContain(
      'normalized.sastStableFingerprint ==='
    );
    expect(store).toContain(
      'Prisma.TransactionIsolationLevel.Serializable'
    );
    expect(store).toContain('SERIALIZABLE_ATTEMPTS = 3');
    expect(store).toContain('replayExisting');
  });

  it('uses exact UTF-8 byte, context, and reconstruction checks', () => {
    expect(shared).toContain('DEFAULT_SAST_EVIDENCE_POLICY');
    expect(shared).toContain('policy.maxTotalBytes');
    expect(shared).toContain('policy.maxFragmentCount');
    expect(shared).toContain('policy.maxFragmentBytes');
    expect(shared).toContain(
      'maximumReconstructedFileCoverageBasisPoints: 2500'
    );
    expect(shared).toContain(
      'maximumFragmentsPerFile: 2'
    );
    expect(shared).toContain(
      "'EVIDENCE_RECONSTRUCTION_OVERLAP'"
    );
    expect(shared).toContain(
      "'EVIDENCE_RECONSTRUCTION_ADJACENT'"
    );
    expect(shared).toContain(
      "'EVIDENCE_RECONSTRUCTION_COVERAGE'"
    );
    expect(shared).toContain(
      'digestCanonical(value.redactedContent) !== value.contentDigest'
    );
    expect(shared).toContain(
      'lineCount(value.redactedContent)'
    );
  });

  it('exports only the T041 sequential handoff with unavailable source by default', () => {
    const exportsBlock =
      module.match(/exports:\s*\[([\s\S]*?)\]\s*\n\}\)/)?.[1] ??
      '';
    expect(exportsBlock).toContain(
      'SastAcceptedEvidenceService'
    );
    expect(exportsBlock).not.toContain(
      'SastScanFreshnessService'
    );
    expect(exportsBlock).not.toContain(
      'SastScanCoverageService'
    );
    expect(module).toMatch(
      /provide:\s*SastAcceptedEvidenceSourceAuthority,[\s\S]{0,140}useExisting:\s*UnavailableSastAcceptedEvidenceSourceAuthority/u
    );
    expect(authority).toContain(
      "return { status: 'UNAVAILABLE' }"
    );
    expect(service).not.toMatch(
      /@Controller|@(Get|Post|Put|Patch|Delete)\(/u
    );
    expect(service).not.toMatch(/\bLogger\b|\bconsole\./u);
    expect(service).toContain('dashboardPayloadCreated: false');
    expect(service).toContain('aiPayloadCreated: false');
    expect(service).toContain('publicationAttempted: false');
  });
});

function read(path: string): string {
  return readFileSync(resolve(__dirname, '../../' + path), 'utf8');
}

function readShared(path: string): string {
  return readFileSync(
    resolve(__dirname, '../../../../packages/shared/' + path),
    'utf8'
  );
}
