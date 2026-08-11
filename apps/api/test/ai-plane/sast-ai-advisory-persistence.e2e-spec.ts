import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { readScanPlaneExports } from '../support/scan-plane-module-source';
import { PrismaSastAiAdvisoryStore } from '../../src/ai-plane/prisma-sast-ai-advisory.store';
import { aiHandoff } from '../support/sast-ai-advisory-fixture';

describe('SAST AI advisory handoff persistence contract', () => {
  const schema = read('prisma/schema.prisma');
  const migration = read(
    'prisma/migrations/20260811040000_sast_ai_advisory_handoff/migration.sql'
  );
  const onlineSchema = read(
    'scripts/apply-online-sast-runtime-schema.mjs'
  );
  const store = read(
    'src/ai-plane/prisma-sast-ai-advisory.store.ts'
  );
  const service = read('src/ai-plane/ai-advisory.service.ts');
  const runtime = read(
    'src/ai-plane/ai-advisory-runtime.client.ts'
  );
  const controller = read(
    'src/ai-plane/ai-advisory.controller.ts'
  );
  const aiModule = read('src/ai-plane/ai-plane.module.ts');
  const scanModule = read('src/scan-plane/scan-plane.module.ts');

  it('adds an immutable reference-only handoff ledger', () => {
    expect(schema).toContain('model SastAiAdvisoryHandoff {');
    expect(migration).toContain(
      'CREATE TABLE "SastAiAdvisoryHandoff"'
    );
    expect(migration).toContain(
      'SastAiAdvisoryHandoff_immutable_update'
    );
    expect(migration).toContain(
      'SastAiAdvisoryHandoff_immutable_delete'
    );
    expect(onlineSchema).toContain(
      'SastAiAdvisoryHandoff_access_scope_fkey'
    );
    expect(onlineSchema).toContain(
      'SastAiAdvisoryHandoff_occurrence_scope_fkey'
    );
    expect(onlineSchema).toContain(
      'SastAiAdvisoryHandoff_finding_scope_fkey'
    );
    expect(onlineSchema).toContain(
      'CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS "SastEvidenceAccessDecision_ai_scope_key"'
    );
    expect(onlineSchema).toContain(
      'CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS "AiAdvisoryMetadata_sastHandoffId_key"'
    );
    expect(onlineSchema).toContain(
      'AiAdvisoryMetadata_sastHandoffId_fkey'
    );
    expect(migration).not.toMatch(
      /SastEvidenceAccessDecision_ai_scope_key|SastAiAdvisoryHandoff_(?:access|occurrence|finding)_scope_fkey/u
    );
    expect(migration).not.toMatch(
      /AiAdvisoryMetadata_sastHandoffId_(?:key|fkey)/u
    );
    expect(migration).toContain(
      '"payloadExpiresAt" TIMESTAMP(3) NOT NULL'
    );
    expect(migration).toContain('"createdAt" TIMESTAMP(3) NOT NULL');
    expect(migration).not.toContain('"handoff" JSONB');
    expect(schema).not.toMatch(
      /model SastAiAdvisoryHandoff \{[\s\S]*?\n\s+handoff\s+Json/u
    );
  });

  it('persists only scope references, digests, expiry, and fixed authority bits', () => {
    for (const value of [
      '"requestPayloadStored" IS FALSE',
      '"rawSourceStored" IS FALSE',
      '"secretValueStored" IS FALSE',
      '"evidenceFragmentStored" IS FALSE',
      '"retrievalAttempted" IS FALSE',
      '"toolsInvoked" IS FALSE',
      '"retrievalAllowed" IS FALSE',
      '"toolsAllowed" IS FALSE',
      '"policyAuthority" IS FALSE',
      '"publicationAuthority" IS FALSE',
      '"lifecycleMutationAuthority" IS FALSE',
      '"scmWriteAuthority" IS FALSE'
    ]) {
      expect(migration).toContain(value);
    }
    expect(store).not.toContain(
      'handoff: handoff as unknown as Prisma.InputJsonValue'
    );
    expect(store).toContain('requestDigest: handoff.requestDigest');
    expect(store).toContain('handoffDigest: handoff.handoffDigest');
    expect(store).toContain('requestPayloadStored: false');
  });

  it('rebinds T042 access to the durable T037 normalized source', () => {
    expect(store).toContain(
      'isSastEvidenceAccessDecisionShapeValid'
    );
    expect(store).toContain(
      'isSastSecretRedactedFindingCandidateShapeValid'
    );
    expect(store).toContain('isStoredDecisionBound');
    expect(store).toContain('isSourceBound');
    expect(store).toContain('id_tenantId');
    expect(store).toContain('isSameInstant');
    expect(store).toContain(
      'Prisma.TransactionIsolationLevel.Serializable'
    );
    expect(service).toContain('classifyForAi');
    expect(service.match(/this\.classify\(scope, clock\)/gu)).toHaveLength(2);
  });

  it('sends no fragment content, retrieval, tools, or decision authority to AI', () => {
    expect(runtime).toContain('snippets: []');
    expect(runtime).toContain("redactionState: 'reduced'");
    expect(runtime).toContain('modelVersion: handoff.modelVersion');
    expect(runtime).toContain('retrievalAllowed: false');
    expect(runtime).toContain('toolsAllowed: false');
    expect(runtime).toContain('policyAuthority: false');
    expect(runtime).toContain('publicationAuthority: false');
    expect(runtime).toContain('lifecycleMutationAuthority: false');
    expect(runtime).toContain('scmWriteAuthority: false');
    expect(runtime).not.toContain('redactedContent');
  });

  it('keeps the boundary narrow and caller intent exact', () => {
    expect(controller).toContain('SastAiAdvisoryIntent');
    expect(aiModule).toContain('ScanPlaneModule');
    expect(aiModule).toContain('SastAiAdvisoryStore');
    const exportsBlock = readScanPlaneExports(scanModule);
    expect(exportsBlock).toContain('SastEvidenceAccessService');
    expect(exportsBlock).not.toContain('SastAcceptedEvidenceService');
  });

  it('persists exact replay metadata without serializing the handoff body', async () => {
    const rows = new Map<string, Record<string, unknown>>();
    const handoffModel = {
      findUnique: jest.fn(({ where }: { where: { id: string } }) =>
        Promise.resolve(rows.get(where.id) ?? null)
      ),
      create: jest.fn(({ data }: { data: Record<string, unknown> }) => {
        rows.set(String(data.id), data);
        return Promise.resolve(data);
      })
    };
    const transaction = { sastAiAdvisoryHandoff: handoffModel };
    const prisma = {
      sastAiAdvisoryHandoff: handoffModel,
      $transaction: jest.fn(
        (operation: (tx: typeof transaction) => Promise<unknown>) =>
          operation(transaction)
      )
    };
    const persistence = new PrismaSastAiAdvisoryStore(prisma as never);
    const handoff = aiHandoff();

    await expect(persistence.persistHandoff(handoff)).resolves.toEqual({
      handoff,
      replayed: false
    });
    const stored = handoffModel.create.mock.calls[0]?.[0].data;
    expect(stored).not.toHaveProperty('handoff');
    expect(stored).toMatchObject({
      id: handoff.handoffId,
      requestDigest: handoff.requestDigest,
      handoffDigest: handoff.handoffDigest,
      requestPayloadStored: false,
      rawSourceStored: false,
      secretValueStored: false,
      evidenceFragmentStored: false,
      retrievalAllowed: false,
      toolsAllowed: false,
      policyAuthority: false,
      publicationAuthority: false,
      lifecycleMutationAuthority: false,
      scmWriteAuthority: false
    });
    await expect(persistence.persistHandoff(handoff)).resolves.toEqual({
      handoff,
      replayed: true
    });

    const exactRow = rows.get(handoff.handoffId);
    expect(exactRow).toBeDefined();
    rows.set(handoff.handoffId, {
      ...exactRow!,
      requestDigest: `sha256:${'f'.repeat(64)}`
    });
    await expect(persistence.persistHandoff(handoff)).rejects.toMatchObject({
      reason: 'REPLAY_CONFLICT'
    });
  });
});

function read(relativePath: string): string {
  return readFileSync(resolve(__dirname, '../..', relativePath), 'utf8');
}
