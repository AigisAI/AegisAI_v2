import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { PrismaSastAiAdvisoryAuthorityStore } from '../../src/ai-plane/prisma-sast-ai-advisory-authority.store';
import {
  aiHandoff,
  aiPolicyReference
} from '../support/sast-ai-advisory-fixture';

describe('SAST AI advisory authority proof persistence contract', () => {
  const schema = read('prisma/schema.prisma');
  const migration = read(
    'prisma/migrations/20260811140000_sast_ai_advisory_authority_proof/migration.sql'
  );
  const onlineSchema = read(
    'scripts/apply-online-sast-runtime-schema.mjs'
  );
  const storeSource = read(
    'src/ai-plane/prisma-sast-ai-advisory-authority.store.ts'
  );

  it('adds a content-free immutable proof ledger with fixed zero authority', () => {
    expect(schema).toContain('model SastAiAdvisoryAuthorityProof {');
    expect(migration).toContain(
      'CREATE TABLE "SastAiAdvisoryAuthorityProof"'
    );
    expect(migration).toContain(
      'SastAiAdvisoryAuthorityProof_immutable_update'
    );
    expect(migration).toContain(
      'SastAiAdvisoryAuthorityProof_immutable_delete'
    );
    expect(migration).toContain(
      '"beforeStateDigest" = "afterStateDigest"'
    );
    for (const fixedBit of [
      '"findingCreateAuthority" IS FALSE',
      '"findingStatusMutationAuthority" IS FALSE',
      '"findingSeverityMutationAuthority" IS FALSE',
      '"lifecycleMutationAuthority" IS FALSE',
      '"waiverMutationAuthority" IS FALSE',
      '"suppressionMutationAuthority" IS FALSE',
      '"policyOverrideAuthority" IS FALSE',
      '"blockDecisionAuthority" IS FALSE',
      '"authoritativeFindingWritten" IS FALSE',
      '"policyDecisionWritten" IS FALSE'
    ]) {
      expect(migration).toContain(fixedBit);
    }
    expect(migration).not.toMatch(/JSONB|rationale|prompt|evidenceFragment/u);
    expect(schema).not.toMatch(
      /model SastAiAdvisoryAuthorityProof \{[\s\S]*?\n\s+(?:proof|advisoryContent|sourceContent)\s+Json/u
    );
  });

  it('installs populated finding scope dependencies through online schema', () => {
    expect(onlineSchema).toContain(
      'NormalizedFinding_ai_authority_scope_key'
    );
    expect(onlineSchema).toContain(
      'SastAiAdvisoryHandoff_authority_scope_key'
    );
    expect(onlineSchema).toContain(
      'SastAiAdvisoryAuthorityProof_handoff_authority_scope_fkey'
    );
    expect(onlineSchema).toContain(
      'SastAiAdvisoryAuthorityProof_occurrence_scope_fkey'
    );
    expect(onlineSchema).toContain(
      'SastAiAdvisoryAuthorityProof_finding_scope_fkey'
    );
    expect(migration).not.toMatch(
      /SastAiAdvisoryAuthorityProof_(?:occurrence|finding)_scope_fkey|SastAiAdvisoryAuthorityProof_handoff_authority_scope_fkey/u
    );
  });

  it('uses one serializable proof write and no authoritative model writes', async () => {
    const fixture = prismaFixture();
    const store = new PrismaSastAiAdvisoryAuthorityStore(
      fixture.prisma as never
    );
    const handoff = aiHandoff();

    const first = await store.createProof({
      tenantId: handoff.tenantId,
      advisoryId: handoff.advisoryId,
      verifiedAt: '2026-08-11T05:30:00.000Z'
    });
    expect(first.replayed).toBe(false);
    expect(first.proof.before.stateDigest).toBe(
      first.proof.after.stateDigest
    );
    expect(fixture.proof.create).toHaveBeenCalledTimes(1);
    expect(fixture.finding.findMany).toHaveBeenCalledTimes(2);
    expect(fixture.lifecycle.findMany).toHaveBeenCalledTimes(2);
    expect(fixture.policy.findMany).toHaveBeenCalledTimes(2);
    expect(fixture.waiver.findMany).toHaveBeenCalledTimes(2);
    expect(fixture.suppression.findMany).toHaveBeenCalledTimes(2);
    expect(storeSource).not.toMatch(
      /\b(?:normalizedFinding|sastFindingLifecycleState|policyDecision|waiver|suppression)\.(?:create|createMany|update|updateMany|upsert|delete|deleteMany)\b/u
    );

    await expect(
      store.createProof({
        tenantId: handoff.tenantId,
        advisoryId: handoff.advisoryId,
        verifiedAt: '2026-08-11T06:00:00.000Z'
      })
    ).resolves.toMatchObject({ replayed: true, proof: first.proof });
    expect(fixture.proof.create).toHaveBeenCalledTimes(1);
  });

  it('verifies only a tenant and finding-bound exact policy reference', async () => {
    const fixture = prismaFixture();
    const store = new PrismaSastAiAdvisoryAuthorityStore(
      fixture.prisma as never
    );
    const handoff = aiHandoff();
    const persisted = await store.createProof({
      tenantId: handoff.tenantId,
      advisoryId: handoff.advisoryId,
      verifiedAt: '2026-08-11T05:30:00.000Z'
    });
    const reference = {
      ...aiPolicyReference(),
      authorityProofId: persisted.proof.proofId,
      authorityProofDigest: persisted.proof.proofDigest
    };

    await expect(
      store.verifyPolicyReference({
        tenantId: handoff.tenantId,
        normalizedFindingId:
          handoff.normalizedFinding.normalizedFindingId,
        reference
      })
    ).resolves.toBe(true);
    await expect(
      store.verifyPolicyReference({
        tenantId: 'foreign-tenant',
        normalizedFindingId:
          handoff.normalizedFinding.normalizedFindingId,
        reference
      })
    ).resolves.toBe(false);
  });

  it('rejects replay after authoritative finding state drift', async () => {
    const fixture = prismaFixture();
    const store = new PrismaSastAiAdvisoryAuthorityStore(
      fixture.prisma as never
    );
    const handoff = aiHandoff();
    const intent = {
      tenantId: handoff.tenantId,
      advisoryId: handoff.advisoryId,
      verifiedAt: '2026-08-11T05:30:00.000Z'
    };
    await store.createProof(intent);
    fixture.finding.findMany.mockResolvedValue([
      {
        id: handoff.normalizedFinding.normalizedFindingId,
        status: 'FIXED',
        severity: 'HIGH',
        updatedAt: new Date('2026-08-11T05:45:00.000Z')
      }
    ]);

    await expect(store.createProof(intent)).rejects.toMatchObject({
      reason: 'STATE_DRIFT'
    });
    expect(fixture.proof.create).toHaveBeenCalledTimes(1);
  });
});

function prismaFixture() {
  const handoff = aiHandoff();
  let proofRow: Record<string, unknown> | null = null;
  const proof = {
    findUnique: jest.fn(() => Promise.resolve(proofRow)),
    findFirst: jest.fn(
      ({ where }: { where: Record<string, unknown> }) =>
        Promise.resolve(
          proofRow &&
            Object.entries(where).every(
              ([key, value]) => proofRow?.[key] === value
            )
            ? proofRow
            : null
        )
    ),
    create: jest.fn(({ data }: { data: Record<string, unknown> }) => {
      proofRow = data;
      return Promise.resolve(data);
    })
  };
  const advisory = {
    findFirst: jest.fn().mockResolvedValue({
      id: handoff.advisoryId,
      sastHandoffId: handoff.handoffId,
      tenantId: handoff.tenantId,
      scanRequestId: handoff.scanRequestId,
      findingId: handoff.normalizedFinding.normalizedFindingId,
      advisoryOnly: true,
      redactedEvidenceOnly: true,
      createdAt: new Date('2026-08-11T04:00:00.500Z')
    })
  };
  const handoffModel = {
    findUnique: jest.fn().mockResolvedValue({
      id: handoff.handoffId,
      advisoryId: handoff.advisoryId,
      tenantId: handoff.tenantId,
      repositoryBindingId: handoff.repositoryBindingId,
      scanRequestId: handoff.scanRequestId,
      attemptId: handoff.attemptId,
      occurrenceId: handoff.normalizedFinding.occurrenceId,
      normalizedFindingId:
        handoff.normalizedFinding.normalizedFindingId,
      findingFingerprint: handoff.normalizedFinding.findingFingerprint,
      requestDigest: handoff.requestDigest,
      handoffDigest: handoff.handoffDigest,
      advisoryOnly: true,
      policyAuthority: false,
      publicationAuthority: false,
      lifecycleMutationAuthority: false,
      scmWriteAuthority: false
    })
  };
  const occurrence = {
    findFirst: jest.fn().mockResolvedValue({
      id: handoff.normalizedFinding.occurrenceId,
      lineageId: `finding-lineage://${'d'.repeat(64)}`,
      observationBatch: {
        lifecycleContextKey: `sha256:${'e'.repeat(64)}`
      }
    })
  };
  const finding = {
    findMany: jest.fn().mockResolvedValue([
      {
        id: handoff.normalizedFinding.normalizedFindingId,
        status: 'OPEN',
        severity: 'HIGH',
        updatedAt: new Date('2026-08-11T04:00:00.000Z')
      }
    ])
  };
  const lifecycle = {
    findMany: jest.fn().mockResolvedValue([
      {
        id: `finding-lifecycle-state://${'f'.repeat(64)}`,
        targetRef: 'refs/heads/dev',
        status: 'OPEN',
        revision: 1,
        lastObservedBatchId: 'batch-ai',
        lastObservedScanRequestId: handoff.scanRequestId,
        lastObservedCommitSha: 'a'.repeat(40),
        lastObservedAt: new Date('2026-08-11T04:00:00.000Z'),
        lastReconciliationSequence: 0,
        fixedAt: null,
        reopenedAt: null,
        updatedAt: new Date('2026-08-11T04:00:00.000Z')
      }
    ])
  };
  const policy = {
    findMany: jest.fn().mockResolvedValue([
      {
        id: 'policy-ai',
        enforcementAction: 'WARN',
        commentAllowed: true,
        dashboardVisible: true,
        ticketRequested: false,
        blockRequested: false,
        reasonCodes: ['SEVERITY_HIGH'],
        requiredCoverage: ['OPENGREP', 'TRIVY', 'SYFT'],
        waiverApplied: false,
        staleSuppressed: false,
        aiAdvisoryVisible: false,
        createdAt: new Date('2026-08-11T04:00:00.000Z'),
        updatedAt: new Date('2026-08-11T04:00:00.000Z')
      }
    ])
  };
  const waiver = { findMany: jest.fn().mockResolvedValue([]) };
  const suppression = { findMany: jest.fn().mockResolvedValue([]) };
  const transaction = {
    aiAdvisoryMetadata: advisory,
    sastAiAdvisoryHandoff: handoffModel,
    sastFindingOccurrence: occurrence,
    sastAiAdvisoryAuthorityProof: proof,
    normalizedFinding: finding,
    sastFindingLifecycleState: lifecycle,
    policyDecision: policy,
    waiver,
    suppression
  };
  const prisma = {
    ...transaction,
    $transaction: jest.fn(
      (operation: (tx: typeof transaction) => Promise<unknown>) =>
        operation(transaction)
    )
  };
  return {
    prisma,
    proof,
    finding,
    lifecycle,
    policy,
    waiver,
    suppression
  };
}

function read(relativePath: string): string {
  return readFileSync(resolve(__dirname, '../..', relativePath), 'utf8');
}
