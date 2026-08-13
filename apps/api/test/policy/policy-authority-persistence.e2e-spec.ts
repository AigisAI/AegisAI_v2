import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { PrismaPolicyDecisionStore } from '../../src/policy/prisma-policy-decision.store';
import { PrismaPolicyLifecycleStore } from '../../src/policy/prisma-policy-lifecycle.store';

describe('Authoritative policy persistence used by T044 snapshots', () => {
  it('persists and reads policy decisions through the PolicyDecision table', async () => {
    const row = policyDecisionRow();
    const prisma = {
      policyDecision: {
        create: jest.fn().mockResolvedValue(row),
        findFirst: jest.fn().mockResolvedValue(row)
      }
    };
    const store = new PrismaPolicyDecisionStore(prisma as never);

    await expect(
      store.create({
        tenantId: row.tenantId,
        scanRequestId: row.scanRequestId,
        findingId: row.findingId,
        enforcementAction: row.enforcementAction,
        commentAllowed: row.commentAllowed,
        dashboardVisible: row.dashboardVisible,
        ticketRequested: row.ticketRequested,
        blockRequested: row.blockRequested,
        reasonCodes: row.reasonCodes,
        requiredCoverage: ['OPENGREP', 'TRIVY', 'SYFT'],
        waiverApplied: row.waiverApplied,
        staleSuppressed: row.staleSuppressed,
        aiAdvisoryVisible: row.aiAdvisoryVisible
      })
    ).resolves.toMatchObject({ id: row.id });
    await expect(
      store.findByTenantAndId(row.tenantId, row.id)
    ).resolves.toMatchObject({ id: row.id });
    expect(prisma.policyDecision.create).toHaveBeenCalledTimes(1);
    expect(prisma.policyDecision.findFirst).toHaveBeenCalledWith({
      where: { id: row.id, tenantId: row.tenantId }
    });
  });

  it('persists waiver and suppression lifecycle changes through shared authoritative tables', async () => {
    const waiver = {
      id: 'waiver-durable',
      tenantId: 'tenant-policy',
      owner: 'security@example.com',
      reason: 'Compensating control',
      scope: 'finding:finding-policy',
      expiresAt: new Date('2026-09-01T00:00:00.000Z'),
      lastReviewedAt: null
    };
    const updated = {
      ...waiver,
      reason: 'Reviewed control',
      lastReviewedAt: new Date('2026-08-13T00:00:00.000Z')
    };
    const suppression = {
      id: 'suppression-durable',
      tenantId: 'tenant-policy',
      scanRequestId: 'scan-policy',
      findingId: 'finding-policy',
      reason: 'POLICY' as const
    };
    const transaction = {
      waiver: {
        findFirst: jest.fn().mockResolvedValue({ id: waiver.id }),
        update: jest.fn().mockResolvedValue(updated)
      }
    };
    const prisma = {
      waiver: { create: jest.fn().mockResolvedValue(waiver) },
      suppression: {
        create: jest.fn().mockResolvedValue(suppression)
      },
      $transaction: jest.fn(
        (operation: (tx: typeof transaction) => Promise<unknown>) =>
          operation(transaction)
      )
    };
    const store = new PrismaPolicyLifecycleStore(prisma as never);

    await expect(
      store.createWaiver({
        tenantId: waiver.tenantId,
        owner: waiver.owner,
        reason: waiver.reason,
        scope: waiver.scope,
        expiresAt: waiver.expiresAt.toISOString()
      })
    ).resolves.toMatchObject({ id: waiver.id });
    await expect(
      store.updateWaiver(waiver.id, {
        tenantId: waiver.tenantId,
        reason: updated.reason,
        lastReviewedAt: updated.lastReviewedAt.toISOString()
      })
    ).resolves.toMatchObject({
      id: waiver.id,
      reason: updated.reason,
      lastReviewedAt: updated.lastReviewedAt.toISOString()
    });
    await expect(
      store.createSuppression({
        tenantId: suppression.tenantId,
        scanRequestId: suppression.scanRequestId,
        findingId: suppression.findingId,
        reason: suppression.reason
      })
    ).resolves.toEqual(suppression);

    expect(prisma.waiver.create).toHaveBeenCalledTimes(1);
    expect(transaction.waiver.update).toHaveBeenCalledTimes(1);
    expect(prisma.suppression.create).toHaveBeenCalledTimes(1);
  });

  it('keeps application-visible policy and lifecycle services off in-memory authority arrays', () => {
    const policyService = read('src/policy/policy-engine.service.ts');
    const lifecycleService = read(
      'src/policy/policy-lifecycle.service.ts'
    );
    const migration = read(
      'prisma/migrations/20260811140000_sast_ai_advisory_authority_proof/migration.sql'
    );

    expect(policyService).toContain('PolicyDecisionStore');
    expect(lifecycleService).toContain('PolicyLifecycleStore');
    expect(policyService).not.toContain('policyDecisions: PolicyDecision[]');
    expect(lifecycleService).not.toContain('waivers: Waiver[]');
    expect(migration).toContain('PolicyDecision_ai_authority_fence');
    expect(migration).toContain('Waiver_ai_authority_fence');
    expect(migration).toContain('Suppression_ai_authority_fence');
  });
});

function policyDecisionRow() {
  return {
    id: 'policy-decision-durable',
    tenantId: 'tenant-policy',
    scanRequestId: 'scan-policy',
    findingId: 'finding-policy',
    enforcementAction: 'WARN' as const,
    commentAllowed: true,
    dashboardVisible: true,
    ticketRequested: false,
    blockRequested: false,
    reasonCodes: ['SEVERITY_HIGH'],
    requiredCoverage: ['OPENGREP', 'TRIVY', 'SYFT'],
    waiverApplied: false,
    staleSuppressed: false,
    aiAdvisoryVisible: false
  };
}

function read(relativePath: string): string {
  return readFileSync(resolve(__dirname, '../..', relativePath), 'utf8');
}
