import { createHash } from 'node:crypto';

import {
  SAST_SCANNER_KINDS,
  buildApplicableSastKillSwitchSelectors,
  buildSastKillSwitchEvaluationContext,
  type SastKillSwitchEvaluationContext,
  type SastScanPlan
} from '@aegisai/shared';

import { PrismaSastQueueAdmissionStore } from '../../src/control-plane/prisma-sast-queue-admission.store';
import { fixtureDigest } from '../support/sast-finding-lineage-fixtures';
import { durableSastScanPlan } from '../support/sast-scan-plan-fixtures';

const digestCanonical = (value: string): `sha256:${string}` =>
  `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;

interface QueueKillSwitchFence {
  assertCurrentSastKillSwitchEvaluation(
    transaction: { $queryRaw: jest.Mock },
    plan: Readonly<SastScanPlan>
  ): Promise<void>;
}

describe('T049 queue kill-switch complete-selector fence', () => {
  it('accepts the exact plan-derived inactive selector set', async () => {
    const { plan, heads } = buildFixture();
    const queryRaw = jest
      .fn()
      .mockResolvedValueOnce([
        {
          headCount: heads.length,
          matchedDecisionCount: 0,
          actualHeadCount: BigInt(heads.length)
        }
      ])
      .mockResolvedValueOnce(heads);
    const store = new PrismaSastQueueAdmissionStore({} as never);

    await expect(
      (store as unknown as QueueKillSwitchFence)
        .assertCurrentSastKillSwitchEvaluation({ $queryRaw: queryRaw }, plan)
    ).resolves.toBeUndefined();
  });

  it('rejects an internally consistent receipt that omits one applicable selector', async () => {
    const { plan, heads } = buildFixture();
    const incompleteHeads = heads.slice(1);
    const queryRaw = jest
      .fn()
      .mockResolvedValueOnce([
        {
          headCount: incompleteHeads.length,
          matchedDecisionCount: 0,
          actualHeadCount: BigInt(incompleteHeads.length)
        }
      ])
      .mockResolvedValueOnce(incompleteHeads);
    const store = new PrismaSastQueueAdmissionStore({} as never);

    await expect(
      (store as unknown as QueueKillSwitchFence)
        .assertCurrentSastKillSwitchEvaluation({ $queryRaw: queryRaw }, plan)
    ).rejects.toThrow('SAST kill-switch state changed before queue admission.');
  });

  it('rejects a planning receipt whose context digest is not derived from the plan', async () => {
    const { plan } = buildFixture();
    const mismatchedPlan: SastScanPlan = {
      ...plan,
      killSwitchEvaluation: {
        ...plan.killSwitchEvaluation!,
        contextDigest: fixtureDigest('foreign-context')
      }
    };
    const queryRaw = jest.fn();
    const store = new PrismaSastQueueAdmissionStore({} as never);

    await expect(
      (store as unknown as QueueKillSwitchFence)
        .assertCurrentSastKillSwitchEvaluation(
          { $queryRaw: queryRaw },
          mismatchedPlan
        )
    ).rejects.toThrow(
      'SAST kill-switch evaluation context does not match the immutable plan.'
    );
    expect(queryRaw).not.toHaveBeenCalled();
  });
});

function buildFixture(): {
  plan: SastScanPlan;
  heads: Array<Record<string, unknown>>;
} {
  const basePlan = durableSastScanPlan();
  const context = contextFor(basePlan);
  const selectors = buildApplicableSastKillSwitchSelectors(
    context,
    'PLANNING',
    digestCanonical
  );
  const plan: SastScanPlan = {
    ...basePlan,
    killSwitchEvaluation: {
      version: 'sast-kill-switch-planning-v1',
      evaluationId: `sast-kill-switch-evaluation://${'e'.repeat(64)}`,
      evaluationReceiptDigest: fixtureDigest('evaluation-receipt'),
      contextDigest: context.contextDigest,
      snapshotDigest: fixtureDigest('snapshot'),
      headSetDigest: fixtureDigest('head-set'),
      evaluatedAt: '2026-08-19T00:00:00.000Z',
      outcome: 'CLEAR'
    }
  };
  return {
    plan,
    heads: selectors.map(({ selectorKey }) => ({
      bindingSelectorKey: selectorKey,
      bindingSequence: 0,
      bindingDecisionId: null,
      bindingDecisionDigest: null,
      bindingAction: null,
      bindingActive: false,
      bindingEffectiveAt: null,
      bindingExpiresAt: null,
      currentSequence: 0,
      currentDecisionId: null,
      currentDecisionDigest: null,
      currentAction: null,
      currentActive: false,
      currentEffectiveAt: null,
      currentExpiresAt: null
    }))
  };
}

function contextFor(
  plan: Readonly<SastScanPlan>
): SastKillSwitchEvaluationContext {
  const context = buildSastKillSwitchEvaluationContext(
    {
      tenantId: plan.tenantId,
      repositoryBindingId: plan.repositoryState.repositoryBindingId,
      scanRequestId: plan.scanRequestId,
      profileId: plan.profile.id,
      profileDigest: plan.profileDigest,
      scannerSetDigest: plan.scannerSet.scannerSetDigest,
      scanners: SAST_SCANNER_KINDS.map((scanner) => ({
        scanner,
        scannerVersion: plan.scannerSet.scanners[scanner].version
      })).sort((left, right) => left.scanner.localeCompare(right.scanner)),
      ruleBundles: plan.scannerSet.ruleBundles
        .map((bundle) => ({
          bundleDigest: bundle.digest,
          ruleSemanticIds: [
            ...new Set(bundle.rules.map((rule) => rule.ruleSemanticId))
          ].sort()
        }))
        .sort((left, right) =>
          left.bundleDigest.localeCompare(right.bundleDigest)
        ),
      requiredCapabilities: [...plan.profile.requiredCapabilities]
    },
    digestCanonical
  );
  if (!context) throw new Error('invalid kill-switch fixture context');
  return context;
}
