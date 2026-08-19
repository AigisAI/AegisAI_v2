import { durableSastScanPlan } from '../support/sast-scan-plan-fixtures';

import { SastKillSwitchArtifactAcceptanceGate } from '../../src/scan-plane/sast-kill-switch-artifact-acceptance.gate';
import { SastKillSwitchFindingLifecycleCoverageGate } from '../../src/scan-plane/sast-kill-switch-finding-lifecycle-coverage.gate';
import { SastKillSwitchRetryRuntimeAuthority } from '../../src/scan-plane/sast-kill-switch-retry-runtime.authority';

describe('T049 Scan Plane kill-switch adapters', () => {
  it.each([
    [
      'CLEAR',
      'ALLOW',
      'artifact-acceptance://control',
      undefined,
      1
    ],
    [
      'ACTIVE',
      'DENY',
      'sast-kill-switch-evaluation://control',
      'SAST_KILL_SWITCH_ACTIVE',
      0
    ]
  ] as const)(
    'maps %s kill-switch authority to %s before independent acceptance',
    async (outcome, expected, controlRef, reasonCode, acceptanceCalls) => {
      const plan = durableSastScanPlan();
      const evaluatePlan = jest.fn().mockResolvedValue({
        receipt: {
          outcome,
          evaluationId: 'sast-kill-switch-evaluation://control',
          evaluatedAt: '2026-08-19T01:00:00.000Z'
        }
      });
      const evaluateAcceptance = jest.fn().mockResolvedValue({
        outcome: 'ALLOW',
        controlRef: 'artifact-acceptance://control',
        evaluatedAt: '2026-08-19T01:00:00.000Z'
      });
      const adapter = new SastKillSwitchArtifactAcceptanceGate(
        { evaluatePlan } as never,
        { evaluate: evaluateAcceptance } as never
      );

      await expect(
        adapter.evaluate({
          scope: {
            tenantId: plan.tenantId,
            repositoryBindingId: plan.repositoryState.repositoryBindingId,
            scanRequestId: plan.scanRequestId,
            attemptId: 'attempt-1',
            scannerRunId: 'scanner-run-1'
          },
          plan,
          scanner: 'OPENGREP',
          scannerVersion: plan.scannerSet.scanners.OPENGREP.version,
          scannerImageDigest: plan.scannerSet.scanners.OPENGREP.digest,
          validationResultDigest: plan.scannerSet.scannerSetDigest,
          scannerSetDigest: plan.scannerSet.scannerSetDigest,
          ruleBundleDigest: plan.scannerSet.ruleBundles[0]!.digest,
          profileId: plan.profile.id,
          profileDigest: plan.profileDigest,
          evaluatedAt: '2026-08-19T01:00:00.000Z'
        })
      ).resolves.toEqual({
        outcome: expected,
        controlRef,
        evaluatedAt: '2026-08-19T01:00:00.000Z',
        ...(reasonCode ? { reasonCode } : {})
      });
      expect(evaluatePlan).toHaveBeenCalledWith({
        gate: 'ARTIFACT_ACCEPTANCE',
        plan,
        scanner: 'OPENGREP',
        evaluatedAt: '2026-08-19T01:00:00.000Z'
      });
      expect(evaluateAcceptance).toHaveBeenCalledTimes(acceptanceCalls);
    }
  );

  it('preserves an independent production acceptance denial after a clear switch evaluation', async () => {
    const plan = durableSastScanPlan();
    const input = {
      scope: {
        tenantId: plan.tenantId,
        repositoryBindingId: plan.repositoryState.repositoryBindingId,
        scanRequestId: plan.scanRequestId,
        attemptId: 'attempt-1',
        scannerRunId: 'scanner-run-1'
      },
      plan,
      scanner: 'OPENGREP' as const,
      scannerVersion: plan.scannerSet.scanners.OPENGREP.version,
      scannerImageDigest: plan.scannerSet.scanners.OPENGREP.digest,
      validationResultDigest: plan.scannerSet.scannerSetDigest,
      scannerSetDigest: plan.scannerSet.scannerSetDigest,
      ruleBundleDigest: plan.scannerSet.ruleBundles[0]!.digest,
      profileId: plan.profile.id,
      profileDigest: plan.profileDigest,
      evaluatedAt: '2026-08-19T01:00:00.000Z'
    };
    const productionDenial = {
      outcome: 'DENY' as const,
      controlRef: 'artifact-acceptance://production-denial',
      evaluatedAt: input.evaluatedAt,
      reasonCode: 'PRODUCTION_POLICY_DENIED'
    };
    const adapter = new SastKillSwitchArtifactAcceptanceGate(
      {
        evaluatePlan: jest.fn().mockResolvedValue({
          receipt: {
            outcome: 'CLEAR',
            evaluationId: 'sast-kill-switch-evaluation://control',
            evaluatedAt: input.evaluatedAt
          }
        })
      } as never,
      { evaluate: jest.fn().mockResolvedValue(productionDenial) } as never
    );

    await expect(adapter.evaluate(input)).resolves.toEqual(
      productionDenial
    );
  });

  it.each(['CLEAR', 'ACTIVE'] as const)(
    'maps %s retry authority without widening immutable intent',
    async (outcome) => {
      const evaluatePersistedScan = jest.fn().mockResolvedValue({
        receipt: {
          outcome,
          scannerSetDigest: `sha256:${'a'.repeat(64)}`,
          snapshotDigest: `sha256:${'b'.repeat(64)}`
        }
      });
      const adapter = new SastKillSwitchRetryRuntimeAuthority({
        evaluatePersistedScan
      } as never);

      const decision = await adapter.verify({
        tenantId: 'tenant-1',
        repositoryBindingId: 'repository-1',
        scanRequestId: 'scan-1'
      } as never);

      expect(decision).toEqual({
        currentScannerSetDigest: `sha256:${'a'.repeat(64)}`,
        scannerSetAvailable: true,
        killSwitchStatus: outcome,
        killSwitchSnapshotDigest: `sha256:${'b'.repeat(64)}`
      });
      expect(evaluatePersistedScan).toHaveBeenCalledWith(
        expect.objectContaining({
          gate: 'RETRY_ADMISSION',
          tenantId: 'tenant-1',
          repositoryBindingId: 'repository-1',
          scanRequestId: 'scan-1',
          evaluatedAt: expect.any(String)
        })
      );
    }
  );

  it('returns unavailable retry authority when the mutable store cannot be read', async () => {
    const adapter = new SastKillSwitchRetryRuntimeAuthority({
      evaluatePersistedScan: jest.fn().mockRejectedValue(new Error('offline'))
    } as never);

    await expect(
      adapter.verify({
        tenantId: 'tenant-1',
        repositoryBindingId: 'repository-1',
        scanRequestId: 'scan-1'
      } as never)
    ).resolves.toEqual({
      currentScannerSetDigest: null,
      scannerSetAvailable: false,
      killSwitchStatus: 'UNAVAILABLE',
      killSwitchSnapshotDigest: null
    });
  });

  it.each([
    ['CLEAR', 'UNCHANGED', 'VERIFIED', 1],
    ['ACTIVE', 'PARTIAL', 'REJECTED', 0],
    ['ACTIVE', 'FAILED', 'REJECTED', 0]
  ] as const)(
    'maps %s/%s to %s before factual lifecycle coverage authority',
    async (outcome, coverageEffect, expected, authorityCalls) => {
      const evaluatePersistedScan = jest.fn().mockResolvedValue({
        receipt: { outcome, coverageEffect }
      });
      const verify = jest.fn().mockResolvedValue('VERIFIED');
      const adapter = new SastKillSwitchFindingLifecycleCoverageGate(
        { evaluatePersistedScan } as never,
        { verify } as never
      );
      const decision = {
        tenantId: 'tenant-1',
        repositoryBindingId: 'repository-1',
        scanRequestId: 'scan-1'
      } as never;

      await expect(adapter.verify(decision)).resolves.toBe(expected);
      expect(evaluatePersistedScan).toHaveBeenCalledWith(
        expect.objectContaining({
          gate: 'COVERAGE',
          tenantId: 'tenant-1',
          repositoryBindingId: 'repository-1',
          scanRequestId: 'scan-1',
          evaluatedAt: expect.any(String)
        })
      );
      expect(verify).toHaveBeenCalledTimes(authorityCalls);
    }
  );

  it('returns unavailable lifecycle coverage when current switch authority cannot be read', async () => {
    const adapter = new SastKillSwitchFindingLifecycleCoverageGate(
      {
        evaluatePersistedScan: jest.fn().mockRejectedValue(new Error('offline'))
      } as never,
      { verify: jest.fn() } as never
    );

    await expect(
      adapter.verify({
        tenantId: 'tenant-1',
        repositoryBindingId: 'repository-1',
        scanRequestId: 'scan-1'
      } as never)
    ).resolves.toBe('UNAVAILABLE');
  });
});
