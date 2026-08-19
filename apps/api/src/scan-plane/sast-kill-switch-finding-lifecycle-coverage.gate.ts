import { Injectable } from '@nestjs/common';

import type {
  SastFindingLifecycleCoverageDecision
} from '@aegisai/shared';

import { SastKillSwitchGate } from '../rule-governance/sast-kill-switch.gate';
import {
  SastFindingLifecycleCoverageAuthority,
  SastFindingLifecycleCoverageGate,
  type SastFindingLifecycleCoverageVerification
} from './sast-finding-lifecycle-coverage.gate';

@Injectable()
export class SastKillSwitchFindingLifecycleCoverageGate
  extends SastFindingLifecycleCoverageGate {
  constructor(
    private readonly killSwitch: SastKillSwitchGate,
    private readonly coverageAuthority: SastFindingLifecycleCoverageAuthority
  ) {
    super();
  }

  async verify(
    decision: Readonly<SastFindingLifecycleCoverageDecision>
  ): Promise<SastFindingLifecycleCoverageVerification> {
    if (!hasBoundedScope(decision)) return 'REJECTED';
    let evaluation;
    try {
      evaluation = await this.killSwitch.evaluatePersistedScan({
        gate: 'COVERAGE',
        tenantId: decision.tenantId,
        repositoryBindingId: decision.repositoryBindingId,
        scanRequestId: decision.scanRequestId,
        evaluatedAt: new Date().toISOString()
      });
    } catch {
      return 'UNAVAILABLE';
    }
    if (
      evaluation.receipt.outcome !== 'CLEAR' ||
      evaluation.receipt.coverageEffect !== 'UNCHANGED'
    ) {
      return 'REJECTED';
    }
    return this.coverageAuthority.verify(decision);
  }
}

function hasBoundedScope(
  decision: Readonly<SastFindingLifecycleCoverageDecision>
): boolean {
  return Boolean(
    decision &&
      isBounded(decision.tenantId) &&
      isBounded(decision.repositoryBindingId) &&
      isBounded(decision.scanRequestId)
  );
}

function isBounded(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 512;
}
