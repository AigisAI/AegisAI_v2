import { Injectable } from '@nestjs/common';

import { SastKillSwitchGate } from '../rule-governance/sast-kill-switch.gate';
import {
  SastRetryRuntimeAuthority,
  type SastRetryRuntimeAuthorityDecision
} from './sast-retry-runtime-authority';
import type { SastScanRetryScope } from '@aegisai/shared';

@Injectable()
export class SastKillSwitchRetryRuntimeAuthority extends SastRetryRuntimeAuthority {
  constructor(private readonly killSwitch: SastKillSwitchGate) {
    super();
  }

  async verify(
    scope: Readonly<SastScanRetryScope>
  ): Promise<SastRetryRuntimeAuthorityDecision> {
    try {
      const result = await this.killSwitch.evaluatePersistedScan({
        gate: 'RETRY_ADMISSION',
        tenantId: scope.tenantId,
        repositoryBindingId: scope.repositoryBindingId,
        scanRequestId: scope.scanRequestId,
        evaluatedAt: new Date().toISOString()
      });
      return {
        currentScannerSetDigest: result.receipt.scannerSetDigest,
        scannerSetAvailable: true,
        killSwitchStatus: result.receipt.outcome,
        killSwitchSnapshotDigest: result.receipt.snapshotDigest
      };
    } catch {
      return {
        currentScannerSetDigest: null,
        scannerSetAvailable: false,
        killSwitchStatus: 'UNAVAILABLE',
        killSwitchSnapshotDigest: null
      };
    }
  }
}
