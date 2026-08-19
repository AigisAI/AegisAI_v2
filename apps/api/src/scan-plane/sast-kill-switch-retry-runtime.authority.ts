import { Injectable } from '@nestjs/common';

import { SastKillSwitchGate } from '../rule-governance/sast-kill-switch.gate';
import {
  SastRetryScannerSetAvailabilityAuthority,
  SastRetryRuntimeAuthority,
  UnavailableSastRetryScannerSetAvailabilityAuthority,
  type SastRetryRuntimeAuthorityDecision,
  type SastRetryScannerSetAvailabilityDecision
} from './sast-retry-runtime-authority';
import type { SastScanRetryScope } from '@aegisai/shared';

@Injectable()
export class SastKillSwitchRetryRuntimeAuthority extends SastRetryRuntimeAuthority {
  constructor(
    private readonly killSwitch: SastKillSwitchGate,
    private readonly scannerSetAuthority: SastRetryScannerSetAvailabilityAuthority =
      new UnavailableSastRetryScannerSetAvailabilityAuthority()
  ) {
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
      const scannerSet = await this.scannerSetAuthority.verify(scope);
      return {
        currentScannerSetDigest: scannerSet.currentScannerSetDigest,
        scannerSetAvailable:
          isAvailableScannerSet(scannerSet) &&
          scannerSet.currentScannerSetDigest ===
            result.receipt.scannerSetDigest,
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

function isAvailableScannerSet(
  decision: Readonly<SastRetryScannerSetAvailabilityDecision>
): boolean {
  return (
    decision.scannerSetAvailable === true &&
    typeof decision.currentScannerSetDigest === 'string' &&
    /^sha256:[a-f0-9]{64}$/u.test(decision.currentScannerSetDigest)
  );
}
