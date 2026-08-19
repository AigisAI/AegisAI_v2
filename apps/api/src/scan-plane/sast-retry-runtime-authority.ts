import type {
  SastScanRetryScope
} from '@aegisai/shared';

export interface SastRetryRuntimeAuthorityDecision {
  currentScannerSetDigest: `sha256:${string}` | null;
  scannerSetAvailable: boolean;
  killSwitchStatus: 'CLEAR' | 'ACTIVE' | 'UNAVAILABLE';
  killSwitchSnapshotDigest: `sha256:${string}` | null;
}

export interface SastRetryScannerSetAvailabilityDecision {
  currentScannerSetDigest: `sha256:${string}` | null;
  scannerSetAvailable: boolean;
}

/**
 * Independent mutable authority for the currently deployable scanner assets.
 * A clear kill switch cannot imply that images, wrappers, rules, or databases
 * are still available.
 */
export abstract class SastRetryScannerSetAvailabilityAuthority {
  abstract verify(
    scope: Readonly<SastScanRetryScope>
  ): Promise<SastRetryScannerSetAvailabilityDecision>;
}

export class UnavailableSastRetryScannerSetAvailabilityAuthority
  extends SastRetryScannerSetAvailabilityAuthority {
  async verify(): Promise<SastRetryScannerSetAvailabilityDecision> {
    return {
      currentScannerSetDigest: null,
      scannerSetAvailable: false
    };
  }
}

/**
 * T040 rechecks mutable runtime safety state without changing immutable scan
 * intent. T049 will install the live kill-switch authority.
 */
export abstract class SastRetryRuntimeAuthority {
  abstract verify(
    scope: Readonly<SastScanRetryScope>
  ): Promise<SastRetryRuntimeAuthorityDecision>;
}

export class UnavailableSastRetryRuntimeAuthority
  extends SastRetryRuntimeAuthority {
  async verify(): Promise<SastRetryRuntimeAuthorityDecision> {
    return {
      currentScannerSetDigest: null,
      scannerSetAvailable: false,
      killSwitchStatus: 'UNAVAILABLE',
      killSwitchSnapshotDigest: null
    };
  }
}
