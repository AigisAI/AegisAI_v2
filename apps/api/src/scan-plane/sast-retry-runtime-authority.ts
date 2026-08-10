import type {
  SastScanRetryScope
} from '@aegisai/shared';

export interface SastRetryRuntimeAuthorityDecision {
  currentScannerSetDigest: `sha256:${string}` | null;
  scannerSetAvailable: boolean;
  killSwitchStatus: 'CLEAR' | 'ACTIVE' | 'UNAVAILABLE';
  killSwitchSnapshotDigest: `sha256:${string}` | null;
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
