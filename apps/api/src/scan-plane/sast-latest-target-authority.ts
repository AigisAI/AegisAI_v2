import type {
  SastScanFreshnessScope
} from '@aegisai/shared';

export type SastLatestTargetObservationResult =
  | {
      status: 'VERIFIED';
      headCommitSha: string;
      sequence: number;
      observerRef: string;
      observedAt: string;
    }
  | { status: 'UNAVAILABLE' };

/**
 * Reads a provider-authoritative target head. The default stays unavailable
 * until a read-only GitHub App or GitLab integration adapter is installed.
 */
export abstract class SastLatestTargetAuthority {
  abstract observe(
    scope: Readonly<SastScanFreshnessScope>
  ): Promise<SastLatestTargetObservationResult>;
}

export class UnavailableSastLatestTargetAuthority
  extends SastLatestTargetAuthority {
  async observe(): Promise<SastLatestTargetObservationResult> {
    return { status: 'UNAVAILABLE' };
  }
}
