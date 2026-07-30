import type {
  SastFindingLifecycleCoverageDecision
} from '@aegisai/shared';

export type SastFindingLifecycleCoverageVerification =
  | 'VERIFIED'
  | 'REJECTED'
  | 'UNAVAILABLE';

/**
 * T039 owns coverage calculation. T037 can only consume a complete,
 * non-stale, comparable decision that this boundary verifies.
 */
export abstract class SastFindingLifecycleCoverageGate {
  abstract verify(
    decision: Readonly<SastFindingLifecycleCoverageDecision>
  ): Promise<SastFindingLifecycleCoverageVerification>;
}

export class UnavailableSastFindingLifecycleCoverageGate
  extends SastFindingLifecycleCoverageGate {
  async verify(): Promise<SastFindingLifecycleCoverageVerification> {
    return 'UNAVAILABLE';
  }
}
