import type {
  PromotionVerifiedScannerSetDescriptor,
  VerifiedScannerSetDescriptor
} from '@aegisai/shared';

export interface SastRuleBundleLifecycleGateInput {
  scannerSet: Readonly<VerifiedScannerSetDescriptor>;
  evaluatedAt: string;
}

export class SastRuleBundleLifecycleGateError extends Error {
  constructor(
    readonly reason:
      | 'PROMOTION_EVIDENCE_UNVERIFIED'
      | 'PROMOTION_APPROVAL_INVALID'
      | 'LIFECYCLE_STATE_NOT_SELECTABLE'
      | 'LIFECYCLE_STATE_STALE'
      | 'LIFECYCLE_AUTHORITY_UNAVAILABLE'
      | 'LIFECYCLE_STORE_UNAVAILABLE'
  ) {
    super('The rule-bundle lifecycle gate failed closed.');
    this.name = 'SastRuleBundleLifecycleGateError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export abstract class SastRuleBundleLifecycleGate {
  abstract verifyScannerSet(
    input: Readonly<SastRuleBundleLifecycleGateInput>
  ): Promise<PromotionVerifiedScannerSetDescriptor>;
}
