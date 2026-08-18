import type {
  CanaryQualifiedScannerSetDescriptor,
  PromotionVerifiedScannerSetDescriptor,
  SastScanProfile
} from '@aegisai/shared';

export type SastRuleBundleCanaryGateReason =
  | 'CANARY_ROLLOUT_UNAVAILABLE'
  | 'CANARY_ELIGIBILITY_UNAVAILABLE'
  | 'CANARY_ASSIGNMENT_INELIGIBLE'
  | 'CANARY_ASSIGNMENT_STALE'
  | 'CANARY_KEY_UNAVAILABLE'
  | 'CANARY_STORE_UNAVAILABLE';

export class SastRuleBundleCanaryGateError extends Error {
  constructor(readonly reason: SastRuleBundleCanaryGateReason) {
    super('The SAST rule-bundle canary gate failed closed.');
    this.name = 'SastRuleBundleCanaryGateError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export interface SastRuleBundleCanaryGateInput {
  tenantId: string;
  repositoryBindingId: string;
  scannerSet: PromotionVerifiedScannerSetDescriptor;
  profile: SastScanProfile;
  profileDigest: `sha256:${string}`;
  evaluatedAt: string;
}

export abstract class SastRuleBundleCanaryGate {
  abstract verifyScannerSet(
    input: Readonly<SastRuleBundleCanaryGateInput>
  ): Promise<CanaryQualifiedScannerSetDescriptor>;
}
