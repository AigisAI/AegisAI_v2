import type {
  SastScanProfile,
  ScannerSetDescriptor,
  VerifiedScannerSetDescriptor
} from '@aegisai/shared';

export interface SastRuleBundleCompatibilityGateInput {
  scannerSet: Readonly<ScannerSetDescriptor>;
  profile: Readonly<SastScanProfile>;
  profileDigest: `sha256:${string}`;
  evaluatedAt: string;
}

export class SastRuleBundleCompatibilityGateError extends Error {
  constructor(
    readonly reason:
      | 'MANIFEST_UNVERIFIED'
      | 'MANIFEST_MISMATCH'
      | 'COMPATIBILITY_UNSUPPORTED'
      | 'VERIFICATION_UNAVAILABLE'
  ) {
    super('The rule-bundle compatibility gate failed closed.');
    this.name = 'SastRuleBundleCompatibilityGateError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export abstract class SastRuleBundleCompatibilityGate {
  abstract verifyScannerSet(
    input: Readonly<SastRuleBundleCompatibilityGateInput>
  ): Promise<VerifiedScannerSetDescriptor>;
}
