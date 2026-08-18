import type {
  RuleBundleState,
  SastRuleBundleLifecycleExternalAuthority
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';

export type RequiredSastRuleBundleLifecycleExternalAuthority = Exclude<
  SastRuleBundleLifecycleExternalAuthority,
  'NONE'
>;

export interface SastRuleBundleLifecycleAuthorityInput {
  authority: RequiredSastRuleBundleLifecycleExternalAuthority;
  manifestId: string;
  manifestDigest: `sha256:${string}`;
  bundleId: string;
  bundleDigest: `sha256:${string}`;
  fromState: RuleBundleState;
  toState: RuleBundleState;
  promotionEvidenceId: string;
  promotionEvidenceDigest: `sha256:${string}`;
  requestedAt: string;
}

export interface SastRuleBundleLifecycleAuthorityReceipt {
  authority: RequiredSastRuleBundleLifecycleExternalAuthority;
  manifestId: string;
  manifestDigest: `sha256:${string}`;
  bundleId: string;
  bundleDigest: `sha256:${string}`;
  fromState: RuleBundleState;
  toState: RuleBundleState;
  promotionEvidenceId: string;
  promotionEvidenceDigest: `sha256:${string}`;
  requestedAt: string;
  receiptRef: string;
  receiptDigest: `sha256:${string}`;
  verifiedAt: string;
}

export class SastRuleBundleLifecycleAuthorityError extends Error {
  constructor(readonly reason: 'UNAVAILABLE' | 'REJECTED' | 'RECEIPT_INVALID') {
    super('The external rule-bundle lifecycle authority failed closed.');
    this.name = 'SastRuleBundleLifecycleAuthorityError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export abstract class SastRuleBundleLifecycleAuthority {
  abstract authorize(
    input: Readonly<SastRuleBundleLifecycleAuthorityInput>
  ): Promise<SastRuleBundleLifecycleAuthorityReceipt>;
}

@Injectable()
export class UnavailableSastRuleBundleLifecycleAuthority extends SastRuleBundleLifecycleAuthority {
  async authorize(): Promise<never> {
    throw new SastRuleBundleLifecycleAuthorityError('UNAVAILABLE');
  }
}
