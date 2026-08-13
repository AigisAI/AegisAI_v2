import type {
  SastRuleBundleManifest,
  SastRuleBundleSupplyChainAttestation
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';

export class SastRuleBundleSupplyChainVerificationError extends Error {
  constructor(
    readonly reason:
      | 'AUTHORITY_UNAVAILABLE'
      | 'SIGNATURE_INVALID'
      | 'PROVENANCE_INVALID'
      | 'SIGNER_UNTRUSTED'
      | 'SUBJECT_MISMATCH'
  ) {
    super('The rule-bundle supply-chain verification failed closed.');
    this.name = 'SastRuleBundleSupplyChainVerificationError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export abstract class SastRuleBundleSupplyChainAuthority {
  abstract verify(
    manifest: Readonly<SastRuleBundleManifest>
  ): Promise<SastRuleBundleSupplyChainAttestation>;
}

@Injectable()
export class UnavailableSastRuleBundleSupplyChainAuthority extends SastRuleBundleSupplyChainAuthority {
  async verify(
    manifest: Readonly<SastRuleBundleManifest>
  ): Promise<SastRuleBundleSupplyChainAttestation> {
    void manifest;
    throw new SastRuleBundleSupplyChainVerificationError(
      'AUTHORITY_UNAVAILABLE'
    );
  }
}
