import type { SastRuleBundleRollbackCommand } from '@aegisai/shared';
import { Injectable } from '@nestjs/common';

export interface SastRuleBundleRollbackSignatureVerificationFacts {
  signerIdentity: string;
  signatureRef: string;
  provenanceRef: string;
  signatureVerified: true;
  provenanceVerified: true;
  trustedSigner: true;
  signatureBytesStored: false;
  provenancePayloadStored: false;
}

export class SastRuleBundleRollbackSignatureAuthorityError extends Error {
  constructor(readonly reason: 'UNAVAILABLE' | 'REJECTED') {
    super('The SAST rule-bundle rollback signature authority failed closed.');
    this.name = 'SastRuleBundleRollbackSignatureAuthorityError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export abstract class SastRuleBundleRollbackSignatureAuthority {
  abstract verify(
    command: Readonly<SastRuleBundleRollbackCommand>
  ): Promise<SastRuleBundleRollbackSignatureVerificationFacts>;
}

@Injectable()
export class UnavailableSastRuleBundleRollbackSignatureAuthority
  extends SastRuleBundleRollbackSignatureAuthority {
  verify(): Promise<never> {
    return Promise.reject(
      new SastRuleBundleRollbackSignatureAuthorityError('UNAVAILABLE')
    );
  }
}
