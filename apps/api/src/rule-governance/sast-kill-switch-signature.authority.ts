import type {
  SastKillSwitchControlDecision
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';

export interface SastKillSwitchSignatureVerificationFacts {
  signerIdentity: string;
  signatureRef: string;
  provenanceRef: string;
  signatureVerified: true;
  provenanceVerified: true;
  trustedSigner: true;
  signatureBytesStored: false;
  provenancePayloadStored: false;
}

export class SastKillSwitchSignatureAuthorityError extends Error {
  constructor(readonly reason: 'UNAVAILABLE' | 'REJECTED') {
    super('The SAST kill-switch signature authority failed closed.');
    this.name = 'SastKillSwitchSignatureAuthorityError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export abstract class SastKillSwitchSignatureAuthority {
  abstract verify(
    decision: Readonly<SastKillSwitchControlDecision>
  ): Promise<SastKillSwitchSignatureVerificationFacts>;
}

@Injectable()
export class UnavailableSastKillSwitchSignatureAuthority
  extends SastKillSwitchSignatureAuthority {
  verify(): Promise<never> {
    return Promise.reject(
      new SastKillSwitchSignatureAuthorityError('UNAVAILABLE')
    );
  }
}
