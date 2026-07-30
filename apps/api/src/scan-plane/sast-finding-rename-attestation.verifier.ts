import type {
  SastFindingRenameAttestation
} from '@aegisai/shared';

export type SastFindingRenameVerification =
  | 'VERIFIED'
  | 'REJECTED'
  | 'UNAVAILABLE';

export abstract class SastFindingRenameAttestationVerifier {
  abstract verify(
    attestation: Readonly<SastFindingRenameAttestation>
  ): Promise<SastFindingRenameVerification>;
}

export class UnavailableSastFindingRenameAttestationVerifier
  extends SastFindingRenameAttestationVerifier {
  async verify(): Promise<SastFindingRenameVerification> {
    return 'UNAVAILABLE';
  }
}
