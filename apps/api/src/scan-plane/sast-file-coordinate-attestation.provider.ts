import type { SastFileCoordinateMetadata } from '@aegisai/shared';
import { Injectable } from '@nestjs/common';

export interface SastFileCoordinateAttestationRequest {
  tenantId: string;
  repositoryBindingId: string;
  scanRequestId: string;
  attemptId: string;
  preflightAttestationRef: string;
  preflightInventoryDigest: `sha256:${string}`;
}

export interface SastFileCoordinateAttestation {
  attestationRef: string;
  inventoryDigest: `sha256:${string}`;
  verified: true;
  files: readonly Readonly<SastFileCoordinateMetadata>[];
}

export abstract class SastFileCoordinateAttestationProvider {
  /**
   * Returns only provisioner-attested metadata for the exact tenant and attempt.
   * Implementations must not return source bytes or accept caller-supplied paths.
   * They must apply the shared file and aggregate-line caps before materializing
   * the result so provider memory use remains bounded.
   */
  abstract load(
    input: Readonly<SastFileCoordinateAttestationRequest>
  ): Promise<Readonly<SastFileCoordinateAttestation> | null>;
}

@Injectable()
export class UnavailableSastFileCoordinateAttestationProvider
  extends SastFileCoordinateAttestationProvider
{
  load(): Promise<null> {
    return Promise.resolve(null);
  }
}
