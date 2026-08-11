import { Injectable } from '@nestjs/common';

export interface SastEvidenceSecretRegistryScope {
  tenantId: string;
  repositoryBindingId: string;
  evidencePackId: string;
}

export type SastEvidenceSecretRegistryResult =
  | { status: 'UNAVAILABLE' }
  | {
      status: 'VERIFIED';
      registryVersion: string;
      platformSecretValues: readonly string[];
    };

export abstract class SastEvidenceSecretRegistry {
  abstract read(
    scope: Readonly<SastEvidenceSecretRegistryScope>
  ): Promise<SastEvidenceSecretRegistryResult>;
}

@Injectable()
export class UnavailableSastEvidenceSecretRegistry
  extends SastEvidenceSecretRegistry {
  read(): Promise<SastEvidenceSecretRegistryResult> {
    return Promise.resolve({ status: 'UNAVAILABLE' });
  }
}
