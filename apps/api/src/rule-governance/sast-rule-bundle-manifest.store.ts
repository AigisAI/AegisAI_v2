import type {
  SastRuleBundleCompatibilityReceipt,
  SastRuleBundleManifest,
  SastRuleBundleSupplyChainAttestation
} from '@aegisai/shared';

export interface PersistedVerifiedSastRuleBundle {
  manifest: SastRuleBundleManifest;
  attestation: SastRuleBundleSupplyChainAttestation;
  replayed: boolean;
}

export interface PersistedSastRuleBundleCompatibilityReceipt {
  receipt: SastRuleBundleCompatibilityReceipt;
  replayed: boolean;
}

export class SastRuleBundleManifestPersistenceError extends Error {
  constructor(
    readonly reason:
      | 'INPUT_INVALID'
      | 'LEDGER_CORRUPT'
      | 'MANIFEST_NOT_FOUND'
      | 'REPLAY_CONFLICT'
  ) {
    super('The immutable SAST rule-bundle ledger rejected the operation.');
    this.name = 'SastRuleBundleManifestPersistenceError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export abstract class SastRuleBundleManifestStore {
  abstract registerVerified(input: {
    manifest: Readonly<SastRuleBundleManifest>;
    attestation: Readonly<SastRuleBundleSupplyChainAttestation>;
  }): Promise<PersistedVerifiedSastRuleBundle>;

  abstract findVerified(
    manifestId: string
  ): Promise<PersistedVerifiedSastRuleBundle | null>;

  abstract recordCompatibilityReceipt(
    receipt: Readonly<SastRuleBundleCompatibilityReceipt>
  ): Promise<PersistedSastRuleBundleCompatibilityReceipt>;
}
