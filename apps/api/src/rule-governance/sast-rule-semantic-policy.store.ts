import type {
  SastRuleDefinitionMetadataBinding,
  SastTenantRulePolicy,
  SastTenantRulePolicyResolutionReceipt
} from '@aegisai/shared';

export interface PersistedSastRuleDefinitionMetadataBinding {
  binding: SastRuleDefinitionMetadataBinding;
  replayed: boolean;
}

export interface PersistedSastTenantRulePolicy {
  policy: SastTenantRulePolicy;
  replayed: boolean;
}

export interface PersistedSastTenantRulePolicyResolution {
  receipt: SastTenantRulePolicyResolutionReceipt;
  replayed: boolean;
}

export interface SastApprovedRulePolicyTargets {
  semanticRuleIds: string[];
  categories: string[];
}

export class SastRuleSemanticPolicyPersistenceError extends Error {
  constructor(
    readonly reason:
      | 'INPUT_INVALID'
      | 'LEDGER_CORRUPT'
      | 'MANIFEST_NOT_FOUND'
      | 'METADATA_NOT_FOUND'
      | 'POLICY_NOT_FOUND'
      | 'TENANT_SCOPE_INVALID'
      | 'REFERENCE_INVALID'
      | 'REPLAY_CONFLICT'
  ) {
    super('The immutable SAST semantic-policy ledger rejected the operation.');
    this.name = 'SastRuleSemanticPolicyPersistenceError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export abstract class SastRuleSemanticPolicyStore {
  abstract registerRuleMetadataBinding(
    binding: Readonly<SastRuleDefinitionMetadataBinding>
  ): Promise<PersistedSastRuleDefinitionMetadataBinding>;

  abstract findRuleMetadataBindingsForManifests(
    manifestIds: readonly string[]
  ): Promise<SastRuleDefinitionMetadataBinding[]>;

  abstract findApprovedPolicyTargets(): Promise<SastApprovedRulePolicyTargets>;

  abstract registerTenantPolicy(
    policy: Readonly<SastTenantRulePolicy>
  ): Promise<PersistedSastTenantRulePolicy>;

  abstract findTenantPolicy(
    tenantId: string,
    policyVersion: string
  ): Promise<PersistedSastTenantRulePolicy | null>;

  abstract recordPolicyResolution(
    receipt: Readonly<SastTenantRulePolicyResolutionReceipt>
  ): Promise<PersistedSastTenantRulePolicyResolution>;
}
