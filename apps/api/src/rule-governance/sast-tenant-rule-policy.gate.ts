import type {
  SastScanProfile,
  VerifiedSastTenantRulePolicyDescriptor,
  VerifiedScannerSetDescriptor
} from '@aegisai/shared';

export interface SastTenantRulePolicyGateInput {
  tenantId: string;
  repositoryBindingId: string;
  policyVersion: string;
  scannerSet: Readonly<VerifiedScannerSetDescriptor>;
  profile: Readonly<SastScanProfile>;
  profileDigest: `sha256:${string}`;
  evaluatedAt: string;
}

export class SastTenantRulePolicyGateError extends Error {
  constructor(
    readonly reason:
      | 'RULE_METADATA_UNVERIFIED'
      | 'RULE_METADATA_MISMATCH'
      | 'TENANT_POLICY_INVALID'
      | 'POLICY_STORE_UNAVAILABLE'
  ) {
    super('The tenant rule-policy gate failed closed.');
    this.name = 'SastTenantRulePolicyGateError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export abstract class SastTenantRulePolicyGate {
  abstract resolve(
    input: Readonly<SastTenantRulePolicyGateInput>
  ): Promise<VerifiedSastTenantRulePolicyDescriptor>;
}
