import { Module } from '@nestjs/common';

import { PrismaSastRuleBundleManifestStore } from './prisma-sast-rule-bundle-manifest.store';
import { PrismaSastRuleSemanticPolicyStore } from './prisma-sast-rule-semantic-policy.store';
import { SastRuleBundleCompatibilityGate } from './sast-rule-bundle-compatibility.gate';
import { SastRuleBundleManifestService } from './sast-rule-bundle-manifest.service';
import { SastRuleBundleManifestStore } from './sast-rule-bundle-manifest.store';
import { SastRuleSemanticPolicyService } from './sast-rule-semantic-policy.service';
import { SastRuleSemanticPolicyStore } from './sast-rule-semantic-policy.store';
import {
  SastRuleBundleSupplyChainAuthority,
  UnavailableSastRuleBundleSupplyChainAuthority
} from './sast-rule-bundle-supply-chain.authority';
import { SastTenantRulePolicyGate } from './sast-tenant-rule-policy.gate';

@Module({
  providers: [
    PrismaSastRuleBundleManifestStore,
    PrismaSastRuleSemanticPolicyStore,
    SastRuleBundleManifestService,
    SastRuleSemanticPolicyService,
    UnavailableSastRuleBundleSupplyChainAuthority,
    {
      provide: SastRuleBundleManifestStore,
      useExisting: PrismaSastRuleBundleManifestStore
    },
    {
      provide: SastRuleBundleCompatibilityGate,
      useExisting: SastRuleBundleManifestService
    },
    {
      provide: SastRuleSemanticPolicyStore,
      useExisting: PrismaSastRuleSemanticPolicyStore
    },
    {
      provide: SastTenantRulePolicyGate,
      useExisting: SastRuleSemanticPolicyService
    },
    {
      provide: SastRuleBundleSupplyChainAuthority,
      useExisting: UnavailableSastRuleBundleSupplyChainAuthority
    }
  ],
  exports: [
    SastRuleBundleManifestService,
    SastRuleBundleCompatibilityGate,
    SastRuleSemanticPolicyService,
    SastTenantRulePolicyGate
  ]
})
export class RuleGovernanceModule {}
