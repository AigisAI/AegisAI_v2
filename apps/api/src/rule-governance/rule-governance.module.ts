import { Module } from '@nestjs/common';

import { PrismaSastRuleBundleManifestStore } from './prisma-sast-rule-bundle-manifest.store';
import { PrismaSastRuleBundleLifecycleStore } from './prisma-sast-rule-bundle-lifecycle.store';
import { PrismaSastRuleSemanticPolicyStore } from './prisma-sast-rule-semantic-policy.store';
import { SastRuleBundleCompatibilityGate } from './sast-rule-bundle-compatibility.gate';
import {
  SastRuleBundleLifecycleAuthority,
  UnavailableSastRuleBundleLifecycleAuthority
} from './sast-rule-bundle-lifecycle.authority';
import {
  SastRuleBundleLifecycleClock,
  SystemSastRuleBundleLifecycleClock
} from './sast-rule-bundle-lifecycle.clock';
import { SastRuleBundleLifecycleGate } from './sast-rule-bundle-lifecycle.gate';
import { SastRuleBundleLifecycleService } from './sast-rule-bundle-lifecycle.service';
import { SastRuleBundleLifecycleStore } from './sast-rule-bundle-lifecycle.store';
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
    PrismaSastRuleBundleLifecycleStore,
    PrismaSastRuleSemanticPolicyStore,
    SastRuleBundleManifestService,
    SastRuleBundleLifecycleService,
    SastRuleSemanticPolicyService,
    UnavailableSastRuleBundleSupplyChainAuthority,
    UnavailableSastRuleBundleLifecycleAuthority,
    SystemSastRuleBundleLifecycleClock,
    {
      provide: SastRuleBundleManifestStore,
      useExisting: PrismaSastRuleBundleManifestStore
    },
    {
      provide: SastRuleBundleCompatibilityGate,
      useExisting: SastRuleBundleManifestService
    },
    {
      provide: SastRuleBundleLifecycleStore,
      useExisting: PrismaSastRuleBundleLifecycleStore
    },
    {
      provide: SastRuleBundleLifecycleGate,
      useExisting: SastRuleBundleLifecycleService
    },
    {
      provide: SastRuleBundleLifecycleAuthority,
      useExisting: UnavailableSastRuleBundleLifecycleAuthority
    },
    {
      provide: SastRuleBundleLifecycleClock,
      useExisting: SystemSastRuleBundleLifecycleClock
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
    SastRuleBundleLifecycleService,
    SastRuleBundleLifecycleGate,
    SastRuleSemanticPolicyService,
    SastTenantRulePolicyGate
  ]
})
export class RuleGovernanceModule {}
