import { Module } from '@nestjs/common';

import { PrismaSastRuleBundleManifestStore } from './prisma-sast-rule-bundle-manifest.store';
import { SastRuleBundleCompatibilityGate } from './sast-rule-bundle-compatibility.gate';
import { SastRuleBundleManifestService } from './sast-rule-bundle-manifest.service';
import { SastRuleBundleManifestStore } from './sast-rule-bundle-manifest.store';
import {
  SastRuleBundleSupplyChainAuthority,
  UnavailableSastRuleBundleSupplyChainAuthority
} from './sast-rule-bundle-supply-chain.authority';

@Module({
  providers: [
    PrismaSastRuleBundleManifestStore,
    SastRuleBundleManifestService,
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
      provide: SastRuleBundleSupplyChainAuthority,
      useExisting: UnavailableSastRuleBundleSupplyChainAuthority
    }
  ],
  exports: [
    SastRuleBundleManifestService,
    SastRuleBundleCompatibilityGate
  ]
})
export class RuleGovernanceModule {}
