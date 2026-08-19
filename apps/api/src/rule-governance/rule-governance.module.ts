import { Module } from '@nestjs/common';

import { PrismaSastRuleBundleManifestStore } from './prisma-sast-rule-bundle-manifest.store';
import { PrismaSastRuleBundleLifecycleStore } from './prisma-sast-rule-bundle-lifecycle.store';
import { PrismaSastRuleBundleCanaryStore } from './prisma-sast-rule-bundle-canary.store';
import { PrismaSastRuleSemanticPolicyStore } from './prisma-sast-rule-semantic-policy.store';
import { PrismaSastKillSwitchStore } from './prisma-sast-kill-switch.store';
import { PrismaSastRuleBundleRollbackStore } from './prisma-sast-rule-bundle-rollback.store';
import {
  SastKillSwitchClock,
  SystemSastKillSwitchClock
} from './sast-kill-switch.clock';
import { SastKillSwitchCanarySuspensionService } from './sast-kill-switch-canary-suspension.service';
import { SastKillSwitchGate } from './sast-kill-switch.gate';
import { SastKillSwitchService } from './sast-kill-switch.service';
import {
  SastKillSwitchSignatureAuthority,
  UnavailableSastKillSwitchSignatureAuthority
} from './sast-kill-switch-signature.authority';
import { SastKillSwitchStore } from './sast-kill-switch.store';
import {
  EnvironmentSastRuleBundleCanaryCohortKeyProvider,
  SastRuleBundleCanaryCohortKeyProvider
} from './sast-rule-bundle-canary-key.provider';
import {
  SastRuleBundleCanaryObservationSource,
  UnavailableSastRuleBundleCanaryObservationSource
} from './sast-rule-bundle-canary-observation.source';
import {
  SastRuleBundleCanaryClock,
  SystemSastRuleBundleCanaryClock
} from './sast-rule-bundle-canary.clock';
import { SastRuleBundleCanaryGate } from './sast-rule-bundle-canary.gate';
import { SastRuleBundleCanaryService } from './sast-rule-bundle-canary.service';
import { SastRuleBundleCanaryStore } from './sast-rule-bundle-canary.store';
import { SastRuleBundleCompatibilityGate } from './sast-rule-bundle-compatibility.gate';
import {
  SastRuleBundleLifecycleAuthority,
  UnavailableSastRuleBundleLifecycleAuthority
} from './sast-rule-bundle-lifecycle.authority';
import { SastRuleBundleLifecycleAuthorityRouter } from './sast-rule-bundle-lifecycle-authority.router';
import {
  SastRuleBundleLifecycleClock,
  SystemSastRuleBundleLifecycleClock
} from './sast-rule-bundle-lifecycle.clock';
import { SastRuleBundleLifecycleGate } from './sast-rule-bundle-lifecycle.gate';
import { SastRuleBundleLifecycleService } from './sast-rule-bundle-lifecycle.service';
import { SastRuleBundleLifecycleStore } from './sast-rule-bundle-lifecycle.store';
import {
  SastRuleBundleRollbackClock,
  SystemSastRuleBundleRollbackClock
} from './sast-rule-bundle-rollback.clock';
import {
  SastRuleBundleRollbackSignatureAuthority,
  UnavailableSastRuleBundleRollbackSignatureAuthority
} from './sast-rule-bundle-rollback-signature.authority';
import { SastRuleBundleRollbackService } from './sast-rule-bundle-rollback.service';
import { SastRuleBundleRollbackStore } from './sast-rule-bundle-rollback.store';
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
    PrismaSastRuleBundleCanaryStore,
    PrismaSastRuleSemanticPolicyStore,
    PrismaSastKillSwitchStore,
    PrismaSastRuleBundleRollbackStore,
    SastRuleBundleManifestService,
    SastRuleBundleLifecycleService,
    SastRuleBundleCanaryService,
    SastRuleSemanticPolicyService,
    SastKillSwitchService,
    SastKillSwitchCanarySuspensionService,
    SastRuleBundleRollbackService,
    UnavailableSastRuleBundleSupplyChainAuthority,
    UnavailableSastRuleBundleLifecycleAuthority,
    UnavailableSastRuleBundleCanaryObservationSource,
    EnvironmentSastRuleBundleCanaryCohortKeyProvider,
    SystemSastRuleBundleCanaryClock,
    SastRuleBundleLifecycleAuthorityRouter,
    SystemSastRuleBundleLifecycleClock,
    SystemSastKillSwitchClock,
    UnavailableSastKillSwitchSignatureAuthority,
    SystemSastRuleBundleRollbackClock,
    UnavailableSastRuleBundleRollbackSignatureAuthority,
    {
      provide: SastKillSwitchStore,
      useExisting: PrismaSastKillSwitchStore
    },
    {
      provide: SastRuleBundleRollbackStore,
      useExisting: PrismaSastRuleBundleRollbackStore
    },
    {
      provide: SastRuleBundleRollbackClock,
      useExisting: SystemSastRuleBundleRollbackClock
    },
    {
      provide: SastRuleBundleRollbackSignatureAuthority,
      useExisting: UnavailableSastRuleBundleRollbackSignatureAuthority
    },
    {
      provide: SastKillSwitchGate,
      useExisting: SastKillSwitchService
    },
    {
      provide: SastKillSwitchClock,
      useExisting: SystemSastKillSwitchClock
    },
    {
      provide: SastKillSwitchSignatureAuthority,
      useExisting: UnavailableSastKillSwitchSignatureAuthority
    },
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
      provide: SastRuleBundleCanaryStore,
      useExisting: PrismaSastRuleBundleCanaryStore
    },
    {
      provide: SastRuleBundleCanaryGate,
      useExisting: SastRuleBundleCanaryService
    },
    {
      provide: SastRuleBundleCanaryCohortKeyProvider,
      useExisting: EnvironmentSastRuleBundleCanaryCohortKeyProvider
    },
    {
      provide: SastRuleBundleCanaryObservationSource,
      useExisting: UnavailableSastRuleBundleCanaryObservationSource
    },
    {
      provide: SastRuleBundleCanaryClock,
      useExisting: SystemSastRuleBundleCanaryClock
    },
    {
      provide: SastRuleBundleLifecycleGate,
      useExisting: SastRuleBundleLifecycleService
    },
    {
      provide: SastRuleBundleLifecycleAuthority,
      useExisting: SastRuleBundleLifecycleAuthorityRouter
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
    SastRuleBundleCanaryService,
    SastRuleBundleCanaryGate,
    SastRuleSemanticPolicyService,
    SastTenantRulePolicyGate,
    SastKillSwitchService,
    SastKillSwitchCanarySuspensionService,
    SastRuleBundleRollbackService,
    SastKillSwitchGate
  ]
})
export class RuleGovernanceModule {}
