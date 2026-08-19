import { Injectable } from '@nestjs/common';

import {
  SastKillSwitchGateError,
} from './sast-kill-switch.gate';
import { SastKillSwitchService } from './sast-kill-switch.service';
import {
  SastRuleBundleCanaryService,
  SastRuleBundleCanaryServiceError
} from './sast-rule-bundle-canary.service';
import {
  SastRuleBundleLifecycleAuthority,
  SastRuleBundleLifecycleAuthorityError,
  UnavailableSastRuleBundleLifecycleAuthority,
  type SastRuleBundleLifecycleAuthorityInput,
  type SastRuleBundleLifecycleAuthorityReceipt
} from './sast-rule-bundle-lifecycle.authority';

@Injectable()
export class SastRuleBundleLifecycleAuthorityRouter extends SastRuleBundleLifecycleAuthority {
  constructor(
    private readonly canary: SastRuleBundleCanaryService,
    private readonly killSwitch: SastKillSwitchService,
    private readonly unavailable: UnavailableSastRuleBundleLifecycleAuthority
  ) {
    super();
  }

  async authorize(
    input: Readonly<SastRuleBundleLifecycleAuthorityInput>
  ): Promise<SastRuleBundleLifecycleAuthorityReceipt> {
    if (input.authority === 'EMERGENCY_SUSPENSION') {
      try {
        return await this.killSwitch.authorizeEmergencySuspension(input);
      } catch (error) {
        if (error instanceof SastKillSwitchGateError) {
          throw new SastRuleBundleLifecycleAuthorityError(
            error.reason === 'STORE_UNAVAILABLE' ||
              error.reason === 'AUTHORITY_UNAVAILABLE'
              ? 'UNAVAILABLE'
              : 'REJECTED'
          );
        }
        throw new SastRuleBundleLifecycleAuthorityError('UNAVAILABLE');
      }
    }
    if (input.authority !== 'CANARY_OBSERVATION') {
      return this.unavailable.authorize();
    }
    try {
      return await this.canary.authorizeLifecycleTransition(input);
    } catch (error) {
      if (error instanceof SastRuleBundleCanaryServiceError) {
        throw new SastRuleBundleLifecycleAuthorityError(
          error.reason === 'STORE_UNAVAILABLE' ? 'UNAVAILABLE' : 'REJECTED'
        );
      }
      throw new SastRuleBundleLifecycleAuthorityError('UNAVAILABLE');
    }
  }
}
