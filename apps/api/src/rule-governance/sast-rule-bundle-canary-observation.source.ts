import type {
  SastRuleBundleCanaryScanObservationInput
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';

export interface SastRuleBundleCanaryObservationSourceRequest {
  rolloutId: string;
  tenantId: string;
  repositoryBindingId: string;
  scanRequestId: string;
  attemptId: string;
}

export class SastRuleBundleCanaryObservationSourceError extends Error {
  constructor(readonly reason: 'UNAVAILABLE' | 'INCOMPLETE' | 'SCOPE_MISMATCH') {
    super('The trusted SAST canary observation source failed closed.');
    this.name = 'SastRuleBundleCanaryObservationSourceError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export abstract class SastRuleBundleCanaryObservationSource {
  abstract load(
    request: Readonly<SastRuleBundleCanaryObservationSourceRequest>
  ): Promise<SastRuleBundleCanaryScanObservationInput>;
}

@Injectable()
export class UnavailableSastRuleBundleCanaryObservationSource extends SastRuleBundleCanaryObservationSource {
  async load(): Promise<never> {
    throw new SastRuleBundleCanaryObservationSourceError('UNAVAILABLE');
  }
}
