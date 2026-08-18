import { Injectable } from '@nestjs/common';

export abstract class SastRuleBundleLifecycleClock {
  abstract now(): Date;
}

@Injectable()
export class SystemSastRuleBundleLifecycleClock extends SastRuleBundleLifecycleClock {
  now(): Date {
    return new Date();
  }
}
