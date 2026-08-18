import { Injectable } from '@nestjs/common';

export abstract class SastRuleBundleCanaryClock {
  abstract now(): Date;
}

@Injectable()
export class SystemSastRuleBundleCanaryClock extends SastRuleBundleCanaryClock {
  now(): Date {
    return new Date();
  }
}
