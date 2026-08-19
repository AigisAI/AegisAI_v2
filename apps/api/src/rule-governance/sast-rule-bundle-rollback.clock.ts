import { Injectable } from '@nestjs/common';

export abstract class SastRuleBundleRollbackClock {
  abstract now(): Date;
}

@Injectable()
export class SystemSastRuleBundleRollbackClock extends SastRuleBundleRollbackClock {
  now(): Date {
    return new Date();
  }
}
