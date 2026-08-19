import { Injectable } from '@nestjs/common';

export abstract class SastKillSwitchClock {
  abstract now(): Date;
}

@Injectable()
export class SystemSastKillSwitchClock extends SastKillSwitchClock {
  now(): Date {
    return new Date();
  }
}
