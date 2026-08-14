import { Injectable } from '@nestjs/common';

@Injectable()
export class SastPolicyEvaluationClock {
  now(): Date {
    return new Date();
  }
}
