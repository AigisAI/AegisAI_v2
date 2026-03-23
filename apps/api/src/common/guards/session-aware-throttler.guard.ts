import { Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import {
  InjectThrottlerOptions,
  InjectThrottlerStorage,
  ThrottlerGuard
} from '@nestjs/throttler';
import type { ThrottlerModuleOptions } from '@nestjs/throttler';
import type { ThrottlerStorage } from '@nestjs/throttler';

interface TrackerRequest {
  sessionID?: string;
  ip?: string;
}

export function getSessionAwareTracker(request: TrackerRequest): string {
  return request.sessionID ?? request.ip ?? 'unknown';
}

@Injectable()
export class SessionAwareThrottlerGuard extends ThrottlerGuard {
  constructor(
    @InjectThrottlerOptions() options: ThrottlerModuleOptions,
    @InjectThrottlerStorage() storageService: ThrottlerStorage,
    reflector: Reflector
  ) {
    super(options, storageService, reflector);
  }

  protected async getTracker(req: TrackerRequest): Promise<string> {
    return getSessionAwareTracker(req);
  }
}
