import { Injectable } from '@nestjs/common';
import { ThrottlerGuard } from '@nestjs/throttler';

interface TrackerRequest {
  sessionID?: string;
  ip?: string;
}

export function getSessionAwareTracker(request: TrackerRequest): string {
  return request.sessionID ?? request.ip ?? 'unknown';
}

@Injectable()
export class SessionAwareThrottlerGuard extends ThrottlerGuard {
  protected async getTracker(req: TrackerRequest): Promise<string> {
    return getSessionAwareTracker(req);
  }
}
