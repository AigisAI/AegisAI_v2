import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException
} from '@nestjs/common';
import type { Request } from 'express';

import {
  type AuthenticatedSastWorkloadIdentity,
  SastWorkloadIdentityAuthenticator
} from './sast-workload-identity.authenticator';

export type SastWorkloadIdentityRequest = Request & {
  sastWorkloadIdentity?: Readonly<AuthenticatedSastWorkloadIdentity>;
};

@Injectable()
export class SastWorkloadIdentityGuard implements CanActivate {
  constructor(
    private readonly authenticator: SastWorkloadIdentityAuthenticator
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request =
      context.switchToHttp().getRequest<SastWorkloadIdentityRequest>();
    const identity = await this.authenticator.authenticate(request);
    if (!identity) {
      throw new UnauthorizedException({
        errorCode: 'SAST_WORKLOAD_IDENTITY_REQUIRED',
        message:
          'A directly authenticated mTLS workload identity is required.'
      });
    }

    request.sastWorkloadIdentity = Object.freeze({ ...identity });
    return true;
  }
}
