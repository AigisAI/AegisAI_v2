import {
  createParamDecorator,
  type ExecutionContext
} from '@nestjs/common';

import type { AuthenticatedSastWorkloadIdentity } from './sast-workload-identity.authenticator';
import type { SastWorkloadIdentityRequest } from './sast-workload-identity.guard';

export const CurrentSastWorkloadIdentity = createParamDecorator(
  (
    _data: unknown,
    context: ExecutionContext
  ): Readonly<AuthenticatedSastWorkloadIdentity> => {
    const request =
      context.switchToHttp().getRequest<SastWorkloadIdentityRequest>();
    if (!request.sastWorkloadIdentity) {
      throw new Error('SAST workload identity guard did not populate request context.');
    }
    return request.sastWorkloadIdentity;
  }
);
