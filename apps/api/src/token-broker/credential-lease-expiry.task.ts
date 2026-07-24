import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit
} from '@nestjs/common';

import { ConfigService } from '../config/config.service';
import { RepositoryCredentialLeaseStore } from './repository-credential-lease.store';

@Injectable()
export class CredentialLeaseExpiryTask
  implements OnModuleInit, OnModuleDestroy
{
  private readonly logger = new Logger(CredentialLeaseExpiryTask.name);
  private timer: NodeJS.Timeout | null = null;

  constructor(
    private readonly leases: RepositoryCredentialLeaseStore,
    private readonly config: ConfigService
  ) {}

  onModuleInit(): void {
    if (this.config.isTest()) {
      return;
    }
    this.timer = setInterval(() => {
      void this.revokeExpired().catch((error: unknown) => {
        this.logger.error(
          'Failed to revoke expired repository credential leases.',
          error as Error
        );
      });
    }, this.config.get('CREDENTIAL_LEASE_EXPIRY_INTERVAL_MS'));
    this.timer.unref?.();
  }

  onModuleDestroy(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  revokeExpired(referenceTime = new Date()): Promise<number> {
    return this.leases.revokeExpired(referenceTime.toISOString());
  }
}
