import { Global, Module } from '@nestjs/common';

import { AuthModule } from '../../auth/auth.module';
import { ConfigModule } from '../../config/config.module';
import { GithubWebhookSignatureGuard } from './github-webhook-signature.guard';
import { InternalServiceGuard } from './internal-service.guard';
import { InternalTenantServiceGuard } from './internal-tenant-service.guard';

@Global()
@Module({
  imports: [AuthModule, ConfigModule],
  providers: [
    GithubWebhookSignatureGuard,
    InternalServiceGuard,
    InternalTenantServiceGuard
  ],
  exports: [
    AuthModule,
    GithubWebhookSignatureGuard,
    InternalServiceGuard,
    InternalTenantServiceGuard
  ]
})
export class SecurityModule {}
