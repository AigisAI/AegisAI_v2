import { Global, Module } from '@nestjs/common';

import { AuthModule } from '../../auth/auth.module';
import { ConfigModule } from '../../config/config.module';
import { GithubWebhookSignatureGuard } from './github-webhook-signature.guard';
import { InternalServiceGuard } from './internal-service.guard';

@Global()
@Module({
  imports: [AuthModule, ConfigModule],
  providers: [GithubWebhookSignatureGuard, InternalServiceGuard],
  exports: [AuthModule, GithubWebhookSignatureGuard, InternalServiceGuard]
})
export class SecurityModule {}
