import { Module } from '@nestjs/common';

import { ConfigModule } from '../config/config.module';
import { TeamsNotifierService } from './teams-notifier.service';

@Module({
  imports: [ConfigModule],
  providers: [TeamsNotifierService],
  exports: [TeamsNotifierService]
})
export class ObservabilityModule {}
