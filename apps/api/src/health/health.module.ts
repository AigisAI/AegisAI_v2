import { Module } from '@nestjs/common';

import { ConfigModule } from '../config/config.module';
import { PrismaModule } from '../prisma/prisma.module';
import { HealthController } from './health.controller';

@Module({
  imports: [ConfigModule, PrismaModule],
  controllers: [HealthController]
})
export class HealthModule {}
