import { Global, Module } from '@nestjs/common';

import { PrismaService } from './prisma.service';
import { ConfigModule } from '../config/config.module';

@Global()
@Module({
  imports: [ConfigModule],
  providers: [PrismaService],
  exports: [PrismaService]
})
export class PrismaModule {}
