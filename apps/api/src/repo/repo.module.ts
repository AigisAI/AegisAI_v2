import { Module } from '@nestjs/common';

import { AuthModule } from '../auth/auth.module';
import { GitClientModule } from '../client/git/git-client.module';
import { ConfigModule } from '../config/config.module';
import { PrismaModule } from '../prisma/prisma.module';
import { RepoController } from './repo.controller';
import { RepoService } from './repo.service';

@Module({
  imports: [AuthModule, ConfigModule, PrismaModule, GitClientModule],
  controllers: [RepoController],
  providers: [RepoService],
  exports: [RepoService]
})
export class RepoModule {}
