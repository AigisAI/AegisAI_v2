import { Module } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';

import { ConfigModule } from '../config/config.module';
import { PrismaModule } from '../prisma/prisma.module';
import { AuthController } from './auth.controller';
import { AuthSerializer } from './auth.serializer';
import { AuthService } from './auth.service';
import { GithubAuthGuard } from './guards/github-auth.guard';
import { GitlabAuthGuard } from './guards/gitlab-auth.guard';
import { SessionAuthGuard } from './guards/session-auth.guard';
import { GithubStrategy } from './strategies/github.strategy';
import { GitlabStrategy } from './strategies/gitlab.strategy';
import { TokenCryptoUtil } from './utils/token-crypto.util';

@Module({
  imports: [ConfigModule, PrismaModule, PassportModule.register({ session: true })],
  controllers: [AuthController],
  providers: [
    AuthService,
    AuthSerializer,
    SessionAuthGuard,
    GithubAuthGuard,
    GitlabAuthGuard,
    TokenCryptoUtil,
    GithubStrategy,
    GitlabStrategy
  ],
  exports: [AuthService, AuthSerializer, SessionAuthGuard, TokenCryptoUtil, PassportModule]
})
export class AuthModule {}
