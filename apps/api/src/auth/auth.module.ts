import { Module } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';

import { ConfigModule } from '../config/config.module';
import { PrismaModule } from '../prisma/prisma.module';
import { AuthSerializer } from './auth.serializer';
import { AuthService } from './auth.service';
import { SessionAuthGuard } from './guards/session-auth.guard';
import { TokenCryptoUtil } from './utils/token-crypto.util';

@Module({
  imports: [ConfigModule, PrismaModule, PassportModule.register({ session: true })],
  providers: [AuthService, AuthSerializer, SessionAuthGuard, TokenCryptoUtil],
  exports: [AuthService, AuthSerializer, SessionAuthGuard, TokenCryptoUtil, PassportModule]
})
export class AuthModule {}
