import { BullModule } from '@nestjs/bullmq';
import { Module } from '@nestjs/common';
import { APP_FILTER, APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import { ThrottlerModule, seconds } from '@nestjs/throttler';

import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { AnalysisApiModule } from './client/analysis/analysis-api.module';
import { GitClientModule } from './client/git/git-client.module';
import { GlobalExceptionFilter } from './common/filters/global-exception.filter';
import { SessionAwareThrottlerGuard } from './common/guards/session-aware-throttler.guard';
import { ResponseTransformInterceptor } from './common/interceptors/response-transform.interceptor';
import { ConfigModule } from './config/config.module';
import { ConfigService } from './config/config.service';
import { HealthModule } from './health/health.module';
import { LanguageModule } from './language/language.module';
import { PrismaModule } from './prisma/prisma.module';
import { ScanModule } from './scan/scan.module';

const runtimeFeatureModules = process.env.NODE_ENV === 'test' ? [HealthModule] : [ScanModule, HealthModule];

@Module({
  imports: [
    ConfigModule,
    BullModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        connection: {
          url: config.get('REDIS_URL')
        },
        extraOptions: {
          manualRegistration: config.get('NODE_ENV') === 'test'
        }
      })
    }),
    ThrottlerModule.forRoot([
      {
        name: 'default',
        ttl: seconds(60),
        limit: 60
      }
    ]),
    PrismaModule,
    AuthModule,
    GitClientModule,
    LanguageModule,
    AnalysisApiModule,
    ...runtimeFeatureModules
  ],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_FILTER,
      useClass: GlobalExceptionFilter
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: ResponseTransformInterceptor
    },
    {
      provide: APP_GUARD,
      useClass: SessionAwareThrottlerGuard
    }
  ]
})
export class AppModule {}
