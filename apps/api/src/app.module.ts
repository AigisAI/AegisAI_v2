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
import { DashboardModule } from './dashboard/dashboard.module';
import { HealthModule } from './health/health.module';
import { LanguageModule } from './language/language.module';
import { ObservabilityModule } from './observability/observability.module';
import { PrismaModule } from './prisma/prisma.module';
import { ReportModule } from './report/report.module';
import { RepoModule } from './repo/repo.module';
import { ScanModule } from './scan/scan.module';
import { VulnerabilityModule } from './vulnerability/vulnerability.module';

const runtimeFeatureModules = [ScanModule, HealthModule, ReportModule];

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
    RepoModule,
    DashboardModule,
    VulnerabilityModule,
    GitClientModule,
    LanguageModule,
    AnalysisApiModule,
    ObservabilityModule,
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
