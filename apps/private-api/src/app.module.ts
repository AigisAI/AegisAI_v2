import { Module } from "@nestjs/common";
import { APP_GUARD } from "@nestjs/core";
import { ThrottlerGuard, ThrottlerModule } from "@nestjs/throttler";

import { AppController } from "./app.controller";
import { AppService } from "./app.service";
import { AuthModule } from "./auth/auth.module";
import { GlobalExceptionFilter } from "./common/filters/global-exception.filter";
import { SecurityModule } from "./common/security/security.module";
import { ConfigModule } from "./config/config.module";
import { ConfigService } from "./config/config.service";
import { ControlPlaneModule } from "./control-plane/control-plane.module";
import { ScanPlaneModule } from "./scan-plane/scan-plane.module";
import { TokenBrokerModule } from "./token-broker/token-broker.module";
import { PrismaModule } from "./prisma/prisma.module";
import { RuntimeModule } from "./runtime/runtime.module";
import { DispatchModule } from "./dispatch/dispatch.module";
import { createRuntimeThrottleStorage } from "./common/security/redis-throttler.storage";
import { RuntimeResourcesService } from "./runtime/runtime-resources.service";

@Module({
  imports: [
    ConfigModule,
    RuntimeModule,
    DispatchModule,
    PrismaModule,
    SecurityModule,
    ThrottlerModule.forRootAsync({
      imports: [ConfigModule, RuntimeModule],
      inject: [ConfigService, RuntimeResourcesService],
      useFactory: async (config: ConfigService, resources: RuntimeResourcesService) => ({
        storage: await createRuntimeThrottleStorage(config, resources),
        throttlers: [
        {
          ttl: config.get("THROTTLE_TTL_MS"),
          limit: config.get("THROTTLE_LIMIT")
        }
        ]
      })
    }),
    AuthModule,
    ControlPlaneModule,
    TokenBrokerModule,
    ScanPlaneModule
  ],
  controllers: [AppController],
  providers: [
    AppService,
    GlobalExceptionFilter,
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard
    }
  ]
})
export class AppModule {}
