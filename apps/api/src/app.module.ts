import { Module } from "@nestjs/common";

import { AppController } from "./app.controller";
import { AppService } from "./app.service";
import { GlobalExceptionFilter } from "./common/filters/global-exception.filter";
import { ControlPlaneModule } from "./control-plane/control-plane.module";
import { TokenBrokerModule } from "./token-broker/token-broker.module";

@Module({
  imports: [ControlPlaneModule, TokenBrokerModule],
  controllers: [AppController],
  providers: [AppService, GlobalExceptionFilter]
})
export class AppModule {}
