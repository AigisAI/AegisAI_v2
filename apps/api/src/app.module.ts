import { Module } from "@nestjs/common";

import { AppController } from "./app.controller";
import { AppService } from "./app.service";
import { GlobalExceptionFilter } from "./common/filters/global-exception.filter";
import { ControlPlaneModule } from "./control-plane/control-plane.module";
import { ScanPlaneModule } from "./scan-plane/scan-plane.module";
import { TokenBrokerModule } from "./token-broker/token-broker.module";

@Module({
  imports: [ControlPlaneModule, TokenBrokerModule, ScanPlaneModule],
  controllers: [AppController],
  providers: [AppService, GlobalExceptionFilter]
})
export class AppModule {}
