import { Module } from "@nestjs/common";

import { ConfigModule } from "../config/config.module";
import { AuthController } from "./auth.controller";
import { AuthService } from "./auth.service";
import { IdentityStoreService } from "./identity-store.service";

@Module({
  imports: [ConfigModule],
  controllers: [AuthController],
  providers: [AuthService, IdentityStoreService],
  exports: [AuthService]
})
export class AuthModule {}
