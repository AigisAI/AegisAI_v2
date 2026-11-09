import { Global, Module } from "@nestjs/common";

import { ConfigModule } from "../../config/config.module";
import { InternalServiceGuard } from "./internal-service.guard";
import { SessionAuthGuard } from "./session-auth.guard";
import { PendingRuntimeGuard } from "./pending-runtime.guard";

@Global()
@Module({
  imports: [ConfigModule],
  providers: [InternalServiceGuard, SessionAuthGuard, PendingRuntimeGuard],
  exports: [InternalServiceGuard, SessionAuthGuard, PendingRuntimeGuard]
})
export class SecurityModule {}
