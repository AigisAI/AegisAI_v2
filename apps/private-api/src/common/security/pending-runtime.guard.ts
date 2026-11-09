import { CanActivate, Injectable, ServiceUnavailableException } from "@nestjs/common";

import { ConfigService } from "../../config/config.service";

@Injectable()
export class PendingRuntimeGuard implements CanActivate {
  constructor(private readonly config: ConfigService) {}

  canActivate(): boolean {
    if (this.config.isProduction()) {
      throw new ServiceUnavailableException({
        errorCode: "PRODUCTION_RUNTIME_NOT_READY",
        message: "This operation requires a verified production runtime."
      });
    }
    return true;
  }
}
