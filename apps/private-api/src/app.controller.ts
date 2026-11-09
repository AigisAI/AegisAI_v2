import { Controller, Get, ServiceUnavailableException } from "@nestjs/common";

import { AppService } from "./app.service";

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  getBootstrapState() {
    return this.appService.getBootstrapState();
  }

  @Get("health")
  getHealth() {
    const health = this.appService.getHealth();
    if (health.status !== "ok") {
      throw new ServiceUnavailableException(health);
    }

    return health;
  }
}
