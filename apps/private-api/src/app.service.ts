import { Injectable } from "@nestjs/common";

import { ConfigService } from "./config/config.service";
import { PrismaService } from "./prisma/prisma.service";
import { RuntimeResourcesService } from "./runtime/runtime-resources.service";

@Injectable()
export class AppService {
  constructor(
    private readonly config: ConfigService,
    private readonly prisma: PrismaService,
    private readonly resources: RuntimeResourcesService
  ) {}

  getBootstrapState() {
    return {
      docs: "specs/002-production-scan-architecture/quickstart.md",
      service: "api",
      status: "bootstrapped"
    };
  }

  getHealth() {
    const testMode = this.config.isTest();
    const database = testMode ? "skipped" : this.prisma.isConnected() ? "up" : "down";
    const sessionStore = testMode ? "memory" : this.resources.isRedisConnected() ? "up" : "down";
    const healthy = testMode || (database === "up" && sessionStore === "up");

    return {
      service: "api",
      status: healthy ? "ok" : "degraded",
      dependencies: {
        database,
        sessionStore
      }
    };
  }
}
