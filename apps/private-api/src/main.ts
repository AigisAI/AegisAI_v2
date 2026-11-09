import { startRuntimeTelemetry } from "./runtime/observability";
import { assertPrivateDatabase } from "./data-security/private-profile";
import { NestFactory } from "@nestjs/core";
import type { NestExpressApplication } from "@nestjs/platform-express";

import { loadRuntimeSecrets } from "./data-security/runtime-secrets";
import { configureApplication } from "./bootstrap/configure-application";
import { ConfigService } from "./config/config.service";

async function bootstrap() {
  const telemetry = await startRuntimeTelemetry();
  await loadRuntimeSecrets("api");
  await assertPrivateDatabase();
  const {AppModule}=await import("./app.module");
  const app = await NestFactory.create<NestExpressApplication>(AppModule);

  await configureApplication(app, telemetry);

  await app.listen(app.get(ConfigService).get("PORT"));
}

void bootstrap().catch(()=>{process.stderr.write("RUNTIME_START_FAILED\n");process.exit(1);});
