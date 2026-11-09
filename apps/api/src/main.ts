import { NestFactory } from "@nestjs/core";
import type { NestExpressApplication } from "@nestjs/platform-express";

import { loadRuntimeSecrets } from "./data-security/runtime-secrets";
import { configureApplication } from "./bootstrap/configure-application";
import { ConfigService } from "./config/config.service";

async function bootstrap() {
  await loadRuntimeSecrets("api");
  const {AppModule}=await import("./app.module");
  const app = await NestFactory.create<NestExpressApplication>(AppModule);

  await configureApplication(app);

  await app.listen(app.get(ConfigService).get("PORT"));
}

void bootstrap().catch(()=>{process.stderr.write("RUNTIME_START_FAILED\n");process.exit(1);});
