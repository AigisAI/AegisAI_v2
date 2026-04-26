import { NestFactory } from "@nestjs/core";

import { AppModule } from "./app.module";
import { GlobalExceptionFilter } from "./common/filters/global-exception.filter";

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.setGlobalPrefix("api");
  app.useGlobalFilters(app.get(GlobalExceptionFilter));

  await app.listen(process.env.PORT ? Number(process.env.PORT) : 3000);
}

void bootstrap();
