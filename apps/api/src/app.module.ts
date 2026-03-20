import { Module } from "@nestjs/common";

import { AppController } from "./app.controller";
import { AppService } from "./app.service";
import { AuthModule } from "./auth/auth.module";
import { AnalysisApiModule } from "./client/analysis/analysis-api.module";
import { GitClientModule } from "./client/git/git-client.module";
import { ConfigModule } from "./config/config.module";
import { LanguageModule } from "./language/language.module";
import { PrismaModule } from "./prisma/prisma.module";

@Module({
  imports: [ConfigModule, PrismaModule, AuthModule, GitClientModule, LanguageModule, AnalysisApiModule],
  controllers: [AppController],
  providers: [AppService]
})
export class AppModule {}
