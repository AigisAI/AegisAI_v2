import { Module } from "@nestjs/common";

import { AppController } from "./app.controller";
import { AppService } from "./app.service";
import { AuthModule } from "./auth/auth.module";
import { GitClientModule } from "./client/git/git-client.module";
import { ConfigModule } from "./config/config.module";
import { PrismaModule } from "./prisma/prisma.module";

@Module({
  imports: [ConfigModule, PrismaModule, AuthModule, GitClientModule],
  controllers: [AppController],
  providers: [AppService]
})
export class AppModule {}
