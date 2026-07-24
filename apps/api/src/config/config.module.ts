import { Global, Module } from '@nestjs/common';
import { ConfigModule as NestConfigModule } from '@nestjs/config';

import { ENV_FILE_PATHS } from './config.paths';
import { ENVIRONMENT_VALIDATION_SCHEMA } from './config.schema';
import { ConfigService } from './config.service';

export { ENVIRONMENT_VALIDATION_SCHEMA } from './config.schema';

@Global()
@Module({
  imports: [
    NestConfigModule.forRoot({
      isGlobal: true,
      envFilePath: ENV_FILE_PATHS,
      validationSchema: ENVIRONMENT_VALIDATION_SCHEMA
    })
  ],
  providers: [ConfigService],
  exports: [ConfigService]
})
export class ConfigModule {}
