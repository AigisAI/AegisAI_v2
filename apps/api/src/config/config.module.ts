import { Module } from '@nestjs/common';
import { ConfigModule as NestConfigModule } from '@nestjs/config';
import * as Joi from 'joi';

import { ConfigService } from './config.service';

@Module({
  imports: [
    NestConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
      validationSchema: Joi.object({
        NODE_ENV: Joi.string().valid('development', 'production', 'test').default('development'),
        PORT: Joi.number().port().default(3000),
        DATABASE_URL: Joi.string().uri().required(),
        REDIS_URL: Joi.string().uri().required(),
        SESSION_SECRET: Joi.string().min(16).required(),
        CSRF_SECRET: Joi.string().min(16).required(),
        GITHUB_CLIENT_ID: Joi.string().required(),
        GITHUB_CLIENT_SECRET: Joi.string().required(),
        GITLAB_CLIENT_ID: Joi.string().required(),
        GITLAB_CLIENT_SECRET: Joi.string().required(),
        APP_URL: Joi.string().uri().required(),
        FRONTEND_URL: Joi.string().uri().required(),
        SESSION_COOKIE_NAME: Joi.string().default('connect.sid'),
        CSRF_COOKIE_NAME: Joi.string().default('csrf_token'),
        COOKIE_DOMAIN: Joi.string().allow('').optional(),
        TOKEN_ENCRYPTION_KEY: Joi.string().length(64).required(),
        ANALYSIS_CLIENT_MODE: Joi.string().valid('mock', 'internal').default('mock'),
        AI_SERVER_URL: Joi.string().uri().default('http://localhost:8000'),
        USE_INTERNAL_AI: Joi.string().valid('true', 'false').default('false'),
        INTERNAL_API_SECRET: Joi.string().allow('').optional(),
        GITHUB_APP_WEBHOOK_SECRET: Joi.string().allow('').optional(),
        GITLAB_WEBHOOK_SECRET: Joi.string().allow('').optional(),
        REPORT_STORAGE_PATH: Joi.string().default('./tmp/reports'),
        REPORT_EXPIRY_HOURS: Joi.number().integer().positive().default(24)
      })
    })
  ],
  providers: [ConfigService],
  exports: [ConfigService]
})
export class ConfigModule {}
