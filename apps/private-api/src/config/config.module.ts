import { Global, Module } from "@nestjs/common";
import { ConfigModule as NestConfigModule } from "@nestjs/config";
import * as Joi from "joi";

import { ENV_FILE_PATHS } from "./config.paths";
import { ConfigService } from "./config.service";

export const ENVIRONMENT_VALIDATION_SCHEMA = Joi.object({
  RUNTIME_CATALOG_MODE: Joi.string().valid('regular','projected').default('regular'),
  GITHUB_APP_PRIVATE_KEY_PEM: Joi.string().allow("").optional(),
  AWS_REGION: Joi.string().allow("").optional(),
  AWS_AUTH_SECRET_ARN: Joi.string().allow("").optional(),
  AWS_SCM_SECRET_ARN: Joi.string().allow("").optional(),
  EVIDENCE_BUCKET: Joi.string().allow("").optional(),
  EVIDENCE_KMS_KEY_ARN: Joi.string().allow("").optional(),
  NODE_ENV: Joi.string().valid("development", "production", "test").default("development"),
  PORT: Joi.number().port().default(3000),
  DATABASE_URL: Joi.string().uri().required(),
  REDIS_URL: Joi.string().uri().required(),
  SESSION_SECRET: Joi.string().min(32).required(),
  CSRF_SECRET: Joi.string().min(32).required(),
  GITHUB_CLIENT_ID: Joi.string().required(),
  GITHUB_CLIENT_SECRET: Joi.string().required(),
  GITHUB_LOGIN_KIND: Joi.string().valid("oauth-app", "github-app").default("oauth-app"),
  GITHUB_APP_ID: Joi.string().pattern(/^[1-9][0-9]{0,15}$/).allow("").default(""),
  GITHUB_APP_SLUG: Joi.string().pattern(/^[a-z0-9][a-z0-9-]{0,99}$/).allow("").default(""),
  GITHUB_APP_PRIVATE_KEY_PATH: Joi.string().allow("").default(""),
  ALLOWED_GITHUB_USER_IDS: Joi.string().pattern(/^[1-9][0-9]*(,[1-9][0-9]*)*$/).when("NODE_ENV", {
    is: "production", then: Joi.required(), otherwise: Joi.allow("").default("")
  }),
  GITLAB_CLIENT_ID: Joi.string().required(),
  GITLAB_CLIENT_SECRET: Joi.string().required(),
  APP_URL: Joi.string().when("NODE_ENV", {
    is: "production",
    then: Joi.string().uri({ scheme: ["https"] }).required(),
    otherwise: Joi.string().uri().required()
  }),
  FRONTEND_URL: Joi.string().when("NODE_ENV", {
    is: "production",
    then: Joi.string().uri({ scheme: ["https"] }).required(),
    otherwise: Joi.string().uri().required()
  }),
  SESSION_COOKIE_NAME: Joi.string().default("connect.sid"),
  CSRF_COOKIE_NAME: Joi.string().default("csrf_token"),
  COOKIE_DOMAIN: Joi.string().allow("").optional(),
  COOKIE_SECURE: Joi.string().when("NODE_ENV", {
    is: "production",
    then: Joi.valid("true").required(),
    otherwise: Joi.valid("true", "false").default("false")
  }),
  SESSION_TTL_SECONDS: Joi.number().integer().min(900).max(86_400).default(28_800),
  THROTTLE_TTL_MS: Joi.number().integer().min(1000).max(3_600_000).default(60_000),
  THROTTLE_LIMIT: Joi.number().integer().min(1).max(10_000).default(120),
  TOKEN_ENCRYPTION_KEY: Joi.string().length(64).required(),
  ANALYSIS_CLIENT_MODE: Joi.string().valid("mock", "internal").default("mock"),
  AI_SERVER_URL: Joi.string().uri().default("http://localhost:8000"),
  USE_INTERNAL_AI: Joi.string().valid("true", "false").default("false"),
  INTERNAL_API_SECRET: Joi.string().min(32).required(),
  GITHUB_APP_WEBHOOK_SECRET: Joi.string().allow("").optional(),
  GITLAB_WEBHOOK_SECRET: Joi.string().allow("").optional(),
  REPORT_STORAGE_PATH: Joi.string().default("./tmp/reports"),
  REPORT_EXPIRY_HOURS: Joi.number().integer().positive().default(24)
});

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
