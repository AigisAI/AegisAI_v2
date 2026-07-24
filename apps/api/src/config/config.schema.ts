import * as Joi from 'joi';

export const ENVIRONMENT_VALIDATION_SCHEMA = Joi.object({
  NODE_ENV: Joi.string().valid('development', 'production', 'test').default('development'),
  PORT: Joi.number().port().default(3000),
  DATABASE_URL: Joi.string().uri().required(),
  REDIS_URL: Joi.string().uri().required(),
  SESSION_SECRET: Joi.string().min(32).required(),
  CSRF_SECRET: Joi.string().min(32).required(),
  GITHUB_CLIENT_ID: Joi.string().required(),
  GITHUB_CLIENT_SECRET: Joi.string().required(),
  GITHUB_APP_ID: Joi.string().allow('').default(''),
  GITHUB_APP_PRIVATE_KEY: Joi.string().allow('').default(''),
  GITLAB_CLIENT_ID: Joi.string().required(),
  GITLAB_CLIENT_SECRET: Joi.string().required(),
  GITLAB_API_BASE_URL: Joi.string().uri().default('https://gitlab.com/api/v4'),
  APP_URL: Joi.string().when('NODE_ENV', {
    is: 'production',
    then: Joi.string().uri({ scheme: ['https'] }).required(),
    otherwise: Joi.string().uri().required()
  }),
  FRONTEND_URL: Joi.string().when('NODE_ENV', {
    is: 'production',
    then: Joi.string().uri({ scheme: ['https'] }).required(),
    otherwise: Joi.string().uri().required()
  }),
  SESSION_COOKIE_NAME: Joi.string().default('connect.sid'),
  CSRF_COOKIE_NAME: Joi.string().default('csrf_token'),
  COOKIE_DOMAIN: Joi.string().allow('').optional(),
  COOKIE_SECURE: Joi.string().when('NODE_ENV', {
    is: 'production',
    then: Joi.valid('true').required(),
    otherwise: Joi.valid('true', 'false').default('false')
  }),
  SESSION_TTL_SECONDS: Joi.number().integer().min(900).max(86_400).default(28_800),
  THROTTLE_TTL_MS: Joi.number().integer().min(1_000).max(3_600_000).default(60_000),
  THROTTLE_LIMIT: Joi.number().integer().min(1).max(10_000).default(120),
  TOKEN_ENCRYPTION_KEY: Joi.string().length(64).required(),
  WORKLOAD_ATTESTATION_KEY: Joi.when('NODE_ENV', {
    is: 'production',
    then: Joi.string()
      .hex()
      .length(64)
      .lowercase()
      .invalid(Joi.ref('TOKEN_ENCRYPTION_KEY'))
      .required(),
    otherwise: Joi.string()
      .hex()
      .length(64)
      .lowercase()
      .invalid(Joi.ref('TOKEN_ENCRYPTION_KEY'))
      .default('a'.repeat(64))
  }),
  PREFLIGHT_ATTESTATION_KEY: Joi.when('NODE_ENV', {
    is: 'production',
    then: Joi.string()
      .hex()
      .length(64)
      .lowercase()
      .invalid(Joi.ref('TOKEN_ENCRYPTION_KEY'))
      .invalid(Joi.ref('WORKLOAD_ATTESTATION_KEY'))
      .required(),
    otherwise: Joi.string()
      .hex()
      .length(64)
      .lowercase()
      .invalid(Joi.ref('TOKEN_ENCRYPTION_KEY'))
      .invalid(Joi.ref('WORKLOAD_ATTESTATION_KEY'))
      .default('b'.repeat(64))
  }),
  ANALYSIS_CLIENT_MODE: Joi.string().valid('mock', 'internal').default('mock'),
  AI_SERVER_URL: Joi.string().uri().default('http://localhost:8000'),
  USE_INTERNAL_AI: Joi.string().valid('true', 'false').default('false'),
  AI_ADVISORY_TIMEOUT_MS: Joi.number().integer().positive().default(2500),
  INTERNAL_API_SECRET: Joi.when('NODE_ENV', {
    is: 'production',
    then: Joi.string().min(32).required(),
    otherwise: Joi.string().allow('').default('')
  }),
  GITHUB_APP_WEBHOOK_SECRET: Joi.when('NODE_ENV', {
    is: 'production',
    then: Joi.string().min(32).required(),
    otherwise: Joi.string().allow('').default('')
  }),
  GITLAB_WEBHOOK_SECRET: Joi.when('NODE_ENV', {
    is: 'production',
    then: Joi.string().min(32).required(),
    otherwise: Joi.string().allow('').default('')
  }),
  REPORT_STORAGE_PATH: Joi.string().default('./tmp/reports'),
  REPORT_EXPIRY_HOURS: Joi.number().integer().positive().default(24),
  REPORT_EXPIRY_INTERVAL_MS: Joi.number().integer().positive().default(15 * 60 * 1000),
  EVIDENCE_STORAGE_PATH: Joi.string().default('./tmp/evidence'),
  EVIDENCE_EXPIRY_INTERVAL_MS: Joi.number().integer().positive().default(15 * 60 * 1000),
  TEAMS_WEBHOOK_URL: Joi.string().uri().allow('').optional()
});
