export type NodeEnv = 'development' | 'production' | 'test';
export type AnalysisClientMode = 'mock' | 'internal';
export type BooleanString = 'true' | 'false';

export interface EnvironmentVariables {
  NODE_ENV: NodeEnv;
  PORT: number;
  DATABASE_URL: string;
  REDIS_URL: string;
  SESSION_SECRET: string;
  CSRF_SECRET: string;
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;
  GITLAB_CLIENT_ID: string;
  GITLAB_CLIENT_SECRET: string;
  APP_URL: string;
  FRONTEND_URL: string;
  SESSION_COOKIE_NAME: string;
  CSRF_COOKIE_NAME: string;
  COOKIE_DOMAIN: string;
  TOKEN_ENCRYPTION_KEY: string;
  ANALYSIS_CLIENT_MODE: AnalysisClientMode;
  AI_SERVER_URL: string;
  USE_INTERNAL_AI: BooleanString;
  INTERNAL_API_SECRET: string;
  GITHUB_APP_WEBHOOK_SECRET: string;
  GITLAB_WEBHOOK_SECRET: string;
  REPORT_STORAGE_PATH: string;
  REPORT_EXPIRY_HOURS: number;
  TEAMS_WEBHOOK_URL: string;
}
