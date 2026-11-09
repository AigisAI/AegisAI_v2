const defaults: Record<string, string> = {
  NODE_ENV: "test",
  PORT: "3000",
  DATABASE_URL: "postgresql://postgres:postgres@localhost:5432/aegisai_test",
  REDIS_URL: "redis://localhost:6379/15",
  SESSION_SECRET: "test-session-secret-at-least-32-characters",
  CSRF_SECRET: "test-csrf-secret-at-least-32-characters-long",
  GITHUB_CLIENT_ID: "test-github-client-id",
  GITHUB_CLIENT_SECRET: "test-github-client-secret",
  ALLOWED_GITHUB_USER_IDS: "42",
  GITLAB_CLIENT_ID: "test-gitlab-client-id",
  GITLAB_CLIENT_SECRET: "test-gitlab-client-secret",
  APP_URL: "http://localhost:3000",
  FRONTEND_URL: "http://localhost:5173",
  SESSION_COOKIE_NAME: "aegisai_test_session",
  CSRF_COOKIE_NAME: "aegisai_test_csrf",
  COOKIE_DOMAIN: "",
  COOKIE_SECURE: "false",
  SESSION_TTL_SECONDS: "3600",
  THROTTLE_TTL_MS: "60000",
  THROTTLE_LIMIT: "1000",
  TOKEN_ENCRYPTION_KEY: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  ANALYSIS_CLIENT_MODE: "mock",
  AI_SERVER_URL: "http://localhost:8000",
  USE_INTERNAL_AI: "false",
  INTERNAL_API_SECRET: "test-internal-api-secret-at-least-32-characters",
  GITHUB_APP_WEBHOOK_SECRET: "",
  GITLAB_WEBHOOK_SECRET: "",
  REPORT_STORAGE_PATH: "./tmp/test-reports",
  REPORT_EXPIRY_HOURS: "24"
};

for (const [key, value] of Object.entries(defaults)) {
  process.env[key] ??= value;
}
