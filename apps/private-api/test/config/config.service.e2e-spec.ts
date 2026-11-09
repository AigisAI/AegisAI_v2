import { ConfigService } from '../../src/config/config.service';
import { ENVIRONMENT_VALIDATION_SCHEMA } from '../../src/config/config.module';

describe('ConfigService', () => {
  it('returns a required value', () => {
    const service = new ConfigService({
      get: (key: string) => {
        const values: Record<string, string> = {
          DATABASE_URL: 'postgresql://postgres:postgres@localhost:5432/aegisai',
          NODE_ENV: 'development'
        };

        return values[key];
      }
    } as never);

    expect(service.get('DATABASE_URL')).toBe('postgresql://postgres:postgres@localhost:5432/aegisai');
  });

  it('returns validated numeric values with their real types', () => {
    const service = new ConfigService({
      get: (key: string) => {
        const values: Record<string, unknown> = {
          PORT: 3000,
          REPORT_EXPIRY_HOURS: 24
        };

        return values[key];
      }
    } as never);

    expect(service.get('PORT')).toBe(3000);
    expect(typeof service.get('PORT')).toBe('number');
    expect(service.getOptional('REPORT_EXPIRY_HOURS')).toBe(24);
  });

  it('throws when a required value is missing', () => {
    const service = new ConfigService({
      get: () => undefined
    } as never);

    expect(() => service.get('DATABASE_URL')).toThrow('Missing environment variable: DATABASE_URL');
  });

  it('reports development and production modes from NODE_ENV', () => {
    const development = new ConfigService({
      get: (key: string) => (key === 'NODE_ENV' ? 'development' : undefined)
    } as never);
    const production = new ConfigService({
      get: (key: string) => (key === 'NODE_ENV' ? 'production' : undefined)
    } as never);

    expect(development.isDevelopment()).toBe(true);
    expect(development.isProduction()).toBe(false);
    expect(production.isProduction()).toBe(true);
    expect(production.isDevelopment()).toBe(false);
  });

  it('fails closed on insecure production origins or cookies', () => {
    const base = {
      NODE_ENV: 'production',
      DATABASE_URL: 'postgresql://postgres:postgres@localhost:5432/aegisai',
      REDIS_URL: 'redis://localhost:6379',
      SESSION_SECRET: 'session-secret-at-least-thirty-two-characters',
      CSRF_SECRET: 'csrf-secret-at-least-thirty-two-characters-long',
      GITHUB_CLIENT_ID: 'github-client-id',
      GITHUB_CLIENT_SECRET: 'github-client-secret',
      ALLOWED_GITHUB_USER_IDS: '42',
      GITLAB_CLIENT_ID: 'gitlab-client-id',
      GITLAB_CLIENT_SECRET: 'gitlab-client-secret',
      APP_URL: 'https://aegis.example',
      FRONTEND_URL: 'https://aegis.example',
      TOKEN_ENCRYPTION_KEY: 'a'.repeat(64),
      INTERNAL_API_SECRET: 'internal-secret-at-least-thirty-two-characters',
      COOKIE_SECURE: 'true'
    };

    expect(ENVIRONMENT_VALIDATION_SCHEMA.validate(base).error).toBeUndefined();
    expect(ENVIRONMENT_VALIDATION_SCHEMA.validate({ ...base, ALLOWED_GITHUB_USER_IDS: '' }).error).toBeDefined();
    expect(
      ENVIRONMENT_VALIDATION_SCHEMA.validate({ ...base, COOKIE_SECURE: 'false' }).error
    ).toBeDefined();
    expect(
      ENVIRONMENT_VALIDATION_SCHEMA.validate({ ...base, APP_URL: 'http://aegis.example' }).error
    ).toBeDefined();
  });
});
