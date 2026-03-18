import { ConfigService } from '../../src/config/config.service';

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
});
