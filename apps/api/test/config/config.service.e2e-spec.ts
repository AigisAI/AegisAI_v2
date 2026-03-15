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
