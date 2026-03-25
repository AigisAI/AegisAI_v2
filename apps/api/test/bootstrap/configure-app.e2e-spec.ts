import type { INestApplication } from '@nestjs/common';
import type { RedisClientType } from 'redis';

import { configureApp } from '../../src/bootstrap/configure-app';
import { ConfigService } from '../../src/config/config.service';

jest.mock('redis', () => ({
  createClient: jest.fn()
}));

describe('configureApp', () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  it('disconnects the Redis-backed session client when the app closes', async () => {
    const redisClient = createRedisClientMock();
    const { createClient } = jest.requireMock('redis') as {
      createClient: jest.Mock;
    };

    createClient.mockReturnValue(redisClient);

    const closeSpy = jest.fn().mockResolvedValue(undefined);
    const app = createAppMock({
      get: jest.fn().mockImplementation((token: unknown) => {
        if (token === ConfigService) {
          return createConfigServiceMock({ nodeEnv: 'development' });
        }

        throw new Error(`Unexpected provider token: ${String(token)}`);
      }),
      close: closeSpy
    });

    await configureApp(app as never);
    await app.close();

    expect(redisClient.connect).toHaveBeenCalledTimes(1);
    expect(redisClient.disconnect).toHaveBeenCalledTimes(1);
    expect(closeSpy).toHaveBeenCalledTimes(1);
  });

  it('does not create a Redis session client outside runtime environments', async () => {
    const { createClient } = jest.requireMock('redis') as {
      createClient: jest.Mock;
    };
    const app = createAppMock({
      get: jest.fn().mockImplementation((token: unknown) => {
        if (token === ConfigService) {
          return createConfigServiceMock({ nodeEnv: 'test' });
        }

        throw new Error(`Unexpected provider token: ${String(token)}`);
      })
    });

    await configureApp(app as never);

    expect(createClient).not.toHaveBeenCalled();
  });
});

function createAppMock(overrides: Partial<INestApplication> = {}): INestApplication {
  const httpAdapter = {
    getInstance: () => ({
      set: jest.fn()
    })
  };

  return {
    get: jest.fn(),
    getHttpAdapter: jest.fn(() => httpAdapter),
    setGlobalPrefix: jest.fn(),
    use: jest.fn(),
    close: jest.fn().mockResolvedValue(undefined),
    ...overrides
  } as unknown as INestApplication;
}

function createConfigServiceMock({
  nodeEnv
}: {
  nodeEnv: 'development' | 'production' | 'test';
}) {
  return {
    get: jest.fn((key: string) => {
      const values: Record<string, string> = {
        SESSION_COOKIE_NAME: 'connect.sid',
        SESSION_SECRET: 'session-secret',
        REDIS_URL: 'redis://localhost:6379'
      };

      return values[key];
    }),
    getOptional: jest.fn().mockReturnValue(null),
    isDevelopment: jest.fn().mockReturnValue(nodeEnv === 'development'),
    isProduction: jest.fn().mockReturnValue(nodeEnv === 'production')
  };
}

function createRedisClientMock(): Pick<RedisClientType, 'connect' | 'disconnect' | 'isOpen'> {
  return {
    connect: jest.fn().mockResolvedValue(undefined),
    disconnect: jest.fn().mockResolvedValue(undefined),
    isOpen: true
  };
}
