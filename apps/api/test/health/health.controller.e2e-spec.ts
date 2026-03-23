import { HealthController } from '../../src/health/health.controller';

describe('HealthController', () => {
  it('returns ok when database and redis are both healthy', async () => {
    const prisma = {
      $queryRawUnsafe: jest.fn().mockResolvedValue([{ result: 1 }])
    };
    const config = {
      get: jest.fn().mockImplementation((key: string) => {
        if (key === 'REDIS_URL') {
          return 'redis://localhost:6379';
        }

        throw new Error(`unexpected config key: ${key}`);
      })
    };
    const controller = new HealthController(prisma as never, config as never);

    jest
      .spyOn(controller as unknown as { checkRedis: () => Promise<'up' | 'down'> }, 'checkRedis')
      .mockResolvedValue('up');

    await expect(controller.getHealth()).resolves.toEqual({
      status: 'ok',
      uptime: expect.any(Number),
      services: {
        database: 'up',
        redis: 'up'
      },
      timestamp: expect.any(String)
    });
  });

  it('returns degraded when any dependency check fails', async () => {
    const prisma = {
      $queryRawUnsafe: jest.fn().mockRejectedValue(new Error('db down'))
    };
    const config = {
      get: jest.fn().mockReturnValue('redis://localhost:6379')
    };
    const controller = new HealthController(prisma as never, config as never);

    jest
      .spyOn(controller as unknown as { checkRedis: () => Promise<'up' | 'down'> }, 'checkRedis')
      .mockResolvedValue('down');

    await expect(controller.getHealth()).resolves.toEqual({
      status: 'degraded',
      uptime: expect.any(Number),
      services: {
        database: 'down',
        redis: 'down'
      },
      timestamp: expect.any(String)
    });
  });
});
