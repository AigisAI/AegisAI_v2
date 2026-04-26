import { Controller, Get } from '@nestjs/common';
import { createClient } from 'redis';

import { SkipTransform } from '../common/decorators/skip-transform.decorator';
import { ConfigService } from '../config/config.service';
import { PrismaService } from '../prisma/prisma.service';

type DependencyStatus = 'up' | 'down';

@Controller('health')
export class HealthController {
  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService
  ) {}

  @Get()
  @SkipTransform()
  async getHealth() {
    const [database, redis] = await Promise.all([this.checkDatabase(), this.checkRedis()]);

    return {
      status: database === 'up' && redis === 'up' ? 'ok' : 'degraded',
      uptime: process.uptime(),
      services: {
        database,
        redis
      },
      timestamp: new Date().toISOString()
    };
  }

  protected async checkDatabase(): Promise<DependencyStatus> {
    try {
      await this.prisma.$queryRawUnsafe('SELECT 1');
      return 'up';
    } catch {
      return 'down';
    }
  }

  protected async checkRedis(): Promise<DependencyStatus> {
    const client = createClient({
      url: this.config.get('REDIS_URL')
    });

    try {
      await client.connect();
      await client.ping();
      return 'up';
    } catch {
      return 'down';
    } finally {
      if (client.isOpen) {
        await client.disconnect();
      }
    }
  }
}
