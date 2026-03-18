import { Injectable } from '@nestjs/common';
import { ConfigService as NestConfigService } from '@nestjs/config';

import type { EnvironmentVariables } from './config.types';

type ConfigKey = keyof EnvironmentVariables;

@Injectable()
export class ConfigService {
  constructor(private readonly nestConfig: NestConfigService<EnvironmentVariables, true>) {}

  get<K extends ConfigKey>(key: K): EnvironmentVariables[K] {
    const value = this.nestConfig.get(key, { infer: true });

    if (value === undefined) {
      throw new Error(`Missing environment variable: ${String(key)}`);
    }

    return value;
  }

  getOptional<K extends ConfigKey>(key: K): EnvironmentVariables[K] | undefined {
    return this.nestConfig.get(key, { infer: true });
  }

  isProduction(): boolean {
    return this.get('NODE_ENV') === 'production';
  }

  isDevelopment(): boolean {
    return this.get('NODE_ENV') === 'development';
  }
}
