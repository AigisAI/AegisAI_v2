import { Injectable } from '@nestjs/common';
import { ConfigService as NestConfigService } from '@nestjs/config';

@Injectable()
export class ConfigService {
  constructor(private readonly nestConfig: NestConfigService) {}

  get(key: string): string {
    const value = this.nestConfig.get<string>(key);

    if (value === undefined) {
      throw new Error(`Missing environment variable: ${key}`);
    }

    return value;
  }

  getOptional(key: string): string | undefined {
    return this.nestConfig.get<string>(key);
  }

  isProduction(): boolean {
    return this.get('NODE_ENV') === 'production';
  }

  isDevelopment(): boolean {
    return this.get('NODE_ENV') === 'development';
  }
}
