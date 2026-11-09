import { Injectable, OnModuleDestroy, OnModuleInit, Optional } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

import { ConfigService } from '../config/config.service';

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {
  private connected = false;

  constructor(@Optional() private readonly configService?: ConfigService) {
    super();
  }

  async onModuleInit(): Promise<void> {
    if (this.configService?.isTest()) {
      return;
    }

    await this.$connect();
    this.connected = true;
  }

  async onModuleDestroy(): Promise<void> {
    if (!this.connected && this.configService?.isTest()) {
      return;
    }

    await this.$disconnect();
    this.connected = false;
  }

  isConnected(): boolean {
    return this.connected;
  }
}
