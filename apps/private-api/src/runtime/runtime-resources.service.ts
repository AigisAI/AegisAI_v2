import { Injectable, OnApplicationShutdown } from "@nestjs/common";
interface RedisShutdownClient {
  readonly isOpen: boolean;
  quit(): Promise<unknown>;
}

@Injectable()
export class RuntimeResourcesService implements OnApplicationShutdown {
  private redisClient?: RedisShutdownClient;

  registerRedisClient(client: RedisShutdownClient): void {
    this.redisClient = client;
  }

  isRedisConnected(): boolean {
    return this.redisClient?.isOpen ?? false;
  }

  async onApplicationShutdown(): Promise<void> {
    if (this.redisClient?.isOpen) {
      await this.redisClient.quit();
    }
  }
}
