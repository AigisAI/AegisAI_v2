import { Injectable, OnApplicationShutdown } from "@nestjs/common";
interface RedisShutdownClient {
  readonly isOpen: boolean;
  quit(): Promise<unknown>;
}

@Injectable()
export class RuntimeResourcesService implements OnApplicationShutdown {
  private readonly callbacks:Array<()=>Promise<void>>=[];

  registerShutdownCallback(callback:()=>Promise<void>):void { this.callbacks.push(callback); }

  private redisClient?: RedisShutdownClient;

  registerRedisClient(client: RedisShutdownClient): void {
    this.redisClient = client;
  }

  isRedisConnected(): boolean {
    return this.redisClient?.isOpen ?? false;
  }

  async onApplicationShutdown(): Promise<void> {
    try {
      if (this.redisClient?.isOpen) await this.redisClient.quit();
    } finally {
      await Promise.allSettled(this.callbacks.map(callback=>callback()));
    }
  }
}
