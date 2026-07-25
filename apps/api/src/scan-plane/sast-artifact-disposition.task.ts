import { randomUUID } from 'node:crypto';

import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit
} from '@nestjs/common';

import { ConfigService } from '../config/config.service';
import { SastArtifactDispositionService } from './sast-artifact-disposition.service';

const MAXIMUM_DISPOSITIONS_PER_TICK = 16;

@Injectable()
export class SastArtifactDispositionTask
  implements OnModuleInit, OnModuleDestroy
{
  private readonly logger = new Logger(
    SastArtifactDispositionTask.name
  );
  private readonly workerId = `artifact-disposition:${randomUUID()}`;
  private timer: NodeJS.Timeout | null = null;
  private inFlight = false;

  constructor(
    private readonly service: SastArtifactDispositionService,
    private readonly config: ConfigService
  ) {}

  onModuleInit(): void {
    if (this.config.isTest()) return;

    this.timer = setInterval(() => {
      if (this.inFlight) return;
      this.inFlight = true;
      void this.processBatch()
        .catch((error: unknown) => {
          this.logger.error(
            'Failed to process SAST artifact dispositions.',
            error instanceof Error ? error.name : 'UnknownError'
          );
        })
        .finally(() => {
          this.inFlight = false;
        });
    }, this.config.get('SAST_ARTIFACT_DISPOSITION_INTERVAL_MS'));
    this.timer.unref?.();
  }

  onModuleDestroy(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  async processBatch(referenceTime?: Date): Promise<number> {
    let processed = 0;
    for (
      let index = 0;
      index < MAXIMUM_DISPOSITIONS_PER_TICK;
      index += 1
    ) {
      const result = await this.service.processNext(
        referenceTime ?? new Date(),
        this.workerId
      );
      if (result === 'IDLE') break;
      if (result !== 'LEASE_LOST') processed += 1;
    }
    return processed;
  }
}
