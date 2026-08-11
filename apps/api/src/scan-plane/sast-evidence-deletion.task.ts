import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit
} from '@nestjs/common';

import { ConfigService } from '../config/config.service';
import {
  SastEvidenceDeletionService,
  createSastEvidenceDeletionWorkerId
} from './sast-evidence-deletion.service';

const EVIDENCE_DELETION_INTERVAL_MILLISECONDS = 15 * 60 * 1000;
const MAXIMUM_DELETIONS_PER_TICK = 16;
const MAXIMUM_BACKFILLS_PER_TICK = 32;

@Injectable()
export class SastEvidenceDeletionTask
  implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(
    SastEvidenceDeletionTask.name
  );
  private readonly workerId = createSastEvidenceDeletionWorkerId();
  private timer: NodeJS.Timeout | null = null;
  private inFlight = false;

  constructor(
    private readonly service: SastEvidenceDeletionService,
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
            'Failed to process bounded evidence deletion.',
            error instanceof Error ? error.name : 'UnknownError'
          );
        })
        .finally(() => {
          this.inFlight = false;
        });
    }, EVIDENCE_DELETION_INTERVAL_MILLISECONDS);
    this.timer.unref?.();
  }

  onModuleDestroy(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  async processBatch(referenceTime = new Date()): Promise<number> {
    await this.service.backfill(
      referenceTime,
      MAXIMUM_BACKFILLS_PER_TICK
    );
    let processed = 0;
    for (
      let index = 0;
      index < MAXIMUM_DELETIONS_PER_TICK;
      index += 1
    ) {
      const result = await this.service.processNext(
        referenceTime,
        this.workerId
      );
      if (result === 'IDLE') break;
      if (result !== 'LEASE_LOST') processed += 1;
    }
    return processed;
  }
}
