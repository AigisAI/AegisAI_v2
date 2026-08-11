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

const EVIDENCE_DELETION_DISCOVERY_INTERVAL_MILLISECONDS = 60_000;
const EVIDENCE_DELETION_ERROR_RETRY_MILLISECONDS = 1_000;
const MAXIMUM_DELETIONS_PER_BATCH = 64;
const MAXIMUM_BACKFILLS_PER_BATCH = 128;

@Injectable()
export class SastEvidenceDeletionTask
  implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(
    SastEvidenceDeletionTask.name
  );
  private readonly workerId = createSastEvidenceDeletionWorkerId();
  private timer: NodeJS.Timeout | null = null;
  private inFlight = false;
  private started = false;
  private batchSaturated = false;

  constructor(
    private readonly service: SastEvidenceDeletionService,
    private readonly config: ConfigService
  ) {}

  onModuleInit(): void {
    if (this.config.isTest()) return;
    this.started = true;
    this.schedule(0);
  }

  onModuleDestroy(): void {
    this.started = false;
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
  }

  async processBatch(referenceTime?: Date): Promise<number> {
    const startedAt = referenceTime ?? new Date();
    const backfilled = await this.service.backfill(
      startedAt,
      MAXIMUM_BACKFILLS_PER_BATCH
    );
    let processed = 0;
    let attempted = 0;
    let reachedIdle = false;
    for (
      let index = 0;
      index < MAXIMUM_DELETIONS_PER_BATCH;
      index += 1
    ) {
      const result = await this.service.processNext(
        referenceTime ?? new Date(),
        this.workerId
      );
      attempted += 1;
      if (result === 'IDLE') {
        reachedIdle = true;
        break;
      }
      if (result !== 'LEASE_LOST') processed += 1;
    }
    this.batchSaturated =
      backfilled === MAXIMUM_BACKFILLS_PER_BATCH ||
      (!reachedIdle && attempted === MAXIMUM_DELETIONS_PER_BATCH);
    return processed;
  }

  private schedule(delayMilliseconds: number): void {
    if (!this.started) return;
    this.timer = setTimeout(() => {
      this.timer = null;
      void this.runScheduled();
    }, delayMilliseconds);
    this.timer.unref?.();
  }

  private async runScheduled(): Promise<void> {
    if (this.inFlight) {
      this.schedule(0);
      return;
    }
    this.inFlight = true;
    let nextDelay = EVIDENCE_DELETION_ERROR_RETRY_MILLISECONDS;
    try {
      await this.processBatch();
      if (this.batchSaturated) {
        nextDelay = 0;
      } else {
        const nextDueAt = await this.service.nextDueAt();
        nextDelay = nextDueAt
          ? Math.max(
              0,
              Math.min(
                EVIDENCE_DELETION_DISCOVERY_INTERVAL_MILLISECONDS,
                nextDueAt.getTime() - Date.now()
              )
            )
          : EVIDENCE_DELETION_DISCOVERY_INTERVAL_MILLISECONDS;
      }
    } catch (error) {
      this.logger.error(
        'Failed to process bounded evidence deletion.',
        error instanceof Error ? error.name : 'UnknownError'
      );
    } finally {
      this.inFlight = false;
      this.schedule(nextDelay);
    }
  }
}
