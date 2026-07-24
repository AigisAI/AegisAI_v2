import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit
} from '@nestjs/common';

import { ConfigService } from '../config/config.service';
import { SastScannerRuntimeStore } from './sast-scanner-runtime.store';

@Injectable()
export class SastAttemptReconciliationTask
  implements OnModuleInit, OnModuleDestroy
{
  private readonly logger = new Logger(SastAttemptReconciliationTask.name);
  private timer: NodeJS.Timeout | null = null;
  private reconciliationInFlight = false;

  constructor(
    private readonly store: SastScannerRuntimeStore,
    private readonly config: ConfigService
  ) {}

  onModuleInit(): void {
    if (this.config.isTest()) {
      return;
    }
    this.timer = setInterval(() => {
      if (this.reconciliationInFlight) {
        return;
      }
      this.reconciliationInFlight = true;
      void this.reconcileOverdueAttempts()
        .catch((error: unknown) => {
          this.logger.error(
            'Failed to reconcile overdue SAST sandbox attempts.',
            error as Error
          );
        })
        .finally(() => {
          this.reconciliationInFlight = false;
        });
    }, this.config.get('SAST_ATTEMPT_RECONCILIATION_INTERVAL_MS'));
    this.timer.unref?.();
  }

  onModuleDestroy(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  reconcileOverdueAttempts(referenceTime = new Date()): Promise<number> {
    return this.store.failOverdueAttempts(referenceTime.toISOString());
  }
}
