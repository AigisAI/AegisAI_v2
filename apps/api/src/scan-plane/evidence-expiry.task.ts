import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from "@nestjs/common";

import { EvidenceObjectStorageService } from "./evidence-object-storage.service";
import { ScanPlaneService } from "./scan-plane.service";

const DEFAULT_EVIDENCE_EXPIRY_INTERVAL_MS = 15 * 60 * 1000;

function parseEvidenceExpiryInterval(): number {
  const rawValue = process.env.EVIDENCE_EXPIRY_INTERVAL_MS;
  const parsed = rawValue ? Number(rawValue) : DEFAULT_EVIDENCE_EXPIRY_INTERVAL_MS;

  if (!Number.isInteger(parsed) || parsed <= 0) {
    return DEFAULT_EVIDENCE_EXPIRY_INTERVAL_MS;
  }

  return parsed;
}

@Injectable()
export class EvidenceExpiryTask implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(EvidenceExpiryTask.name);
  private timer: NodeJS.Timeout | null = null;

  constructor(
    private readonly scanPlaneService: ScanPlaneService,
    private readonly storage: EvidenceObjectStorageService
  ) {}

  onModuleInit(): void {
    if (process.env.NODE_ENV === "test") {
      return;
    }

    this.timer = setInterval(() => {
      void this.deleteExpiredEvidence().catch((error: unknown) => {
        this.logger.error("Failed to delete expired evidence objects.", error as Error);
      });
    }, parseEvidenceExpiryInterval());
    this.timer.unref?.();
  }

  onModuleDestroy(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  async deleteExpiredEvidence(referenceTime = new Date()): Promise<void> {
    const expiredEvidencePacks = this.scanPlaneService.listExpiredEvidencePacks(referenceTime);

    for (const evidence of expiredEvidencePacks) {
      try {
        await this.storage.delete(evidence.objectKey);
        this.scanPlaneService.removeEvidencePack(evidence.id);
      } catch (error) {
        this.logger.error(
          `Failed to delete expired evidence object for evidence pack ${evidence.id}.`,
          error as Error
        );
      }
    }
  }
}
