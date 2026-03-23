import { Injectable } from '@nestjs/common';
import { ScanStatus } from '@prisma/client';

import { PrismaService } from '../prisma/prisma.service';
import { SCAN_ACTIVE_TIMEOUT_MS } from './scan.constants';

@Injectable()
export class StuckScanRecoveryTask {
  constructor(private readonly prisma: PrismaService) {}

  async recover(now: Date = new Date()): Promise<number> {
    const result = await this.prisma.scan.updateMany({
      where: {
        status: { in: [ScanStatus.PENDING, ScanStatus.RUNNING] },
        updatedAt: { lt: new Date(now.getTime() - SCAN_ACTIVE_TIMEOUT_MS) }
      },
      data: {
        status: ScanStatus.FAILED,
        errorMessage: 'Scan recovery marked this scan as failed after exceeding the active timeout.',
        completedAt: now
      }
    });

    return result.count;
  }
}
