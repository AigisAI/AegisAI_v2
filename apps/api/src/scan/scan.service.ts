import type { ScanRequestResponse } from '@aegisai/shared';
import { InjectQueue } from '@nestjs/bullmq';
import { ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { ScanStatus } from '@prisma/client';
import type { Queue } from 'bullmq';

import { PrismaService } from '../prisma/prisma.service';
import { SCAN_PROCESS_JOB, SCAN_QUEUE } from './scan.constants';

interface CreateScanInput {
  userId: string;
  connectedRepoId: string;
  branch: string;
  language?: string;
}

@Injectable()
export class ScanService {
  constructor(
    private readonly prisma: PrismaService,
    @InjectQueue(SCAN_QUEUE) private readonly scanQueue: Queue
  ) {}

  async createScan(input: CreateScanInput): Promise<ScanRequestResponse> {
    const connectedRepo = await this.prisma.connectedRepo.findFirst({
      where: {
        id: input.connectedRepoId,
        userId: input.userId
      }
    });

    if (!connectedRepo) {
      throw new NotFoundException('Connected repository not found');
    }

    const existingScan = await this.prisma.scan.findFirst({
      where: {
        connectedRepoId: input.connectedRepoId,
        branch: input.branch,
        status: { in: [ScanStatus.PENDING, ScanStatus.RUNNING] }
      }
    });

    if (existingScan) {
      throw new ConflictException('An active scan already exists for this repository branch');
    }

    const scan = await this.prisma.scan.create({
      data: {
        connectedRepoId: input.connectedRepoId,
        branch: input.branch,
        language: input.language ?? 'java',
        status: ScanStatus.PENDING
      }
    });

    await this.scanQueue.add(SCAN_PROCESS_JOB, { scanId: scan.id }, { jobId: scan.id });

    return {
      scanId: scan.id,
      status: 'PENDING',
      message: 'Scan queued successfully.'
    };
  }
}
