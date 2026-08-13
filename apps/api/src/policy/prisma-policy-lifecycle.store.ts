import type {
  Suppression,
  SuppressionCreateInput,
  Waiver,
  WaiverCreateInput,
  WaiverUpdateInput
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';
import type { Prisma } from '@prisma/client';

import { PrismaService } from '../prisma/prisma.service';
import { PolicyLifecycleStore } from './policy-lifecycle.store';

interface WaiverRow {
  id: string;
  tenantId: string;
  owner: string;
  reason: string;
  scope: string;
  expiresAt: Date;
  lastReviewedAt: Date | null;
}

interface SuppressionRow {
  id: string;
  tenantId: string;
  scanRequestId: string;
  findingId: string | null;
  reason: Suppression['reason'];
}

@Injectable()
export class PrismaPolicyLifecycleStore extends PolicyLifecycleStore {
  constructor(private readonly prisma: PrismaService) {
    super();
  }

  async createWaiver(
    input: Readonly<WaiverCreateInput>
  ): Promise<Waiver> {
    const row = await this.prisma.waiver.create({
      data: {
        tenantId: input.tenantId,
        owner: input.owner,
        reason: input.reason,
        scope: input.scope,
        expiresAt: new Date(input.expiresAt)
      }
    });
    return waiverFromRow(row);
  }

  async updateWaiver(
    waiverId: string,
    input: Readonly<WaiverUpdateInput>
  ): Promise<Waiver | null> {
    return this.prisma.$transaction(
      async (tx: Prisma.TransactionClient) => {
        const existing = await tx.waiver.findFirst({
          where: { id: waiverId, tenantId: input.tenantId },
          select: { id: true }
        });
        if (!existing) return null;
        const row = await tx.waiver.update({
          where: { id: existing.id },
          data: {
            ...(input.owner !== undefined
              ? { owner: input.owner }
              : {}),
            ...(input.reason !== undefined
              ? { reason: input.reason }
              : {}),
            ...(input.scope !== undefined
              ? { scope: input.scope }
              : {}),
            ...(input.expiresAt !== undefined
              ? { expiresAt: new Date(input.expiresAt) }
              : {}),
            ...(input.lastReviewedAt !== undefined
              ? { lastReviewedAt: new Date(input.lastReviewedAt) }
              : {})
          }
        });
        return waiverFromRow(row);
      }
    );
  }

  async createSuppression(
    input: Readonly<SuppressionCreateInput>
  ): Promise<Suppression> {
    const row = await this.prisma.suppression.create({
      data: {
        tenantId: input.tenantId,
        scanRequestId: input.scanRequestId,
        findingId: input.findingId ?? null,
        reason: input.reason
      }
    });
    return suppressionFromRow(row);
  }
}

function waiverFromRow(row: WaiverRow): Waiver {
  return {
    id: row.id,
    tenantId: row.tenantId,
    owner: row.owner,
    reason: row.reason,
    scope: row.scope,
    expiresAt: row.expiresAt.toISOString(),
    ...(row.lastReviewedAt
      ? { lastReviewedAt: row.lastReviewedAt.toISOString() }
      : {})
  };
}

function suppressionFromRow(row: SuppressionRow): Suppression {
  return {
    id: row.id,
    tenantId: row.tenantId,
    scanRequestId: row.scanRequestId,
    ...(row.findingId ? { findingId: row.findingId } : {}),
    reason: row.reason
  };
}
