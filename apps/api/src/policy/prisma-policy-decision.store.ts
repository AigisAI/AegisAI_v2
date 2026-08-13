import type {
  PolicyAction,
  PolicyDecision,
  ScannerKind
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';

import { PrismaService } from '../prisma/prisma.service';
import {
  PolicyDecisionStore,
  type PolicyDecisionCreate
} from './policy-decision.store';

interface PolicyDecisionRow {
  id: string;
  tenantId: string;
  scanRequestId: string;
  findingId: string | null;
  enforcementAction: PolicyAction;
  commentAllowed: boolean;
  dashboardVisible: boolean;
  ticketRequested: boolean;
  blockRequested: boolean;
  reasonCodes: Prisma.JsonValue;
  requiredCoverage: Prisma.JsonValue;
  waiverApplied: boolean;
  staleSuppressed: boolean;
  aiAdvisoryVisible: boolean;
}

@Injectable()
export class PrismaPolicyDecisionStore extends PolicyDecisionStore {
  constructor(private readonly prisma: PrismaService) {
    super();
  }

  async create(
    input: Readonly<PolicyDecisionCreate>
  ): Promise<PolicyDecision> {
    const row = await this.prisma.policyDecision.create({
      data: {
        tenantId: input.tenantId,
        scanRequestId: input.scanRequestId,
        findingId: input.findingId ?? null,
        enforcementAction: input.enforcementAction,
        commentAllowed: input.commentAllowed,
        dashboardVisible: input.dashboardVisible,
        ticketRequested: input.ticketRequested,
        blockRequested: input.blockRequested,
        reasonCodes: input.reasonCodes,
        requiredCoverage: input.requiredCoverage,
        waiverApplied: input.waiverApplied,
        staleSuppressed: input.staleSuppressed,
        aiAdvisoryVisible: input.aiAdvisoryVisible
      }
    });
    return policyDecisionFromRow(row);
  }

  async findByTenantAndId(
    tenantId: string,
    policyDecisionId: string
  ): Promise<PolicyDecision | null> {
    const row = await this.prisma.policyDecision.findFirst({
      where: { id: policyDecisionId, tenantId }
    });
    return row ? policyDecisionFromRow(row) : null;
  }
}

function policyDecisionFromRow(
  row: PolicyDecisionRow
): PolicyDecision {
  return {
    id: row.id,
    tenantId: row.tenantId,
    scanRequestId: row.scanRequestId,
    ...(row.findingId ? { findingId: row.findingId } : {}),
    enforcementAction: row.enforcementAction,
    commentAllowed: row.commentAllowed,
    dashboardVisible: row.dashboardVisible,
    ticketRequested: row.ticketRequested,
    blockRequested: row.blockRequested,
    reasonCodes: stringArray(row.reasonCodes, 'reasonCodes'),
    requiredCoverage: stringArray(
      row.requiredCoverage,
      'requiredCoverage'
    ) as ScannerKind[],
    waiverApplied: row.waiverApplied,
    staleSuppressed: row.staleSuppressed,
    aiAdvisoryVisible: row.aiAdvisoryVisible
  };
}

function stringArray(value: Prisma.JsonValue, field: string): string[] {
  if (
    !Array.isArray(value) ||
    !value.every((item): item is string => typeof item === 'string')
  ) {
    throw new Error(`Persisted policy decision ${field} is invalid.`);
  }
  return [...value];
}
