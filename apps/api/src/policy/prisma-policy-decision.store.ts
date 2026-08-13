import {
  SCANNER_KINDS,
  type PolicyAction,
  type PolicyDecision,
  type ScannerKind
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';

import { PrismaService } from '../prisma/prisma.service';
import {
  PolicyDecisionStore,
  type PolicyDecisionCreate
} from './policy-decision.store';

const SUPPORTED_SCANNER_KINDS = new Set<string>(SCANNER_KINDS);

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
    const requiredCoverage = scannerKinds(
      [...input.requiredCoverage],
      'requiredCoverage'
    );
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
        requiredCoverage,
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
    requiredCoverage: scannerKinds(
      row.requiredCoverage,
      'requiredCoverage'
    ),
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

function scannerKinds(
  value: Prisma.JsonValue,
  field: string
): ScannerKind[] {
  const values = stringArray(value, field);
  if (!values.every((value) => SUPPORTED_SCANNER_KINDS.has(value))) {
    throw new Error(
      `Policy decision ${field} contains an unsupported scanner kind.`
    );
  }
  return values as ScannerKind[];
}
