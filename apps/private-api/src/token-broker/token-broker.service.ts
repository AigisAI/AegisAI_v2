import { randomUUID } from "node:crypto";

import { BadRequestException, Injectable } from "@nestjs/common";
import {
  MAX_SCAN_CREDENTIAL_TTL_SECONDS,
  type TokenBrokerIssueRequest
} from "@aegisai/shared/private-runtime";

import { ControlPlaneService } from "../control-plane/control-plane.service";
import type { TokenBrokerAuditEvent, TokenBrokerIssueResponse } from "./token-broker.types";

@Injectable()
export class TokenBrokerService {
  private readonly auditEvents: TokenBrokerAuditEvent[] = [];

  constructor(private readonly controlPlane: ControlPlaneService) {}

  async issue(input: TokenBrokerIssueRequest): Promise<TokenBrokerIssueResponse> {
    if (input.ttlSeconds < 1 || input.ttlSeconds > MAX_SCAN_CREDENTIAL_TTL_SECONDS) {
      throw new BadRequestException({
        errorCode: "CREDENTIAL_TTL_INVALID",
        message: `Credential TTL must be between 1 and ${MAX_SCAN_CREDENTIAL_TTL_SECONDS} seconds.`
      });
    }

    const scanRequest = await this.controlPlane.getScanRequest(input.tenantId, input.scanRequestId);
    if (
      scanRequest.repositoryBindingId !== input.repositoryBindingId ||
      scanRequest.commitSha.toLowerCase() !== input.commitSha.toLowerCase()
    ) {
      throw new BadRequestException({
        errorCode: "SCAN_CREDENTIAL_SCOPE_INVALID",
        message: "Credential scope must match the immutable scan request repository and commit."
      });
    }

    const issuedAt = new Date();
    const expiresAt = new Date(issuedAt.getTime() + input.ttlSeconds * 1000).toISOString();
    const response: TokenBrokerIssueResponse = {
      credentialId: `credential_${randomUUID()}`,
      repositoryBindingId: input.repositoryBindingId,
      scanRequestId: input.scanRequestId,
      principal: input.principal,
      expiresInSeconds: input.ttlSeconds,
      expiresAt,
      auditEventType: "token.issued"
    };

    this.auditEvents.push({
      id: `audit_event_${randomUUID()}`,
      tenantId: input.tenantId,
      eventType: "token.issued",
      actor: "token-broker",
      targetType: "scan_request",
      targetId: input.scanRequestId,
      occurredAt: issuedAt.toISOString(),
      metadata: {
        repositoryBindingId: input.repositoryBindingId,
        principal: input.principal,
        commitSha: input.commitSha,
        ttlSeconds: input.ttlSeconds,
        auditReason: input.auditReason
      }
    });

    return response;
  }

  listAuditEvents(tenantId: string): TokenBrokerAuditEvent[] {
    return this.auditEvents.filter((event) => event.tenantId === tenantId);
  }
}
