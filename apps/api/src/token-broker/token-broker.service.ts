import { BadRequestException, Injectable } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import {
  MAX_SCAN_CREDENTIAL_TTL_SECONDS,
  type TokenBrokerIssueRequest
} from '@aegisai/shared';

import { ControlPlaneService } from '../control-plane/control-plane.service';
import { TokenCredentialIssuerService } from "./token-credential-issuer.service";
import type { TokenBrokerAuditEvent, TokenBrokerIssueResponse } from "./token-broker.types";

@Injectable()
export class TokenBrokerService {
  private readonly auditEvents: TokenBrokerAuditEvent[] = [];

  constructor(
    private readonly tokenCredentialIssuer: TokenCredentialIssuerService,
    private readonly controlPlaneService: ControlPlaneService
  ) {}

  async issue(input: TokenBrokerIssueRequest): Promise<TokenBrokerIssueResponse> {
    await this.assertBoundToScan(input);
    const issuedCredential = this.tokenCredentialIssuer.issue(input);
    const response: TokenBrokerIssueResponse = {
      ...input,
      credentialId: `credential_${randomUUID()}`,
      ...issuedCredential,
      expiresInSeconds: input.ttlSeconds,
      auditEventType: "token.issued"
    };

    this.auditEvents.push({
      id: `audit_event_${randomUUID()}`,
      tenantId: input.tenantId,
      eventType: "token.issued",
      actor: "token-broker",
      targetType: "scan_request",
      targetId: input.scanRequestId,
      occurredAt: issuedCredential.issuedAt,
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

  private async assertBoundToScan(input: TokenBrokerIssueRequest): Promise<void> {
    if (
      input.principal !== 'REPO_READ' ||
      !Number.isInteger(input.ttlSeconds) ||
      input.ttlSeconds < 1 ||
      input.ttlSeconds > MAX_SCAN_CREDENTIAL_TTL_SECONDS
    ) {
      throw new BadRequestException('Token scope or TTL is outside the scan credential policy.');
    }

    const scanRequest = await this.controlPlaneService.getScanRequest(
      input.tenantId,
      input.scanRequestId
    );
    if (
      scanRequest.repositoryBindingId !== input.repositoryBindingId ||
      scanRequest.commitSha !== input.commitSha
    ) {
      throw new BadRequestException('Token request does not match the immutable scan scope.');
    }
  }
}
