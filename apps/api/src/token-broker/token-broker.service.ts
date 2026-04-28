import { Injectable } from "@nestjs/common";
import type { TokenBrokerIssueRequest } from "../../../../packages/shared/src";

import { TokenCredentialIssuerService } from "./token-credential-issuer.service";
import type { TokenBrokerAuditEvent, TokenBrokerIssueResponse } from "./token-broker.types";

@Injectable()
export class TokenBrokerService {
  private readonly auditEvents: TokenBrokerAuditEvent[] = [];
  private credentialSequence = 0;
  private auditSequence = 0;

  constructor(private readonly tokenCredentialIssuer: TokenCredentialIssuerService) {}

  issue(input: TokenBrokerIssueRequest): TokenBrokerIssueResponse {
    const issuedCredential = this.tokenCredentialIssuer.issue(input);
    const response: TokenBrokerIssueResponse = {
      ...input,
      credentialId: `credential_${++this.credentialSequence}`,
      ...issuedCredential,
      expiresInSeconds: input.ttlSeconds,
      auditEventType: "token.issued"
    };

    this.auditEvents.push({
      id: `audit_event_${++this.auditSequence}`,
      tenantId: input.tenantId,
      eventType: "token.issued",
      actor: "token-broker",
      targetType: "scan_request",
      targetId: input.scanRequestId,
      occurredAt: new Date(0).toISOString(),
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
