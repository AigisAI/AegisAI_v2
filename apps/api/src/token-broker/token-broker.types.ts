import type { AuditEvent, ScmPrincipal, TokenBrokerIssueRequest } from "../../../../packages/shared/src";

export interface TokenBrokerIssueResponse extends TokenBrokerIssueRequest {
  credentialId: string;
  expiresInSeconds: number;
  auditEventType: "token.issued";
}

export interface TokenBrokerAuditEvent extends AuditEvent {
  metadata: {
    repositoryBindingId: string;
    principal: Extract<ScmPrincipal, "REPO_READ">;
    commitSha: string;
    ttlSeconds: number;
    auditReason: string;
  };
}
