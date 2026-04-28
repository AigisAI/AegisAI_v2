import type { AuditEvent, ScmPrincipal, TokenBrokerIssueRequest } from "../../../../packages/shared/src";

export interface TokenBrokerIssueResponse extends TokenBrokerIssueRequest {
  credentialId: string;
  credentialType: "SCM_REPOSITORY_ACCESS";
  credentialValue: string;
  issuedAt: string;
  expiresAt: string;
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
