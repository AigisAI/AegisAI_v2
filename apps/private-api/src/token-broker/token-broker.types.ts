import type { AuditEvent, ScmPrincipal } from "@aegisai/shared/private-runtime";

export interface TokenBrokerIssueResponse {
  credentialId: string;
  repositoryBindingId: string;
  scanRequestId: string;
  principal: Extract<ScmPrincipal, "REPO_READ">;
  expiresInSeconds: number;
  expiresAt: string;
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
