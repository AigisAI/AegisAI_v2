import type { AuditEvent, ScmPrincipal, TokenBrokerIssueRequest } from '@aegisai/shared';

export interface TokenBrokerIssueResponse
  extends Omit<TokenBrokerIssueRequest, 'workloadIdentityAttestation'> {
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
    attemptId: string;
    workloadIdentityRef: string;
    credentialId: string;
    principal: Extract<ScmPrincipal, "REPO_READ">;
    commitSha: string;
    ttlSeconds: number;
    auditReason: string;
  };
}
