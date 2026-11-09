import type { ScanDispatchLease } from './scan-dispatch';

/** Private worker/gateway contracts only. Values must never be logged or stored. */
export interface FetchCapabilityIssue {
  credentialId: string;
  capability: string;
  expiresAt: string;
  expiresInSeconds: number;
}

export interface FetchGatewayClaim {
  credentialId: string;
  claimToken: string;
  expiresAt: string;
  tenantId: string;
  scanRequestId: string;
  dispatchJobId: string;
  repositoryBindingId: string;
  providerRepoId: string;
  providerUserId: string;
  fullName: string;
  installationId: string;
  commitSha: string;
}

export interface FetchGatewayOutcome {
  success: boolean;
  upstreamRevoked: boolean;
}

export interface FetchGatewayCompletion {
  handoffAllowed: boolean;
  integrationSuspended: boolean;
}

export interface FetchCapabilityConsume {
  lease: ScanDispatchLease;
  capability: string;
}
