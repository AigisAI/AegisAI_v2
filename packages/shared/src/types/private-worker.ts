import type { FetchCapabilityIssue, FetchGatewayClaim, FetchGatewayCompletion } from './fetch-capability';
import type { ScanDispatchLease } from './scan-dispatch';

/** Local Unix-socket protocol only; never mount or forward these sockets to parsers. */
export type PrivateBrokerResponse<T> = { ok: true; data: T } | { ok: false; errorCode: string };
export interface PrivateWorkerAssignment {
  lease: ScanDispatchLease;
  execution: {
    id: string; tenantId: string; repositoryBindingId: string; commitSha: string;
    targetRef: string; policyVersion: string; scannerSetVersion: string; isolationClass: string;
  };
}
export interface GatewayScopeFrame { kind: 'fetch-scope'; claim: FetchGatewayClaim; }
/** Secret frame: only the authenticated source gateway may receive it; no persistence/logging. */
export interface GatewayUpstreamFrame { upstreamToken: string; expiresAt: string; }
export type PrivateWorkerIssueResponse = PrivateBrokerResponse<FetchCapabilityIssue>;
export type PrivateGatewayCompletionResponse = PrivateBrokerResponse<FetchGatewayCompletion>;
