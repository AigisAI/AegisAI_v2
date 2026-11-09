/** Internal dispatch ownership; never conveys repository or infrastructure access. */
export interface ScanDispatchLease {
  jobId: string;
  tenantId: string;
  scanRequestId: string;
  attempt: number;
  leaseToken: string;
  expiresAt: string;
}

export type ScanDispatchFailureCode = "UPSTREAM_UNAVAILABLE" | "LEASE_EXPIRED" | "DISPATCH_REJECTED";
