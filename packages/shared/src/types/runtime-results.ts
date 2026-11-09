/** Reduced deterministic output only: no source snippets or raw tool messages. */
export type RuntimeScanner = 'OPENGREP' | 'TRIVY' | 'SYFT';
export interface RuntimeScannerReport {
  scanner: RuntimeScanner;
  status: 'COMPLETED' | 'FAILED' | 'TIMED_OUT' | 'SKIPPED';
  durationMs: number;
}
export interface RuntimeFindingInput {
  scanner: 'OPENGREP' | 'TRIVY';
  ruleId: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  filePath: string;
  lineStart: number | null;
  lineEnd: number | null;
}
export interface RuntimeResultInput {
  scannerSetVersion: string;
  vulnerabilityDatabaseDigest: string;
  runs: RuntimeScannerReport[];
  findings: RuntimeFindingInput[];
}
export type RuntimeAiState = 'DISABLED' | 'AVAILABLE' | 'UNAVAILABLE';
export const RUNTIME_REJECTION_REASONS = ['UNSUPPORTED_SCAN_PROFILE','SOURCE_LIMIT_EXCEEDED','SOURCE_ENTRY_UNSUPPORTED','RUNTIME_SCOPE_UNSUPPORTED'] as const;
export type RuntimeRejectionReason = typeof RUNTIME_REJECTION_REASONS[number];

export interface RuntimeStatus {
  ready: boolean;
  busy: boolean;
  ai: 'DISABLED';
  updatedAt: string | null;
  scannerSetVersion?: string;
  policyVersion?: string;
}
export interface RuntimeScanSummary {
  id: string;
  status: 'QUEUED' | 'PLANNING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELED';
  repositoryBindingId: string;
  repositoryName: string;
  branch: string;
  commitSha: string;
  createdAt: string;
  startedAt: string | null;
  completedAt: string | null;
}
export interface RuntimeScanDetail extends RuntimeScanSummary {
  evidence: {available:boolean;expiresAt:string}|null;
  failureReason: string | null;
  ai: 'DISABLED';
  coverage: 'LIMITED' | 'UNAVAILABLE' | 'PENDING';
  runs: Array<{scanner: RuntimeScanner; status: string; scannerVersion: string}>;
  findings: Array<RuntimeFindingInput & {id: string; title: string; status: string}>;
  policy: {action: string; reasonCodes: string[]; mergeEnforced: false} | null;
}
export interface RuntimeSessionResponse {
  authenticated: boolean;
  csrfToken: string;
  user: {id: string; name: string; email: string | null; avatarUrl?: string} | null;
}
