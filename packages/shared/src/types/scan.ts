export interface ScanSeveritySummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export type ScanStatus = 'PENDING' | 'RUNNING' | 'DONE' | 'FAILED';

export interface ScanSummary {
  id: string;
  repoFullName: string;
  branch: string;
  commitSha: string | null;
  status: ScanStatus;
  language: string;
  totalFiles: number | null;
  totalLines: number | null;
  summary: ScanSeveritySummary;
  startedAt: string | null;
  completedAt: string | null;
  errorMessage: string | null;
  createdAt: string;
}

export type ScanDetail = ScanSummary;

export interface ScanRequestBody {
  repoId: string;
  branch: string;
}

export interface ScanRequestResponse {
  scanId: string;
  status: 'PENDING';
  message: string;
}
