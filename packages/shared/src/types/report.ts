export type ReportStatus = 'GENERATING' | 'READY' | 'FAILED' | 'EXPIRED';

export interface RequestReportParams {
  scanId: string;
}

export interface ReportParams {
  reportId: string;
}

export interface ReportRequestResponse {
  reportId: string;
  status: 'GENERATING' | 'READY';
  message: string;
}

export interface ReportDetail {
  id: string;
  scanId: string;
  status: ReportStatus;
  downloadUrl: string | null;
  errorMessage: string | null;
  createdAt: string;
  expiresAt: string | null;
}
