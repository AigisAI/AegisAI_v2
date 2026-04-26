import type {
  ApiResponse,
  ReportDetail,
  ReportRequestResponse,
} from "@aegisai/shared";

import { apiClient, resolveApiBaseUrl, unwrapApiResponse } from "./client";

export async function requestPdfReport(scanId: string): Promise<ReportRequestResponse> {
  const response = await apiClient.post<ApiResponse<ReportRequestResponse>>(
    `/reports/scans/${scanId}/pdf`
  );

  return unwrapApiResponse(response.data);
}

export async function getReportDetail(reportId: string): Promise<ReportDetail> {
  const response = await apiClient.get<ApiResponse<ReportDetail>>(`/reports/${reportId}`);
  return unwrapApiResponse(response.data);
}

export function getReportDownloadUrl(reportId: string): string {
  const baseUrl = resolveApiBaseUrl().replace(/\/$/, "");

  try {
    return new URL(`reports/${reportId}/download`, `${baseUrl}/`).toString();
  } catch {
    return `${baseUrl}/reports/${reportId}/download`.replace(/(?<!:)\/{2,}/g, "/");
  }
}
