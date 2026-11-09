import type {
  ApiResponse,
  ReportDetail,
  ReportRequestResponse,
} from "@aegisai/shared";

import { apiClient, resolveApiBaseUrl, unwrapApiResponse } from "./client";
import { DEMO_REPORT_ID, demoReport } from "../demo/demoData";
import { buildDemoPath, isDemoMode } from "../demo/demoMode";

export async function requestPdfReport(scanId: string): Promise<ReportRequestResponse> {
  if (isDemoMode()) {
    return {
      reportId: DEMO_REPORT_ID,
      status: "READY",
      message: `Natural-language security report prepared for ${scanId}.`,
    };
  }

  const response = await apiClient.post<ApiResponse<ReportRequestResponse>>(
    `/reports/scans/${scanId}/pdf`
  );

  return unwrapApiResponse(response.data);
}

export async function getReportDetail(reportId: string): Promise<ReportDetail> {
  if (isDemoMode()) {
    return { ...demoReport, id: reportId };
  }

  const response = await apiClient.get<ApiResponse<ReportDetail>>(`/reports/${reportId}`);
  return unwrapApiResponse(response.data);
}

export function getReportDownloadUrl(reportId: string): string {
  if (isDemoMode()) {
    return buildDemoPath(`/reports/${reportId}`);
  }

  const baseUrl = resolveApiBaseUrl().replace(/\/$/, "");

  try {
    return new URL(`reports/${reportId}/download`, `${baseUrl}/`).toString();
  } catch {
    return `${baseUrl}/reports/${reportId}/download`.replace(/(?<!:)\/{2,}/g, "/");
  }
}
