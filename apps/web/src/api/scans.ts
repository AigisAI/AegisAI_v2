import type {
  ApiResponse,
  RepoScanListResponse,
  ScanDetail,
  ScanRequestBody,
  ScanRequestResponse,
} from "@aegisai/shared";

import { apiClient, unwrapApiResponse } from "./client";
import {
  DEMO_SCAN_ID,
  demoRepoScans,
  getDemoScan,
} from "../demo/demoData";
import { isDemoMode } from "../demo/demoMode";

export async function requestScan(
  body: ScanRequestBody
): Promise<ScanRequestResponse> {
  if (isDemoMode()) {
    return {
      scanId: DEMO_SCAN_ID,
      status: "PENDING",
      message: `Demo scan queued for ${body.branch}. The deterministic pipeline is now tracking the fixed commit snapshot.`,
    };
  }

  const response = await apiClient.post<ApiResponse<ScanRequestResponse>>("/scans", body);
  return unwrapApiResponse(response.data);
}

export async function getScan(scanId: string): Promise<ScanDetail> {
  if (isDemoMode()) {
    return getDemoScan(scanId);
  }

  const response = await apiClient.get<ApiResponse<ScanDetail>>(`/scans/${scanId}`);
  return unwrapApiResponse(response.data);
}

export async function listRepoScans(
  repoId: string,
  page = 1,
  size = 10
): Promise<RepoScanListResponse> {
  if (isDemoMode()) {
    return demoRepoScans;
  }

  const response = await apiClient.get<ApiResponse<RepoScanListResponse>>(
    `/repos/${repoId}/scans`,
    {
      params: { page, size },
    }
  );

  return unwrapApiResponse(response.data);
}
