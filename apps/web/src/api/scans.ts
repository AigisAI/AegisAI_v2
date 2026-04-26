import type {
  ApiResponse,
  RepoScanListResponse,
  ScanDetail,
  ScanRequestBody,
  ScanRequestResponse,
} from "@aegisai/shared";

import { apiClient, unwrapApiResponse } from "./client";

export async function requestScan(
  body: ScanRequestBody
): Promise<ScanRequestResponse> {
  const response = await apiClient.post<ApiResponse<ScanRequestResponse>>("/scans", body);
  return unwrapApiResponse(response.data);
}

export async function getScan(scanId: string): Promise<ScanDetail> {
  const response = await apiClient.get<ApiResponse<ScanDetail>>(`/scans/${scanId}`);
  return unwrapApiResponse(response.data);
}

export async function listRepoScans(
  repoId: string,
  page = 1,
  size = 10
): Promise<RepoScanListResponse> {
  const response = await apiClient.get<ApiResponse<RepoScanListResponse>>(
    `/repos/${repoId}/scans`,
    {
      params: { page, size },
    }
  );

  return unwrapApiResponse(response.data);
}
