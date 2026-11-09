import type {
  ApiResponse,
  VulnerabilityDetail,
  VulnerabilityFeedbackRequest,
  VulnerabilityFeedbackResponse,
  VulnerabilityPageResponse,
} from "@aegisai/shared";

import { apiClient, unwrapApiResponse } from "./client";
import {
  createDemoFeedbackResponse,
  demoVulnerabilities,
  getDemoVulnerability,
} from "../demo/demoData";
import { isDemoMode } from "../demo/demoMode";

export async function listScanVulnerabilities(
  scanId: string,
  page = 1,
  size = 50
): Promise<VulnerabilityPageResponse> {
  if (isDemoMode()) {
    return demoVulnerabilities;
  }

  const response = await apiClient.get<ApiResponse<VulnerabilityPageResponse>>(
    `/scans/${scanId}/vulnerabilities`,
    {
      params: { page, size },
    }
  );

  return unwrapApiResponse(response.data);
}

export async function getVulnerability(vulnId: string): Promise<VulnerabilityDetail> {
  if (isDemoMode()) {
    return getDemoVulnerability(vulnId);
  }

  const response = await apiClient.get<ApiResponse<VulnerabilityDetail>>(
    `/vulnerabilities/${vulnId}`
  );

  return unwrapApiResponse(response.data);
}

export async function submitVulnerabilityFeedback(
  vulnId: string,
  body: VulnerabilityFeedbackRequest
): Promise<VulnerabilityFeedbackResponse> {
  if (isDemoMode()) {
    return createDemoFeedbackResponse(vulnId, body.feedback);
  }

  const response = await apiClient.post<ApiResponse<VulnerabilityFeedbackResponse>>(
    `/vulnerabilities/${vulnId}/feedback`,
    body
  );

  return unwrapApiResponse(response.data);
}
