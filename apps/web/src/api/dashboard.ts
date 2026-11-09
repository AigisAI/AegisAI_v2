import type { ApiResponse, DashboardWorkspaceData } from "@aegisai/shared";

import { apiClient, unwrapApiResponse } from "./client";
import { demoDashboard } from "../demo/demoData";
import { isDemoMode } from "../demo/demoMode";

export async function getDashboardWorkspaceData(): Promise<DashboardWorkspaceData> {
  if (isDemoMode()) {
    return demoDashboard;
  }

  const response = await apiClient.get<ApiResponse<DashboardWorkspaceData>>("/dashboard");
  return unwrapApiResponse(response.data);
}
