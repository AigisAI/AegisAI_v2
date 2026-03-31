import type { ApiResponse, DashboardWorkspaceData } from "@aegisai/shared";

import { apiClient, unwrapApiResponse } from "./client";

export async function getDashboardWorkspaceData(): Promise<DashboardWorkspaceData> {
  const response = await apiClient.get<ApiResponse<DashboardWorkspaceData>>("/dashboard");
  return unwrapApiResponse(response.data);
}
