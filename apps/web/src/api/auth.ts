import type { ApiResponse, AuthMeResponse, LogoutResponse } from "@aegisai/shared";
import axios from "axios";

import { apiClient, unwrapApiResponse } from "./client";

export async function fetchCurrentUser(): Promise<AuthMeResponse | null> {
  try {
    const response = await apiClient.get<ApiResponse<AuthMeResponse>>("/auth/me");
    return unwrapApiResponse(response.data);
  } catch (error) {
    if (axios.isAxiosError(error) && error.response?.status === 401) {
      return null;
    }

    throw error;
  }
}

export async function logout(): Promise<LogoutResponse> {
  const response = await apiClient.post<ApiResponse<LogoutResponse>>("/auth/logout");
  return unwrapApiResponse(response.data);
}
