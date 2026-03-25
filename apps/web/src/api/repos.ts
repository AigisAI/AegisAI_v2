import type {
  ApiResponse,
  AvailableRepoListResponse,
  ConnectedRepoListResponse,
  ListAvailableReposQuery,
  ListRepoBranchesQuery,
  RepoBranchListResponse,
} from "@aegisai/shared";

import { apiClient, unwrapApiResponse } from "./client";

export async function listConnectedRepos(): Promise<ConnectedRepoListResponse> {
  const response = await apiClient.get<ApiResponse<ConnectedRepoListResponse>>("/repos");
  return unwrapApiResponse(response.data);
}

export async function listAvailableRepos(
  query: ListAvailableReposQuery
): Promise<AvailableRepoListResponse> {
  const response = await apiClient.get<ApiResponse<AvailableRepoListResponse>>(
    "/repos/available",
    {
      params: query,
    }
  );

  return unwrapApiResponse(response.data);
}

export async function listRepoBranches(
  repoId: string,
  query: ListRepoBranchesQuery
): Promise<RepoBranchListResponse> {
  const response = await apiClient.get<ApiResponse<RepoBranchListResponse>>(
    `/repos/${repoId}/branches`,
    {
      params: query,
    }
  );

  return unwrapApiResponse(response.data);
}
