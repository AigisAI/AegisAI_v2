import type {
  ApiResponse,
  AvailableRepoListResponse,
  ConnectRepoRequest,
  ConnectRepoResponse,
  ConnectedRepoListResponse,
  ListAvailableReposQuery,
  ListRepoBranchesQuery,
  RepoBranchListResponse,
} from "@aegisai/shared";

import { apiClient, unwrapApiResponse } from "./client";
import {
  demoAvailableRepos,
  demoBranches,
  demoConnectedRepos,
} from "../demo/demoData";
import { isDemoMode } from "../demo/demoMode";

export async function listConnectedRepos(): Promise<ConnectedRepoListResponse> {
  if (isDemoMode()) {
    return demoConnectedRepos;
  }

  const response = await apiClient.get<ApiResponse<ConnectedRepoListResponse>>("/repos");
  return unwrapApiResponse(response.data);
}

export async function listAvailableRepos(
  query: ListAvailableReposQuery
): Promise<AvailableRepoListResponse> {
  if (isDemoMode()) {
    return demoAvailableRepos;
  }

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
  if (isDemoMode()) {
    return demoBranches;
  }

  const response = await apiClient.get<ApiResponse<RepoBranchListResponse>>(
    `/repos/${repoId}/branches`,
    {
      params: query,
    }
  );

  return unwrapApiResponse(response.data);
}

export async function connectRepo(
  input: ConnectRepoRequest
): Promise<ConnectRepoResponse> {
  if (isDemoMode()) {
    const repository = demoAvailableRepos.items.find(
      (item) => item.providerRepoId === input.providerRepoId
    );

    return {
      id: `repo-${input.providerRepoId}`,
      fullName: repository?.fullName ?? "acme-payments/settlement-worker",
      connectedAt: "2026-08-21T07:10:00.000Z",
    };
  }

  const response = await apiClient.post<ApiResponse<ConnectRepoResponse>>(
    "/repos",
    input
  );

  return unwrapApiResponse(response.data);
}

export async function disconnectRepo(repoId: string): Promise<void> {
  if (isDemoMode()) {
    return;
  }

  await apiClient.delete(`/repos/${repoId}`);
}
