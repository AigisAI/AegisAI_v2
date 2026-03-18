import type { CursorPageResponse, Provider } from './common';
import type { ScanStatus, ScanSummary } from './scan';

export interface ConnectedRepoItem {
  id: string;
  provider: Provider;
  fullName: string;
  cloneUrl: string;
  defaultBranch: string;
  isPrivate: boolean;
  lastScanAt: string | null;
  lastScanStatus: ScanStatus | null;
}

export interface RepoBranchItem {
  name: string;
  isDefault: boolean;
  lastCommitSha: string | null;
}

export interface AvailableRepoItem {
  providerRepoId: string;
  fullName: string;
  cloneUrl: string;
  defaultBranch: string;
  isPrivate: boolean;
  alreadyConnected: boolean;
}

export interface ConnectRepoRequest {
  provider: Provider;
  providerRepoId: string;
}

export interface ConnectRepoResponse {
  id: string;
  fullName: string;
  connectedAt: string;
}

export type ConnectedRepoListResponse = ConnectedRepoItem[];
export type RepoBranchListResponse = CursorPageResponse<RepoBranchItem>;
export type AvailableRepoListResponse = CursorPageResponse<AvailableRepoItem>;
export type RepoScanListItem = ScanSummary;
