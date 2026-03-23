import type { Provider } from '@aegisai/shared';

export interface ProviderRepoListItem {
  providerRepoId: string;
  fullName: string;
  cloneUrl: string;
  defaultBranch: string;
  isPrivate: boolean;
}

export interface RepoListResult {
  items: ProviderRepoListItem[];
  hasNextPage: boolean;
}

export interface BranchListItem {
  name: string;
  isDefault: boolean;
  lastCommitSha: string | null;
}

export interface BranchListResult {
  items: BranchListItem[];
  hasNextPage: boolean;
}

export interface FileTreeItem {
  path: string;
  size: number;
  type: 'blob' | 'tree';
}

export interface AnalysisFileItem {
  path: string;
  content: string;
  size: number;
}

export interface TarballCollectionResult {
  files: AnalysisFileItem[];
  skippedFiles: { path: string; reason: string }[];
}

export interface IGitProviderClient {
  readonly provider: Provider;

  getRepositories(accessToken: string, page: number, size: number): Promise<RepoListResult>;
  getRepository(providerRepoId: string, accessToken: string): Promise<ProviderRepoListItem>;
  getBranches(
    fullName: string,
    page: number,
    size: number,
    accessToken: string
  ): Promise<BranchListResult>;
  getLatestCommitSha(fullName: string, branch: string, accessToken: string): Promise<string>;
  getFileTree(fullName: string, branch: string, accessToken: string): Promise<FileTreeItem[]>;
  getFileContent(
    fullName: string,
    filePath: string,
    branch: string,
    accessToken: string
  ): Promise<string>;
  collectByTarball?(
    fullName: string,
    branch: string,
    accessToken: string,
    items: FileTreeItem[],
    maxTotalSize: number
  ): Promise<TarballCollectionResult>;
}
