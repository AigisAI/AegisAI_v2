import type { Provider } from '@aegisai/shared';
import { HttpService } from '@nestjs/axios';
import { Injectable } from '@nestjs/common';
import { firstValueFrom } from 'rxjs';

import {
  GitProviderNotFoundError,
  GitProviderRateLimitError,
  GitProviderUnauthorizedError,
  GitProviderUnavailableError
} from './git-provider-client.errors';
import type {
  BranchListResult,
  FileTreeItem,
  IGitProviderClient,
  ProviderRepoListItem,
  RepoListResult
} from './git-provider-client.interface';

interface GithubRepositoryResponse {
  id: number;
  full_name: string;
  clone_url: string;
  default_branch: string | null;
  private: boolean;
}

interface GithubBranchResponse {
  name: string;
  commit?: {
    sha?: string | null;
  };
}

interface GithubRepositoryMetadataResponse {
  default_branch: string | null;
}

interface GithubTreeResponse {
  truncated?: boolean;
  tree: Array<{
    path: string;
    size?: number;
    type: 'blob' | 'tree' | string;
  }>;
}

interface GithubContentsResponse {
  content?: string;
  encoding?: string;
  download_url?: string | null;
}

@Injectable()
export class GithubClient implements IGitProviderClient {
  readonly provider: Provider = 'github';
  private readonly baseUrl = 'https://api.github.com';

  constructor(private readonly http: HttpService) {}

  async getRepositories(accessToken: string, page: number, size: number): Promise<RepoListResult> {
    return this.wrapRequest(async () => {
      const response = await firstValueFrom(
        this.http.get<GithubRepositoryResponse[]>(`${this.baseUrl}/user/repos`, {
          headers: this.buildHeaders(accessToken),
          params: {
            page,
            per_page: size,
            sort: 'updated'
          }
        })
      );

      return {
        items: response.data.map((repository) => ({
          providerRepoId: String(repository.id),
          fullName: repository.full_name,
          cloneUrl: repository.clone_url,
          defaultBranch: this.requireString(
            repository.default_branch,
            `GitHub repository ${repository.full_name} is missing a default branch`
          ),
          isPrivate: repository.private
        })),
        hasNextPage: this.hasNextLink(response.headers?.link)
      };
    });
  }

  async getRepository(
    providerRepoId: string,
    accessToken: string
  ): Promise<ProviderRepoListItem> {
    return this.wrapRequest(async () => {
      const response = await firstValueFrom(
        this.http.get<GithubRepositoryResponse>(
          `${this.baseUrl}/repositories/${encodeURIComponent(providerRepoId)}`,
          {
            headers: this.buildHeaders(accessToken)
          }
        )
      );

      return {
        providerRepoId: String(response.data.id),
        fullName: response.data.full_name,
        cloneUrl: response.data.clone_url,
        defaultBranch: this.requireString(
          response.data.default_branch,
          `GitHub repository ${response.data.full_name} is missing a default branch`
        ),
        isPrivate: response.data.private
      };
    });
  }

  async getBranches(
    fullName: string,
    page: number,
    size: number,
    accessToken: string
  ): Promise<BranchListResult> {
    return this.wrapRequest(async () => {
      const repositoryResponse = await firstValueFrom(
        this.http.get<GithubRepositoryMetadataResponse>(`${this.baseUrl}/repos/${fullName}`, {
          headers: this.buildHeaders(accessToken)
        })
      );
      const defaultBranch = this.requireString(
        repositoryResponse.data.default_branch,
        `GitHub repository ${fullName} is missing a default branch`
      );
      const branchesResponse = await firstValueFrom(
        this.http.get<GithubBranchResponse[]>(`${this.baseUrl}/repos/${fullName}/branches`, {
          headers: this.buildHeaders(accessToken),
          params: {
            page,
            per_page: size
          }
        })
      );

      return {
        items: branchesResponse.data.map((branch) => ({
          name: branch.name,
          isDefault: branch.name === defaultBranch,
          lastCommitSha: branch.commit?.sha ?? null
        })),
        hasNextPage: this.hasNextLink(branchesResponse.headers?.link)
      };
    });
  }

  async getLatestCommitSha(
    fullName: string,
    branch: string,
    accessToken: string
  ): Promise<string> {
    return this.wrapRequest(async () => {
      const response = await firstValueFrom(
        this.http.get<GithubBranchResponse>(
          `${this.baseUrl}/repos/${fullName}/branches/${encodeURIComponent(branch)}`,
          {
            headers: this.buildHeaders(accessToken)
          }
        )
      );

      return this.requireString(
        response.data.commit?.sha ?? null,
        `GitHub branch ${branch} in ${fullName} is missing a commit SHA`
      );
    });
  }

  async getFileTree(
    fullName: string,
    branch: string,
    accessToken: string
  ): Promise<FileTreeItem[]> {
    return this.wrapRequest(async () => {
      const response = await firstValueFrom(
        this.http.get<GithubTreeResponse>(
          `${this.baseUrl}/repos/${fullName}/git/trees/${encodeURIComponent(branch)}`,
          {
            headers: this.buildHeaders(accessToken),
            params: { recursive: 1 }
          }
        )
      );

      if (response.data.truncated) {
        throw new GitProviderUnavailableError(
          `GitHub tree response for ${fullName} at ${branch} was truncated`,
          this.provider
        );
      }

      return response.data.tree.map((item) => ({
        path: item.path,
        size: item.size ?? 0,
        type: item.type === 'tree' ? 'tree' : 'blob'
      }));
    });
  }

  async getFileContent(
    fullName: string,
    filePath: string,
    branch: string,
    accessToken: string
  ): Promise<string> {
    return this.wrapRequest(async () => {
      const encodedFilePath = filePath
        .split('/')
        .map((segment) => encodeURIComponent(segment))
        .join('/');
      const response = await firstValueFrom(
        this.http.get<GithubContentsResponse>(
          `${this.baseUrl}/repos/${fullName}/contents/${encodedFilePath}`,
          {
            headers: this.buildHeaders(accessToken),
            params: { ref: branch }
          }
        )
      );

      if (response.data.content && response.data.encoding === 'base64') {
        return Buffer.from(response.data.content.replace(/\n/g, ''), 'base64').toString('utf8');
      }

      if (response.data.download_url) {
        const rawResponse = await firstValueFrom(
          this.http.get<string>(response.data.download_url, {
            headers: this.buildHeaders(accessToken),
            responseType: 'text'
          })
        );

        return rawResponse.data;
      }

      throw new GitProviderUnavailableError(
        `GitHub file ${filePath} in ${fullName} is missing a readable content payload`,
        this.provider
      );
    });
  }

  private buildHeaders(accessToken: string): Record<string, string> {
    return {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${accessToken}`,
      'X-GitHub-Api-Version': '2022-11-28'
    };
  }

  private hasNextLink(linkHeader: unknown): boolean {
    return typeof linkHeader === 'string' && /rel="next"/.test(linkHeader);
  }

  private requireString(value: string | null | undefined, message: string): string {
    if (!value) {
      throw new GitProviderUnavailableError(message, this.provider);
    }

    return value;
  }

  private async wrapRequest<T>(operation: () => Promise<T>): Promise<T> {
    try {
      return await operation();
    } catch (error) {
      throw this.translateError(error);
    }
  }

  private translateError(error: unknown): Error {
    if (
      error instanceof GitProviderUnauthorizedError ||
      error instanceof GitProviderNotFoundError ||
      error instanceof GitProviderRateLimitError ||
      error instanceof GitProviderUnavailableError
    ) {
      return error;
    }

    const statusCode =
      typeof error === 'object' &&
      error !== null &&
      'response' in error &&
      typeof (error as { response?: { status?: unknown } }).response?.status === 'number'
        ? (error as { response: { status: number } }).response.status
        : undefined;
    const headers =
      typeof error === 'object' &&
      error !== null &&
      'response' in error &&
      typeof (error as { response?: { headers?: unknown } }).response?.headers === 'object'
        ? ((error as { response: { headers: Record<string, string | undefined> } }).response.headers ?? {})
        : {};
    const message =
      error instanceof Error ? error.message : 'GitHub request failed';

    if (statusCode === 401) {
      return new GitProviderUnauthorizedError(message, this.provider, statusCode);
    }

    if (statusCode === 404) {
      return new GitProviderNotFoundError(message, this.provider, statusCode);
    }

    if (statusCode === 403 || statusCode === 429) {
      return new GitProviderRateLimitError(
        message,
        this.provider,
        statusCode,
        this.parseResetAt(headers)
      );
    }

    return new GitProviderUnavailableError(message, this.provider, statusCode);
  }

  private parseResetAt(headers: Record<string, string | undefined>): number | undefined {
    const rawValue = headers['x-ratelimit-reset'] ?? headers['retry-after'];

    if (!rawValue) {
      return undefined;
    }

    const parsed = Number(rawValue);

    return Number.isFinite(parsed) ? parsed : undefined;
  }
}
