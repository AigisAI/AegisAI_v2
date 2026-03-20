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
  RepoListResult
} from './git-provider-client.interface';

interface GitlabProjectResponse {
  id: number;
  path_with_namespace: string;
  http_url_to_repo: string;
  default_branch: string | null;
  visibility: string;
}

interface GitlabBranchResponse {
  name: string;
  default?: boolean;
  commit?: {
    id?: string | null;
  };
}

interface GitlabTreeEntryResponse {
  path: string;
  type: 'blob' | 'tree' | string;
  size?: number;
}

@Injectable()
export class GitlabClient implements IGitProviderClient {
  readonly provider: Provider = 'gitlab';
  private readonly baseUrl = 'https://gitlab.com/api/v4';

  constructor(private readonly http: HttpService) {}

  async getRepositories(accessToken: string, page: number, size: number): Promise<RepoListResult> {
    return this.wrapRequest(async () => {
      const response = await firstValueFrom(
        this.http.get<GitlabProjectResponse[]>(`${this.baseUrl}/projects`, {
          headers: this.buildHeaders(accessToken),
          params: {
            membership: true,
            order_by: 'updated_at',
            sort: 'desc',
            page,
            per_page: size
          }
        })
      );

      return {
        items: response.data.map((project) => ({
          providerRepoId: String(project.id),
          fullName: project.path_with_namespace,
          cloneUrl: project.http_url_to_repo,
          defaultBranch: this.requireString(
            project.default_branch,
            `GitLab project ${project.path_with_namespace} is missing a default branch`
          ),
          isPrivate: project.visibility !== 'public'
        })),
        hasNextPage: this.hasNextPage(response.headers)
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
      const response = await firstValueFrom(
        this.http.get<GitlabBranchResponse[]>(
          `${this.baseUrl}/projects/${encodeURIComponent(fullName)}/repository/branches`,
          {
            headers: this.buildHeaders(accessToken),
            params: {
              page,
              per_page: size
            }
          }
        )
      );

      return {
        items: response.data.map((branch) => ({
          name: branch.name,
          isDefault: Boolean(branch.default),
          lastCommitSha: branch.commit?.id ?? null
        })),
        hasNextPage: this.hasNextPage(response.headers)
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
        this.http.get<GitlabBranchResponse>(
          `${this.baseUrl}/projects/${encodeURIComponent(fullName)}/repository/branches/${encodeURIComponent(branch)}`,
          {
            headers: this.buildHeaders(accessToken)
          }
        )
      );

      return this.requireString(
        response.data.commit?.id ?? null,
        `GitLab branch ${branch} in ${fullName} is missing a commit SHA`
      );
    });
  }

  async getFileTree(
    fullName: string,
    branch: string,
    accessToken: string
  ): Promise<FileTreeItem[]> {
    return this.wrapRequest(async () => {
      const items: FileTreeItem[] = [];
      let page = 1;
      let hasNextPage = true;

      while (hasNextPage) {
        const response = await firstValueFrom(
          this.http.get<GitlabTreeEntryResponse[]>(
            `${this.baseUrl}/projects/${encodeURIComponent(fullName)}/repository/tree`,
            {
              headers: this.buildHeaders(accessToken),
              params: {
                ref: branch,
                recursive: true,
                page,
                per_page: 100
              }
            }
          )
        );

        items.push(...response.data.map((entry) => this.toFileTreeItem(entry)));
        hasNextPage = this.hasNextPage(response.headers);
        page += 1;
      }

      return items;
    });
  }

  async getFileContent(
    fullName: string,
    filePath: string,
    branch: string,
    accessToken: string
  ): Promise<string> {
    return this.wrapRequest(async () => {
      const response = await firstValueFrom(
        this.http.get<string>(
          `${this.baseUrl}/projects/${encodeURIComponent(fullName)}/repository/files/${encodeURIComponent(filePath)}/raw`,
          {
            headers: this.buildHeaders(accessToken),
            params: { ref: branch },
            responseType: 'text'
          }
        )
      );

      return response.data;
    });
  }

  private buildHeaders(accessToken: string): Record<string, string> {
    return {
      Authorization: `Bearer ${accessToken}`
    };
  }

  private hasNextPage(headers: unknown): boolean {
    return Boolean(this.readHeader(headers, 'x-next-page'));
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
        ? (error as { response: { headers: unknown } }).response.headers
        : {};
    const message =
      error instanceof Error ? error.message : 'GitLab request failed';

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

  private parseResetAt(headers: unknown): number | undefined {
    const rawValue = this.readHeader(headers, 'ratelimit-reset') ?? this.readHeader(headers, 'retry-after');

    if (!rawValue) {
      return undefined;
    }

    const parsed = Number(rawValue);

    return Number.isFinite(parsed) ? parsed : undefined;
  }

  private readHeader(headers: unknown, headerName: string): string | undefined {
    if (!headers || typeof headers !== 'object') {
      return undefined;
    }

    const value = (headers as Record<string, unknown>)[headerName];

    if (typeof value === 'string') {
      return value;
    }

    if (Array.isArray(value)) {
      const firstValue = value[0];

      return typeof firstValue === 'string' ? firstValue : undefined;
    }

    if (typeof value === 'number') {
      return String(value);
    }

    return undefined;
  }

  private toFileTreeItem(entry: GitlabTreeEntryResponse): FileTreeItem {
    return {
      path: entry.path,
      size: entry.size ?? 0,
      type: entry.type === 'tree' ? 'tree' : 'blob'
    };
  }
}
