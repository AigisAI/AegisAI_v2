import { HttpService } from '@nestjs/axios';
import type { AxiosResponse } from 'axios';
import { of, throwError } from 'rxjs';

import {
  GitProviderRateLimitError,
  GitProviderUnauthorizedError
} from '../../../src/client/git/git-provider-client.errors';
import { GithubClient } from '../../../src/client/git/github.client';

describe('GithubClient', () => {
  it('normalizes repositories and derives hasNextPage from the Link header', async () => {
    const http = createHttpService();
    http.get.mockReturnValueOnce(
      of(
        createAxiosResponse([
          {
            id: 101,
            full_name: 'aegisai/platform',
            clone_url: 'https://github.com/aegisai/platform.git',
            default_branch: 'main',
            private: true
          }
        ], {
          link: '<https://api.github.com/user/repos?page=2&per_page=30>; rel="next"'
        })
      )
    );
    const client = new GithubClient(http as never);

    await expect(client.getRepositories('github-token', 1, 30)).resolves.toEqual({
      items: [
        {
          providerRepoId: '101',
          fullName: 'aegisai/platform',
          cloneUrl: 'https://github.com/aegisai/platform.git',
          defaultBranch: 'main',
          isPrivate: true
        }
      ],
      hasNextPage: true
    });

    expect(http.get).toHaveBeenCalledWith(
      'https://api.github.com/user/repos',
      expect.objectContaining({
        headers: expect.objectContaining({
          Accept: 'application/vnd.github+json',
          Authorization: 'Bearer github-token',
          'X-GitHub-Api-Version': '2022-11-28'
        }),
        params: expect.objectContaining({
          page: 1,
          per_page: 30,
          sort: 'updated'
        })
      })
    );
  });

  it('normalizes branches and marks the default branch from repository metadata', async () => {
    const http = createHttpService();
    http.get
      .mockReturnValueOnce(
        of(
          createAxiosResponse({
            default_branch: 'main'
          })
        )
      )
      .mockReturnValueOnce(
        of(
          createAxiosResponse(
            [
              { name: 'main', commit: { sha: 'sha-main' } },
              { name: 'feature/auth', commit: { sha: 'sha-feature' } }
            ],
            {
              link: ''
            }
          )
        )
      );
    const client = new GithubClient(http as never);

    await expect(client.getBranches('aegisai/platform', 1, 50, 'github-token')).resolves.toEqual({
      items: [
        { name: 'main', isDefault: true, lastCommitSha: 'sha-main' },
        { name: 'feature/auth', isDefault: false, lastCommitSha: 'sha-feature' }
      ],
      hasNextPage: false
    });
  });

  it('loads repository metadata directly by provider repo id', async () => {
    const http = createHttpService();
    http.get.mockReturnValueOnce(
      of(
        createAxiosResponse({
          id: 101,
          full_name: 'aegisai/platform',
          clone_url: 'https://github.com/aegisai/platform.git',
          default_branch: 'main',
          private: true
        })
      )
    );
    const client = new GithubClient(http as never);

    await expect(client.getRepository('101', 'github-token')).resolves.toEqual({
      providerRepoId: '101',
      fullName: 'aegisai/platform',
      cloneUrl: 'https://github.com/aegisai/platform.git',
      defaultBranch: 'main',
      isPrivate: true
    });

    expect(http.get).toHaveBeenCalledWith(
      'https://api.github.com/repositories/101',
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: 'Bearer github-token'
        })
      })
    );
  });

  it('decodes repository file contents from GitHub base64 payloads', async () => {
    const http = createHttpService();
    http.get.mockReturnValueOnce(
      of(
        createAxiosResponse({
          content: Buffer.from('class Demo {}').toString('base64'),
          encoding: 'base64'
        })
      )
    );
    const client = new GithubClient(http as never);

    await expect(
      client.getFileContent('aegisai/platform', 'src/Main.java', 'main', 'github-token')
    ).resolves.toBe('class Demo {}');
  });

  it('translates 401 responses into a provider unauthorized error', async () => {
    const http = createHttpService();
    http.get.mockReturnValueOnce(
      throwError(() => createAxiosError(401))
    );
    const client = new GithubClient(http as never);

    await expect(client.getRepositories('bad-token', 1, 30)).rejects.toBeInstanceOf(
      GitProviderUnauthorizedError
    );
  });

  it('translates 403 rate-limit responses into a rate-limit error with reset metadata', async () => {
    const http = createHttpService();
    http.get.mockReturnValueOnce(
      throwError(() =>
        createAxiosError(403, {
          'x-ratelimit-reset': '1711111111'
        })
      )
    );
    const client = new GithubClient(http as never);

    await expect(client.getRepositories('github-token', 1, 30)).rejects.toMatchObject<
      Partial<GitProviderRateLimitError>
    >({
      name: GitProviderRateLimitError.name,
      resetAtEpochSeconds: 1711111111
    });
  });
});

function createHttpService(): Pick<HttpService, 'get'> & {
  get: jest.Mock;
} {
  return {
    get: jest.fn()
  };
}

function createAxiosResponse<T>(
  data: T,
  headers: Record<string, string> = {}
): AxiosResponse<T> {
  return {
    data,
    status: 200,
    statusText: 'OK',
    headers,
    config: { headers: undefined as never }
  };
}

function createAxiosError(status: number, headers: Record<string, string> = {}): Error {
  return {
    name: 'AxiosError',
    message: `Request failed with status code ${status}`,
    isAxiosError: true,
    response: {
      status,
      headers,
      data: {}
    }
  } as Error;
}
