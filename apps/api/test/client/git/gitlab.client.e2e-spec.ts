import { HttpService } from '@nestjs/axios';
import type { AxiosResponse } from 'axios';
import { of, throwError } from 'rxjs';

import {
  GitProviderNotFoundError,
  GitProviderRateLimitError
} from '../../../src/client/git/git-provider-client.errors';
import { GitlabClient } from '../../../src/client/git/gitlab.client';

describe('GitlabClient', () => {
  it('normalizes repositories and uses X-Next-Page for pagination', async () => {
    const http = createHttpService();
    http.get.mockReturnValueOnce(
      of(
        createAxiosResponse(
          [
            {
              id: 55,
              path_with_namespace: 'aegisai/platform',
              http_url_to_repo: 'https://gitlab.com/aegisai/platform.git',
              default_branch: 'main',
              visibility: 'private'
            }
          ],
          {
            'x-next-page': '2'
          }
        )
      )
    );
    const client = new GitlabClient(http as never);

    await expect(client.getRepositories('gitlab-token', 1, 20)).resolves.toEqual({
      items: [
        {
          providerRepoId: '55',
          fullName: 'aegisai/platform',
          cloneUrl: 'https://gitlab.com/aegisai/platform.git',
          defaultBranch: 'main',
          isPrivate: true
        }
      ],
      hasNextPage: true
    });
  });

  it('normalizes recursive tree results and preserves file sizes', async () => {
    const http = createHttpService();
    http.get.mockReturnValueOnce(
      of(
        createAxiosResponse(
          [
            { path: 'src', type: 'tree', size: 0 },
            { path: 'vendor/submodule', type: 'commit', size: 0 },
            { path: 'src/Main.java', type: 'blob', size: 128 }
          ],
          {
            'x-next-page': ''
          }
        )
      )
    );
    const client = new GitlabClient(http as never);

    await expect(client.getFileTree('aegisai/platform', 'main', 'gitlab-token')).resolves.toEqual([
      { path: 'src', type: 'tree', size: 0 },
      { path: 'vendor/submodule', type: 'submodule', size: 0 },
      { path: 'src/Main.java', type: 'blob', size: 128 }
    ]);
  });

  it('loads repository metadata directly by provider repo id', async () => {
    const http = createHttpService();
    http.get.mockReturnValueOnce(
      of(
        createAxiosResponse({
          id: 55,
          path_with_namespace: 'aegisai/platform',
          http_url_to_repo: 'https://gitlab.com/aegisai/platform.git',
          default_branch: 'main',
          visibility: 'private'
        })
      )
    );
    const client = new GitlabClient(http as never);

    await expect(client.getRepository('55', 'gitlab-token')).resolves.toEqual({
      providerRepoId: '55',
      fullName: 'aegisai/platform',
      cloneUrl: 'https://gitlab.com/aegisai/platform.git',
      defaultBranch: 'main',
      isPrivate: true
    });

    expect(http.get).toHaveBeenCalledWith(
      'https://gitlab.com/api/v4/projects/55',
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: 'Bearer gitlab-token'
        })
      })
    );
  });

  it('fetches raw file contents from GitLab', async () => {
    const http = createHttpService();
    http.get.mockReturnValueOnce(of(createAxiosResponse('class Main {}')));
    const client = new GitlabClient(http as never);

    await expect(
      client.getFileContent('aegisai/platform', 'src/Main.java', 'main', 'gitlab-token')
    ).resolves.toBe('class Main {}');
  });

  it('translates 404 responses into a provider not-found error', async () => {
    const http = createHttpService();
    http.get.mockReturnValueOnce(throwError(() => createAxiosError(404)));
    const client = new GitlabClient(http as never);

    await expect(
      client.getBranches('aegisai/platform', 1, 50, 'gitlab-token')
    ).rejects.toBeInstanceOf(GitProviderNotFoundError);
  });

  it('translates 429 responses into a rate-limit error with reset metadata', async () => {
    const http = createHttpService();
    http.get.mockReturnValueOnce(
      throwError(() =>
        createAxiosError(429, {
          'ratelimit-reset': '1712222222'
        })
      )
    );
    const client = new GitlabClient(http as never);

    await expect(client.getRepositories('gitlab-token', 1, 20)).rejects.toMatchObject<
      Partial<GitProviderRateLimitError>
    >({
      name: GitProviderRateLimitError.name,
      resetAtEpochSeconds: 1712222222
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
