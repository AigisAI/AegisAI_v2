import { HttpService } from "@nestjs/axios";
import { ServiceUnavailableException } from "@nestjs/common";
import type { AxiosResponse } from "axios";
import { of } from "rxjs";

import { GitlabCloudIntegrationClient } from "../../src/control-plane/gitlab-cloud-integration.client";

describe("GitlabCloudIntegrationClient", () => {
  it("lists GitLab Cloud integration repositories with a runtime-only token", async () => {
    const http = createHttpService();
    http.get.mockReturnValueOnce(
      of(
        createAxiosResponse([
          {
            id: 7007,
            path_with_namespace: "acme/gitlab-runtime",
            default_branch: "main",
            visibility: "private"
          }
        ])
      )
    );
    const client = new GitlabCloudIntegrationClient(
      http as never,
      createConfigService("https://gitlab.example/api/v4") as never
    );

    await expect(client.listIntegrationRepositories("group:acme", "gitlab-runtime-token")).resolves.toEqual([
      {
        providerRepoId: "7007",
        fullName: "acme/gitlab-runtime",
        defaultBranch: "main",
        isPrivate: true
      }
    ]);

    expect(http.get).toHaveBeenCalledWith(
      "https://gitlab.example/api/v4/projects",
      expect.objectContaining({
        headers: {
          Authorization: "Bearer gitlab-runtime-token"
        },
        params: expect.objectContaining({
          membership: true,
          namespace: "acme",
          per_page: 100
        })
      })
    );
  });

  it("rejects repository listing when the runtime access token is absent", async () => {
    const client = new GitlabCloudIntegrationClient(
      createHttpService() as never,
      createConfigService("https://gitlab.example/api/v4") as never
    );

    await expect(client.listIntegrationRepositories("group:acme", undefined)).rejects.toBeInstanceOf(
      ServiceUnavailableException
    );
  });
});

function createHttpService(): Pick<HttpService, "get"> & {
  get: jest.Mock;
} {
  return {
    get: jest.fn()
  };
}

function createConfigService(baseUrl: string) {
  return {
    get: (key: string) => {
      if (key === "GITLAB_API_BASE_URL") {
        return baseUrl;
      }

      throw new Error(`Unexpected config key: ${key}`);
    }
  };
}

function createAxiosResponse<T>(data: T): AxiosResponse<T> {
  return {
    data,
    status: 200,
    statusText: "OK",
    headers: {},
    config: { headers: undefined as never }
  };
}
