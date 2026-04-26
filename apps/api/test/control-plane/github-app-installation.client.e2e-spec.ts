import { HttpService } from "@nestjs/axios";
import { ServiceUnavailableException } from "@nestjs/common";
import type { AxiosResponse } from "axios";
import { generateKeyPairSync } from "node:crypto";
import { of } from "rxjs";

import { GithubAppInstallationClient } from "../../src/control-plane/github-app-installation.client";

describe("GithubAppInstallationClient", () => {
  it("exchanges an app JWT for an installation token and lists installation repositories", async () => {
    const http = createHttpService();
    http.post.mockReturnValueOnce(of(createAxiosResponse({ token: "installation-token" })));
    http.get.mockReturnValueOnce(
      of(
        createAxiosResponse({
          repositories: [
            {
              id: 1001,
              full_name: "acme/payments",
              default_branch: "main",
              private: true
            }
          ]
        })
      )
    );
    const client = new GithubAppInstallationClient(
      http as never,
      createConfigService({
        GITHUB_APP_ID: "12345",
        GITHUB_APP_PRIVATE_KEY: createPrivateKeyPem()
      }) as never
    );

    await expect(client.listInstallationRepositories("98765")).resolves.toEqual([
      {
        providerRepoId: "1001",
        fullName: "acme/payments",
        defaultBranch: "main",
        isPrivate: true
      }
    ]);

    expect(http.post).toHaveBeenCalledWith(
      "https://api.github.com/app/installations/98765/access_tokens",
      {},
      expect.objectContaining({
        headers: expect.objectContaining({
          Accept: "application/vnd.github+json",
          Authorization: expect.stringMatching(/^Bearer [^.]+\.[^.]+\.[^.]+$/),
          "X-GitHub-Api-Version": "2022-11-28"
        })
      })
    );
    expect(http.get).toHaveBeenCalledWith(
      "https://api.github.com/installation/repositories",
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: "Bearer installation-token"
        }),
        params: { per_page: 100 }
      })
    );
    expect(JSON.stringify(http.get.mock.calls)).not.toContain(createPrivateKeyPem());
  });

  it("fails before GitHub calls when app credentials are not configured", async () => {
    const http = createHttpService();
    const client = new GithubAppInstallationClient(
      http as never,
      createConfigService({
        GITHUB_APP_ID: "",
        GITHUB_APP_PRIVATE_KEY: ""
      }) as never
    );

    await expect(client.listInstallationRepositories("98765")).rejects.toBeInstanceOf(
      ServiceUnavailableException
    );
    expect(http.post).not.toHaveBeenCalled();
    expect(http.get).not.toHaveBeenCalled();
  });
});

function createHttpService(): Pick<HttpService, "get" | "post"> & {
  get: jest.Mock;
  post: jest.Mock;
} {
  return {
    get: jest.fn(),
    post: jest.fn()
  };
}

function createConfigService(values: Record<string, string>) {
  return {
    get: (key: string) => values[key],
    getOptional: (key: string) => values[key]
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

function createPrivateKeyPem(): string {
  return generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: {
      format: "pem",
      type: "pkcs8"
    },
    publicKeyEncoding: {
      format: "pem",
      type: "spki"
    }
  }).privateKey;
}
