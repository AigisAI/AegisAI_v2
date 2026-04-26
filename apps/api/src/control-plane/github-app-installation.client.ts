import { HttpService } from "@nestjs/axios";
import { Injectable, ServiceUnavailableException } from "@nestjs/common";
import { createSign } from "node:crypto";
import { firstValueFrom } from "rxjs";

import { ConfigService } from "../config/config.service";
import type { InstallRepositoryInput } from "./control-plane.types";

interface GithubInstallationTokenResponse {
  token?: string;
}

interface GithubInstallationRepositoriesResponse {
  repositories?: GithubInstallationRepositoryResponse[];
}

interface GithubInstallationRepositoryResponse {
  id: number;
  full_name: string;
  default_branch: string | null;
  private: boolean;
}

@Injectable()
export class GithubAppInstallationClient {
  private readonly baseUrl = "https://api.github.com";

  constructor(
    private readonly http: HttpService,
    private readonly config: ConfigService
  ) {}

  async listInstallationRepositories(installationId: string): Promise<InstallRepositoryInput[]> {
    const installationToken = await this.issueInstallationToken(installationId);
    const response = await firstValueFrom(
      this.http.get<GithubInstallationRepositoriesResponse>(
        `${this.baseUrl}/installation/repositories`,
        {
          headers: this.buildHeaders(installationToken),
          params: { per_page: 100 }
        }
      )
    );

    return (response.data.repositories ?? []).map((repository) => ({
      providerRepoId: String(repository.id),
      fullName: repository.full_name,
      defaultBranch: this.requireString(
        repository.default_branch,
        `GitHub App repository ${repository.full_name} is missing a default branch`
      ),
      isPrivate: repository.private
    }));
  }

  private async issueInstallationToken(installationId: string): Promise<string> {
    const response = await firstValueFrom(
      this.http.post<GithubInstallationTokenResponse>(
        `${this.baseUrl}/app/installations/${encodeURIComponent(installationId)}/access_tokens`,
        {},
        {
          headers: this.buildHeaders(this.createAppJwt())
        }
      )
    );

    return this.requireString(response.data.token, "GitHub App installation token response is missing token");
  }

  private createAppJwt(): string {
    const appId = this.requireString(this.config.get("GITHUB_APP_ID"), "GitHub App ID is not configured");
    const privateKey = this.normalizePrivateKey(
      this.requireString(this.config.get("GITHUB_APP_PRIVATE_KEY"), "GitHub App private key is not configured")
    );
    const issuedAt = Math.floor(Date.now() / 1000) - 60;
    const expiresAt = issuedAt + 9 * 60;
    const header = this.base64UrlJson({ alg: "RS256", typ: "JWT" });
    const payload = this.base64UrlJson({
      iat: issuedAt,
      exp: expiresAt,
      iss: appId
    });
    const unsignedToken = `${header}.${payload}`;
    const signature = createSign("RSA-SHA256").update(unsignedToken).sign(privateKey, "base64url");

    return `${unsignedToken}.${signature}`;
  }

  private buildHeaders(token: string): Record<string, string> {
    return {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "X-GitHub-Api-Version": "2022-11-28"
    };
  }

  private normalizePrivateKey(privateKey: string): string {
    return privateKey.replace(/\\n/g, "\n");
  }

  private base64UrlJson(value: unknown): string {
    return Buffer.from(JSON.stringify(value)).toString("base64url");
  }

  private requireString(value: string | null | undefined, message: string): string {
    if (!value) {
      throw new ServiceUnavailableException(message);
    }

    return value;
  }
}
