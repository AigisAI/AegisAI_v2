import { HttpService } from "@nestjs/axios";
import { Injectable, ServiceUnavailableException } from "@nestjs/common";
import { firstValueFrom } from "rxjs";

import { ConfigService } from "../config/config.service";
import type { InstallRepositoryInput } from "./control-plane.types";

interface GitlabProjectResponse {
  id: number;
  path_with_namespace: string;
  default_branch: string | null;
  visibility: string;
}

@Injectable()
export class GitlabCloudIntegrationClient {
  constructor(
    private readonly http: HttpService,
    private readonly config: ConfigService
  ) {}

  async listIntegrationRepositories(
    externalInstallationId: string,
    runtimeAccessToken: string | undefined
  ): Promise<InstallRepositoryInput[]> {
    const response = await firstValueFrom(
      this.http.get<GitlabProjectResponse[]>(`${this.baseUrl}/projects`, {
        headers: this.buildHeaders(
          this.requireString(runtimeAccessToken, "GitLab runtime access token is required")
        ),
        params: {
          membership: true,
          order_by: "updated_at",
          sort: "desc",
          per_page: 100,
          ...this.scopeParams(externalInstallationId)
        }
      })
    );

    return response.data.map((project) => ({
      providerRepoId: String(project.id),
      fullName: project.path_with_namespace,
      defaultBranch: this.requireString(
        project.default_branch,
        `GitLab project ${project.path_with_namespace} is missing a default branch`
      ),
      isPrivate: project.visibility !== "public"
    }));
  }

  private get baseUrl(): string {
    return this.config.get("GITLAB_API_BASE_URL").replace(/\/$/, "");
  }

  private buildHeaders(runtimeAccessToken: string): Record<string, string> {
    return {
      Authorization: `Bearer ${runtimeAccessToken}`
    };
  }

  private scopeParams(externalInstallationId: string): Record<string, string> {
    if (externalInstallationId.startsWith("group:")) {
      return { namespace: externalInstallationId.slice("group:".length) };
    }

    return {};
  }

  private requireString(value: string | null | undefined, message: string): string {
    if (!value) {
      throw new ServiceUnavailableException(message);
    }

    return value;
  }
}
