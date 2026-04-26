import type { Provider } from '@aegisai/shared';
import { Injectable } from '@nestjs/common';

import { GithubClient } from './github.client';
import type { IGitProviderClient } from './git-provider-client.interface';
import { GitlabClient } from './gitlab.client';

@Injectable()
export class GitClientRegistry {
  private readonly clients: Record<Provider, IGitProviderClient>;

  constructor(githubClient: GithubClient, gitlabClient: GitlabClient) {
    this.clients = {
      github: githubClient,
      gitlab: gitlabClient
    };
  }

  get(provider: Provider): IGitProviderClient {
    const client = this.clients[provider];

    if (!client) {
      throw new Error(`Unsupported git provider: ${provider}`);
    }

    return client;
  }
}
