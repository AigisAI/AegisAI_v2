import { BadRequestException, Injectable, NotFoundException } from "@nestjs/common";
import {
  buildCanonicalScanKey,
  shouldEscalateIsolation,
  type IsolationClass
} from "../../../../packages/shared/src";

import type {
  ControlPlaneIntegration,
  ControlPlaneRepositoryBinding,
  ControlPlaneScanRequest,
  CreateScanRequestInput,
  GithubInstallationWebhookAck,
  GithubInstallationWebhookInput,
  GithubWebhookRepositoryInput,
  InstallIntegrationInput,
  InstallIntegrationOptions,
  InstallRepositoryInput
} from "./control-plane.types";
import { GithubAppInstallationClient } from "./github-app-installation.client";
import { GithubAppInstallationStateService } from "./github-app-installation-state.service";
import { GitlabCloudIntegrationClient } from "./gitlab-cloud-integration.client";

@Injectable()
export class ControlPlaneService {
  private readonly integrations = new Map<string, ControlPlaneIntegration>();
  private readonly repositoryBindings = new Map<string, ControlPlaneRepositoryBinding>();
  private readonly scanRequests = new Map<string, ControlPlaneScanRequest>();

  private integrationSequence = 0;
  private repositorySequence = 0;
  private scanSequence = 0;

  constructor(
    private readonly githubAppInstallationClient: GithubAppInstallationClient,
    private readonly githubAppInstallationState: GithubAppInstallationStateService,
    private readonly gitlabCloudIntegrationClient: GitlabCloudIntegrationClient
  ) {}

  async installGithubAppIntegration(input: InstallIntegrationInput): Promise<ControlPlaneIntegration> {
    const repositories =
      input.repositories ??
      (await this.githubAppInstallationClient.listInstallationRepositories(input.externalInstallationId));

    const integration = this.installIntegration(
      {
        ...input,
        repositories
      },
      {
        provider: "GITHUB",
        integrationType: "GITHUB_APP"
      }
    );

    await this.githubAppInstallationState.persistInstallation(integration, repositories);

    return integration;
  }

  async installGitlabCloudIntegration(input: InstallIntegrationInput): Promise<ControlPlaneIntegration> {
    const repositories =
      input.repositories ??
      (await this.gitlabCloudIntegrationClient.listIntegrationRepositories(
        input.externalInstallationId,
        input.runtimeAccessToken
      ));

    return this.installIntegration(
      {
        ...input,
        repositories,
        runtimeAccessToken: undefined
      },
      {
        provider: "GITLAB",
        integrationType: "GITLAB_CLOUD_INTEGRATION"
      }
    );
  }

  installIntegration(
    input: InstallIntegrationInput,
    options: InstallIntegrationOptions
  ): ControlPlaneIntegration {
    const integration: ControlPlaneIntegration = {
      id: `integration_${++this.integrationSequence}`,
      tenantId: input.tenantId,
      provider: options.provider,
      integrationType: options.integrationType,
      externalInstallationId: input.externalInstallationId,
      repoReadPrincipalId: input.repoReadPrincipalId,
      commentWritePrincipalId: input.commentWritePrincipalId,
      integrationAdminPrincipalId: input.integrationAdminPrincipalId,
      status: "ACTIVE"
    };

    this.integrations.set(integration.id, integration);

    for (const repository of input.repositories ?? []) {
      const binding: ControlPlaneRepositoryBinding = {
        id: `repository_binding_${++this.repositorySequence}`,
        tenantId: input.tenantId,
        scmIntegrationId: integration.id,
        providerRepoId: repository.providerRepoId,
        fullName: repository.fullName,
        defaultBranch: repository.defaultBranch,
        isPrivate: repository.isPrivate
      };
      this.repositoryBindings.set(binding.id, binding);
    }

    return integration;
  }

  listIntegrations(tenantId: string): ControlPlaneIntegration[] {
    return Array.from(this.integrations.values()).filter((integration) => integration.tenantId === tenantId);
  }

  removeIntegration(integrationId: string): { deleted: true; id: string } {
    if (!this.integrations.has(integrationId)) {
      throw new NotFoundException("Integration not found");
    }

    this.integrations.delete(integrationId);

    for (const binding of this.repositoryBindings.values()) {
      if (binding.scmIntegrationId === integrationId) {
        this.repositoryBindings.delete(binding.id);
      }
    }

    return { deleted: true, id: integrationId };
  }

  listRepositoryBindings(tenantId: string): ControlPlaneRepositoryBinding[] {
    return Array.from(this.repositoryBindings.values()).filter((binding) => binding.tenantId === tenantId);
  }

  async reconcileGithubInstallationWebhook(
    event: string,
    input: GithubInstallationWebhookInput
  ): Promise<GithubInstallationWebhookAck> {
    const externalInstallationId = String(input.installation?.id ?? "");
    if (!externalInstallationId) {
      throw new BadRequestException("GitHub installation webhook is missing installation id");
    }

    const integration = this.findGithubAppIntegration(externalInstallationId, input.tenantId);

    const addedRepositories = this.normalizeGithubRepositories(
      input.repositories_added ?? (input.action === "created" ? input.repositories : undefined)
    );
    const removedProviderRepoIds = this.normalizeGithubRepositories(input.repositories_removed).map(
      (repository) => repository.providerRepoId
    );

    for (const repository of addedRepositories) {
      this.upsertRepositoryBinding(integration, repository);
    }

    for (const providerRepoId of removedProviderRepoIds) {
      this.removeRepositoryBinding(integration, providerRepoId);
    }

    await this.githubAppInstallationState.reconcileRepositories(
      integration,
      addedRepositories,
      removedProviderRepoIds,
      event,
      input.action
    );

    return {
      acknowledged: true,
      provider: "GITHUB",
      event,
      externalInstallationId,
      addedRepositoryCount: addedRepositories.length,
      removedRepositoryCount: removedProviderRepoIds.length
    };
  }

  createScanRequest(input: CreateScanRequestInput): ControlPlaneScanRequest {
    const repositoryBinding = this.repositoryBindings.get(input.repositoryBindingId);
    if (!repositoryBinding || repositoryBinding.tenantId !== input.tenantId) {
      throw new NotFoundException("Repository binding not found for tenant");
    }

    const isolationClass: IsolationClass =
      input.isolationSignals && shouldEscalateIsolation(input.isolationSignals) ? "HARDENED" : "STANDARD";

    const scanRequest: ControlPlaneScanRequest = {
      id: `scan_request_${++this.scanSequence}`,
      tenantId: input.tenantId,
      repositoryBindingId: input.repositoryBindingId,
      lane: input.lane,
      targetRef: input.targetRef,
      commitSha: input.commitSha,
      policyVersion: input.policyVersion,
      scannerSetVersion: input.scannerSetVersion,
      canonicalKey: buildCanonicalScanKey(input),
      isolationClass,
      status: "QUEUED"
    };

    this.scanRequests.set(scanRequest.id, scanRequest);

    return scanRequest;
  }

  getScanRequest(scanRequestId: string): ControlPlaneScanRequest {
    const scanRequest = this.scanRequests.get(scanRequestId);
    if (!scanRequest) {
      throw new NotFoundException("Scan request not found");
    }

    return scanRequest;
  }

  private findGithubAppIntegration(
    externalInstallationId: string,
    tenantId?: string
  ): ControlPlaneIntegration {
    const integration = Array.from(this.integrations.values()).find(
      (candidate) =>
        candidate.provider === "GITHUB" &&
        candidate.integrationType === "GITHUB_APP" &&
        candidate.externalInstallationId === externalInstallationId &&
        (!tenantId || candidate.tenantId === tenantId)
    );

    if (!integration) {
      throw new NotFoundException("GitHub App installation integration not found");
    }

    return integration;
  }

  private upsertRepositoryBinding(
    integration: ControlPlaneIntegration,
    repository: InstallRepositoryInput
  ): ControlPlaneRepositoryBinding {
    const existing = Array.from(this.repositoryBindings.values()).find(
      (binding) =>
        binding.tenantId === integration.tenantId &&
        binding.scmIntegrationId === integration.id &&
        binding.providerRepoId === repository.providerRepoId
    );

    const binding: ControlPlaneRepositoryBinding = {
      id: existing?.id ?? `repository_binding_${++this.repositorySequence}`,
      tenantId: integration.tenantId,
      scmIntegrationId: integration.id,
      providerRepoId: repository.providerRepoId,
      fullName: repository.fullName,
      defaultBranch: repository.defaultBranch,
      isPrivate: repository.isPrivate
    };

    this.repositoryBindings.set(binding.id, binding);

    return binding;
  }

  private removeRepositoryBinding(
    integration: ControlPlaneIntegration,
    providerRepoId: string
  ): void {
    for (const binding of this.repositoryBindings.values()) {
      if (
        binding.tenantId === integration.tenantId &&
        binding.scmIntegrationId === integration.id &&
        binding.providerRepoId === providerRepoId
      ) {
        this.repositoryBindings.delete(binding.id);
      }
    }
  }

  private normalizeGithubRepositories(
    repositories: GithubWebhookRepositoryInput[] | undefined
  ): InstallRepositoryInput[] {
    return (repositories ?? []).map((repository) => {
      const providerRepoId = String(repository.providerRepoId ?? repository.id ?? "");
      const fullName = repository.fullName ?? repository.full_name ?? "";
      if (!providerRepoId || !fullName) {
        throw new BadRequestException("GitHub repository webhook entry is missing repository id or full name");
      }

      return {
        providerRepoId,
        fullName,
        defaultBranch: repository.defaultBranch ?? repository.default_branch ?? "main",
        isPrivate: repository.isPrivate ?? repository.private ?? true
      };
    });
  }
}
