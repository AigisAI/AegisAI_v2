import { Injectable } from "@nestjs/common";
import { Prisma } from "@prisma/client";

import { PrismaService } from "../prisma/prisma.service";
import type {
  ControlPlaneIntegration,
  InstallRepositoryInput
} from "./control-plane.types";

@Injectable()
export class GithubAppInstallationStateService {
  constructor(private readonly prisma: PrismaService) {}

  async persistInstallation(
    integration: ControlPlaneIntegration,
    repositories: InstallRepositoryInput[]
  ): Promise<void> {
    await this.upsertTenant(integration.tenantId);

    await this.prisma.scmIntegration.upsert({
      where: {
        tenantId_provider_externalInstallationId: {
          tenantId: integration.tenantId,
          provider: "GITHUB",
          externalInstallationId: integration.externalInstallationId
        }
      },
      update: {
        repoReadPrincipalId: integration.repoReadPrincipalId,
        commentWritePrincipalId: integration.commentWritePrincipalId,
        integrationAdminPrincipalId: integration.integrationAdminPrincipalId,
        status: "ACTIVE"
      },
      create: {
        id: integration.id,
        tenantId: integration.tenantId,
        provider: "GITHUB",
        integrationType: "GITHUB_APP",
        externalInstallationId: integration.externalInstallationId,
        repoReadPrincipalId: integration.repoReadPrincipalId,
        commentWritePrincipalId: integration.commentWritePrincipalId,
        integrationAdminPrincipalId: integration.integrationAdminPrincipalId,
        status: "ACTIVE"
      }
    });

    for (const repository of repositories) {
      await this.upsertRepositoryBinding(integration, repository);
    }

    await this.recordAuditEvent(
      integration,
      "github_app.installation.persisted",
      {
        externalInstallationId: integration.externalInstallationId,
        repositoryCount: repositories.length
      }
    );
  }

  async reconcileRepositories(
    integration: ControlPlaneIntegration,
    addedRepositories: InstallRepositoryInput[],
    removedProviderRepoIds: string[],
    event: string,
    action: string
  ): Promise<void> {
    await this.upsertTenant(integration.tenantId);

    for (const repository of addedRepositories) {
      await this.upsertRepositoryBinding(integration, repository);
    }

    if (removedProviderRepoIds.length > 0) {
      await this.prisma.repositoryBinding.deleteMany({
        where: {
          tenantId: integration.tenantId,
          scmIntegrationId: integration.id,
          providerRepoId: { in: removedProviderRepoIds }
        }
      });
    }

    await this.recordAuditEvent(
      integration,
      "github_app.installation_repositories.reconciled",
      {
        event,
        action,
        addedRepositoryCount: addedRepositories.length,
        removedRepositoryCount: removedProviderRepoIds.length
      }
    );
  }

  private async upsertTenant(tenantId: string): Promise<void> {
    await this.prisma.tenant.upsert({
      where: { id: tenantId },
      update: {},
      create: {
        id: tenantId,
        slug: this.toTenantSlug(tenantId),
        name: tenantId,
        status: "ACTIVE"
      }
    });
  }

  private async upsertRepositoryBinding(
    integration: ControlPlaneIntegration,
    repository: InstallRepositoryInput
  ): Promise<void> {
    await this.prisma.repositoryBinding.upsert({
      where: {
        tenantId_scmIntegrationId_providerRepoId: {
          tenantId: integration.tenantId,
          scmIntegrationId: integration.id,
          providerRepoId: repository.providerRepoId
        }
      },
      update: {
        fullName: repository.fullName,
        defaultBranch: repository.defaultBranch,
        isPrivate: repository.isPrivate
      },
      create: {
        tenantId: integration.tenantId,
        scmIntegrationId: integration.id,
        providerRepoId: repository.providerRepoId,
        fullName: repository.fullName,
        defaultBranch: repository.defaultBranch,
        isPrivate: repository.isPrivate
      }
    });
  }

  private async recordAuditEvent(
    integration: ControlPlaneIntegration,
    eventType: string,
    metadata: Prisma.InputJsonObject
  ): Promise<void> {
    await this.prisma.auditEvent.create({
      data: {
        tenantId: integration.tenantId,
        eventType,
        actor: "github-app",
        targetType: "scm_integration",
        targetId: integration.id,
        metadata
      }
    });
  }

  private toTenantSlug(tenantId: string): string {
    return tenantId.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "tenant";
  }
}
