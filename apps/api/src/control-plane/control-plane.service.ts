import { Injectable, NotFoundException } from "@nestjs/common";
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
  InstallIntegrationInput,
  InstallIntegrationOptions
} from "./control-plane.types";

@Injectable()
export class ControlPlaneService {
  private readonly integrations = new Map<string, ControlPlaneIntegration>();
  private readonly repositoryBindings = new Map<string, ControlPlaneRepositoryBinding>();
  private readonly scanRequests = new Map<string, ControlPlaneScanRequest>();

  private integrationSequence = 0;
  private repositorySequence = 0;
  private scanSequence = 0;

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
}
