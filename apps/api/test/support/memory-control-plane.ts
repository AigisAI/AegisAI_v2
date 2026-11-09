import { randomUUID } from "node:crypto";

import { Injectable, NotFoundException } from "@nestjs/common";
import {
  buildCanonicalScanKey,
  shouldEscalateIsolation,
  type IsolationClass
} from "@aegisai/shared";

import type {
  ControlPlaneIntegration,
  ControlPlaneRepositoryBinding,
  ControlPlaneScanRequest,
  CreateScanRequestInput,
  InstallIntegrationInput,
  InstallIntegrationOptions
} from "../../src/control-plane/control-plane.types";

@Injectable()
export class MemoryControlPlaneService {
  private readonly integrations = new Map<string, ControlPlaneIntegration>();
  private readonly integrationIdsByExternalKey = new Map<string, string>();
  private readonly repositoryBindings = new Map<string, ControlPlaneRepositoryBinding>();
  private readonly repositoryIdsByExternalKey = new Map<string, string>();
  private readonly scanRequests = new Map<string, ControlPlaneScanRequest>();
  private readonly scanIdsByCanonicalKey = new Map<string, string>();

  installIntegration(
    input: InstallIntegrationInput,
    options: InstallIntegrationOptions
  ): ControlPlaneIntegration {
    const externalKey = JSON.stringify([
      input.tenantId,
      options.provider,
      input.externalInstallationId
    ]);
    const existingId = this.integrationIdsByExternalKey.get(externalKey);
    const integration: ControlPlaneIntegration = existingId
      ? this.integrations.get(existingId)!
      : {
          id: `integration_${randomUUID()}`,
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
    this.integrationIdsByExternalKey.set(externalKey, integration.id);

    for (const repository of input.repositories ?? []) {
      const repositoryExternalKey = JSON.stringify([
        input.tenantId,
        integration.id,
        repository.providerRepoId
      ]);
      if (this.repositoryIdsByExternalKey.has(repositoryExternalKey)) {
        continue;
      }

      const binding: ControlPlaneRepositoryBinding = {
        id: `repository_binding_${randomUUID()}`,
        tenantId: input.tenantId,
        scmIntegrationId: integration.id,
        providerRepoId: repository.providerRepoId,
        fullName: repository.fullName,
        defaultBranch: repository.defaultBranch,
        isPrivate: repository.isPrivate
      };
      this.repositoryBindings.set(binding.id, binding);
      this.repositoryIdsByExternalKey.set(repositoryExternalKey, binding.id);
    }

    return integration;
  }

  listIntegrations(tenantId: string): ControlPlaneIntegration[] {
    return Array.from(this.integrations.values()).filter((integration) => integration.tenantId === tenantId);
  }

  removeIntegration(tenantId: string, integrationId: string): { deleted: true; id: string } {
    const integration = this.integrations.get(integrationId);
    if (!integration || integration.tenantId !== tenantId) {
      throw new NotFoundException("Integration not found");
    }

    this.integrations.delete(integrationId);
    this.integrationIdsByExternalKey.delete(
      JSON.stringify([tenantId, integration.provider, integration.externalInstallationId])
    );

    for (const binding of this.repositoryBindings.values()) {
      if (binding.scmIntegrationId === integrationId) {
        this.repositoryBindings.delete(binding.id);
        this.repositoryIdsByExternalKey.delete(
          JSON.stringify([tenantId, integrationId, binding.providerRepoId])
        );

        for (const scanRequest of this.scanRequests.values()) {
          if (scanRequest.repositoryBindingId === binding.id) {
            this.scanRequests.delete(scanRequest.id);
            this.scanIdsByCanonicalKey.delete(scanRequest.canonicalKey);
          }
        }
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

    const canonicalKey = buildCanonicalScanKey(input);
    const existingScanRequestId = this.scanIdsByCanonicalKey.get(canonicalKey);
    if (existingScanRequestId) {
      return this.scanRequests.get(existingScanRequestId)!;
    }

    const scanRequest: ControlPlaneScanRequest = {
      id: `scan_request_${randomUUID()}`,
      tenantId: input.tenantId,
      repositoryBindingId: input.repositoryBindingId,
      lane: input.lane,
      targetRef: input.targetRef,
      commitSha: input.commitSha,
      policyVersion: input.policyVersion,
      scannerSetVersion: input.scannerSetVersion,
      canonicalKey,
      isolationClass,
      status: "QUEUED"
    };

    this.scanRequests.set(scanRequest.id, scanRequest);
    this.scanIdsByCanonicalKey.set(canonicalKey, scanRequest.id);

    return scanRequest;
  }

  getScanRequest(tenantId: string, scanRequestId: string): ControlPlaneScanRequest {
    const scanRequest = this.scanRequests.get(scanRequestId);
    if (!scanRequest || scanRequest.tenantId !== tenantId) {
      throw new NotFoundException("Scan request not found");
    }

    return scanRequest;
  }
}
