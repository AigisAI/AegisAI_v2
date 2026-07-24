import { ConflictException, NotFoundException } from '@nestjs/common';
import type { ScmProvider, SastUserVisiblePlanningState } from '@aegisai/shared';

import {
  ControlPlaneScanRequestStore,
  isScanRequestStatusTransitionAllowed,
  type ControlPlaneIntegrationContext,
  type ControlPlaneIntegrationContextInput,
  type ControlPlaneRepositoryContext,
  type ControlPlaneScanRequestCreateInput,
  type ControlPlaneScanRequestPlanningInput,
  type ControlPlaneScanRequestStatusInput
} from '../../src/control-plane/control-plane-scan-request.store';
import type {
  ControlPlaneIntegration,
  ControlPlaneRepositoryBinding,
  ControlPlaneScanRequest
} from '../../src/control-plane/control-plane.types';

export class InMemoryControlPlaneScanRequestStore extends ControlPlaneScanRequestStore {
  private readonly requests = new Map<string, ControlPlaneScanRequest>();
  private readonly integrations = new Map<string, ControlPlaneIntegration>();
  private readonly repositoryBindings = new Map<string, ControlPlaneRepositoryBinding>();
  private readonly revokedRepositoryBindingIds = new Set<string>();
  private lockTail: Promise<void> = Promise.resolve();

  async persistIntegrationContext(
    input: ControlPlaneIntegrationContextInput
  ): Promise<ControlPlaneIntegrationContext> {
    return this.exclusive(() => {
      const existingIntegration = Array.from(this.integrations.values()).find(
        (candidate) =>
          candidate.tenantId === input.integration.tenantId &&
          candidate.provider === input.integration.provider &&
          candidate.externalInstallationId === input.integration.externalInstallationId
      );
      const integration: ControlPlaneIntegration = {
        ...input.integration,
        id: existingIntegration?.id ?? input.integration.id
      };
      this.integrations.set(integration.id, integration);

      const repositoryBindings = input.repositoryBindings.map((candidate) => {
        const existing = Array.from(this.repositoryBindings.values()).find(
          (binding) =>
            binding.tenantId === integration.tenantId &&
            binding.scmIntegrationId === integration.id &&
            binding.providerRepoId === candidate.providerRepoId
        );
        const repositoryBinding: ControlPlaneRepositoryBinding = {
          ...candidate,
          id: existing?.id ?? candidate.id,
          tenantId: integration.tenantId,
          scmIntegrationId: integration.id
        };
        this.repositoryBindings.set(repositoryBinding.id, repositoryBinding);
        this.revokedRepositoryBindingIds.delete(repositoryBinding.id);
        return { ...repositoryBinding };
      });

      return { integration: { ...integration }, repositoryBindings };
    });
  }

  async findRepositoryContext(
    tenantId: string,
    repositoryBindingId: string
  ): Promise<ControlPlaneRepositoryContext | null> {
    const repositoryBinding = this.repositoryBindings.get(repositoryBindingId);
    if (
      !repositoryBinding ||
      repositoryBinding.tenantId !== tenantId ||
      this.revokedRepositoryBindingIds.has(repositoryBindingId)
    ) {
      return null;
    }
    const integration = this.integrations.get(repositoryBinding.scmIntegrationId);
    if (!integration || integration.tenantId !== tenantId || integration.status !== 'ACTIVE') {
      return null;
    }

    return {
      integration: { ...integration },
      repositoryBinding: { ...repositoryBinding }
    };
  }

  async findIntegrationByExternalInstallation(
    provider: ScmProvider,
    externalInstallationId: string
  ): Promise<ControlPlaneIntegration | null> {
    const integration = Array.from(this.integrations.values()).find(
      (candidate) =>
        candidate.provider === provider &&
        candidate.externalInstallationId === externalInstallationId &&
        candidate.status === 'ACTIVE'
    );
    return integration ? { ...integration } : null;
  }

  async listIntegrations(tenantId: string): Promise<ControlPlaneIntegration[]> {
    return Array.from(this.integrations.values())
      .filter((integration) => integration.tenantId === tenantId && integration.status === 'ACTIVE')
      .map((integration) => ({ ...integration }));
  }

  async listRepositoryBindings(
    tenantId: string
  ): Promise<ControlPlaneRepositoryBinding[]> {
    return Array.from(this.repositoryBindings.values())
      .filter((binding) => {
        const integration = this.integrations.get(binding.scmIntegrationId);
        return (
          binding.tenantId === tenantId &&
          !this.revokedRepositoryBindingIds.has(binding.id) &&
          integration?.status === 'ACTIVE'
        );
      })
      .map((binding) => ({ ...binding }));
  }

  async revokeIntegration(tenantId: string, integrationId: string): Promise<boolean> {
    return this.exclusive(() => {
      const integration = this.integrations.get(integrationId);
      if (!integration || integration.tenantId !== tenantId) {
        return false;
      }
      this.integrations.set(integrationId, { ...integration, status: 'REVOKED' });
      for (const binding of this.repositoryBindings.values()) {
        if (binding.scmIntegrationId === integrationId) {
          this.revokedRepositoryBindingIds.add(binding.id);
        }
      }
      return true;
    });
  }

  async revokeRepositoryBindings(
    tenantId: string,
    integrationId: string,
    providerRepoIds: string[]
  ): Promise<void> {
    await this.exclusive(() => {
      const providerRepoIdSet = new Set(providerRepoIds);
      for (const binding of this.repositoryBindings.values()) {
        if (
          binding.tenantId === tenantId &&
          binding.scmIntegrationId === integrationId &&
          providerRepoIdSet.has(binding.providerRepoId)
        ) {
          this.revokedRepositoryBindingIds.add(binding.id);
        }
      }
    });
  }

  async createOrGet(
    input: ControlPlaneScanRequestCreateInput
  ): Promise<ControlPlaneScanRequest> {
    return this.exclusive(() => {
      const repositoryBinding = this.repositoryBindings.get(input.repositoryBinding.id);
      const integration = this.integrations.get(input.integration.id);
      if (
        !repositoryBinding ||
        !integration ||
        repositoryBinding.tenantId !== input.scanRequest.tenantId ||
        integration.tenantId !== input.scanRequest.tenantId ||
        integration.status !== 'ACTIVE'
      ) {
        throw new ConflictException(
          'Durable repository binding is revoked or does not match runtime state.'
        );
      }

      const existing = Array.from(this.requests.values()).find(
        (request) => request.canonicalKey === input.scanRequest.canonicalKey
      );
      if (existing) {
        return this.cloneRequest(existing);
      }

      const stored = this.cloneRequest(input.scanRequest);
      this.requests.set(stored.id, stored);
      return this.cloneRequest(stored);
    });
  }

  async find(
    tenantId: string,
    scanRequestId: string
  ): Promise<ControlPlaneScanRequest | null> {
    const request = this.requests.get(scanRequestId);
    return request?.tenantId === tenantId ? this.cloneRequest(request) : null;
  }

  async recordPlanningState(
    input: ControlPlaneScanRequestPlanningInput
  ): Promise<ControlPlaneScanRequest> {
    return this.exclusive(() => {
      const request = this.requests.get(input.scanRequestId);
      if (!request || request.tenantId !== input.tenantId) {
        throw new NotFoundException('Scan request not found');
      }

      const nextPlanning: SastUserVisiblePlanningState = {
        ...input.planning,
        canonicalScanKey:
          input.planning.canonicalScanKey ?? request.sastPlanning?.canonicalScanKey,
        reasonCodes: [...input.planning.reasonCodes]
      };
      this.assertPlanningMutationAllowed(request, nextPlanning);
      if (request.sastPlanning?.state !== 'ADMITTED') {
        request.sastPlanning = nextPlanning;
        request.status =
          nextPlanning.state === 'ADMITTED'
            ? 'QUEUED'
            : nextPlanning.state === 'DEFERRED'
              ? 'PLANNING'
              : 'FAILED';
      }

      return this.cloneRequest(request);
    });
  }

  async updateStatus(
    input: ControlPlaneScanRequestStatusInput
  ): Promise<ControlPlaneScanRequest> {
    return this.exclusive(() => {
      const request = this.requests.get(input.scanRequestId);
      if (!request || request.tenantId !== input.tenantId) {
        throw new NotFoundException('Scan request not found');
      }
      if (!isScanRequestStatusTransitionAllowed(request.status, input.status)) {
        throw new ConflictException(
          `Scan request status cannot transition from ${request.status} to ${input.status}.`
        );
      }
      request.status = input.status;
      return this.cloneRequest(request);
    });
  }

  private assertPlanningMutationAllowed(
    request: ControlPlaneScanRequest,
    nextPlanning: SastUserVisiblePlanningState
  ): void {
    if (request.status !== 'QUEUED' && request.status !== 'PLANNING') {
      throw new ConflictException('SAST planning cannot rewrite a terminal or running scan.');
    }
    if (
      nextPlanning.canonicalScanKey !== undefined &&
      request.sastPlanning?.canonicalScanKey &&
      nextPlanning.canonicalScanKey !== request.sastPlanning.canonicalScanKey
    ) {
      throw new ConflictException('SAST canonical planning identity is immutable.');
    }
    if (
      request.sastPlanning?.state === 'ADMITTED' &&
      !this.isEquivalentPlanning(request.sastPlanning, nextPlanning)
    ) {
      throw new ConflictException('An admitted SAST planning decision is immutable.');
    }
  }

  private isEquivalentPlanning(
    left: SastUserVisiblePlanningState,
    right: SastUserVisiblePlanningState
  ): boolean {
    return (
      left.state === right.state &&
      left.profileId === right.profileId &&
      left.coverageClaim === right.coverageClaim &&
      left.queueName === right.queueName &&
      left.queuePolicyVersion === right.queuePolicyVersion &&
      left.queuePolicyDigest === right.queuePolicyDigest &&
      left.canonicalScanKey === right.canonicalScanKey &&
      left.retryAfterSeconds === right.retryAfterSeconds &&
      left.reasonCodes.length === right.reasonCodes.length &&
      left.reasonCodes.every((reasonCode, index) => reasonCode === right.reasonCodes[index])
    );
  }

  private cloneRequest(request: ControlPlaneScanRequest): ControlPlaneScanRequest {
    return {
      ...request,
      sastPlanning: request.sastPlanning
        ? { ...request.sastPlanning, reasonCodes: [...request.sastPlanning.reasonCodes] }
        : undefined
    };
  }

  private async exclusive<T>(operation: () => T): Promise<T> {
    const previous = this.lockTail;
    let release!: () => void;
    this.lockTail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return operation();
    } finally {
      release();
    }
  }
}
