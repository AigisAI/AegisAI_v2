import type { ScmProvider, SastUserVisiblePlanningState } from '@aegisai/shared';

import type {
  ControlPlaneIntegration,
  ControlPlaneRepositoryBinding,
  ControlPlaneScanRequest
} from './control-plane.types';

export interface ControlPlaneScanRequestCreateInput {
  scanRequest: ControlPlaneScanRequest;
  repositoryBinding: ControlPlaneRepositoryBinding;
  integration: ControlPlaneIntegration;
}

export interface ControlPlaneIntegrationContextInput {
  integration: ControlPlaneIntegration;
  repositoryBindings: ControlPlaneRepositoryBinding[];
}

export interface ControlPlaneIntegrationContext {
  integration: ControlPlaneIntegration;
  repositoryBindings: ControlPlaneRepositoryBinding[];
}

export interface ControlPlaneRepositoryContext {
  integration: ControlPlaneIntegration;
  repositoryBinding: ControlPlaneRepositoryBinding;
}

export interface ControlPlaneScanRequestPlanningInput {
  tenantId: string;
  scanRequestId: string;
  planning: SastUserVisiblePlanningState;
}

export interface ControlPlaneScanRequestStatusInput {
  tenantId: string;
  scanRequestId: string;
  status: ControlPlaneScanRequest['status'];
}

export abstract class ControlPlaneScanRequestStore {
  abstract persistIntegrationContext(
    input: ControlPlaneIntegrationContextInput
  ): Promise<ControlPlaneIntegrationContext>;

  abstract findRepositoryContext(
    tenantId: string,
    repositoryBindingId: string
  ): Promise<ControlPlaneRepositoryContext | null>;

  abstract findIntegrationByExternalInstallation(
    provider: ScmProvider,
    externalInstallationId: string
  ): Promise<ControlPlaneIntegration | null>;

  abstract listIntegrations(tenantId: string): Promise<ControlPlaneIntegration[]>;

  abstract listRepositoryBindings(
    tenantId: string
  ): Promise<ControlPlaneRepositoryBinding[]>;

  abstract revokeIntegration(tenantId: string, integrationId: string): Promise<boolean>;

  abstract revokeRepositoryBindings(
    tenantId: string,
    integrationId: string,
    providerRepoIds: string[]
  ): Promise<void>;

  abstract createOrGet(
    input: ControlPlaneScanRequestCreateInput
  ): Promise<ControlPlaneScanRequest>;

  abstract find(
    tenantId: string,
    scanRequestId: string
  ): Promise<ControlPlaneScanRequest | null>;

  abstract recordPlanningState(
    input: ControlPlaneScanRequestPlanningInput
  ): Promise<ControlPlaneScanRequest>;

  abstract updateStatus(
    input: ControlPlaneScanRequestStatusInput
  ): Promise<ControlPlaneScanRequest>;
}

export const isScanRequestStatusTransitionAllowed = (
  current: ControlPlaneScanRequest['status'],
  next: ControlPlaneScanRequest['status']
): boolean => {
  if (current === next) {
    return true;
  }

  const allowed: Record<
    ControlPlaneScanRequest['status'],
    readonly ControlPlaneScanRequest['status'][]
  > = {
    QUEUED: ['PLANNING', 'RUNNING', 'FAILED', 'CANCELED'],
    PLANNING: ['QUEUED', 'FAILED', 'CANCELED'],
    RUNNING: ['COMPLETED', 'FAILED', 'CANCELED'],
    COMPLETED: [],
    FAILED: [],
    CANCELED: []
  };

  return allowed[current].includes(next);
};
