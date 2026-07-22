import type { SastUserVisiblePlanningState } from '@aegisai/shared';

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
