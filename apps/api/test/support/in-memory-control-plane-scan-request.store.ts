import { ConflictException, NotFoundException } from '@nestjs/common';
import type { SastUserVisiblePlanningState } from '@aegisai/shared';

import {
  ControlPlaneScanRequestStore,
  type ControlPlaneScanRequestCreateInput,
  type ControlPlaneScanRequestPlanningInput,
  type ControlPlaneScanRequestStatusInput
} from '../../src/control-plane/control-plane-scan-request.store';
import type { ControlPlaneScanRequest } from '../../src/control-plane/control-plane.types';

export class InMemoryControlPlaneScanRequestStore extends ControlPlaneScanRequestStore {
  private readonly requests = new Map<string, ControlPlaneScanRequest>();
  private lockTail: Promise<void> = Promise.resolve();

  async createOrGet(
    input: ControlPlaneScanRequestCreateInput
  ): Promise<ControlPlaneScanRequest> {
    return this.exclusive(() => {
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
