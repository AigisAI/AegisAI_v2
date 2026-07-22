import { ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import {
  SAST_COVERAGE_CLAIMS,
  SAST_PLANNING_REASON_CODES,
  SAST_PLANNING_STATES,
  SAST_PROFILE_IDS,
  type SastPlanningReasonCode,
  type SastUserVisiblePlanningState
} from '@aegisai/shared';

import { PrismaService } from '../prisma/prisma.service';
import {
  ControlPlaneScanRequestStore,
  type ControlPlaneScanRequestCreateInput,
  type ControlPlaneScanRequestPlanningInput,
  type ControlPlaneScanRequestStatusInput
} from './control-plane-scan-request.store';
import type { ControlPlaneScanRequest } from './control-plane.types';

interface PersistedScanRequestRow {
  id: string;
  tenantId: string;
  repositoryBindingId: string;
  lane: 'FAST' | 'DEEP';
  targetRef: string;
  commitSha: string;
  policyVersion: string;
  scannerSetVersion: string;
  canonicalKey: string;
  status: ControlPlaneScanRequest['status'];
  isolationClass: ControlPlaneScanRequest['isolationClass'];
  sastPlanning: Prisma.JsonValue | null;
}

@Injectable()
export class PrismaControlPlaneScanRequestStore extends ControlPlaneScanRequestStore {
  private static readonly MAX_TRANSACTION_ATTEMPTS = 5;

  constructor(private readonly prisma: PrismaService) {
    super();
  }

  async createOrGet(
    input: ControlPlaneScanRequestCreateInput
  ): Promise<ControlPlaneScanRequest> {
    return this.runSerializable(async (transaction) => {
      await transaction.tenant.upsert({
        where: { id: input.scanRequest.tenantId },
        update: {},
        create: {
          id: input.scanRequest.tenantId,
          slug: this.toTenantSlug(input.scanRequest.tenantId),
          name: input.scanRequest.tenantId,
          status: 'ACTIVE'
        }
      });

      const integration = await transaction.scmIntegration.upsert({
        where: {
          tenantId_provider_externalInstallationId: {
            tenantId: input.integration.tenantId,
            provider: input.integration.provider,
            externalInstallationId: input.integration.externalInstallationId
          }
        },
        update: {
          repoReadPrincipalId: input.integration.repoReadPrincipalId,
          commentWritePrincipalId: input.integration.commentWritePrincipalId,
          integrationAdminPrincipalId: input.integration.integrationAdminPrincipalId,
          status: input.integration.status
        },
        create: {
          id: input.integration.id,
          tenantId: input.integration.tenantId,
          provider: input.integration.provider,
          integrationType: input.integration.integrationType,
          externalInstallationId: input.integration.externalInstallationId,
          repoReadPrincipalId: input.integration.repoReadPrincipalId,
          commentWritePrincipalId: input.integration.commentWritePrincipalId,
          integrationAdminPrincipalId: input.integration.integrationAdminPrincipalId,
          status: input.integration.status
        }
      });
      if (integration.id !== input.integration.id) {
        throw new ConflictException('Durable SCM integration identity does not match runtime state.');
      }

      const repositoryBinding = await transaction.repositoryBinding.upsert({
        where: {
          tenantId_scmIntegrationId_providerRepoId: {
            tenantId: input.repositoryBinding.tenantId,
            scmIntegrationId: input.repositoryBinding.scmIntegrationId,
            providerRepoId: input.repositoryBinding.providerRepoId
          }
        },
        update: {
          fullName: input.repositoryBinding.fullName,
          defaultBranch: input.repositoryBinding.defaultBranch,
          isPrivate: input.repositoryBinding.isPrivate
        },
        create: {
          id: input.repositoryBinding.id,
          tenantId: input.repositoryBinding.tenantId,
          scmIntegrationId: input.repositoryBinding.scmIntegrationId,
          providerRepoId: input.repositoryBinding.providerRepoId,
          fullName: input.repositoryBinding.fullName,
          defaultBranch: input.repositoryBinding.defaultBranch,
          isPrivate: input.repositoryBinding.isPrivate
        }
      });
      if (repositoryBinding.id !== input.repositoryBinding.id) {
        throw new ConflictException(
          'Durable repository binding identity does not match runtime state.'
        );
      }

      const existing = await transaction.scanRequest.findUnique({
        where: { canonicalKey: input.scanRequest.canonicalKey }
      });
      if (existing) {
        const mapped = this.toScanRequest(existing);
        this.assertSameImmutableRequest(mapped, input.scanRequest);
        return mapped;
      }

      const created = await transaction.scanRequest.create({
        data: {
          id: input.scanRequest.id,
          tenantId: input.scanRequest.tenantId,
          repositoryBindingId: input.scanRequest.repositoryBindingId,
          lane: input.scanRequest.lane,
          targetRef: input.scanRequest.targetRef,
          commitSha: input.scanRequest.commitSha,
          policyVersion: input.scanRequest.policyVersion,
          scannerSetVersion: input.scanRequest.scannerSetVersion,
          canonicalKey: input.scanRequest.canonicalKey,
          status: input.scanRequest.status,
          isolationClass: input.scanRequest.isolationClass
        }
      });

      return this.toScanRequest(created);
    });
  }

  async find(
    tenantId: string,
    scanRequestId: string
  ): Promise<ControlPlaneScanRequest | null> {
    const row = await this.prisma.scanRequest.findFirst({
      where: { id: scanRequestId, tenantId }
    });
    return row ? this.toScanRequest(row) : null;
  }

  async recordPlanningState(
    input: ControlPlaneScanRequestPlanningInput
  ): Promise<ControlPlaneScanRequest> {
    return this.runSerializable(async (transaction) => {
      const row = await transaction.scanRequest.findUnique({
        where: { id: input.scanRequestId }
      });
      if (!row || row.tenantId !== input.tenantId) {
        throw new NotFoundException('Scan request not found');
      }

      const current = this.toScanRequest(row);
      const nextPlanning = this.mergePlanning(current.sastPlanning, input.planning);
      this.assertPlanningMutationAllowed(current, nextPlanning);
      if (current.sastPlanning?.state === 'ADMITTED') {
        return current;
      }

      const updated = await transaction.scanRequest.update({
        where: { id: current.id },
        data: {
          sastPlanning: this.toJson(nextPlanning),
          status: this.statusForPlanning(nextPlanning)
        }
      });
      return this.toScanRequest(updated);
    });
  }

  async updateStatus(
    input: ControlPlaneScanRequestStatusInput
  ): Promise<ControlPlaneScanRequest> {
    const updated = await this.prisma.scanRequest.updateMany({
      where: { id: input.scanRequestId, tenantId: input.tenantId },
      data: { status: input.status }
    });
    if (updated.count !== 1) {
      throw new NotFoundException('Scan request not found');
    }

    const row = await this.prisma.scanRequest.findUniqueOrThrow({
      where: { id: input.scanRequestId }
    });
    return this.toScanRequest(row);
  }

  private async runSerializable<T>(
    operation: (transaction: Prisma.TransactionClient) => Promise<T>
  ): Promise<T> {
    let lastError: unknown;
    for (
      let attempt = 1;
      attempt <= PrismaControlPlaneScanRequestStore.MAX_TRANSACTION_ATTEMPTS;
      attempt += 1
    ) {
      try {
        return await this.prisma.$transaction(operation, {
          isolationLevel: Prisma.TransactionIsolationLevel.Serializable,
          maxWait: 5_000,
          timeout: 10_000
        });
      } catch (error) {
        lastError = error;
        if (
          !(error instanceof Prisma.PrismaClientKnownRequestError) ||
          (error.code !== 'P2002' && error.code !== 'P2034') ||
          attempt === PrismaControlPlaneScanRequestStore.MAX_TRANSACTION_ATTEMPTS
        ) {
          throw error;
        }
      }
    }

    throw lastError;
  }

  private toScanRequest(row: PersistedScanRequestRow): ControlPlaneScanRequest {
    return {
      id: row.id,
      tenantId: row.tenantId,
      repositoryBindingId: row.repositoryBindingId,
      lane: row.lane,
      targetRef: row.targetRef,
      commitSha: row.commitSha,
      policyVersion: row.policyVersion,
      scannerSetVersion: row.scannerSetVersion,
      canonicalKey: row.canonicalKey,
      status: row.status,
      isolationClass: row.isolationClass,
      sastPlanning: row.sastPlanning === null ? undefined : this.parsePlanning(row.sastPlanning)
    };
  }

  private parsePlanning(value: Prisma.JsonValue): SastUserVisiblePlanningState {
    if (!value || Array.isArray(value) || typeof value !== 'object') {
      throw new Error('Persisted SAST planning state is invalid.');
    }
    const candidate = value as Record<string, Prisma.JsonValue>;
    const reasonCodes = candidate.reasonCodes;
    if (
      typeof candidate.state !== 'string' ||
      !(SAST_PLANNING_STATES as readonly string[]).includes(candidate.state) ||
      typeof candidate.coverageClaim !== 'string' ||
      !(SAST_COVERAGE_CLAIMS as readonly string[]).includes(candidate.coverageClaim) ||
      !Array.isArray(reasonCodes) ||
      !reasonCodes.every(
        (reasonCode): reasonCode is SastPlanningReasonCode =>
          typeof reasonCode === 'string' &&
          (SAST_PLANNING_REASON_CODES as readonly string[]).includes(reasonCode)
      ) ||
      typeof candidate.updatedAt !== 'string' ||
      !Number.isFinite(Date.parse(candidate.updatedAt))
    ) {
      throw new Error('Persisted SAST planning state is invalid.');
    }

    const profileId =
      typeof candidate.profileId === 'string' &&
      (SAST_PROFILE_IDS as readonly string[]).includes(candidate.profileId)
        ? (candidate.profileId as SastUserVisiblePlanningState['profileId'])
        : undefined;
    const canonicalScanKey =
      typeof candidate.canonicalScanKey === 'string' &&
      /^sha256:[a-f0-9]{64}$/u.test(candidate.canonicalScanKey)
        ? (candidate.canonicalScanKey as `sha256:${string}`)
        : undefined;

    return {
      state: candidate.state as SastUserVisiblePlanningState['state'],
      profileId,
      coverageClaim: candidate.coverageClaim as SastUserVisiblePlanningState['coverageClaim'],
      queueName:
        candidate.queueName === 'scan.fast.v1' || candidate.queueName === 'scan.deep.v1'
          ? candidate.queueName
          : undefined,
      queuePolicyVersion:
        typeof candidate.queuePolicyVersion === 'string'
          ? candidate.queuePolicyVersion
          : undefined,
      queuePolicyDigest:
        typeof candidate.queuePolicyDigest === 'string' &&
        /^sha256:[a-f0-9]{64}$/u.test(candidate.queuePolicyDigest)
          ? (candidate.queuePolicyDigest as `sha256:${string}`)
          : undefined,
      canonicalScanKey,
      reasonCodes: [...reasonCodes],
      retryAfterSeconds:
        typeof candidate.retryAfterSeconds === 'number'
          ? candidate.retryAfterSeconds
          : undefined,
      updatedAt: new Date(candidate.updatedAt).toISOString()
    };
  }

  private mergePlanning(
    existing: SastUserVisiblePlanningState | undefined,
    incoming: SastUserVisiblePlanningState
  ): SastUserVisiblePlanningState {
    return {
      ...incoming,
      canonicalScanKey: incoming.canonicalScanKey ?? existing?.canonicalScanKey,
      reasonCodes: [...incoming.reasonCodes]
    };
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

  private statusForPlanning(
    planning: SastUserVisiblePlanningState
  ): ControlPlaneScanRequest['status'] {
    return planning.state === 'ADMITTED'
      ? 'QUEUED'
      : planning.state === 'DEFERRED'
        ? 'PLANNING'
        : 'FAILED';
  }

  private assertSameImmutableRequest(
    left: ControlPlaneScanRequest,
    right: ControlPlaneScanRequest
  ): void {
    if (
      left.tenantId !== right.tenantId ||
      left.repositoryBindingId !== right.repositoryBindingId ||
      left.lane !== right.lane ||
      left.targetRef !== right.targetRef ||
      left.commitSha !== right.commitSha ||
      left.policyVersion !== right.policyVersion ||
      left.scannerSetVersion !== right.scannerSetVersion ||
      left.canonicalKey !== right.canonicalKey ||
      left.isolationClass !== right.isolationClass
    ) {
      throw new ConflictException('Durable scan request identity is immutable.');
    }
  }

  private toJson(value: unknown): Prisma.InputJsonValue {
    return JSON.parse(JSON.stringify(value)) as Prisma.InputJsonValue;
  }

  private toTenantSlug(tenantId: string): string {
    return tenantId.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'tenant';
  }
}
