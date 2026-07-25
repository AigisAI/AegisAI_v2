import {
  SAST_SCANNER_KINDS,
  isSastScanPlanValid,
  type SastScannerKind,
  type SastScanPlan
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';

import { PrismaService } from '../prisma/prisma.service';
import {
  type AbortSastArtifactIngressInput,
  type CompleteSastArtifactIngressInput,
  type RejectSastArtifactIngressInput,
  type ReserveSastArtifactIngressInput,
  SastArtifactIngressReplayConflictError,
  SastArtifactIngressReservationRetryError,
  type SastArtifactIngressReservation,
  type SastArtifactIngressRejectionAudit,
  SastArtifactIngressStateConflictError,
  type SastArtifactIngressExpectedBinding,
  SastArtifactIngressStore
} from './sast-artifact-ingress.store';

@Injectable()
export class PrismaSastArtifactIngressStore
  extends SastArtifactIngressStore
{
  constructor(private readonly prisma: PrismaService) {
    super();
  }

  async loadExpectedBinding(
    scanRequestId: string,
    scannerRunId: string
  ): Promise<SastArtifactIngressExpectedBinding | null> {
    const scannerRun = await this.prisma.scannerRun.findFirst({
      where: {
        id: scannerRunId,
        scanRequestId
      },
      select: {
        id: true,
        scanner: true,
        status: true,
        artifactMetadata: true,
        preflightAttestationRef: true,
        preflightInventoryDigest: true,
        attempt: {
          select: {
            id: true,
            workloadIdentityRef: true,
            stage: true,
            attemptDeadlineAt: true
          }
        },
        scanRequest: {
          select: {
            sastQueueReservation: {
              select: {
                immutablePlan: true
              }
            }
          }
        }
      }
    });

    const plan = scannerRun?.scanRequest.sastQueueReservation
      ?.immutablePlan as unknown as SastScanPlan | undefined;
    const artifactMetadata = this.asRecord(scannerRun?.artifactMetadata);
    const artifactRef = artifactMetadata?.artifactRef;
    if (
      !scannerRun?.attempt ||
      !plan ||
      !isSastScanPlanValid(plan) ||
      !SAST_SCANNER_KINDS.includes(scannerRun.scanner as SastScannerKind) ||
      typeof scannerRun.preflightAttestationRef !== 'string' ||
      !this.isDigest(scannerRun.preflightInventoryDigest) ||
      typeof artifactRef !== 'string' ||
      artifactRef.length === 0
    ) {
      return null;
    }

    return {
      plan,
      attemptId: scannerRun.attempt.id,
      scannerRunId: scannerRun.id,
      workloadIdentityRef: scannerRun.attempt.workloadIdentityRef,
      preflightAttestationRef: scannerRun.preflightAttestationRef,
      preflightInventoryDigest: scannerRun.preflightInventoryDigest,
      scanner: scannerRun.scanner as SastScannerKind,
      artifactRef,
      attemptStage: scannerRun.attempt.stage,
      attemptDeadlineAt: scannerRun.attempt.attemptDeadlineAt.toISOString(),
      scannerRunStatus: scannerRun.status
    };
  }

  async reserve(
    input: Readonly<ReserveSastArtifactIngressInput>
  ): Promise<SastArtifactIngressReservation> {
    try {
      return await this.prisma.$transaction(
        async (transaction) => {
          const attempt = await transaction.sastScanAttempt.findFirst({
            where: {
              id: input.expected.attemptId,
              tenantId: input.expected.plan.tenantId,
              repositoryBindingId:
                input.expected.plan.repositoryState.repositoryBindingId,
              scanRequestId: input.expected.plan.scanRequestId,
              workloadIdentityRef: input.expected.workloadIdentityRef,
              stage: 'SCANNING',
              attemptDeadlineAt: {
                gt: new Date(input.now)
              }
            },
            select: { id: true }
          });
          if (!attempt) {
            throw new SastArtifactIngressStateConflictError();
          }

          const existing =
            await transaction.sastArtifactIngestion.findUnique({
              where: {
                scannerRunId: input.expected.scannerRunId
              }
            });
          if (existing) {
            return this.replay(existing, input);
          }

          const scannerRun = await transaction.scannerRun.findFirst({
            where: {
              id: input.expected.scannerRunId,
              attemptId: input.expected.attemptId,
              tenantId: input.expected.plan.tenantId,
              repositoryBindingId:
                input.expected.plan.repositoryState.repositoryBindingId,
              scanRequestId: input.expected.plan.scanRequestId,
              scanner: input.expected.scanner,
              status: 'RUNNING'
            },
            select: { id: true }
          });
          if (!scannerRun) {
            throw new SastArtifactIngressStateConflictError();
          }

          await transaction.sastArtifactIngestion.create({
            data: {
              id: input.ingestionId,
              tenantId: input.expected.plan.tenantId,
              repositoryBindingId:
                input.expected.plan.repositoryState.repositoryBindingId,
              scanRequestId: input.expected.plan.scanRequestId,
              attemptId: input.expected.attemptId,
              scannerRunId: input.expected.scannerRunId,
              workloadIdentityRef: input.expected.workloadIdentityRef,
              idempotencyKey: input.idempotencyKey,
              envelope:
                input.envelope as unknown as Prisma.InputJsonValue,
              envelopeDigest: input.envelopeDigest,
              declaredContentDigest: input.declaredContentDigest,
              declaredByteSize: input.declaredByteSize,
              identityValidated: true,
              status: 'RECEIVING',
              validationMetadata: {
                workloadIdentityValidated: true
              }
            }
          });
          await transaction.auditEvent.create({
            data: {
              tenantId: input.expected.plan.tenantId,
              scanRequestId: input.expected.plan.scanRequestId,
              attemptId: input.expected.attemptId,
              eventType: 'artifact.ingress_reserved',
              actor: input.expected.workloadIdentityRef,
              targetType: 'sast_artifact_ingestion',
              targetId: input.ingestionId,
              occurredAt: new Date(input.now),
              metadata: {
                scannerRunId: input.expected.scannerRunId,
                scanner: input.expected.scanner,
                envelopeDigest: input.envelopeDigest,
                declaredByteSize: input.declaredByteSize,
                workloadIdentityValidated: true
              }
            }
          });

          return {
            kind: 'RESERVED' as const,
            ingestionId: input.ingestionId,
            state: 'RECEIVING' as const
          };
        },
        {
          isolationLevel: Prisma.TransactionIsolationLevel.Serializable
        }
      );
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2034'
      ) {
        throw new SastArtifactIngressReservationRetryError();
      }
      if (this.isUniqueViolation(error)) {
        const existing = await this.prisma.sastArtifactIngestion.findUnique({
          where: {
            scannerRunId: input.expected.scannerRunId
          }
        });
        if (existing) {
          return this.replay(existing, input);
        }
        throw new SastArtifactIngressReplayConflictError();
      }
      throw error;
    }
  }

  async complete(
    input: Readonly<CompleteSastArtifactIngressInput>
  ): Promise<void> {
    await this.prisma.$transaction(
      async (transaction) => {
        const ingestion = await transaction.sastArtifactIngestion.findUnique({
        where: { id: input.ingestionId },
        select: {
          tenantId: true,
          scanRequestId: true,
          repositoryBindingId: true,
          attemptId: true,
          scannerRunId: true,
          workloadIdentityRef: true,
          status: true
        }
      });
      if (!ingestion || ingestion.status !== 'RECEIVING') {
        throw new SastArtifactIngressStateConflictError();
      }
      const activeAttempt = await transaction.sastScanAttempt.findFirst({
        where: {
          id: ingestion.attemptId,
          tenantId: ingestion.tenantId,
          repositoryBindingId: ingestion.repositoryBindingId,
          scanRequestId: ingestion.scanRequestId,
          stage: 'SCANNING',
          attemptDeadlineAt: {
            gt: new Date(input.receivedAt)
          }
        },
        select: { id: true }
      });
      if (!activeAttempt) {
        throw new SastArtifactIngressStateConflictError();
      }

      const update = await transaction.sastArtifactIngestion.updateMany({
        where: {
          id: input.ingestionId,
          status: 'RECEIVING'
        },
        data: {
          objectKey: input.objectKey,
          observedContentDigest: input.observedContentDigest,
          observedByteSize: input.observedByteSize,
          status: 'PENDING_VALIDATION',
          receivedAt: new Date(input.receivedAt),
          validationMetadata: {
            workloadIdentityValidated: true,
            transportByteCountValidated: true,
            artifactValidation:
              input.validation as unknown as Prisma.InputJsonValue
          }
        }
      });
      if (update.count !== 1) {
        throw new SastArtifactIngressStateConflictError();
      }
      const scannerRunUpdate = await transaction.scannerRun.updateMany({
        where: {
          id: ingestion.scannerRunId,
          tenantId: ingestion.tenantId,
          scanRequestId: ingestion.scanRequestId,
          attemptId: ingestion.attemptId,
          status: 'RUNNING',
          rawArtifactObjectKey: null
        },
        data: {
          rawArtifactObjectKey: input.objectKey
        }
      });
      if (scannerRunUpdate.count !== 1) {
        throw new SastArtifactIngressStateConflictError();
      }

        await transaction.auditEvent.create({
          data: {
            tenantId: ingestion.tenantId,
            scanRequestId: ingestion.scanRequestId,
            attemptId: ingestion.attemptId,
            eventType: 'artifact.ingress_received',
            actor: ingestion.workloadIdentityRef,
            targetType: 'sast_artifact_ingestion',
            targetId: input.ingestionId,
            occurredAt: new Date(input.receivedAt),
            metadata: {
              scannerRunId: ingestion.scannerRunId,
              observedContentDigest: input.observedContentDigest,
              observedByteSize: input.observedByteSize,
              validationOutcome: input.validation.outcome,
              validationResultDigest: input.validation.resultDigest,
              validationReasonCodes: [...input.validation.reasonCodes],
              nextState: 'PENDING_VALIDATION'
            }
          }
        });
      },
      {
        isolationLevel: Prisma.TransactionIsolationLevel.Serializable
      }
    );
  }

  async reject(
    input: Readonly<RejectSastArtifactIngressInput>
  ): Promise<void> {
    await this.prisma.$transaction(async (transaction) => {
      const ingestion = await transaction.sastArtifactIngestion.findUnique({
        where: { id: input.ingestionId },
        select: {
          tenantId: true,
          scanRequestId: true,
          attemptId: true,
          scannerRunId: true,
          workloadIdentityRef: true,
          status: true
        }
      });
      if (!ingestion || ingestion.status !== 'RECEIVING') {
        throw new SastArtifactIngressStateConflictError();
      }

      await transaction.sastArtifactIngestion.update({
        where: { id: input.ingestionId },
        data: {
          status: 'REJECTED',
          rejectionReason: input.reasonCode,
          observedContentDigest: input.observedContentDigest,
          observedByteSize: input.observedByteSize,
          receivedAt: new Date(input.rejectedAt),
          validationMetadata: {
            workloadIdentityValidated: true,
            transportByteCountValidated: false
          }
        }
      });
      await transaction.auditEvent.create({
        data: {
          tenantId: ingestion.tenantId,
          scanRequestId: ingestion.scanRequestId,
          attemptId: ingestion.attemptId,
          eventType: 'artifact.ingress_rejected',
          actor: ingestion.workloadIdentityRef,
          targetType: 'sast_artifact_ingestion',
          targetId: input.ingestionId,
          occurredAt: new Date(input.rejectedAt),
          metadata: {
            scannerRunId: ingestion.scannerRunId,
            reasonCode: input.reasonCode,
            observedByteSize: input.observedByteSize
          }
        }
      });
    });
  }

  async abort(
    input: Readonly<AbortSastArtifactIngressInput>
  ): Promise<void> {
    await this.prisma.$transaction(async (transaction) => {
      const ingestion = await transaction.sastArtifactIngestion.findUnique({
        where: { id: input.ingestionId },
        select: {
          tenantId: true,
          scanRequestId: true,
          attemptId: true,
          scannerRunId: true,
          status: true
        }
      });
      if (!ingestion || ingestion.status !== 'RECEIVING') {
        return;
      }

      await transaction.sastArtifactIngestion.delete({
        where: { id: input.ingestionId }
      });
      await transaction.auditEvent.create({
        data: {
          tenantId: ingestion.tenantId,
          scanRequestId: ingestion.scanRequestId,
          attemptId: ingestion.attemptId,
          eventType: 'artifact.ingress_aborted',
          actor: 'scan-plane',
          targetType: 'scanner_run',
          targetId: ingestion.scannerRunId,
          occurredAt: new Date(input.occurredAt),
          metadata: {
            reasonCode: input.reasonCode
          }
        }
      });
    });
  }

  async recordRejectedRequest(
    input: Readonly<SastArtifactIngressRejectionAudit>
  ): Promise<void> {
    await this.prisma.auditEvent.create({
      data: {
        tenantId: input.expected.plan.tenantId,
        scanRequestId: input.expected.plan.scanRequestId,
        attemptId: input.expected.attemptId,
        eventType: 'artifact.ingress_rejected',
        actor: input.certificateFingerprint,
        targetType: 'scanner_run',
        targetId: input.expected.scannerRunId,
        occurredAt: new Date(input.occurredAt),
        metadata: {
          reasonCode: input.reasonCode,
          workloadIdentityValidated: input.workloadIdentityValidated
        }
      }
    });
  }

  private replay(
    existing: {
      id: string;
      envelopeDigest: string;
      idempotencyKey: string;
      declaredContentDigest: string;
      declaredByteSize: number;
      status: string;
      receivedAt: Date | null;
    },
    input: Readonly<ReserveSastArtifactIngressInput>
  ): SastArtifactIngressReservation {
    if (
      existing.envelopeDigest !== input.envelopeDigest ||
      existing.idempotencyKey !== input.idempotencyKey ||
      existing.declaredContentDigest !== input.declaredContentDigest ||
      existing.declaredByteSize !== input.declaredByteSize
    ) {
      throw new SastArtifactIngressReplayConflictError();
    }
    if (
      existing.status !== 'PENDING_VALIDATION' ||
      existing.receivedAt === null
    ) {
      throw new SastArtifactIngressStateConflictError();
    }

    return {
      kind: 'REPLAY',
      ingestionId: existing.id,
      state: 'PENDING_VALIDATION',
      receivedAt: existing.receivedAt.toISOString()
    };
  }

  private isUniqueViolation(
    error: unknown
  ): error is Prisma.PrismaClientKnownRequestError {
    return (
      error instanceof Prisma.PrismaClientKnownRequestError &&
      error.code === 'P2002'
    );
  }

  private asRecord(
    value: Prisma.JsonValue | null | undefined
  ): Record<string, unknown> | null {
    return value && typeof value === 'object' && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  }

  private isDigest(value: string | null): value is `sha256:${string}` {
    return typeof value === 'string' && /^sha256:[a-f0-9]{64}$/u.test(value);
  }
}
