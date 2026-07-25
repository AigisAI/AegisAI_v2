import { createHash, randomUUID } from 'node:crypto';

import {
  SAST_SANDBOX_CLEANUP_TIMEOUT_SECONDS,
  buildSastScanPlanDigestPreimage,
  isSastScanPlanValid,
  type SastScannerExecutionRecord,
  type SastScannerInvocation,
  type SastScannerRuntimeAuditSignal,
  type SastScannerWrapperExecutionRequest,
  type SastScanPlan
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';
import {
  ArchitectureScanStatus,
  Prisma,
  SastCredentialLeaseStatus,
  type ScannerRunStatus,
  type SastScanFailureClass,
  type SastScanAttemptStage
} from '@prisma/client';

import { PrismaService } from '../prisma/prisma.service';
import {
  retryableInfrastructureFailure,
  securityViolation
} from './scanner-runtime.errors';
import {
  type FinishSastAttemptInput,
  type PersistedSastAttemptStage,
  SastScannerRuntimeStore
} from './sast-scanner-runtime.store';

const OVERDUE_ATTEMPT_BATCH_SIZE = 100;
const OVERDUE_CLEANUP_REASON = 'SANDBOX_CLEANUP_EVIDENCE_OVERDUE';

interface LatestSastAttemptRetryState {
  attemptNumber: number;
  stage: SastScanAttemptStage;
  failureClass: SastScanFailureClass | null;
  retryEligible: boolean;
  completedAt: Date | null;
  finalAuditEventId: string | null;
}

export function isSastAttemptSequenceEligible(
  attemptNumber: number,
  latestAttempt: LatestSastAttemptRetryState | null
): boolean {
  if (attemptNumber === 1) {
    return latestAttempt === null;
  }
  return (
    attemptNumber === 2 &&
    latestAttempt?.attemptNumber === 1 &&
    latestAttempt.stage === 'FAILED' &&
    latestAttempt.failureClass === 'RETRYABLE_INFRASTRUCTURE' &&
    latestAttempt.retryEligible === true &&
    latestAttempt.completedAt !== null &&
    latestAttempt.finalAuditEventId !== null
  );
}

@Injectable()
export class PrismaSastScannerRuntimeStore extends SastScannerRuntimeStore {
  constructor(private readonly prisma: PrismaService) {
    super();
  }

  async beginAttempt(
    request: Readonly<SastScannerWrapperExecutionRequest>,
    startedAt: string
  ): Promise<void> {
    try {
      await this.prisma.$transaction(
        async (transaction) => {
          const scanRequest = await transaction.scanRequest.findFirst({
            where: {
              id: request.plan.scanRequestId,
              tenantId: request.plan.tenantId,
              repositoryBindingId:
                request.plan.repositoryState.repositoryBindingId,
              status: ArchitectureScanStatus.RUNNING
            },
            include: {
              sastQueueReservation: {
                select: {
                  canonicalScanKey: true,
                  immutablePlan: true
                }
              }
            }
          });

          if (!scanRequest?.sastQueueReservation) {
            throw securityViolation(
              'DURABLE_SCAN_PLAN_NOT_RUNNING',
              'Scanner execution requires a running durable scan and admitted plan.'
            );
          }

          const durablePlan =
            scanRequest.sastQueueReservation
              .immutablePlan as unknown as SastScanPlan;
          if (
            !isSastScanPlanValid(durablePlan) ||
            scanRequest.sastQueueReservation.canonicalScanKey !==
              request.plan.canonicalScanKey ||
            this.planDigest(durablePlan) !== this.planDigest(request.plan)
          ) {
            throw securityViolation(
              'DURABLE_SCAN_PLAN_MISMATCH',
              'Runtime plan does not match the admitted durable scan plan.'
            );
          }

          const activeAttempt = await transaction.sastScanAttempt.findFirst({
            where: {
              scanRequestId: request.plan.scanRequestId,
              stage: {
                in: ['VALIDATING', 'SCANNING', 'CLEANUP_PENDING']
              }
            },
            select: { id: true }
          });
          if (activeAttempt) {
            throw securityViolation(
              'SCAN_ATTEMPT_ALREADY_ACTIVE',
              'A scan may have only one active sandbox attempt.'
            );
          }

          const latestAttempt = await transaction.sastScanAttempt.findFirst({
            where: {
              scanRequestId: request.plan.scanRequestId
            },
            orderBy: {
              attemptNumber: 'desc'
            },
            select: {
              attemptNumber: true,
              stage: true,
              failureClass: true,
              retryEligible: true,
              completedAt: true,
              finalAuditEventId: true
            }
          });

          if (
            !isSastAttemptSequenceEligible(
              request.attemptNumber,
              latestAttempt
            )
          ) {
            throw securityViolation(
              'SCAN_ATTEMPT_RETRY_NOT_ELIGIBLE',
              'Attempt sequencing requires a first attempt with no predecessor or a completed retry-eligible infrastructure failure from attempt one.'
            );
          }

          await transaction.sastScanAttempt.create({
            data: {
              id: request.attemptId,
              tenantId: request.plan.tenantId,
              repositoryBindingId:
                request.plan.repositoryState.repositoryBindingId,
              scanRequestId: request.plan.scanRequestId,
              attemptNumber: request.attemptNumber,
              sandboxId: request.sandboxId,
              workloadIdentityRef: request.workloadIdentityRef,
              stage: 'VALIDATING',
              retryEligible: false,
              startedAt: new Date(startedAt),
              attemptDeadlineAt: new Date(
                request.sandboxAttestation.claims.attemptDeadlineAt
              )
            }
          });
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
        throw retryableInfrastructureFailure(
          'SCAN_ATTEMPT_SERIALIZATION_CONFLICT',
          'Concurrent scan attempt admission must be retried.'
        );
      }
      if (this.isUniqueViolation(error)) {
        throw securityViolation(
          'SCAN_ATTEMPT_REPLAYED',
          'The scan attempt identifier, scope, or attempt number was already used.'
        );
      }
      throw error;
    }
  }

  async markStage(
    request: Readonly<SastScannerWrapperExecutionRequest>,
    stage: Extract<
      PersistedSastAttemptStage,
      'SCANNING' | 'CLEANUP_PENDING'
    >
  ): Promise<void> {
    const allowedPriorStages: SastScanAttemptStage[] =
      stage === 'SCANNING' ? ['VALIDATING'] : ['VALIDATING', 'SCANNING'];
    const transition = async (
      client: Pick<PrismaService, 'sastArtifactIngestion' | 'sastScanAttempt'>
    ) => {
      if (stage === 'CLEANUP_PENDING') {
        const activeIngress = await client.sastArtifactIngestion.count({
          where: {
            tenantId: request.plan.tenantId,
            scanRequestId: request.plan.scanRequestId,
            attemptId: request.attemptId,
            status: 'RECEIVING'
          }
        });
        if (activeIngress !== 0) {
          throw securityViolation(
            'ARTIFACT_INGRESS_STILL_RECEIVING',
            'Cleanup cannot start while an artifact ingress is receiving bytes.'
          );
        }
      }

      const result = await client.sastScanAttempt.updateMany({
        where: {
          id: request.attemptId,
          tenantId: request.plan.tenantId,
          repositoryBindingId:
            request.plan.repositoryState.repositoryBindingId,
          scanRequestId: request.plan.scanRequestId,
          sandboxId: request.sandboxId,
          workloadIdentityRef: request.workloadIdentityRef,
          stage: { in: allowedPriorStages }
        },
        data: { stage }
      });
      if (result.count !== 1) {
        throw securityViolation(
          'SCAN_ATTEMPT_STAGE_CONFLICT',
          'Scan attempt stage transition was rejected.'
        );
      }
    };

    if (stage === 'SCANNING') {
      await transition(this.prisma);
      return;
    }

    try {
      await this.prisma.$transaction(
        async (transaction) => transition(transaction),
        {
          isolationLevel: Prisma.TransactionIsolationLevel.Serializable
        }
      );
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2034'
      ) {
        throw retryableInfrastructureFailure(
          'ARTIFACT_INGRESS_STAGE_SERIALIZATION_CONFLICT',
          'Artifact ingress and cleanup stage transition must be retried.'
        );
      }
      throw error;
    }
  }

  async recordScannerRun(
    request: Readonly<SastScannerWrapperExecutionRequest>,
    record: Readonly<SastScannerExecutionRecord>
  ): Promise<void> {
    const startedAt = new Date(record.observation.startedAt);
    const completedAt = new Date(record.observation.completedAt);
    const durationMilliseconds = completedAt.getTime() - startedAt.getTime();

    const result = await this.prisma.scannerRun.updateMany({
      where: {
        id: record.scannerRunId,
        tenantId: request.plan.tenantId,
        repositoryBindingId:
          request.plan.repositoryState.repositoryBindingId,
        scanRequestId: request.plan.scanRequestId,
        attemptId: request.attemptId,
        scanner: record.invocation.scanner,
        status: 'RUNNING'
      },
      data: {
        scannerWorkspaceInventoryDigest:
          record.observation.scannerWorkspaceInventoryDigest,
        exitCode: record.observation.exitCode,
        terminationSignal: record.observation.terminationSignal,
        timedOut: record.observation.timedOut,
        outputLimitExceeded: record.observation.outputLimitExceeded,
        durationMilliseconds,
        stdoutMetadata:
          record.observation.stdout as unknown as Prisma.InputJsonValue,
        stderrMetadata:
          record.observation.stderr as unknown as Prisma.InputJsonValue,
        resourceMetadata:
          record.observation.resources as unknown as Prisma.InputJsonValue,
        artifactMetadata: record.observation.artifact
          ? (record.observation.artifact as unknown as Prisma.InputJsonValue)
          : Prisma.JsonNull,
        status: this.scannerRunStatus(record.status),
        errorMessage:
          record.status === 'SUCCEEDED' ? null : record.status,
        startedAt,
        completedAt
      }
    });
    if (result.count !== 1) {
      throw securityViolation(
        'SCANNER_RUN_STATE_CONFLICT',
        'Scanner terminal state did not match one running scanner record.'
      );
    }
  }

  async beginScannerRun(
    request: Readonly<SastScannerWrapperExecutionRequest>,
    scannerRunId: string,
    invocation: Readonly<SastScannerInvocation>,
    startedAt: string
  ): Promise<void> {
    try {
      await this.prisma.scannerRun.create({
        data: {
          id: scannerRunId,
          tenantId: request.plan.tenantId,
          scanRequestId: request.plan.scanRequestId,
          repositoryBindingId:
            request.plan.repositoryState.repositoryBindingId,
          attemptId: request.attemptId,
          scanner: invocation.scanner,
          scannerVersion: invocation.scannerVersion,
          required: invocation.required,
          wrapperDigest: invocation.wrapperDigest,
          scannerImageDigest: invocation.scannerImageDigest,
          ruleBundleDigest: invocation.ruleBundleDigest,
          databaseDigest: invocation.vulnerabilityDatabaseDigest,
          scannerSetDigest: invocation.scannerSetDigest,
          schemaBundleDigest: invocation.schemaBundleDigest,
          normalizerBundleDigest: invocation.normalizerBundleDigest,
          profileId: invocation.profileId,
          profileDigest: invocation.profileDigest,
          preflightAttestationRef: invocation.preflightAttestationRef,
          preflightInventoryDigest: invocation.preflightInventoryDigest,
          artifactSchema: invocation.artifactSchema,
          artifactSchemaVersion: invocation.artifactSchemaVersion,
          artifactMetadata: {
            artifactRef: `${request.plan.resultIngressRef}/${invocation.scanner.toLowerCase()}`
          },
          status: 'RUNNING',
          startedAt: new Date(startedAt)
        }
      });
    } catch (error) {
      if (this.isUniqueViolation(error)) {
        throw securityViolation(
          'SCANNER_RUN_REPLAYED',
          'A scanner may execute only once per scan attempt.'
        );
      }
      throw error;
    }
  }

  async failScannerRun(
    request: Readonly<SastScannerWrapperExecutionRequest>,
    scannerRunId: string,
    invocation: Readonly<SastScannerInvocation>,
    reasonCode: string,
    completedAt: string
  ): Promise<void> {
    const terminalAt = new Date(completedAt);
    const started = await this.prisma.scannerRun.findFirst({
      where: {
        id: scannerRunId,
        tenantId: request.plan.tenantId,
        repositoryBindingId:
          request.plan.repositoryState.repositoryBindingId,
        scanRequestId: request.plan.scanRequestId,
        attemptId: request.attemptId,
        scanner: invocation.scanner,
        status: 'RUNNING'
      },
      select: { startedAt: true }
    });
    if (!started?.startedAt) {
      return;
    }

    const timedOut = /(?:DEADLINE|TIMEOUT)/u.test(reasonCode);
    const result = await this.prisma.scannerRun.updateMany({
      where: {
        id: scannerRunId,
        tenantId: request.plan.tenantId,
        repositoryBindingId:
          request.plan.repositoryState.repositoryBindingId,
        scanRequestId: request.plan.scanRequestId,
        attemptId: request.attemptId,
        scanner: invocation.scanner,
        status: 'RUNNING'
      },
      data: {
        scannerWorkspaceInventoryDigest:
          invocation.preflightInventoryDigest,
        exitCode: -1,
        timedOut,
        outputLimitExceeded: false,
        durationMilliseconds: Math.max(
          0,
          terminalAt.getTime() - started.startedAt.getTime()
        ),
        stdoutMetadata: {
          byteSize: 0,
          truncated: false,
          secretRedactionApplied: true
        },
        stderrMetadata: {
          byteSize: 0,
          truncated: false,
          secretRedactionApplied: true
        },
        resourceMetadata: {
          unavailable: true
        },
        artifactMetadata: Prisma.JsonNull,
        status: timedOut ? 'TIMED_OUT' : 'FAILED',
        errorMessage: reasonCode,
        completedAt: terminalAt
      }
    });
    if (result.count !== 1) {
      throw securityViolation(
        'SCANNER_RUN_STATE_CONFLICT',
        'Scanner failure did not match one running scanner record.'
      );
    }
  }

  async recordAuditSignal(
    signal: Readonly<SastScannerRuntimeAuditSignal>
  ): Promise<void> {
    await this.prisma.auditEvent.create({
      data: {
        id: signal.eventId,
        tenantId: signal.tenantId,
        scanRequestId: signal.scanRequestId,
        attemptId: signal.attemptId,
        eventType: signal.eventType,
        actor: signal.workloadIdentityRef,
        targetType: signal.scannerRunId
          ? 'scanner_run'
          : signal.scanner
            ? 'scanner'
            : 'sast_scan_attempt',
        targetId:
          signal.scannerRunId ??
          (signal.scanner
            ? `${signal.attemptId}:${signal.scanner}`
            : signal.attemptId),
        occurredAt: new Date(signal.occurredAt),
        metadata: this.toJson({
          repositoryBindingId: signal.repositoryBindingId,
          sandboxId: signal.sandboxId,
          workloadIdentityRef: signal.workloadIdentityRef,
          scanner: signal.scanner,
          scannerRunId: signal.scannerRunId,
          executionStatus: signal.executionStatus,
          reasonCode: signal.reasonCode,
          metadataDigest: signal.metadataDigest
        })
      }
    });
  }

  async isCredentialHandoffTerminal(
    request: Readonly<SastScannerWrapperExecutionRequest>
  ): Promise<boolean> {
    const terminalLease =
      await this.prisma.sastRepositoryCredentialLease.count({
        where: {
          tenantId: request.plan.tenantId,
          repositoryBindingId:
            request.plan.repositoryState.repositoryBindingId,
          scanRequestId: request.plan.scanRequestId,
          attemptId: request.attemptId,
          status: {
            in: [
              SastCredentialLeaseStatus.WIPED,
              SastCredentialLeaseStatus.REVOKED
            ]
          }
        }
      });
    return terminalLease === 1;
  }

  async failOverdueAttempts(referenceTime: string): Promise<number> {
    const completedAt = new Date(referenceTime);
    if (!Number.isFinite(completedAt.getTime())) {
      throw new Error('Overdue attempt reconciliation reference time is invalid.');
    }
    const overdueBefore = new Date(
      completedAt.getTime() -
        SAST_SANDBOX_CLEANUP_TIMEOUT_SECONDS * 1_000
    );
    const candidates = await this.prisma.sastScanAttempt.findMany({
      where: {
        stage: { in: ['VALIDATING', 'SCANNING', 'CLEANUP_PENDING'] },
        attemptDeadlineAt: { lte: overdueBefore }
      },
      select: { id: true },
      orderBy: [{ attemptDeadlineAt: 'asc' }, { id: 'asc' }],
      take: OVERDUE_ATTEMPT_BATCH_SIZE
    });

    let reconciled = 0;
    for (const candidate of candidates) {
      try {
        const transitioned = await this.prisma.$transaction(
          async (transaction) => {
            const attempt = await transaction.sastScanAttempt.findFirst({
              where: {
                id: candidate.id,
                stage: {
                  in: ['VALIDATING', 'SCANNING', 'CLEANUP_PENDING']
                },
                attemptDeadlineAt: { lte: overdueBefore }
              },
              select: {
                id: true,
                tenantId: true,
                repositoryBindingId: true,
                scanRequestId: true,
                sandboxId: true,
                workloadIdentityRef: true,
                attemptDeadlineAt: true
              }
            });
            if (!attempt) {
              return false;
            }

            const eventId = `audit_${randomUUID()}`;
            await transaction.auditEvent.create({
              data: {
                id: eventId,
                tenantId: attempt.tenantId,
                scanRequestId: attempt.scanRequestId,
                attemptId: attempt.id,
                eventType: 'sandbox.cleanup_failed',
                actor: 'sast-attempt-reconciler',
                targetType: 'sast_scan_attempt',
                targetId: attempt.id,
                occurredAt: completedAt,
                metadata: {
                  repositoryBindingId: attempt.repositoryBindingId,
                  sandboxId: attempt.sandboxId,
                  workloadIdentityRef: attempt.workloadIdentityRef,
                  attemptDeadlineAt:
                    attempt.attemptDeadlineAt.toISOString(),
                  reasonCode: OVERDUE_CLEANUP_REASON
                }
              }
            });
            const update = await transaction.sastScanAttempt.updateMany({
              where: {
                id: attempt.id,
                tenantId: attempt.tenantId,
                stage: {
                  in: ['VALIDATING', 'SCANNING', 'CLEANUP_PENDING']
                }
              },
              data: {
                stage: 'CLEANUP_FAILED',
                failureClass: 'SECURITY_VIOLATION',
                failureReason: OVERDUE_CLEANUP_REASON,
                retryEligible: false,
                finalAuditEventId: eventId,
                completedAt
              }
            });
            if (update.count !== 1) {
              throw retryableInfrastructureFailure(
                'OVERDUE_ATTEMPT_RECONCILIATION_CONFLICT',
                'Overdue attempt state changed during reconciliation.'
              );
            }
            return true;
          },
          {
            isolationLevel: Prisma.TransactionIsolationLevel.Serializable
          }
        );
        if (transitioned) {
          reconciled += 1;
        }
      } catch (error) {
        if (
          error instanceof Prisma.PrismaClientKnownRequestError &&
          error.code === 'P2034'
        ) {
          continue;
        }
        throw error;
      }
    }
    return reconciled;
  }

  async finishAttempt(input: FinishSastAttemptInput): Promise<void> {
    const cleanupEvidence = input.cleanup
      ? (input.cleanup as unknown as Prisma.InputJsonValue)
      : undefined;
    const cleanupEvidenceDigest = input.cleanup
      ? this.digest(JSON.stringify(input.cleanup))
      : undefined;
    const update = await this.prisma.sastScanAttempt.updateMany({
      where: {
        id: input.request.attemptId,
        tenantId: input.request.plan.tenantId,
        repositoryBindingId:
          input.request.plan.repositoryState.repositoryBindingId,
        scanRequestId: input.request.plan.scanRequestId,
        sandboxId: input.request.sandboxId,
        workloadIdentityRef: input.request.workloadIdentityRef,
        stage: { in: ['VALIDATING', 'SCANNING', 'CLEANUP_PENDING'] }
      },
      data: {
        stage: input.stage,
        failureClass: input.failureClass,
        failureReason: input.reasonCode?.slice(0, 255),
        retryEligible: input.retryEligible,
        cleanupEvidence,
        cleanupEvidenceDigest,
        finalAuditEventId: input.finalAuditEventId,
        completedAt: new Date(input.completedAt)
      }
    });
    if (update.count !== 1) {
      throw retryableInfrastructureFailure(
        'SCAN_ATTEMPT_FINALIZATION_CONFLICT',
        'Scan attempt finalization could not be committed.'
      );
    }
  }

  private scannerRunStatus(status: string): ScannerRunStatus {
    if (status === 'SUCCEEDED') {
      return 'COMPLETED';
    }
    if (status === 'TIMED_OUT') {
      return 'TIMED_OUT';
    }
    if (status === 'PENDING') {
      return 'QUEUED';
    }
    if (status === 'RUNNING') {
      return 'RUNNING';
    }
    if (status === 'SKIPPED_BY_POLICY') {
      return 'SKIPPED';
    }
    if (status === 'QUARANTINED') {
      return 'QUARANTINED';
    }
    if (status === 'KILLED') {
      return 'KILLED';
    }
    return 'FAILED';
  }

  private planDigest(plan: SastScanPlan): string {
    return this.digest(buildSastScanPlanDigestPreimage(plan));
  }

  private digest(value: string): `sha256:${string}` {
    return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
  }

  private isUniqueViolation(error: unknown): boolean {
    return (
      error instanceof Prisma.PrismaClientKnownRequestError &&
      error.code === 'P2002'
    );
  }

  private toJson(value: unknown): Prisma.InputJsonValue {
    return JSON.parse(JSON.stringify(value)) as Prisma.InputJsonValue;
  }
}
