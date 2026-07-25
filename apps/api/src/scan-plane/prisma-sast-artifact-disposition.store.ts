import {
  isSastArtifactDispositionDecisionShapeValid,
  isSastArtifactDispositionIntentShapeValid,
  type SastArtifactDispositionDecision
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';

import { PrismaService } from '../prisma/prisma.service';
import {
  SAST_ARTIFACT_QUARANTINE_OBJECT_PREFIX
} from './sast-artifact-disposition-storage';
import {
  type ClaimSastArtifactDispositionInput,
  type FinalizeSastArtifactDispositionInput,
  type ReleaseSastArtifactDispositionInput,
  type SaveSastArtifactDispositionIntentInput,
  type SastArtifactDispositionCandidate,
  SastArtifactDispositionFenceError,
  SastArtifactDispositionStore
} from './sast-artifact-disposition.store';

const TERMINAL_SCANNER_RUN_STATUSES = [
  'COMPLETED',
  'FAILED',
  'TIMED_OUT',
  'QUARANTINED',
  'KILLED'
] as const;

@Injectable()
export class PrismaSastArtifactDispositionStore
  extends SastArtifactDispositionStore
{
  constructor(private readonly prisma: PrismaService) {
    super();
  }

  async claimNext(
    input: Readonly<ClaimSastArtifactDispositionInput>
  ): Promise<SastArtifactDispositionCandidate | null> {
    try {
      return await this.prisma.$transaction(
        async (transaction) => {
          const claimedAt = new Date(input.claimedAt);
          const row = await transaction.sastArtifactIngestion.findFirst({
            where: {
              status: 'PENDING_VALIDATION',
              OR: [
                { dispositionNextAttemptAt: null },
                { dispositionNextAttemptAt: { lte: claimedAt } }
              ],
              AND: [
                {
                  OR: [
                    { dispositionLeaseExpiresAt: null },
                    { dispositionLeaseExpiresAt: { lte: claimedAt } }
                  ]
                }
              ],
              scannerRun: {
                status: {
                  in: [...TERMINAL_SCANNER_RUN_STATUSES]
                },
                completedAt: { not: null }
              }
            },
            orderBy: [
              { dispositionNextAttemptAt: 'asc' },
              { receivedAt: 'asc' },
              { id: 'asc' }
            ],
            select: {
              id: true,
              tenantId: true,
              repositoryBindingId: true,
              scanRequestId: true,
              attemptId: true,
              scannerRunId: true,
              workloadIdentityRef: true,
              identityValidated: true,
              envelope: true,
              envelopeDigest: true,
              declaredContentDigest: true,
              observedContentDigest: true,
              declaredByteSize: true,
              observedByteSize: true,
              objectKey: true,
              validationMetadata: true,
              receivedAt: true,
              dispositionIntent: true,
              dispositionIntentDigest: true,
              dispositionOperationId: true,
              scannerRun: {
                select: {
                  scanner: true,
                  scannerVersion: true,
                  scannerImageDigest: true,
                  wrapperDigest: true,
                  ruleBundleDigest: true,
                  databaseDigest: true,
                  scannerSetDigest: true,
                  schemaBundleDigest: true,
                  normalizerBundleDigest: true,
                  profileId: true,
                  profileDigest: true,
                  scannerWorkspaceInventoryDigest: true,
                  artifactSchema: true,
                  artifactSchemaVersion: true,
                  exitCode: true,
                  timedOut: true,
                  outputLimitExceeded: true,
                  status: true,
                  completedAt: true,
                  rawArtifactObjectKey: true,
                  artifactMetadata: true,
                  preflightAttestationRef: true,
                  preflightInventoryDigest: true
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
          if (
            !row ||
            !row.objectKey ||
            !row.receivedAt ||
            !row.scannerRun.completedAt
          ) {
            return null;
          }

          const claimed = await transaction.sastArtifactIngestion.updateMany({
            where: {
              id: row.id,
              status: 'PENDING_VALIDATION',
              AND: [
                {
                  OR: [
                    { dispositionNextAttemptAt: null },
                    { dispositionNextAttemptAt: { lte: claimedAt } }
                  ]
                },
                {
                  OR: [
                    { dispositionLeaseExpiresAt: null },
                    { dispositionLeaseExpiresAt: { lte: claimedAt } }
                  ]
                }
              ],
              scannerRun: {
                status: {
                  in: [...TERMINAL_SCANNER_RUN_STATUSES]
                },
                completedAt: { not: null }
              }
            },
            data: {
              dispositionLeaseOwner: input.workerId,
              dispositionLeaseToken: input.leaseToken,
              dispositionLeaseExpiresAt: new Date(input.leaseExpiresAt),
              dispositionNextAttemptAt: null,
              dispositionAttemptCount: { increment: 1 }
            }
          });
          if (claimed.count !== 1) return null;

          const artifactMetadata = this.asRecord(
            row.scannerRun.artifactMetadata
          );
          return {
            ingestionId: row.id,
            scope: {
              tenantId: row.tenantId,
              repositoryBindingId: row.repositoryBindingId,
              scanRequestId: row.scanRequestId,
              attemptId: row.attemptId,
              scannerRunId: row.scannerRunId
            },
            workloadIdentityRef: row.workloadIdentityRef,
            identityValidated: row.identityValidated,
            envelope: row.envelope,
            envelopeDigest: row.envelopeDigest,
            declaredContentDigest: row.declaredContentDigest,
            observedContentDigest: row.observedContentDigest,
            declaredByteSize: row.declaredByteSize,
            observedByteSize: row.observedByteSize,
            objectKey: row.objectKey,
            validationMetadata: row.validationMetadata,
            receivedAt: row.receivedAt.toISOString(),
            scanner: row.scannerRun.scanner,
            scannerVersion: row.scannerRun.scannerVersion,
            scannerImageDigest:
              row.scannerRun.scannerImageDigest,
            wrapperDigest: row.scannerRun.wrapperDigest,
            ruleBundleDigest: row.scannerRun.ruleBundleDigest,
            vulnerabilityDatabaseDigest:
              row.scannerRun.databaseDigest,
            scannerSetDigest: row.scannerRun.scannerSetDigest,
            schemaBundleDigest: row.scannerRun.schemaBundleDigest,
            normalizerBundleDigest:
              row.scannerRun.normalizerBundleDigest,
            profileId: row.scannerRun.profileId,
            profileDigest: row.scannerRun.profileDigest,
            scannerWorkspaceInventoryDigest:
              row.scannerRun.scannerWorkspaceInventoryDigest,
            scannerArtifactSchema:
              row.scannerRun.artifactSchema,
            scannerArtifactSchemaVersion:
              row.scannerRun.artifactSchemaVersion,
            scannerExitCode: row.scannerRun.exitCode,
            scannerTimedOut: row.scannerRun.timedOut,
            scannerOutputLimitExceeded:
              row.scannerRun.outputLimitExceeded,
            scannerArtifactByteSize:
              typeof artifactMetadata?.byteSize === 'number'
                ? artifactMetadata.byteSize
                : null,
            scannerRunStatus: row.scannerRun.status,
            scannerRunCompletedAt:
              row.scannerRun.completedAt.toISOString(),
            scannerRawArtifactObjectKey:
              row.scannerRun.rawArtifactObjectKey,
            scannerArtifactRef:
              typeof artifactMetadata?.artifactRef === 'string'
                ? artifactMetadata.artifactRef
                : null,
            preflightAttestationRef:
              row.scannerRun.preflightAttestationRef,
            preflightInventoryDigest:
              row.scannerRun.preflightInventoryDigest,
            immutablePlan:
              row.scanRequest.sastQueueReservation?.immutablePlan ?? null,
            persistedIntent: row.dispositionIntent,
            persistedIntentDigest: row.dispositionIntentDigest,
            persistedOperationId: row.dispositionOperationId,
            leaseToken: input.leaseToken,
            leaseExpiresAt: input.leaseExpiresAt
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
        return null;
      }
      throw error;
    }
  }

  async saveIntent(
    input: Readonly<SaveSastArtifactDispositionIntentInput>
  ): Promise<void> {
    const sourceMissing = input.intent.reasonCodes.includes(
      'ARTIFACT_SOURCE_OBJECT_MISSING'
    );
    if (
      !isSastArtifactDispositionIntentShapeValid(input.intent) ||
      input.intent.ingestionId !== input.ingestionId ||
      (!sourceMissing &&
        input.operationId !==
          `sast-artifact-disposition-v1:${input.intent.intentDigest.slice(
            'sha256:'.length
          )}`)
    ) {
      throw new Error('Artifact disposition intent binding is invalid.');
    }
    const saved = await this.prisma.sastArtifactIngestion.updateMany({
      where: {
        id: input.ingestionId,
        status: 'PENDING_VALIDATION',
        dispositionLeaseToken: input.leaseToken,
        dispositionLeaseExpiresAt: {
          gt: new Date(input.savedAt)
        },
        dispositionIntentDigest: input.expectedIntentDigest
      },
      data: {
        dispositionIntent:
          input.intent as unknown as Prisma.InputJsonValue,
        dispositionIntentDigest: input.intent.intentDigest,
        dispositionOperationId: input.operationId,
        retentionExpiresAt: input.intent.retentionExpiresAt
          ? new Date(input.intent.retentionExpiresAt)
          : null,
        dispositionLastErrorCode: null
      }
    });
    if (saved.count !== 1) {
      throw new SastArtifactDispositionFenceError();
    }
  }

  async finalize(
    input: Readonly<FinalizeSastArtifactDispositionInput>
  ): Promise<void> {
    if (
      !isSastArtifactDispositionDecisionShapeValid(input.decision) ||
      input.decision.ingestionId !== input.ingestionId ||
      input.decision.storageOperationId !== input.operationId
    ) {
      throw new Error('Artifact disposition operation binding is invalid.');
    }
    this.assertFinalObjectKey(input.decision, input.finalObjectKey);
    const decidedAt = new Date(input.decision.decidedAt);
    const fencedAt = new Date(input.fencedAt);

    await this.prisma.$transaction(
      async (transaction) => {
        const finalized =
          await transaction.sastArtifactIngestion.updateMany({
            where: {
              id: input.ingestionId,
              status: 'PENDING_VALIDATION',
              dispositionLeaseToken: input.leaseToken,
              dispositionLeaseExpiresAt: { gt: fencedAt },
              dispositionIntentDigest: input.decision.intentDigest,
              dispositionOperationId: input.operationId
            },
            data: {
              status: input.decision.disposition,
              objectKey:
                input.decision.disposition === 'REJECTED'
                  ? null
                  : input.finalObjectKey,
              rejectionReason:
                input.decision.disposition === 'ACCEPTED'
                  ? null
                  : input.decision.reasonCodes[0],
              retentionExpiresAt: input.decision.retentionExpiresAt
                ? new Date(input.decision.retentionExpiresAt)
                : null,
              dispositionDecidedAt: decidedAt,
              dispositionLeaseOwner: null,
              dispositionLeaseToken: null,
              dispositionLeaseExpiresAt: null,
              dispositionNextAttemptAt: null,
              dispositionLastErrorCode: null
            }
          });
        if (finalized.count !== 1) {
          throw new SastArtifactDispositionFenceError();
        }

        await this.updateScannerRun(
          transaction,
          input
        );

        await transaction.auditEvent.create({
          data: {
            id: input.auditEventId,
            tenantId: input.scope.tenantId,
            scanRequestId: input.scope.scanRequestId,
            attemptId: input.scope.attemptId,
            eventType: 'artifact.disposition_decided',
            actor: 'scan-plane-artifact-disposition',
            targetType: 'sast_artifact_ingestion',
            targetId: input.ingestionId,
            occurredAt: decidedAt,
            metadata: {
              disposition: input.decision.disposition,
              ...(input.decision.failureClass
                ? {
                    failureClass: input.decision.failureClass
                  }
                : {}),
              reasonCodes: [...input.decision.reasonCodes],
              validationReasonCodes: [
                ...input.decision.validationReasonCodes
              ],
              validationResultDigest:
                input.decision.validationResultDigest,
              intentDigest: input.decision.intentDigest,
              decisionDigest: input.decision.decisionDigest,
              storageAction: input.decision.storageAction,
              storageOperationId: input.operationId,
              storageReceiptRef:
                input.decision.storageReceiptRef,
              storageReceiptDigest:
                input.decision.storageReceiptDigest,
              ...(input.decision.acceptanceControlRef
                ? {
                    acceptanceControlRef:
                      input.decision.acceptanceControlRef
                  }
                : {}),
              ...(input.decision.encryptionContextDigest
                ? {
                    encryptionContextDigest:
                      input.decision.encryptionContextDigest
                  }
                : {}),
              normalizationEligible:
                input.decision.normalizationEligible,
              ...(input.decision.retentionExpiresAt
                ? {
                    retentionExpiresAt:
                      input.decision.retentionExpiresAt
                  }
                : {})
            }
          }
        });

        await transaction.sastArtifactDispositionDecision.create({
          data: {
            id: input.decisionId,
            ingestionId: input.ingestionId,
            tenantId: input.scope.tenantId,
            repositoryBindingId: input.scope.repositoryBindingId,
            scanRequestId: input.scope.scanRequestId,
            attemptId: input.scope.attemptId,
            scannerRunId: input.scope.scannerRunId,
            disposition: input.decision.disposition,
            failureClass: input.decision.failureClass ?? null,
            reasonCodes:
              input.decision.reasonCodes as unknown as Prisma.InputJsonValue,
            validationReasonCodes:
              input.decision
                .validationReasonCodes as unknown as Prisma.InputJsonValue,
            validationResultDigest:
              input.decision.validationResultDigest,
            intentDigest: input.decision.intentDigest,
            operationId: input.operationId,
            decision:
              input.decision as unknown as Prisma.InputJsonValue,
            decisionDigest: input.decision.decisionDigest,
            storageReceiptRef: input.decision.storageReceiptRef,
            storageReceiptDigest:
              input.decision.storageReceiptDigest,
            acceptanceControlRef:
              input.decision.acceptanceControlRef ?? null,
            encryptionContextDigest:
              input.decision.encryptionContextDigest ?? null,
            retentionExpiresAt: input.decision.retentionExpiresAt
              ? new Date(input.decision.retentionExpiresAt)
              : null,
            normalizationEligible:
              input.decision.normalizationEligible,
            auditEventId: input.auditEventId,
            decidedAt
          }
        });
      },
      {
        isolationLevel: Prisma.TransactionIsolationLevel.Serializable
      }
    );
  }

  async release(
    input: Readonly<ReleaseSastArtifactDispositionInput>
  ): Promise<void> {
    const released = await this.prisma.sastArtifactIngestion.updateMany({
      where: {
        id: input.ingestionId,
        status: 'PENDING_VALIDATION',
        dispositionLeaseToken: input.leaseToken,
        dispositionLeaseExpiresAt: {
          gt: new Date(input.releasedAt)
        }
      },
      data: {
        dispositionLeaseOwner: null,
        dispositionLeaseToken: null,
        dispositionLeaseExpiresAt: null,
        dispositionNextAttemptAt: new Date(input.retryAt),
        dispositionLastErrorCode: input.errorCode
      }
    });
    if (released.count !== 1) {
      throw new SastArtifactDispositionFenceError();
    }
  }

  private async updateScannerRun(
    transaction: Prisma.TransactionClient,
    input: Readonly<FinalizeSastArtifactDispositionInput>
  ): Promise<void> {
    const disposition = input.decision.disposition;
    const update = await transaction.scannerRun.updateMany({
      where: {
        id: input.scope.scannerRunId,
        tenantId: input.scope.tenantId,
        repositoryBindingId: input.scope.repositoryBindingId,
        scanRequestId: input.scope.scanRequestId,
        attemptId: input.scope.attemptId,
        status:
          disposition === 'ACCEPTED'
            ? 'COMPLETED'
            : { in: [...TERMINAL_SCANNER_RUN_STATUSES] }
      },
      data:
        disposition === 'ACCEPTED'
          ? {
              rawArtifactObjectKey: input.finalObjectKey
            }
          : disposition === 'QUARANTINED'
            ? {
                status: 'QUARANTINED',
                rawArtifactObjectKey: input.finalObjectKey,
                errorMessage: input.decision.reasonCodes[0]
              }
            : {
                status: 'FAILED',
                rawArtifactObjectKey: null,
                errorMessage: input.decision.reasonCodes[0]
              }
    });
    if (update.count !== 1) {
      throw new SastArtifactDispositionFenceError();
    }
  }

  private assertFinalObjectKey(
    decision: Readonly<SastArtifactDispositionDecision>,
    finalObjectKey: string | undefined
  ): void {
    if (
      (decision.disposition === 'REJECTED' &&
        finalObjectKey !== undefined) ||
      (decision.disposition !== 'REJECTED' &&
        (!finalObjectKey ||
          Buffer.byteLength(finalObjectKey, 'utf8') > 2048 ||
          this.hasControlCharacters(finalObjectKey))) ||
      (decision.disposition === 'QUARANTINED' &&
        !finalObjectKey?.startsWith(
          SAST_ARTIFACT_QUARANTINE_OBJECT_PREFIX
        ))
    ) {
      throw new Error('Artifact disposition storage result is invalid.');
    }
  }

  private asRecord(
    value: Prisma.JsonValue | null | undefined
  ): Record<string, unknown> | null {
    return value && typeof value === 'object' && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  }

  private hasControlCharacters(value: string): boolean {
    return [...value].some((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return (
        codePoint <= 0x1f ||
        (codePoint >= 0x7f && codePoint <= 0x9f)
      );
    });
  }
}
