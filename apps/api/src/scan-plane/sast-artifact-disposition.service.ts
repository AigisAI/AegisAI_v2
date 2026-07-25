import { createHash, randomUUID } from 'node:crypto';

import {
  SAST_ARTIFACT_DISPOSITION_REASON_CODES,
  SAST_ARTIFACT_DISPOSITION_VERSION,
  SAST_ARTIFACT_MAX_RETENTION_SECONDS,
  SAST_ARTIFACT_VALIDATION_REASON_CODES,
  SAST_SCANNER_KINDS,
  canonicalizeSastArtifactDispositionDecision,
  canonicalizeSastArtifactDispositionIntent,
  canonicalizeSastArtifactValidationResult,
  canonicalizeScannerArtifactEnvelope,
  isSastArtifactDispositionDecisionShapeValid,
  isSastArtifactDispositionIntentShapeValid,
  isSastArtifactStorageReceiptReferenceValid,
  isSastArtifactValidationResultShapeValid,
  isSastScanPlanValid,
  isScannerArtifactEnvelopeBoundToPlan,
  isScannerArtifactEnvelopeShapeValid,
  type ExpectedScannerArtifactBinding,
  type SastArtifactDispositionDecision,
  type SastArtifactDispositionIntent,
  type SastArtifactDispositionIntentCore,
  type SastArtifactDispositionReasonCode,
  type SastArtifactValidationReasonCode,
  type SastArtifactValidationResult,
  type SastScanPlan,
  type SastScannerKind,
  type ScannerArtifactEnvelope
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';

import {
  SastArtifactAcceptanceGate,
  SastArtifactAcceptanceGateUnavailableError
} from './sast-artifact-acceptance-gate';
import {
  SAST_ARTIFACT_QUARANTINE_CONTEXT_VERSION,
  SAST_ARTIFACT_QUARANTINE_OBJECT_PREFIX,
  SastArtifactDispositionStorage,
  SastArtifactDispositionStorageUnavailableError,
  SastArtifactSourceObjectMissingError,
  canonicalizeSastArtifactQuarantineEncryptionContext,
  type SastArtifactQuarantineEncryptionContext,
  type SastArtifactStorageDispositionReceipt
} from './sast-artifact-disposition-storage';
import {
  SastArtifactDispositionFenceError,
  SastArtifactDispositionStore,
  type SastArtifactDispositionCandidate
} from './sast-artifact-disposition.store';

const DISPOSITION_LEASE_MILLISECONDS = 60_000;
const DISPOSITION_RETRY_MILLISECONDS = 60_000;

export type SastArtifactDispositionProcessingResult =
  | 'IDLE'
  | 'ACCEPTED'
  | 'REJECTED'
  | 'QUARANTINED'
  | 'RETRY_SCHEDULED'
  | 'LEASE_LOST';

interface DurableValidation {
  envelope: ScannerArtifactEnvelope | null;
  plan: SastScanPlan | null;
  validation: SastArtifactValidationResult | null;
  validationResultDigest: `sha256:${string}`;
  validationReasonCodes: readonly SastArtifactValidationReasonCode[];
  reasons: ReadonlySet<SastArtifactDispositionReasonCode>;
}

@Injectable()
export class SastArtifactDispositionService {
  constructor(
    private readonly store: SastArtifactDispositionStore,
    private readonly storage: SastArtifactDispositionStorage,
    private readonly acceptanceGate: SastArtifactAcceptanceGate
  ) {}

  async processNext(
    referenceTime = new Date(),
    workerId = `artifact-disposition:${process.pid}`
  ): Promise<SastArtifactDispositionProcessingResult> {
    const claimedAt = referenceTime.toISOString();
    const leaseToken = randomUUID();
    const candidate = await this.store.claimNext({
      workerId,
      leaseToken,
      claimedAt,
      leaseExpiresAt: new Date(
        referenceTime.getTime() + DISPOSITION_LEASE_MILLISECONDS
      ).toISOString()
    });
    if (!candidate) return 'IDLE';

    try {
      const durable = this.validateDurableCandidate(candidate);
      let intent = this.reusePersistedIntent(
        candidate,
        durable,
        claimedAt
      );
      let operationId = candidate.persistedOperationId;
      if (!intent) {
        const hasPersistedIntentState =
          candidate.persistedIntent !== null ||
          candidate.persistedIntentDigest !== null ||
          candidate.persistedOperationId !== null;
        const derivationInput = hasPersistedIntentState
          ? {
              ...durable,
              reasons: new Set([
                ...durable.reasons,
                'ARTIFACT_DURABLE_METADATA_INVALID' as const
              ])
            }
          : durable;
        intent = await this.deriveIntent(
          candidate,
          derivationInput,
          claimedAt
        );
        operationId = this.operationIdForIntent(intent);
        await this.store.saveIntent({
          ingestionId: candidate.ingestionId,
          leaseToken: candidate.leaseToken,
          expectedIntentDigest: candidate.persistedIntentDigest,
          intent,
          operationId,
          savedAt: new Date().toISOString()
        });
      }
      if (!operationId) {
        throw new Error('Artifact disposition operation is unavailable.');
      }

      const storageInput = this.storageInput(
        candidate,
        intent,
        operationId
      );
      let receipt: SastArtifactStorageDispositionReceipt;
      try {
        receipt = await this.storage.apply(storageInput);
      } catch (error) {
        if (!(error instanceof SastArtifactSourceObjectMissingError)) {
          throw error;
        }
        receipt = error.receipt;
        this.assertReceipt(
          candidate,
          intent,
          receipt,
          true,
          operationId
        );
        if (
          intent.disposition !== 'REJECTED' ||
          !intent.reasonCodes.includes(
            'ARTIFACT_SOURCE_OBJECT_MISSING'
          )
        ) {
          const missingIntent = this.createIntent(
            candidate,
            {
              disposition: 'REJECTED',
              storageAction: 'DELETE_REJECTED',
              failureClass: 'SECURITY_VIOLATION',
              reasons: new Set([
                ...intent.reasonCodes.filter(
                  (reason) =>
                    reason !== 'ARTIFACT_VALIDATION_ACCEPTED'
                ),
                'ARTIFACT_SOURCE_OBJECT_MISSING'
              ]),
              validationResultDigest:
                intent.validationResultDigest,
              validationReasonCodes:
                intent.validationReasonCodes,
              ...(intent.reasonCodes.includes(
                'ARTIFACT_ACCEPTANCE_DENIED'
              ) && intent.acceptanceControlRef
                ? {
                    acceptanceControlRef:
                      intent.acceptanceControlRef
                  }
                : {}),
              createdAt: claimedAt
            }
          );
          await this.store.saveIntent({
            ingestionId: candidate.ingestionId,
            leaseToken: candidate.leaseToken,
            expectedIntentDigest: intent.intentDigest,
            intent: missingIntent,
            operationId,
            savedAt: new Date().toISOString()
          });
          intent = missingIntent;
        }
      }

      this.assertReceipt(
        candidate,
        intent,
        receipt,
        false,
        operationId
      );
      const decision = this.createDecision(intent, receipt);
      await this.store.finalize({
        decisionId: randomUUID(),
        auditEventId: randomUUID(),
        ingestionId: candidate.ingestionId,
        scope: candidate.scope,
        leaseToken: candidate.leaseToken,
        operationId,
        decision,
        fencedAt: new Date().toISOString(),
        finalObjectKey:
          decision.disposition === 'REJECTED'
            ? undefined
            : receipt.finalObjectKey
      });
      return decision.disposition;
    } catch (error) {
      if (error instanceof SastArtifactDispositionFenceError) {
        return 'LEASE_LOST';
      }
      const releasedAt = new Date();
      try {
        await this.store.release({
          ingestionId: candidate.ingestionId,
          leaseToken: candidate.leaseToken,
          errorCode: this.retryErrorCode(error),
          releasedAt: releasedAt.toISOString(),
          retryAt: new Date(
            releasedAt.getTime() + DISPOSITION_RETRY_MILLISECONDS
          ).toISOString()
        });
      } catch (releaseError) {
        if (releaseError instanceof SastArtifactDispositionFenceError) {
          return 'LEASE_LOST';
        }
        throw releaseError;
      }
      return 'RETRY_SCHEDULED';
    }
  }

  private validateDurableCandidate(
    candidate: Readonly<SastArtifactDispositionCandidate>
  ): DurableValidation {
    const reasons = new Set<SastArtifactDispositionReasonCode>();
    const metadata = this.asRecord(candidate.validationMetadata);
    const metadataKeys = metadata ? Object.keys(metadata).sort() : [];
    const metadataShapeValid =
      metadata !== null &&
      JSON.stringify(metadataKeys) ===
        JSON.stringify([
          'artifactValidation',
          'transportByteCountValidated',
          'workloadIdentityValidated'
        ]) &&
      metadata.workloadIdentityValidated === true &&
      metadata.transportByteCountValidated === true;
    const rawValidation = metadata?.artifactValidation;
    const validation = isSastArtifactValidationResultShapeValid(
      rawValidation
    )
      ? rawValidation
      : null;
    let validationDigestValid = false;
    if (validation) {
      const { resultDigest, ...core } = validation;
      validationDigestValid =
        resultDigest ===
        this.digest(
          canonicalizeSastArtifactValidationResult(core)
        );
    }
    if (!metadataShapeValid || !validation || !validationDigestValid) {
      reasons.add('ARTIFACT_DURABLE_METADATA_INVALID');
    }

    const envelope = isScannerArtifactEnvelopeShapeValid(
      candidate.envelope
    )
      ? candidate.envelope
      : null;
    const durablePlan = candidate.immutablePlan as SastScanPlan;
    const plan = isSastScanPlanValid(durablePlan)
      ? durablePlan
      : null;
    if (!envelope || !plan) {
      reasons.add('ARTIFACT_DURABLE_METADATA_INVALID');
    }

    if (
      envelope &&
      this.digest(canonicalizeScannerArtifactEnvelope(envelope)) !==
        candidate.envelopeDigest
    ) {
      reasons.add('ARTIFACT_DURABLE_METADATA_INVALID');
    }

    if (
      !this.isDigest(candidate.envelopeDigest) ||
      !this.isDigest(candidate.declaredContentDigest) ||
      !this.isDigest(candidate.observedContentDigest) ||
      candidate.observedByteSize === null ||
      candidate.observedByteSize !== candidate.declaredByteSize ||
      candidate.identityValidated !== true ||
      !this.isBoundedReference(candidate.objectKey) ||
      candidate.scannerRawArtifactObjectKey !== candidate.objectKey
    ) {
      reasons.add('ARTIFACT_DURABLE_METADATA_INVALID');
    }

    if (
      validation &&
      (validation.envelopeDigest !== candidate.envelopeDigest ||
        (envelope !== null &&
          validation.artifactSchema !== envelope.artifactSchema) ||
        validation.observedContentDigest !==
          candidate.observedContentDigest ||
        validation.statistics.observedByteSize !==
          candidate.observedByteSize)
    ) {
      reasons.add('ARTIFACT_DURABLE_METADATA_INVALID');
    }

    if (
      envelope &&
      (envelope.contentDigest !== candidate.declaredContentDigest ||
        envelope.contentDigest !== candidate.observedContentDigest ||
        envelope.byteSize !== candidate.declaredByteSize ||
        envelope.byteSize !== candidate.observedByteSize ||
        (validation !== null &&
          envelope.recordCount !==
            validation.statistics.observedRecordCount))
    ) {
      reasons.add('ARTIFACT_DURABLE_METADATA_INVALID');
    }

    if (
      envelope &&
      plan &&
      (!this.isChronological(
        plan.createdAt,
        envelope.producedAt,
        candidate.receivedAt,
        candidate.scannerRunCompletedAt
      ) ||
        envelope.truncated !== false)
    ) {
      reasons.add('ARTIFACT_DURABLE_METADATA_INVALID');
    }

    if (
      !envelope ||
      !plan ||
      !SAST_SCANNER_KINDS.includes(
        candidate.scanner as SastScannerKind
      ) ||
      !candidate.scannerArtifactRef ||
      !candidate.preflightAttestationRef ||
      !this.isDigest(candidate.preflightInventoryDigest)
    ) {
      reasons.add('ARTIFACT_DURABLE_BINDING_MISMATCH');
    } else {
      const expected: ExpectedScannerArtifactBinding = {
        attemptId: candidate.scope.attemptId,
        scannerRunId: candidate.scope.scannerRunId,
        scanner: candidate.scanner as SastScannerKind,
        artifactRef: candidate.scannerArtifactRef,
        workloadIdentityRef: candidate.workloadIdentityRef,
        preflightAttestationRef:
          candidate.preflightAttestationRef,
        preflightInventoryDigest:
          candidate.preflightInventoryDigest
      };
      if (
        !isScannerArtifactEnvelopeBoundToPlan(
          envelope,
          plan,
          expected
        ) ||
        envelope.tenantId !== candidate.scope.tenantId ||
        envelope.repositoryBindingId !==
          candidate.scope.repositoryBindingId ||
        envelope.scanRequestId !== candidate.scope.scanRequestId ||
        !this.isEnvelopeBoundToScannerRun(envelope, candidate)
      ) {
        reasons.add('ARTIFACT_DURABLE_BINDING_MISMATCH');
      }
    }

    if (
      candidate.scannerRunStatus !== 'COMPLETED' ||
      !Number.isFinite(Date.parse(candidate.scannerRunCompletedAt)) ||
      envelope?.executionStatus !== 'SUCCEEDED' ||
      envelope.exitCode !== 0 ||
      envelope.truncated !== false ||
      candidate.scannerExitCode !== 0 ||
      candidate.scannerTimedOut !== false ||
      candidate.scannerOutputLimitExceeded !== false ||
      candidate.scannerArtifactByteSize !==
        candidate.observedByteSize
    ) {
      reasons.add('ARTIFACT_SCANNER_RUN_NOT_SUCCESSFUL');
    }
    if (validation?.outcome === 'FAILED') {
      reasons.add('ARTIFACT_VALIDATION_FAILED');
    }

    return {
      envelope,
      plan,
      validation,
      validationResultDigest:
        validation && validationDigestValid
          ? validation.resultDigest
          : this.digest(
              `invalid-validation:${candidate.ingestionId}:${candidate.envelopeDigest}`
            ),
      validationReasonCodes: validation?.reasonCodes ?? [],
      reasons
    };
  }

  private async deriveIntent(
    candidate: Readonly<SastArtifactDispositionCandidate>,
    durable: Readonly<DurableValidation>,
    createdAt: string
  ): Promise<SastArtifactDispositionIntent> {
    const retentionExpiresAt = this.retentionExpiresAt(
      candidate.receivedAt
    );
    if (Date.parse(createdAt) >= Date.parse(retentionExpiresAt)) {
      const expiredReasons = new Set([
        ...durable.reasons,
        'ARTIFACT_RETENTION_EXPIRED' as const
      ]);
      return this.createIntent(candidate, {
        disposition: 'REJECTED',
        storageAction: 'DELETE_REJECTED',
        failureClass:
          durable.reasons.size > 0
            ? 'SECURITY_VIOLATION'
            : 'NON_RETRYABLE_INPUT',
        reasons: expiredReasons,
        validationResultDigest: durable.validationResultDigest,
        validationReasonCodes: durable.validationReasonCodes,
        createdAt
      });
    }

    if (durable.reasons.size > 0) {
      return this.createIntent(candidate, {
        disposition: 'QUARANTINED',
        storageAction: 'MOVE_REENCRYPT_QUARANTINE',
        failureClass: 'SECURITY_VIOLATION',
        reasons: durable.reasons,
        validationResultDigest: durable.validationResultDigest,
        validationReasonCodes: durable.validationReasonCodes,
        retentionExpiresAt,
        createdAt
      });
    }

    if (!durable.envelope || !durable.plan) {
      throw new Error('Validated artifact binding is unavailable.');
    }
    const gate = await this.acceptanceGate.evaluate({
      scope: candidate.scope,
      scanner: durable.envelope.scanner,
      scannerVersion: durable.envelope.scannerVersion,
      scannerImageDigest:
        durable.envelope.scannerImageDigest,
      validationResultDigest: durable.validationResultDigest,
      scannerSetDigest:
        durable.envelope.scannerSetDigest,
      ruleBundleDigest: durable.envelope.ruleBundleDigest,
      profileId: durable.envelope.profileId,
      profileDigest: durable.envelope.profileDigest,
      evaluatedAt: createdAt
    });
    this.assertGateDecision(gate, createdAt);
    if (gate.outcome === 'DENY') {
      return this.createIntent(candidate, {
        disposition: 'QUARANTINED',
        storageAction: 'MOVE_REENCRYPT_QUARANTINE',
        failureClass: 'SECURITY_VIOLATION',
        reasons: new Set(['ARTIFACT_ACCEPTANCE_DENIED']),
        validationResultDigest: durable.validationResultDigest,
        validationReasonCodes: durable.validationReasonCodes,
        retentionExpiresAt,
        acceptanceControlRef: gate.controlRef,
        createdAt
      });
    }

    return this.createIntent(candidate, {
      disposition: 'ACCEPTED',
      storageAction: 'RETAIN_ACCEPTED',
      reasons: new Set(['ARTIFACT_VALIDATION_ACCEPTED']),
      validationResultDigest: durable.validationResultDigest,
      validationReasonCodes: durable.validationReasonCodes,
      retentionExpiresAt,
      acceptanceControlRef: gate.controlRef,
      createdAt
    });
  }

  private createIntent(
    candidate: Readonly<SastArtifactDispositionCandidate>,
    input: {
      disposition: SastArtifactDispositionIntent['disposition'];
      storageAction: SastArtifactDispositionIntent['storageAction'];
      failureClass?: SastArtifactDispositionIntent['failureClass'];
      reasons: ReadonlySet<SastArtifactDispositionReasonCode>;
      validationResultDigest: `sha256:${string}`;
      validationReasonCodes:
        readonly SastArtifactValidationReasonCode[];
      retentionExpiresAt?: string;
      acceptanceControlRef?: string;
      createdAt: string;
    }
  ): SastArtifactDispositionIntent {
    const core: SastArtifactDispositionIntentCore = {
      version: SAST_ARTIFACT_DISPOSITION_VERSION,
      ingestionId: candidate.ingestionId,
      scope: candidate.scope,
      disposition: input.disposition,
      storageAction: input.storageAction,
      ...(input.failureClass
        ? { failureClass: input.failureClass }
        : {}),
      reasonCodes: this.orderReasons(input.reasons),
      validationReasonCodes: this.orderValidationReasons(
        input.validationReasonCodes
      ),
      validationResultDigest: input.validationResultDigest,
      normalizationEligible: input.disposition === 'ACCEPTED',
      ...(input.retentionExpiresAt
        ? { retentionExpiresAt: input.retentionExpiresAt }
        : {}),
      ...(input.acceptanceControlRef
        ? { acceptanceControlRef: input.acceptanceControlRef }
        : {}),
      createdAt: input.createdAt
    };
    const intent = {
      ...core,
      intentDigest: this.digest(
        canonicalizeSastArtifactDispositionIntent(core)
      )
    };
    if (!isSastArtifactDispositionIntentShapeValid(intent)) {
      throw new Error('Artifact disposition intent is invalid.');
    }
    return intent;
  }

  private reusePersistedIntent(
    candidate: Readonly<SastArtifactDispositionCandidate>,
    durable: Readonly<DurableValidation>,
    claimedAt: string
  ): SastArtifactDispositionIntent | null {
    const intent = candidate.persistedIntent;
    if (
      !isSastArtifactDispositionIntentShapeValid(intent) ||
      candidate.persistedIntentDigest !== intent.intentDigest ||
      !this.isOperationId(candidate.persistedOperationId) ||
      (!intent.reasonCodes.includes(
        'ARTIFACT_SOURCE_OBJECT_MISSING'
      ) &&
        candidate.persistedOperationId !==
          this.operationIdForIntent(intent))
    ) {
      return null;
    }
    const { intentDigest, ...core } = intent;
    const scopeMatches =
      intent.ingestionId === candidate.ingestionId &&
      Object.entries(candidate.scope).every(
        ([key, value]) =>
          intent.scope[key as keyof typeof intent.scope] === value
      );
    const retentionMatches =
      intent.retentionExpiresAt === undefined ||
      intent.retentionExpiresAt ===
        this.retentionExpiresAt(candidate.receivedAt);
    const nowExpired =
      intent.retentionExpiresAt !== undefined &&
      Date.parse(claimedAt) >= Date.parse(intent.retentionExpiresAt);
    const durableReasonsMatch =
      durable.reasons.size === 0 ||
      ((intent.disposition === 'QUARANTINED' ||
        (intent.disposition === 'REJECTED' &&
          intent.reasonCodes.includes(
            'ARTIFACT_SOURCE_OBJECT_MISSING'
          ))) &&
        [...durable.reasons].every((reason) =>
          intent.reasonCodes.includes(reason)
        ));
    if (
      !scopeMatches ||
      !retentionMatches ||
      nowExpired ||
      !durableReasonsMatch ||
      Date.parse(intent.createdAt) < Date.parse(candidate.receivedAt) ||
      Date.parse(intent.createdAt) > Date.parse(claimedAt) ||
      intent.validationResultDigest !==
        durable.validationResultDigest ||
      intentDigest !==
        this.digest(
          canonicalizeSastArtifactDispositionIntent(core)
        )
    ) {
      return null;
    }
    return intent;
  }

  private storageInput(
    candidate: Readonly<SastArtifactDispositionCandidate>,
    intent: Readonly<SastArtifactDispositionIntent>,
    operationId: string
  ) {
    if (
      !this.isDigest(candidate.observedContentDigest) ||
      candidate.observedByteSize === null ||
      !Number.isSafeInteger(candidate.observedByteSize) ||
      candidate.observedByteSize <= 0 ||
      !this.isBoundedReference(candidate.objectKey)
    ) {
      throw new Error('Artifact storage binding is invalid.');
    }
    const quarantineEncryptionContext =
      intent.disposition === 'QUARANTINED'
        ? this.quarantineContext(candidate, intent)
        : undefined;
    return {
      operationId,
      ingestionId: candidate.ingestionId,
      scope: candidate.scope,
      action: intent.storageAction,
      sourceObjectKey: candidate.objectKey,
      expectedContentDigest: candidate.observedContentDigest,
      expectedByteSize: candidate.observedByteSize,
      ...(intent.retentionExpiresAt
        ? { retentionExpiresAt: intent.retentionExpiresAt }
        : {}),
      ...(quarantineEncryptionContext
        ? { quarantineEncryptionContext }
        : {})
    };
  }

  private quarantineContext(
    candidate: Readonly<SastArtifactDispositionCandidate>,
    intent: Readonly<SastArtifactDispositionIntent>
  ): SastArtifactQuarantineEncryptionContext {
    return {
      version: SAST_ARTIFACT_QUARANTINE_CONTEXT_VERSION,
      purpose: 'SAST_ARTIFACT_FORENSIC_QUARANTINE',
      ingestionId: candidate.ingestionId,
      scope: candidate.scope,
      validationResultDigest: intent.validationResultDigest,
      intentDigest: intent.intentDigest
    };
  }

  private assertReceipt(
    candidate: Readonly<SastArtifactDispositionCandidate>,
    intent: Readonly<SastArtifactDispositionIntent>,
    receipt: Readonly<SastArtifactStorageDispositionReceipt>,
    sourceMissing: boolean,
    operationId: string
  ): void {
    if (
      receipt.operationId !== operationId ||
      !isSastArtifactStorageReceiptReferenceValid(
        receipt.storageReceiptRef
      ) ||
      receipt.storageReceiptRef === candidate.objectKey ||
      receipt.storageReceiptRef === receipt.finalObjectKey ||
      !this.isDigest(receipt.storageReceiptDigest) ||
      !this.isIsoTimestamp(receipt.completedAt) ||
      Date.parse(receipt.completedAt) <
        Date.parse(candidate.receivedAt) ||
      Date.parse(receipt.completedAt) <
        Date.parse(intent.createdAt) ||
      Date.parse(receipt.completedAt) >=
        Date.parse(candidate.leaseExpiresAt)
    ) {
      throw new Error('Artifact storage receipt is invalid.');
    }
    if (sourceMissing) {
      if (
        receipt.finalObjectKey !== undefined ||
        receipt.encryptionContextDigest !== undefined
      ) {
        throw new Error('Missing-object receipt is invalid.');
      }
      return;
    }
    if (intent.disposition === 'ACCEPTED') {
      if (
        receipt.finalObjectKey !== candidate.objectKey ||
        receipt.encryptionContextDigest !== undefined ||
        !intent.retentionExpiresAt ||
        Date.parse(receipt.completedAt) >=
          Date.parse(intent.retentionExpiresAt)
      ) {
        throw new Error('Accepted artifact storage receipt is invalid.');
      }
    } else if (intent.disposition === 'REJECTED') {
      if (
        receipt.finalObjectKey !== undefined ||
        receipt.encryptionContextDigest !== undefined
      ) {
        throw new Error('Rejected artifact storage receipt is invalid.');
      }
    } else {
      const expectedContextDigest = this.digest(
        canonicalizeSastArtifactQuarantineEncryptionContext(
          this.quarantineContext(candidate, intent)
        )
      );
      if (
        !this.isRestrictedQuarantineObjectKey(
          receipt.finalObjectKey
        ) ||
        receipt.encryptionContextDigest !== expectedContextDigest ||
        !intent.retentionExpiresAt ||
        Date.parse(receipt.completedAt) >=
          Date.parse(intent.retentionExpiresAt)
      ) {
        throw new Error('Quarantine artifact storage receipt is invalid.');
      }
    }
  }

  private createDecision(
    intent: Readonly<SastArtifactDispositionIntent>,
    receipt: Readonly<SastArtifactStorageDispositionReceipt>
  ): SastArtifactDispositionDecision {
    const core = {
      version: SAST_ARTIFACT_DISPOSITION_VERSION,
      ingestionId: intent.ingestionId,
      disposition: intent.disposition,
      storageAction: intent.storageAction,
      ...(intent.failureClass
        ? { failureClass: intent.failureClass }
        : {}),
      reasonCodes: intent.reasonCodes,
      validationReasonCodes: intent.validationReasonCodes,
      validationResultDigest: intent.validationResultDigest,
      normalizationEligible: intent.normalizationEligible,
      ...(intent.retentionExpiresAt
        ? { retentionExpiresAt: intent.retentionExpiresAt }
        : {}),
      ...(intent.acceptanceControlRef
        ? { acceptanceControlRef: intent.acceptanceControlRef }
        : {}),
      intentDigest: intent.intentDigest,
      storageOperationId: receipt.operationId,
      storageReceiptRef: receipt.storageReceiptRef,
      storageReceiptDigest: receipt.storageReceiptDigest,
      ...(receipt.encryptionContextDigest
        ? {
            encryptionContextDigest:
              receipt.encryptionContextDigest
          }
        : {}),
      decidedAt: receipt.completedAt
    } satisfies Omit<SastArtifactDispositionDecision, 'decisionDigest'>;
    const decision = {
      ...core,
      decisionDigest: this.digest(
        canonicalizeSastArtifactDispositionDecision(core)
      )
    };
    if (!isSastArtifactDispositionDecisionShapeValid(decision)) {
      throw new Error('Artifact disposition decision is invalid.');
    }
    return decision;
  }

  private retentionExpiresAt(receivedAt: string): string {
    return new Date(
      Date.parse(receivedAt) +
        SAST_ARTIFACT_MAX_RETENTION_SECONDS * 1000
    ).toISOString();
  }

  private operationIdForIntent(
    intent: Pick<SastArtifactDispositionIntent, 'intentDigest'>
  ): string {
    return `sast-artifact-disposition-v1:${intent.intentDigest.slice(
      'sha256:'.length
    )}`;
  }

  private orderReasons(
    reasons: ReadonlySet<SastArtifactDispositionReasonCode>
  ): SastArtifactDispositionReasonCode[] {
    return SAST_ARTIFACT_DISPOSITION_REASON_CODES.filter((reason) =>
      reasons.has(reason)
    );
  }

  private orderValidationReasons(
    reasons: readonly SastArtifactValidationReasonCode[]
  ): SastArtifactValidationReasonCode[] {
    const set = new Set(reasons);
    return SAST_ARTIFACT_VALIDATION_REASON_CODES.filter((reason) =>
      set.has(reason)
    );
  }

  private assertGateDecision(
    value: {
      outcome: unknown;
      controlRef: unknown;
      evaluatedAt: unknown;
      reasonCode?: unknown;
    },
    expectedEvaluatedAt: string
  ): void {
    if (
      (value.outcome !== 'ALLOW' && value.outcome !== 'DENY') ||
      !this.isBoundedReference(value.controlRef) ||
      value.evaluatedAt !== expectedEvaluatedAt ||
      (value.outcome === 'ALLOW'
        ? value.reasonCode !== undefined
        : !this.isBoundedReference(value.reasonCode))
    ) {
      throw new Error('Artifact acceptance gate response is invalid.');
    }
  }

  private retryErrorCode(error: unknown): string {
    if (error instanceof SastArtifactAcceptanceGateUnavailableError) {
      return 'ARTIFACT_ACCEPTANCE_GATE_UNAVAILABLE';
    }
    if (
      error instanceof SastArtifactDispositionStorageUnavailableError
    ) {
      return 'ARTIFACT_DISPOSITION_STORAGE_UNAVAILABLE';
    }
    return 'ARTIFACT_DISPOSITION_RETRYABLE_FAILURE';
  }

  private digest(value: string): `sha256:${string}` {
    return `sha256:${createHash('sha256')
      .update(value, 'utf8')
      .digest('hex')}`;
  }

  private isDigest(
    value: unknown
  ): value is `sha256:${string}` {
    return (
      typeof value === 'string' &&
      /^sha256:[a-f0-9]{64}$/u.test(value)
    );
  }

  private isOperationId(value: unknown): value is string {
    return (
      typeof value === 'string' &&
      /^sast-artifact-disposition-v1:[a-f0-9]{64}$/u.test(value)
    );
  }

  private isIsoTimestamp(value: unknown): value is string {
    return (
      typeof value === 'string' &&
      Number.isFinite(Date.parse(value)) &&
      new Date(value).toISOString() === value
    );
  }

  private isChronological(...timestamps: readonly string[]): boolean {
    const values = timestamps.map(Date.parse);
    return (
      values.every(Number.isFinite) &&
      values.every(
        (value, index) => index === 0 || values[index - 1]! <= value
      )
    );
  }

  private isEnvelopeBoundToScannerRun(
    envelope: Readonly<ScannerArtifactEnvelope>,
    candidate: Readonly<SastArtifactDispositionCandidate>
  ): boolean {
    return (
      candidate.scannerVersion === envelope.scannerVersion &&
      candidate.scannerImageDigest === envelope.scannerImageDigest &&
      candidate.wrapperDigest === envelope.wrapperDigest &&
      (candidate.ruleBundleDigest ?? undefined) ===
        envelope.ruleBundleDigest &&
      (candidate.vulnerabilityDatabaseDigest ?? undefined) ===
        envelope.vulnerabilityDatabaseDigest &&
      candidate.scannerSetDigest === envelope.scannerSetDigest &&
      candidate.schemaBundleDigest === envelope.schemaBundleDigest &&
      candidate.normalizerBundleDigest ===
        envelope.normalizerBundleDigest &&
      candidate.profileId === envelope.profileId &&
      candidate.profileDigest === envelope.profileDigest &&
      candidate.preflightAttestationRef ===
        envelope.preflightAttestationRef &&
      candidate.preflightInventoryDigest ===
        envelope.preflightInventoryDigest &&
      candidate.scannerWorkspaceInventoryDigest ===
        envelope.scannerWorkspaceInventoryDigest &&
      candidate.scannerArtifactSchema === envelope.artifactSchema &&
      candidate.scannerArtifactSchemaVersion ===
        envelope.artifactSchemaVersion &&
      candidate.scannerExitCode === envelope.exitCode
    );
  }

  private isBoundedReference(value: unknown): value is string {
    return (
      typeof value === 'string' &&
      value === value.trim() &&
      value === value.normalize('NFC') &&
      value.length > 0 &&
      !this.hasControlCharacters(value) &&
      Buffer.byteLength(value, 'utf8') <= 2048
    );
  }

  private isRestrictedQuarantineObjectKey(
    value: unknown
  ): value is string {
    if (
      !this.isBoundedReference(value) ||
      !value.startsWith(SAST_ARTIFACT_QUARANTINE_OBJECT_PREFIX)
    ) {
      return false;
    }
    const suffix = value.slice(
      SAST_ARTIFACT_QUARANTINE_OBJECT_PREFIX.length
    );
    return (
      suffix.length > 0 &&
      !suffix.includes('..') &&
      !suffix.includes('\\') &&
      !suffix.includes('//')
    );
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

  private asRecord(value: unknown): Record<string, unknown> | null {
    return value && typeof value === 'object' && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  }
}
