import { createHash } from 'node:crypto';

import {
  SAST_APPROVED_PROFILE_DIGESTS,
  SAST_ARTIFACT_DISPOSITION_VERSION,
  SAST_ARTIFACT_SCHEMA_VERSIONS,
  SAST_ARTIFACT_VALIDATION_VERSION,
  SAST_FORBIDDEN_CAPABILITIES,
  SAST_SCAN_PROFILES,
  canonicalizeSastArtifactValidationResult,
  canonicalizeScannerArtifactEnvelope,
  isSastArtifactDispositionDecisionShapeValid,
  isSastArtifactDispositionIntentShapeValid,
  type ScannerArtifactEnvelope,
  type SastArtifactValidationResult,
  type SastScanPlan
} from '@aegisai/shared';

import {
  SastArtifactAcceptanceGate,
  SastArtifactAcceptanceGateUnavailableError,
  type SastArtifactAcceptanceGateInput,
  type SastArtifactAcceptanceGateDecision
} from '../../src/scan-plane/sast-artifact-acceptance-gate';
import {
  SAST_ARTIFACT_QUARANTINE_OBJECT_PREFIX,
  SastArtifactDispositionStorage,
  SastArtifactSourceObjectMissingError,
  canonicalizeSastArtifactQuarantineEncryptionContext,
  type ApplySastArtifactStorageDispositionInput,
  type SastArtifactStorageDispositionReceipt
} from '../../src/scan-plane/sast-artifact-disposition-storage';
import { SastArtifactDispositionService } from '../../src/scan-plane/sast-artifact-disposition.service';
import {
  SastArtifactDispositionFenceError,
  SastArtifactDispositionStore,
  type ClaimSastArtifactDispositionInput,
  type FinalizeSastArtifactDispositionInput,
  type ReleaseSastArtifactDispositionInput,
  type SaveSastArtifactDispositionIntentInput,
  type SastArtifactDispositionCandidate
} from '../../src/scan-plane/sast-artifact-disposition.store';

const NOW = new Date('2026-07-26T12:01:00.000Z');
const RECEIVED_AT = '2026-07-26T12:00:00.000Z';
const STORAGE_COMPLETED_AT = '2026-07-26T12:01:01.000Z';
const OBJECT_KEY = 'ingress/opaque-artifact-1';
const RECEIPT_DIGEST = digest('storage-receipt');

describe('SastArtifactDispositionService', () => {
  it('accepts a fully rebound artifact only after an explicit gate allow', async () => {
    const harness = createHarness();

    await expect(
      harness.service.processNext(NOW, 'worker-1')
    ).resolves.toBe('ACCEPTED');

    expect(harness.gate.evaluate).toHaveBeenCalledTimes(1);
    expect(harness.storage.apply).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'RETAIN_ACCEPTED',
        sourceObjectKey: OBJECT_KEY
      })
    );
    expect(
      harness.storage.apply.mock.calls[0]![0]
    ).not.toHaveProperty('quarantineEncryptionContext');
    const savedIntent =
      harness.store.saveIntent.mock.calls[0]![0].intent;
    expect(isSastArtifactDispositionIntentShapeValid(savedIntent)).toBe(
      true
    );
    expect(savedIntent?.normalizationEligible).toBe(true);
    expect(
      harness.store.saveIntent.mock.calls[0]![0].operationId
    ).toBe(
      `sast-artifact-disposition-v1:${savedIntent!.intentDigest.slice(
        'sha256:'.length
      )}`
    );

    const finalized = harness.store.finalize.mock.calls[0]![0];
    expect(finalized?.finalObjectKey).toBe(OBJECT_KEY);
    expect(
      isSastArtifactDispositionDecisionShapeValid(
        finalized?.decision
      )
    ).toBe(true);
    expect(finalized?.decision).toEqual(
      expect.objectContaining({
        version: SAST_ARTIFACT_DISPOSITION_VERSION,
        disposition: 'ACCEPTED',
        normalizationEligible: true,
        acceptanceControlRef: 'kill-switch-evaluation://allow-1',
        reasonCodes: ['ARTIFACT_VALIDATION_ACCEPTED']
      })
    );
    expect(harness.store.release).not.toHaveBeenCalled();
  });

  it('quarantines tampered durable validation without consulting the acceptance gate', async () => {
    const candidate = validCandidate();
    const metadata = candidate.validationMetadata as {
      artifactValidation: SastArtifactValidationResult;
    };
    candidate.validationMetadata = {
      ...candidate.validationMetadata as object,
      artifactValidation: {
        ...metadata.artifactValidation,
        resultDigest: digest('tampered-result')
      }
    };
    const harness = createHarness(candidate);
    harness.storage.apply.mockImplementation(async (input) => ({
      operationId: input.operationId,
      storageReceiptRef: 'storage-receipt://quarantine-1',
      storageReceiptDigest: RECEIPT_DIGEST,
      finalObjectKey:
        `${SAST_ARTIFACT_QUARANTINE_OBJECT_PREFIX}opaque-1`,
      encryptionContextDigest: digest(
        canonicalizeSastArtifactQuarantineEncryptionContext(
          input.quarantineEncryptionContext!
        )
      ),
      completedAt: STORAGE_COMPLETED_AT
    }));

    await expect(
      harness.service.processNext(NOW, 'worker-1')
    ).resolves.toBe('QUARANTINED');

    expect(harness.gate.evaluate).not.toHaveBeenCalled();
    expect(harness.storage.apply).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'MOVE_REENCRYPT_QUARANTINE',
        quarantineEncryptionContext: expect.objectContaining({
          purpose: 'SAST_ARTIFACT_FORENSIC_QUARANTINE',
          ingestionId: 'ingestion-1'
        })
      })
    );
    expect(
      harness.store.finalize.mock.calls[0]![0].decision
    ).toEqual(
      expect.objectContaining({
        disposition: 'QUARANTINED',
        failureClass: 'SECURITY_VIOLATION',
        normalizationEligible: false,
        reasonCodes: ['ARTIFACT_DURABLE_METADATA_INVALID']
      })
    );
  });

  it('quarantines a scanner-run digest that no longer matches the bound envelope', async () => {
    const candidate = validCandidate();
    candidate.scannerImageDigest = digest(
      'tampered-scanner-image'
    );
    const harness = createHarness(candidate);
    harness.storage.apply.mockImplementation(async (input) => ({
      operationId: input.operationId,
      storageReceiptRef: 'storage-receipt://quarantine-binding-1',
      storageReceiptDigest: RECEIPT_DIGEST,
      finalObjectKey:
        `${SAST_ARTIFACT_QUARANTINE_OBJECT_PREFIX}binding-1`,
      encryptionContextDigest: digest(
        canonicalizeSastArtifactQuarantineEncryptionContext(
          input.quarantineEncryptionContext!
        )
      ),
      completedAt: STORAGE_COMPLETED_AT
    }));

    await expect(
      harness.service.processNext(NOW, 'worker-1')
    ).resolves.toBe('QUARANTINED');

    expect(harness.gate.evaluate).not.toHaveBeenCalled();
    expect(
      harness.store.finalize.mock.calls[0]![0].decision.reasonCodes
    ).toEqual(['ARTIFACT_DURABLE_BINDING_MISMATCH']);
  });

  it('deletes and rejects an expired artifact without extending retention from decision time', async () => {
    const candidate = validCandidate();
    const plan = candidate.immutablePlan as SastScanPlan;
    candidate.immutablePlan = {
      ...plan,
      createdAt: '2026-07-19T11:00:00.000Z'
    };
    const envelope = candidate.envelope as ScannerArtifactEnvelope;
    candidate.envelope = {
      ...envelope,
      producedAt: '2026-07-19T12:00:00.000Z'
    };
    candidate.envelopeDigest = digest(
      canonicalizeScannerArtifactEnvelope(
        candidate.envelope as ScannerArtifactEnvelope
      )
    );
    candidate.validationMetadata = {
      workloadIdentityValidated: true,
      transportByteCountValidated: true,
      artifactValidation: buildValidation(
        candidate.envelope as ScannerArtifactEnvelope,
        candidate.envelopeDigest as `sha256:${string}`
      )
    };
    candidate.receivedAt = '2026-07-19T12:00:10.000Z';
    candidate.scannerRunCompletedAt =
      '2026-07-19T12:00:30.000Z';
    const harness = createHarness(candidate);
    harness.storage.apply.mockImplementation(async (input) => ({
      operationId: input.operationId,
      storageReceiptRef: 'storage-receipt://delete-expired-1',
      storageReceiptDigest: RECEIPT_DIGEST,
      completedAt: STORAGE_COMPLETED_AT
    }));

    await expect(
      harness.service.processNext(NOW, 'worker-1')
    ).resolves.toBe('REJECTED');

    expect(harness.gate.evaluate).not.toHaveBeenCalled();
    expect(harness.storage.apply).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'DELETE_REJECTED'
      })
    );
    expect(
      harness.storage.apply.mock.calls[0]![0]
    ).not.toHaveProperty('retentionExpiresAt');
    const finalized = harness.store.finalize.mock.calls[0]![0];
    expect(finalized?.finalObjectKey).toBeUndefined();
    expect(finalized?.decision).toEqual(
      expect.objectContaining({
        disposition: 'REJECTED',
        failureClass: 'NON_RETRYABLE_INPUT',
        reasonCodes: ['ARTIFACT_RETENTION_EXPIRED']
      })
    );
    expect(finalized.decision).not.toHaveProperty(
      'retentionExpiresAt'
    );
  });

  it('keeps a valid artifact pending when the acceptance gate is unavailable', async () => {
    const harness = createHarness();
    harness.gate.evaluate.mockRejectedValue(
      new SastArtifactAcceptanceGateUnavailableError()
    );

    await expect(
      harness.service.processNext(NOW, 'worker-1')
    ).resolves.toBe('RETRY_SCHEDULED');

    expect(harness.store.saveIntent).not.toHaveBeenCalled();
    expect(harness.storage.apply).not.toHaveBeenCalled();
    expect(harness.store.finalize).not.toHaveBeenCalled();
    const release =
      harness.store.release.mock.calls[0]![0];
    expect(release).toEqual(
      expect.objectContaining({
        errorCode: 'ARTIFACT_ACCEPTANCE_GATE_UNAVAILABLE'
      })
    );
    expect(
      Date.parse(release.retryAt) - Date.parse(release.releasedAt)
    ).toBe(60_000);
  });

  it('reports lease loss instead of rescheduling through a stale release fence', async () => {
    const harness = createHarness();
    harness.gate.evaluate.mockRejectedValue(
      new SastArtifactAcceptanceGateUnavailableError()
    );
    harness.store.release.mockRejectedValue(
      new SastArtifactDispositionFenceError()
    );

    await expect(
      harness.service.processNext(NOW, 'worker-1')
    ).resolves.toBe('LEASE_LOST');

    expect(harness.store.finalize).not.toHaveBeenCalled();
  });

  it('does not finalize accepted retention at or after its original expiry', async () => {
    const harness = createHarness();
    harness.storage.apply.mockImplementation(async (input) => ({
      operationId: input.operationId,
      storageReceiptRef: 'storage-receipt://accepted-after-expiry-1',
      storageReceiptDigest: RECEIPT_DIGEST,
      finalObjectKey: OBJECT_KEY,
      completedAt: '2026-08-02T12:00:00.000Z'
    }));

    await expect(
      harness.service.processNext(
        new Date('2026-08-02T11:59:59.000Z'),
        'worker-1'
      )
    ).resolves.toBe('RETRY_SCHEDULED');

    expect(harness.store.saveIntent).toHaveBeenCalledWith(
      expect.objectContaining({
        intent: expect.objectContaining({
          disposition: 'ACCEPTED',
          retentionExpiresAt: '2026-08-02T12:00:00.000Z'
        })
      })
    );
    expect(harness.store.finalize).not.toHaveBeenCalled();
  });

  it('quarantines an explicit acceptance denial with its control reference', async () => {
    const harness = createHarness();
    harness.gate.evaluate.mockImplementation(async (input) => ({
      outcome: 'DENY',
      controlRef: 'kill-switch-evaluation://deny-1',
      evaluatedAt: input.evaluatedAt,
      reasonCode: 'SCANNER_VERSION_DISABLED'
    }));
    harness.storage.apply.mockImplementation(async (input) => ({
      operationId: input.operationId,
      storageReceiptRef: 'storage-receipt://quarantine-denied-1',
      storageReceiptDigest: RECEIPT_DIGEST,
      finalObjectKey:
        `${SAST_ARTIFACT_QUARANTINE_OBJECT_PREFIX}denied-1`,
      encryptionContextDigest: digest(
        canonicalizeSastArtifactQuarantineEncryptionContext(
          input.quarantineEncryptionContext!
        )
      ),
      completedAt: STORAGE_COMPLETED_AT
    }));

    await expect(
      harness.service.processNext(NOW, 'worker-1')
    ).resolves.toBe('QUARANTINED');

    expect(
      harness.store.finalize.mock.calls[0]![0].decision
    ).toEqual(
      expect.objectContaining({
        disposition: 'QUARANTINED',
        acceptanceControlRef:
          'kill-switch-evaluation://deny-1',
        reasonCodes: ['ARTIFACT_ACCEPTANCE_DENIED']
      })
    );
  });

  it('keeps a quarantine pending when its encryption-context receipt is tampered', async () => {
    const candidate = validCandidate();
    const validation = (
      candidate.validationMetadata as {
        artifactValidation: SastArtifactValidationResult;
      }
    ).artifactValidation;
    candidate.validationMetadata = {
      workloadIdentityValidated: true,
      transportByteCountValidated: true,
      artifactValidation: {
        ...validation,
        resultDigest: digest('tampered-validation')
      }
    };
    const harness = createHarness(candidate);
    harness.storage.apply.mockImplementation(async (input) => ({
      operationId: input.operationId,
      storageReceiptRef: 'storage-receipt://tampered-context-1',
      storageReceiptDigest: RECEIPT_DIGEST,
      finalObjectKey:
        `${SAST_ARTIFACT_QUARANTINE_OBJECT_PREFIX}tampered-1`,
      encryptionContextDigest: digest('wrong-encryption-context'),
      completedAt: STORAGE_COMPLETED_AT
    }));

    await expect(
      harness.service.processNext(NOW, 'worker-1')
    ).resolves.toBe('RETRY_SCHEDULED');

    expect(harness.store.finalize).not.toHaveBeenCalled();
    expect(harness.store.release).toHaveBeenCalledWith(
      expect.objectContaining({
        errorCode: 'ARTIFACT_DISPOSITION_RETRYABLE_FAILURE'
      })
    );
  });

  it('quarantines an unsuccessful or truncated scanner result even when validation metadata says passed', async () => {
    const candidate = validCandidate();
    candidate.scannerRunStatus = 'FAILED';
    const envelope = candidate.envelope as ScannerArtifactEnvelope;
    candidate.envelope = {
      ...envelope,
      truncated: true
    };
    candidate.envelopeDigest = digest(
      canonicalizeScannerArtifactEnvelope(
        candidate.envelope as ScannerArtifactEnvelope
      )
    );
    const validation = buildValidation(
      candidate.envelope as ScannerArtifactEnvelope,
      candidate.envelopeDigest as `sha256:${string}`
    );
    candidate.validationMetadata = {
      workloadIdentityValidated: true,
      transportByteCountValidated: true,
      artifactValidation: validation
    };
    const harness = createHarness(candidate);
    harness.storage.apply.mockImplementation(async (input) => ({
      operationId: input.operationId,
      storageReceiptRef: 'storage-receipt://quarantine-failed-1',
      storageReceiptDigest: RECEIPT_DIGEST,
      finalObjectKey:
        `${SAST_ARTIFACT_QUARANTINE_OBJECT_PREFIX}failed-1`,
      encryptionContextDigest: digest(
        canonicalizeSastArtifactQuarantineEncryptionContext(
          input.quarantineEncryptionContext!
        )
      ),
      completedAt: STORAGE_COMPLETED_AT
    }));

    await expect(
      harness.service.processNext(NOW, 'worker-1')
    ).resolves.toBe('QUARANTINED');

    expect(harness.gate.evaluate).not.toHaveBeenCalled();
    expect(
      harness.store.finalize.mock.calls[0]![0].decision.reasonCodes
    ).toEqual([
      'ARTIFACT_DURABLE_METADATA_INVALID',
      'ARTIFACT_SCANNER_RUN_NOT_SUCCESSFUL'
    ]);
  });

  it('durably downgrades an accepted intent to metadata-only rejection when the object is absent', async () => {
    const harness = createHarness();
    harness.storage.apply.mockImplementation(async (input) => {
      throw new SastArtifactSourceObjectMissingError({
        operationId: input.operationId,
        storageReceiptRef: 'storage-receipt://source-absent-1',
        storageReceiptDigest: RECEIPT_DIGEST,
        completedAt: STORAGE_COMPLETED_AT
      });
    });

    await expect(
      harness.service.processNext(NOW, 'worker-1')
    ).resolves.toBe('REJECTED');

    expect(harness.store.saveIntent).toHaveBeenCalledTimes(2);
    const first = harness.store.saveIntent.mock.calls[0]![0];
    const second = harness.store.saveIntent.mock.calls[1]![0];
    expect(first.intent.disposition).toBe('ACCEPTED');
    expect(second).toEqual(
      expect.objectContaining({
        expectedIntentDigest: first.intent.intentDigest,
        operationId: first.operationId,
        intent: expect.objectContaining({
          disposition: 'REJECTED',
          failureClass: 'SECURITY_VIOLATION',
          reasonCodes: ['ARTIFACT_SOURCE_OBJECT_MISSING']
        })
      })
    );
    expect(harness.store.finalize).toHaveBeenCalledWith(
      expect.objectContaining({
        finalObjectKey: undefined,
        decision: expect.objectContaining({
          disposition: 'REJECTED',
          normalizationEligible: false
        })
      })
    );
  });

  it('reuses a valid durable intent and operation id after a crash boundary', async () => {
    const first = createHarness();
    await first.service.processNext(NOW, 'worker-1');
    const saved = first.store.saveIntent.mock.calls[0]![0];
    const replayCandidate = validCandidate();
    replayCandidate.persistedIntent = saved.intent;
    replayCandidate.persistedIntentDigest = saved.intent.intentDigest;
    replayCandidate.persistedOperationId = saved.operationId;
    const replay = createHarness(replayCandidate);
    replay.gate.evaluate.mockRejectedValue(
      new Error('must not be re-evaluated')
    );

    await expect(
      replay.service.processNext(NOW, 'worker-2')
    ).resolves.toBe('ACCEPTED');

    expect(replay.gate.evaluate).not.toHaveBeenCalled();
    expect(replay.store.saveIntent).not.toHaveBeenCalled();
    expect(replay.storage.apply).toHaveBeenCalledWith(
      expect.objectContaining({
        operationId: saved.operationId
      })
    );
  });

  it('replays a missing-source rejection without losing prior tamper reasons', async () => {
    const candidate = validCandidate();
    const validation = (
      candidate.validationMetadata as {
        artifactValidation: SastArtifactValidationResult;
      }
    ).artifactValidation;
    candidate.validationMetadata = {
      workloadIdentityValidated: true,
      transportByteCountValidated: true,
      artifactValidation: {
        ...validation,
        resultDigest: digest('tampered-before-source-missing')
      }
    };
    const first = createHarness(candidate);
    first.storage.apply.mockImplementation(async (input) => {
      throw new SastArtifactSourceObjectMissingError({
        operationId: input.operationId,
        storageReceiptRef:
          'storage-receipt://tampered-source-absent-1',
        storageReceiptDigest: RECEIPT_DIGEST,
        completedAt: STORAGE_COMPLETED_AT
      });
    });

    await expect(
      first.service.processNext(NOW, 'worker-1')
    ).resolves.toBe('REJECTED');

    const missing = first.store.saveIntent.mock.calls[1]![0];
    expect(missing.intent.reasonCodes).toEqual([
      'ARTIFACT_SOURCE_OBJECT_MISSING',
      'ARTIFACT_DURABLE_METADATA_INVALID'
    ]);

    const replayCandidate = {
      ...candidate,
      persistedIntent: missing.intent,
      persistedIntentDigest: missing.intent.intentDigest,
      persistedOperationId: missing.operationId
    };
    const replay = createHarness(replayCandidate);
    replay.storage.apply.mockImplementation(async (input) => {
      throw new SastArtifactSourceObjectMissingError({
        operationId: input.operationId,
        storageReceiptRef:
          'storage-receipt://tampered-source-absent-1',
        storageReceiptDigest: RECEIPT_DIGEST,
        completedAt: STORAGE_COMPLETED_AT
      });
    });

    await expect(
      replay.service.processNext(NOW, 'worker-2')
    ).resolves.toBe('REJECTED');

    expect(replay.store.saveIntent).not.toHaveBeenCalled();
    expect(replay.storage.apply).toHaveBeenCalledWith(
      expect.objectContaining({
        operationId: missing.operationId
      })
    );
  });

  it('does not reuse a previously accepted intent after durable scanner state changes', async () => {
    const first = createHarness();
    await first.service.processNext(NOW, 'worker-1');
    const saved = first.store.saveIntent.mock.calls[0]![0];
    const changed = validCandidate();
    changed.persistedIntent = saved.intent;
    changed.persistedIntentDigest = saved.intent.intentDigest;
    changed.persistedOperationId = saved.operationId;
    changed.scannerRunStatus = 'TIMED_OUT';
    const replay = createHarness(changed);
    replay.storage.apply.mockImplementation(async (input) => ({
      operationId: input.operationId,
      storageReceiptRef: 'storage-receipt://quarantine-stale-1',
      storageReceiptDigest: RECEIPT_DIGEST,
      finalObjectKey:
        `${SAST_ARTIFACT_QUARANTINE_OBJECT_PREFIX}stale-1`,
      encryptionContextDigest: digest(
        canonicalizeSastArtifactQuarantineEncryptionContext(
          input.quarantineEncryptionContext!
        )
      ),
      completedAt: STORAGE_COMPLETED_AT
    }));

    await expect(
      replay.service.processNext(NOW, 'worker-2')
    ).resolves.toBe('QUARANTINED');

    expect(replay.gate.evaluate).not.toHaveBeenCalled();
    expect(replay.store.saveIntent).toHaveBeenCalledWith(
      expect.objectContaining({
        expectedIntentDigest: saved.intent.intentDigest,
        intent: expect.objectContaining({
          disposition: 'QUARANTINED',
          reasonCodes: [
            'ARTIFACT_DURABLE_METADATA_INVALID',
            'ARTIFACT_SCANNER_RUN_NOT_SUCCESSFUL'
          ]
        })
      })
    );
    expect(
      replay.store.saveIntent.mock.calls[0]![0].operationId
    ).not.toBe(saved.operationId);
  });
});

function createHarness(candidate = validCandidate()) {
  const store = {
    claimNext: jest.fn(
      async (input: ClaimSastArtifactDispositionInput) => ({
        ...candidate,
        leaseToken: input.leaseToken,
        leaseExpiresAt: input.leaseExpiresAt
      })
    ),
    saveIntent: jest.fn(
      async (input: SaveSastArtifactDispositionIntentInput) => {
        void input;
      }
    ),
    finalize: jest.fn(
      async (input: FinalizeSastArtifactDispositionInput) => {
        void input;
      }
    ),
    release: jest.fn(
      async (input: ReleaseSastArtifactDispositionInput) => {
        void input;
      }
    )
  };
  const gate = {
    evaluate: jest.fn(
      async (
        input: SastArtifactAcceptanceGateInput
      ): Promise<SastArtifactAcceptanceGateDecision> => ({
        outcome: 'ALLOW',
        controlRef: 'kill-switch-evaluation://allow-1',
        evaluatedAt: input.evaluatedAt
      })
    )
  };
  const storage = {
    apply: jest.fn(
      async (
        input: ApplySastArtifactStorageDispositionInput
      ): Promise<SastArtifactStorageDispositionReceipt> => ({
        operationId: input.operationId,
        storageReceiptRef: 'storage-receipt://accepted-1',
        storageReceiptDigest: RECEIPT_DIGEST,
        finalObjectKey: OBJECT_KEY,
        completedAt: STORAGE_COMPLETED_AT
      })
    )
  };
  return {
    store,
    gate,
    storage,
    service: new SastArtifactDispositionService(
      store as unknown as SastArtifactDispositionStore,
      storage as unknown as SastArtifactDispositionStorage,
      gate as unknown as SastArtifactAcceptanceGate
    )
  };
}

function validCandidate(): SastArtifactDispositionCandidate {
  const plan = buildPlan();
  const envelope = buildEnvelope(plan);
  const envelopeDigest = digest(
    canonicalizeScannerArtifactEnvelope(envelope)
  );
  const validation = buildValidation(envelope, envelopeDigest);
  return {
    ingestionId: 'ingestion-1',
    scope: {
      tenantId: plan.tenantId,
      repositoryBindingId: plan.repositoryState.repositoryBindingId,
      scanRequestId: plan.scanRequestId,
      attemptId: envelope.attemptId,
      scannerRunId: envelope.scannerRunId
    },
    workloadIdentityRef: envelope.workloadIdentityRef,
    identityValidated: true,
    envelope,
    envelopeDigest,
    declaredContentDigest: envelope.contentDigest,
    observedContentDigest: envelope.contentDigest,
    declaredByteSize: envelope.byteSize,
    observedByteSize: envelope.byteSize,
    objectKey: OBJECT_KEY,
    validationMetadata: {
      workloadIdentityValidated: true,
      transportByteCountValidated: true,
      artifactValidation: validation
    },
    receivedAt: RECEIVED_AT,
    scanner: envelope.scanner,
    scannerVersion: envelope.scannerVersion,
    scannerImageDigest: envelope.scannerImageDigest,
    wrapperDigest: envelope.wrapperDigest,
    ruleBundleDigest: envelope.ruleBundleDigest ?? null,
    vulnerabilityDatabaseDigest:
      envelope.vulnerabilityDatabaseDigest ?? null,
    scannerSetDigest: envelope.scannerSetDigest,
    schemaBundleDigest: envelope.schemaBundleDigest,
    normalizerBundleDigest: envelope.normalizerBundleDigest,
    profileId: envelope.profileId,
    profileDigest: envelope.profileDigest,
    scannerWorkspaceInventoryDigest:
      envelope.scannerWorkspaceInventoryDigest,
    scannerArtifactSchema: envelope.artifactSchema,
    scannerArtifactSchemaVersion:
      envelope.artifactSchemaVersion,
    scannerExitCode: envelope.exitCode,
    scannerTimedOut: false,
    scannerOutputLimitExceeded: false,
    scannerArtifactByteSize: envelope.byteSize,
    scannerRunStatus: 'COMPLETED',
    scannerRunCompletedAt: '2026-07-26T12:00:30.000Z',
    scannerRawArtifactObjectKey: OBJECT_KEY,
    scannerArtifactRef: envelope.artifactRef,
    preflightAttestationRef: envelope.preflightAttestationRef,
    preflightInventoryDigest: envelope.preflightInventoryDigest,
    immutablePlan: plan,
    persistedIntent: null,
    persistedIntentDigest: null,
    persistedOperationId: null,
    leaseToken: 'replaced-by-store',
    leaseExpiresAt: 'replaced-by-store'
  };
}

function buildValidation(
  envelope: ScannerArtifactEnvelope,
  envelopeDigest: `sha256:${string}`
): SastArtifactValidationResult {
  const core = {
    version: SAST_ARTIFACT_VALIDATION_VERSION,
    outcome: 'PASSED' as const,
    artifactSchema: envelope.artifactSchema,
    envelopeDigest,
    observedContentDigest: envelope.contentDigest,
    checks: {
      planBinding: true,
      schema: true,
      contentDigest: true,
      byteSize: true,
      recordCount: true,
      encoding: true,
      jsonStructure: true,
      path: true,
      coordinate: true
    },
    reasonCodes: [],
    statistics: {
      observedByteSize: envelope.byteSize,
      observedRecordCount: envelope.recordCount,
      maximumObservedDepth: 4,
      maximumObservedStringBytes: 8,
      normalizedPathCount: 0,
      coordinateCount: 0
    }
  };
  return {
    ...core,
    resultDigest: digest(
      canonicalizeSastArtifactValidationResult(core)
    )
  };
}

function buildEnvelope(plan: SastScanPlan): ScannerArtifactEnvelope {
  const descriptor = plan.scannerSet.scanners.OPENGREP;
  const rule = plan.scannerSet.ruleBundles[0];
  return {
    tenantId: plan.tenantId,
    repositoryBindingId:
      plan.repositoryState.repositoryBindingId,
    scanRequestId: plan.scanRequestId,
    attemptId: 'attempt-1',
    scannerRunId: 'scanner-run-1',
    workloadIdentityRef: 'spiffe://aegis/scan/attempt-1',
    scanner: 'OPENGREP',
    scannerVersion: descriptor.version,
    scannerImageDigest: descriptor.digest,
    wrapperDigest: descriptor.wrapper.digest,
    ruleBundleDigest: rule.digest,
    scannerSetDigest: plan.scannerSet.scannerSetDigest,
    schemaBundleDigest: plan.scannerSet.schemaBundle.digest,
    normalizerBundleDigest:
      plan.scannerSet.normalizerBundle.digest,
    profileId: plan.profile.id,
    profileDigest: plan.profileDigest,
    preflightAttestationRef: 'preflight://attempt-1',
    preflightInventoryDigest: digest('inventory'),
    scannerWorkspaceInventoryDigest: digest('inventory'),
    inputCommitSha: plan.repositoryState.fixedCommitSha,
    artifactSchema: 'OPENGREP_SARIF',
    artifactSchemaVersion:
      SAST_ARTIFACT_SCHEMA_VERSIONS.OPENGREP_SARIF,
    artifactRef: `${plan.resultIngressRef}/opengrep`,
    contentDigest: digest('artifact-body'),
    byteSize: 128,
    recordCount: 0,
    truncated: false,
    exitCode: 0,
    executionStatus: 'SUCCEEDED',
    producedAt: '2026-07-26T12:00:00.000Z'
  };
}

function buildPlan(): SastScanPlan {
  const profile = SAST_SCAN_PROFILES.JAVA_FAST_V1;
  const signed = (value: string) => ({
    digest: digest(value),
    signatureRef: `signature://${value}`,
    provenanceRef: `provenance://${value}`
  });
  const scanner = (
    kind: 'OPENGREP' | 'TRIVY' | 'SYFT',
    version: string
  ) => ({
    ...signed(`scanner-${kind}`),
    scanner: kind,
    version,
    sbomRef: `sbom://${kind.toLowerCase()}`,
    wrapper: signed(`wrapper-${kind}`)
  });
  const rule = (kind: 'OPENGREP' | 'TRIVY') => ({
    ...signed(`rule-${kind}`),
    bundleId: `${kind.toLowerCase()}-rules`,
    version: '1',
    state: 'ACTIVE' as const,
    compatibilityRef: `compatibility://${kind}`,
    rolloutPolicyRef: `rollout://${kind}`,
    killSwitchRef: `kill-switch://${kind}`,
    scanner: kind,
    source: 'PLATFORM_MANAGED' as const,
    immutable: true as const,
    customerExecutableConfigAllowed: false as const,
    rules: [
      {
        ruleId: `${kind.toLowerCase()}.fixture`,
        ruleRevision: '1',
        ruleSemanticId: `${kind.toLowerCase()}.fixture`,
        metadataDigest: digest(`rule-metadata-${kind}`)
      }
    ]
  });
  return {
    tenantId: 'tenant-1',
    scanRequestId: 'scan-1',
    canonicalScanKey: digest('canonical'),
    profile,
    profileDigest: SAST_APPROVED_PROFILE_DIGESTS[profile.id],
    policyVersion: 'policy-v1',
    repositoryState: {
      repositoryBindingId: 'repository-1',
      fixedCommitSha: 'a'.repeat(40),
      targetRef: 'refs/heads/main',
      inventoryDigest: digest('inventory'),
      attestationRef: 'preflight://attempt-1',
      shallowFetchPreferred: true,
      submodulesEnabled: false,
      lfsObjectsFetched: false
    },
    scannerSet: {
      scannerSetVersion: 'scanner-set-v1',
      scannerSetDigest: digest('scanner-set'),
      signatureRef: 'signature://scanner-set',
      provenanceRef: 'provenance://scanner-set',
      scanners: {
        OPENGREP: scanner('OPENGREP', '1.1.0'),
        TRIVY: scanner('TRIVY', '0.66.0'),
        SYFT: scanner('SYFT', '1.30.0')
      },
      ruleBundles: [rule('OPENGREP'), rule('TRIVY')],
      vulnerabilityDatabase: {
        ...signed('trivy-db'),
        databaseVersion: '2026-07-26',
        publishedAt: '2026-07-26T00:00:00.000Z'
      },
      schemaBundle: signed('schema'),
      normalizerBundle: signed('normalizer'),
      sbomSchema: 'CYCLONEDX_JSON',
      rollbackRef: 'rollback://scanner-set-v0'
    },
    isolationClass: 'HARDENED',
    resultIngressRef: 'result-ingress://tenant-1/scan-1',
    evidenceOutputRef: 'evidence-output://tenant-1/scan-1',
    auditSinkRef: 'audit-sink://tenant-1/scan-1',
    forbiddenCapabilities: [...SAST_FORBIDDEN_CAPABILITIES],
    createdAt: '2026-07-26T11:00:00.000Z'
  };
}

function digest(value: string): `sha256:${string}` {
  return `sha256:${createHash('sha256')
    .update(value, 'utf8')
    .digest('hex')}`;
}
