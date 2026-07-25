import assert from 'node:assert/strict';
import test from 'node:test';

import {
  SAST_ARTIFACT_DISPOSITION_VERSION,
  SAST_ARTIFACT_MAX_RETENTION_SECONDS,
  canonicalizeSastArtifactDispositionDecision,
  canonicalizeSastArtifactDispositionIntent,
  isSastArtifactDispositionDecisionShapeValid,
  isSastArtifactDispositionIntentShapeValid
} from '../dist/index.js';

const DIGEST = `sha256:${'a'.repeat(64)}`;

test('exports the seven-day maximum without permitting an accepted artifact to omit its gate', () => {
  assert.equal(SAST_ARTIFACT_MAX_RETENTION_SECONDS, 604800);
  const intent = acceptedIntent();
  assert.equal(isSastArtifactDispositionIntentShapeValid(intent), true);
  delete intent.acceptanceControlRef;
  assert.equal(isSastArtifactDispositionIntentShapeValid(intent), false);
});

test('canonicalizes intent fields in contract order independent of input insertion order', () => {
  const first = acceptedIntent();
  const { intentDigest: _firstDigest, ...firstCore } = first;
  const secondCore = {
    createdAt: firstCore.createdAt,
    acceptanceControlRef: firstCore.acceptanceControlRef,
    retentionExpiresAt: firstCore.retentionExpiresAt,
    normalizationEligible: firstCore.normalizationEligible,
    validationResultDigest: firstCore.validationResultDigest,
    validationReasonCodes: firstCore.validationReasonCodes,
    reasonCodes: firstCore.reasonCodes,
    storageAction: firstCore.storageAction,
    disposition: firstCore.disposition,
    scope: {
      scannerRunId: firstCore.scope.scannerRunId,
      attemptId: firstCore.scope.attemptId,
      scanRequestId: firstCore.scope.scanRequestId,
      repositoryBindingId: firstCore.scope.repositoryBindingId,
      tenantId: firstCore.scope.tenantId
    },
    ingestionId: firstCore.ingestionId,
    version: firstCore.version
  };
  assert.equal(
    canonicalizeSastArtifactDispositionIntent(firstCore),
    canonicalizeSastArtifactDispositionIntent(secondCore)
  );
});

test('rejects unordered, duplicated, and disposition-incompatible reason codes', () => {
  const unordered = {
    ...quarantinedIntent(),
    reasonCodes: [
      'ARTIFACT_VALIDATION_FAILED',
      'ARTIFACT_DURABLE_METADATA_INVALID'
    ]
  };
  assert.equal(
    isSastArtifactDispositionIntentShapeValid(unordered),
    false
  );

  const duplicated = {
    ...quarantinedIntent(),
    reasonCodes: [
      'ARTIFACT_VALIDATION_FAILED',
      'ARTIFACT_VALIDATION_FAILED'
    ]
  };
  assert.equal(
    isSastArtifactDispositionIntentShapeValid(duplicated),
    false
  );

  const authoritativeAcceptedReasonOnRejected = {
    ...rejectedIntent(),
    reasonCodes: [
      'ARTIFACT_SOURCE_OBJECT_MISSING',
      'ARTIFACT_VALIDATION_ACCEPTED'
    ]
  };
  assert.equal(
    isSastArtifactDispositionIntentShapeValid(
      authoritativeAcceptedReasonOnRejected
    ),
    false
  );
});

test('requires a quarantine encryption-context digest only for quarantined decisions', () => {
  const quarantine = quarantinedDecision();
  assert.equal(
    isSastArtifactDispositionDecisionShapeValid(quarantine),
    true
  );
  const { encryptionContextDigest: _removed, ...missingContext } =
    quarantine;
  assert.equal(
    isSastArtifactDispositionDecisionShapeValid(missingContext),
    false
  );

  const accepted = {
    ...acceptedDecision(),
    encryptionContextDigest: DIGEST
  };
  assert.equal(
    isSastArtifactDispositionDecisionShapeValid(accepted),
    false
  );

  assert.equal(
    isSastArtifactDispositionDecisionShapeValid({
      ...quarantine,
      storageOperationId:
        `sast-artifact-disposition-v1:${'b'.repeat(64)}`
    }),
    false
  );
  assert.equal(
    isSastArtifactDispositionDecisionShapeValid({
      ...quarantine,
      storageReceiptRef: 'restricted/sast-artifact-quarantine/object-1'
    }),
    false
  );
  assert.equal(
    isSastArtifactDispositionDecisionShapeValid({
      ...quarantine,
      decidedAt: quarantine.retentionExpiresAt
    }),
    false
  );
});

test('canonicalizes final decisions without storage object keys or key material', () => {
  const decision = quarantinedDecision();
  const { decisionDigest: _decisionDigest, ...core } = decision;
  const serialized = canonicalizeSastArtifactDispositionDecision(core);
  assert.equal(serialized.includes('objectKey'), false);
  assert.equal(serialized.includes('kms'), false);
  assert.equal(serialized.includes('plaintext'), false);
});

function acceptedIntent() {
  return {
    version: SAST_ARTIFACT_DISPOSITION_VERSION,
    ingestionId: 'ingestion-1',
    scope: scope(),
    disposition: 'ACCEPTED',
    storageAction: 'RETAIN_ACCEPTED',
    reasonCodes: ['ARTIFACT_VALIDATION_ACCEPTED'],
    validationReasonCodes: [],
    validationResultDigest: DIGEST,
    normalizationEligible: true,
    retentionExpiresAt: '2026-08-02T12:00:00.000Z',
    acceptanceControlRef: 'kill-switch-evaluation://allow-1',
    createdAt: '2026-07-26T12:01:00.000Z',
    intentDigest: DIGEST
  };
}

function rejectedIntent() {
  return {
    version: SAST_ARTIFACT_DISPOSITION_VERSION,
    ingestionId: 'ingestion-1',
    scope: scope(),
    disposition: 'REJECTED',
    storageAction: 'DELETE_REJECTED',
    failureClass: 'SECURITY_VIOLATION',
    reasonCodes: ['ARTIFACT_SOURCE_OBJECT_MISSING'],
    validationReasonCodes: [],
    validationResultDigest: DIGEST,
    normalizationEligible: false,
    createdAt: '2026-07-26T12:01:00.000Z',
    intentDigest: DIGEST
  };
}

function quarantinedIntent() {
  return {
    version: SAST_ARTIFACT_DISPOSITION_VERSION,
    ingestionId: 'ingestion-1',
    scope: scope(),
    disposition: 'QUARANTINED',
    storageAction: 'MOVE_REENCRYPT_QUARANTINE',
    failureClass: 'SECURITY_VIOLATION',
    reasonCodes: ['ARTIFACT_VALIDATION_FAILED'],
    validationReasonCodes: ['ARTIFACT_JSON_MALFORMED'],
    validationResultDigest: DIGEST,
    normalizationEligible: false,
    retentionExpiresAt: '2026-08-02T12:00:00.000Z',
    createdAt: '2026-07-26T12:01:00.000Z',
    intentDigest: DIGEST
  };
}

function acceptedDecision() {
  const intent = acceptedIntent();
  return {
    version: intent.version,
    ingestionId: intent.ingestionId,
    disposition: intent.disposition,
    storageAction: intent.storageAction,
    reasonCodes: intent.reasonCodes,
    validationReasonCodes: intent.validationReasonCodes,
    validationResultDigest: intent.validationResultDigest,
    normalizationEligible: intent.normalizationEligible,
    retentionExpiresAt: intent.retentionExpiresAt,
    acceptanceControlRef: intent.acceptanceControlRef,
    intentDigest: intent.intentDigest,
    storageOperationId:
      `sast-artifact-disposition-v1:${'a'.repeat(64)}`,
    storageReceiptRef: 'storage-receipt://accepted-1',
    storageReceiptDigest: DIGEST,
    decidedAt: '2026-07-26T12:01:01.000Z',
    decisionDigest: DIGEST
  };
}

function quarantinedDecision() {
  const intent = quarantinedIntent();
  return {
    version: intent.version,
    ingestionId: intent.ingestionId,
    disposition: intent.disposition,
    storageAction: intent.storageAction,
    failureClass: intent.failureClass,
    reasonCodes: intent.reasonCodes,
    validationReasonCodes: intent.validationReasonCodes,
    validationResultDigest: intent.validationResultDigest,
    normalizationEligible: intent.normalizationEligible,
    retentionExpiresAt: intent.retentionExpiresAt,
    intentDigest: intent.intentDigest,
    storageOperationId:
      `sast-artifact-disposition-v1:${'a'.repeat(64)}`,
    storageReceiptRef: 'storage-receipt://quarantine-1',
    storageReceiptDigest: DIGEST,
    encryptionContextDigest: DIGEST,
    decidedAt: '2026-07-26T12:01:01.000Z',
    decisionDigest: DIGEST
  };
}

function scope() {
  return {
    tenantId: 'tenant-1',
    repositoryBindingId: 'repository-1',
    scanRequestId: 'scan-1',
    attemptId: 'attempt-1',
    scannerRunId: 'scanner-run-1'
  };
}
