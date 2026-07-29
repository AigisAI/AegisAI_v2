import assert from 'node:assert/strict';
import test from 'node:test';

import {
  OPENGREP_SARIF_NORMALIZER_VERSION,
  SAST_SECRET_REDACTION_TOKEN,
  SAST_SECRET_REDACTION_VERSION,
  canonicalizeSastSecretRedactionBatch,
  canonicalizeSastSecretRedactionDecision,
  canonicalizeSastSecretRedactionRejection,
  isSastSecretRedactedFindingCandidateShapeValid,
  isSastSecretRedactionBatchShapeValid,
  isSastSecretRedactionRejectionShapeValid,
  orderSastSecretDetectorKinds,
  orderSastSecretRedactableFields,
  orderSastSecretRedactionRejectionReasons,
  stripSastSecretRedaction,
  toSastSecretRedactionAuditMetadata
} from '../dist/index.js';

const DIGEST = `sha256:${'a'.repeat(64)}`;
const DECISION_REF =
  `redaction://${SAST_SECRET_REDACTION_VERSION}/${'a'.repeat(64)}`;

test('validates a canonical transient redacted-candidate batch', () => {
  const finding = redactedFinding();
  const batch = redactedBatch(finding);

  assert.equal(
    isSastSecretRedactedFindingCandidateShapeValid(finding),
    true
  );
  assert.equal(isSastSecretRedactionBatchShapeValid(batch), true);
  assert.equal(batch.durablePersistenceAllowed, false);
  assert.equal(batch.redaction.secretValuesStored, false);
  assert.equal(batch.redaction.matchedValueDigestsStored, false);
  assert.equal(batch.redaction.sourceCandidateDigestStored, false);
  assert.equal(
    stripSastSecretRedaction(finding).durablePersistenceAllowed,
    false
  );

  const { batchDigest, ...batchCore } = batch;
  void batchDigest;
  const canonical =
    canonicalizeSastSecretRedactionBatch(batchCore);
  assert.match(canonical, /"sourceCandidateDigestStored":false/u);
  assert.match(canonical, /"durablePersistenceAllowed":false/u);
  assert.doesNotMatch(canonical, /\bstableFingerprint\b/u);
  assert.doesNotMatch(canonical, /\bevidencePackIds\b/u);
  assert.doesNotMatch(canonical, /\bstatus\b/u);
});

test('binds only sanitized candidate content into a redaction decision', () => {
  const finding = redactedFinding();
  const { decisionDigest, decisionRef, ...redactionCore } =
    finding.redaction;
  void decisionDigest;
  void decisionRef;
  const canonical = canonicalizeSastSecretRedactionDecision({
    ...finding,
    redaction: redactionCore
  });

  assert.match(canonical, /\[REDACTED\]/u);
  assert.doesNotMatch(canonical, /"matchedValueDigest":/u);
  assert.doesNotMatch(canonical, /sourceBatchDigest/u);
  assert.doesNotMatch(canonical, /rawCandidateStored":true/u);
});

test('rejects forged redaction metadata and summary totals', () => {
  const finding = redactedFinding();
  const batch = redactedBatch(finding);
  for (const forged of [
    {
      ...finding,
      redaction: {
        ...finding.redaction,
        replacementCount: 0
      }
    },
    {
      ...finding,
      redaction: {
        ...finding.redaction,
        redactedFields: []
      }
    },
    {
      ...finding,
      redaction: {
        ...finding.redaction,
        decisionRef:
          `redaction://${SAST_SECRET_REDACTION_VERSION}/${'b'.repeat(64)}`
      }
    },
    {
      ...finding,
      durablePersistenceAllowed: true
    }
  ]) {
    assert.equal(
      isSastSecretRedactedFindingCandidateShapeValid(forged),
      false
    );
  }
  assert.equal(
    isSastSecretRedactionBatchShapeValid({
      ...batch,
      redaction: {
        ...batch.redaction,
        replacementCount: 2
      }
    }),
    false
  );
  assert.equal(
    isSastSecretRedactionBatchShapeValid({
      ...batch,
      vulnerabilityDatabaseDigest: DIGEST
    }),
    false
  );
});

test('orders detector, field, and rejection enums canonically', () => {
  assert.deepEqual(
    orderSastSecretDetectorKinds([
      'JWT',
      'PLATFORM_VALUE',
      'JWT',
      'GITHUB_TOKEN'
    ]),
    ['PLATFORM_VALUE', 'GITHUB_TOKEN', 'JWT']
  );
  assert.deepEqual(
    orderSastSecretRedactableFields([
      'LOCATION_SYMBOL',
      'TITLE',
      'TITLE'
    ]),
    ['TITLE', 'LOCATION_SYMBOL']
  );
  assert.deepEqual(
    orderSastSecretRedactionRejectionReasons([
      'SECRET_REDACTION_OUTPUT_INVALID',
      'SECRET_REDACTION_INPUT_INVALID',
      'SECRET_REDACTION_OUTPUT_INVALID'
    ]),
    [
      'SECRET_REDACTION_INPUT_INVALID',
      'SECRET_REDACTION_OUTPUT_INVALID'
    ]
  );
});

test('exposes bounded safe audit metadata only', () => {
  const batch = redactedBatch(redactedFinding());
  const acceptedAudit = toSastSecretRedactionAuditMetadata({
    outcome: 'REDACTED',
    batch
  });
  assert.deepEqual(Object.keys(acceptedAudit), [
    'version',
    'outcome',
    'batchDigest',
    'artifactDigest',
    'dispositionDecisionDigest',
    'candidateCount',
    'redactedCandidateCount',
    'replacementCount',
    'detectorKinds'
  ]);

  const rejectionCore = {
    version: SAST_SECRET_REDACTION_VERSION,
    outcome: 'REJECTED',
    reasonCodes: ['SECRET_REDACTION_IDENTITY_FIELD_BLOCKED'],
    secretValuesStored: false,
    matchedValueDigestsStored: false,
    sourceCandidateDigestStored: false
  };
  const rejection = {
    ...rejectionCore,
    rejectionDigest: DIGEST
  };
  assert.equal(
    isSastSecretRedactionRejectionShapeValid(rejection),
    true
  );
  assert.deepEqual(
    toSastSecretRedactionAuditMetadata(rejection),
    {
      version: SAST_SECRET_REDACTION_VERSION,
      outcome: 'REJECTED',
      reasonCodes: ['SECRET_REDACTION_IDENTITY_FIELD_BLOCKED'],
      rejectionDigest: DIGEST
    }
  );
  assert.throws(
    () =>
      toSastSecretRedactionAuditMetadata({
        outcome: 'REDACTED',
        batch,
        secretValue: 'must-not-project'
      }),
    /result is invalid/u
  );
  assert.doesNotMatch(
    canonicalizeSastSecretRedactionRejection(rejectionCore),
    /candidate|matchedValueDigest":|secretValue":/u
  );
});

function redactedFinding() {
  return {
    tenantId: 'tenant-1',
    repositoryBindingId: 'repository-1',
    scanRequestId: 'scan-1',
    attemptId: 'attempt-1',
    scannerRunId: 'scanner-run-1',
    planDigest: DIGEST,
    canonicalScanKey: DIGEST,
    preflightAttestationRef: 'preflight://attempt-1',
    preflightInventoryDigest: DIGEST,
    commitSha: 'a'.repeat(40),
    lane: 'FAST',
    capability: 'SAST',
    title: `${SAST_SECRET_REDACTION_TOKEN} exposure`,
    description: 'A credential-like value was removed.',
    severity: 'HIGH',
    confidence: 'HIGH',
    cweIds: ['CWE-798'],
    cveIds: [],
    location: {
      kind: 'FILE',
      normalizedPath: 'src/config.ts',
      lineStart: 4,
      lineEnd: 4
    },
    identityMaterial: {
      ruleSemanticId: 'javascript.hardcoded-secret',
      symbolAnchor: '',
      sinkKind: '',
      structuralHash: DIGEST,
      scannerMatchBasedId: 'rules.secret:match-1'
    },
    provenance: {
      scanner: 'OPENGREP',
      scannerVersion: '1.22.0',
      scannerImageDigest: DIGEST,
      ruleId: 'rules.secret',
      ruleRevision: '2026.07.1',
      ruleBundleDigest: DIGEST,
      artifactDigest: DIGEST
    },
    notes: [],
    redaction: {
      version: SAST_SECRET_REDACTION_VERSION,
      secretRedactionApplied: true,
      replacementToken: SAST_SECRET_REDACTION_TOKEN,
      inspectedFieldCount: 10,
      redactedFields: ['TITLE'],
      replacementCount: 1,
      detectorKinds: ['GITHUB_TOKEN'],
      secretValueStored: false,
      matchedValueDigestStored: false,
      rawCandidateStored: false,
      decisionDigest: DIGEST,
      decisionRef: DECISION_REF
    },
    durablePersistenceAllowed: false
  };
}

function redactedBatch(finding) {
  return {
    version: SAST_SECRET_REDACTION_VERSION,
    outcome: 'REDACTED',
    sourceAdapterVersion: OPENGREP_SARIF_NORMALIZER_VERSION,
    artifactSchema: 'OPENGREP_SARIF',
    artifactSchemaVersion: '2.1.0',
    ingestionId: 'ingestion-1',
    scope: {
      tenantId: 'tenant-1',
      repositoryBindingId: 'repository-1',
      scanRequestId: 'scan-1',
      attemptId: 'attempt-1',
      scannerRunId: 'scanner-run-1'
    },
    scannerRunId: 'scanner-run-1',
    scanner: 'OPENGREP',
    scannerVersion: '1.22.0',
    scannerImageDigest: DIGEST,
    ruleBundleDigest: DIGEST,
    planDigest: DIGEST,
    canonicalScanKey: DIGEST,
    preflightAttestationRef: 'preflight://attempt-1',
    preflightInventoryDigest: DIGEST,
    lane: 'FAST',
    commitSha: 'a'.repeat(40),
    envelopeDigest: DIGEST,
    artifactDigest: DIGEST,
    schemaBundleDigest: DIGEST,
    normalizerBundleDigest: DIGEST,
    validationResultDigest: DIGEST,
    dispositionDecisionDigest: DIGEST,
    retentionExpiresAt: '2026-08-01T00:00:00.000Z',
    findings: [finding],
    redaction: {
      version: SAST_SECRET_REDACTION_VERSION,
      secretRedactionApplied: true,
      candidateCount: 1,
      batchInspectedFieldCount: 8,
      inspectedFieldCount: 18,
      redactedCandidateCount: 1,
      redactedFieldCount: 1,
      replacementCount: 1,
      detectorKinds: ['GITHUB_TOKEN'],
      secretValuesStored: false,
      matchedValueDigestsStored: false,
      rawCandidatesStored: false,
      sourceCandidateDigestStored: false
    },
    durablePersistenceAllowed: false,
    batchDigest: DIGEST
  };
}
