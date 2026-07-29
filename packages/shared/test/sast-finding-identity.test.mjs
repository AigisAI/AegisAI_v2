import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  OPENGREP_SARIF_NORMALIZER_VERSION,
  SAST_FINDING_FINGERPRINT_FIELDS,
  SAST_FINDING_FINGERPRINT_VERSION,
  SAST_FINDING_IDENTITY_REJECTION_REASON_CODES,
  SAST_FINDING_IDENTITY_VERSION,
  SAST_FINDING_UNKNOWN_NORMALIZED_PATH,
  SAST_SECRET_REDACTION_BATCH_INSPECTED_FIELD_COUNT,
  SAST_SECRET_REDACTION_TOKEN,
  SAST_SECRET_REDACTION_VERSION,
  buildFindingFingerprintPreimage,
  canonicalizeSastFindingFingerprintDecision,
  canonicalizeSastFindingIdentityRejection,
  canonicalizeSastFingerprintedFindingBatch,
  canonicalizeSastSecretRedactionBatch,
  canonicalizeSastSecretRedactionDecision,
  isSastFindingIdentityRejectionShapeValid,
  isSastFingerprintedFindingBatchShapeValid,
  isSastFingerprintedFindingShapeValid,
  orderSastFindingIdentityRejectionReasons,
  stripSastFindingFingerprint,
  toSastFindingFingerprintInput,
  toSastFindingIdentityAuditMetadata
} from '../dist/index.js';

const DIGEST = `sha256:${'a'.repeat(64)}`;

test('pins the byte-exact sast-fingerprint-v1 field contract', () => {
  const input = {
    repositoryBindingId: 'repo-é',
    capability: 'SAST',
    ruleSemanticId: 'java.sql-injection',
    normalizedPath: 'src/Café.java',
    symbolAnchor: 'com.example.Café#run',
    sinkKind: 'SQL_EXECUTE',
    structuralHash: 'ast:v1|call(é)'
  };
  const decomposed = {
    ...input,
    repositoryBindingId: 'repo-e\u0301',
    normalizedPath: 'src/Cafe\u0301.java',
    symbolAnchor: 'com.example.Cafe\u0301#run',
    structuralHash: 'ast:v1|call(e\u0301)'
  };
  const expected =
    'sast-fingerprint-v1\0' +
    '7:repo-é4:SAST18:java.sql-injection14:src/Café.java' +
    '21:com.example.Café#run11:SQL_EXECUTE15:ast:v1|call(é)';

  assert.equal(SAST_FINDING_FINGERPRINT_VERSION, 'sast-fingerprint-v1');
  assert.deepEqual(SAST_FINDING_FINGERPRINT_FIELDS, [
    'repositoryBindingId',
    'capability',
    'ruleSemanticId',
    'normalizedPath',
    'symbolAnchor',
    'sinkKind',
    'structuralHash'
  ]);
  assert.equal(buildFindingFingerprintPreimage(input), expected);
  assert.equal(
    buildFindingFingerprintPreimage(decomposed),
    expected
  );
  assert.equal(
    digest(expected),
    'sha256:7bc64e19d97c160a7d58334c79149af47c9148d7238732d6092f51c7df269661'
  );
});

test('length framing keeps delimiters unambiguous and preserves canonical path case', () => {
  const base = {
    repositoryBindingId: 'repository-1',
    capability: 'SAST',
    ruleSemanticId: 'rule',
    normalizedPath: 'src/File.ts',
    symbolAnchor: '',
    sinkKind: '',
    structuralHash: DIGEST
  };
  const leftSplit = buildFindingFingerprintPreimage({
    ...base,
    ruleSemanticId: 'a',
    normalizedPath: 'bc'
  });
  const rightSplit = buildFindingFingerprintPreimage({
    ...base,
    ruleSemanticId: 'ab',
    normalizedPath: 'c'
  });
  const controlCharacters = buildFindingFingerprintPreimage({
    ...base,
    ruleSemanticId: 'a:b\n\0c',
    sinkKind: '한'
  });

  assert.notEqual(leftSplit, rightSplit);
  assert.notEqual(
    buildFindingFingerprintPreimage(base),
    buildFindingFingerprintPreimage({
      ...base,
      normalizedPath: 'src/file.ts'
    })
  );
  assert.ok(controlCharacters.includes('6:a:b\n\0c'));
  assert.ok(controlCharacters.includes('3:한'));
});

test('validates a durable fingerprinted finding batch while reconstructing T035', () => {
  const sourceFinding = redactedFinding();
  const sourceBatch = redactedBatch([sourceFinding]);
  const finding = fingerprintedFinding(sourceFinding);
  const batch = fingerprintedBatch(sourceBatch, [finding]);

  assert.equal(
    isSastFingerprintedFindingShapeValid(finding, digest),
    true
  );
  assert.equal(
    isSastFingerprintedFindingBatchShapeValid(batch, digest),
    true
  );
  assert.equal(finding.durablePersistenceAllowed, true);
  assert.equal(batch.durablePersistenceAllowed, true);
  assert.equal(batch.authority.occurrenceAuthority, false);
  assert.equal(batch.authority.policyAuthority, false);
  assert.equal(batch.authority.aiPayloadEligible, false);
  assert.equal(
    stripSastFindingFingerprint(finding)
      .durablePersistenceAllowed,
    false
  );

  const { batchDigest, ...batchCore } = batch;
  void batchDigest;
  const canonical =
    canonicalizeSastFingerprintedFindingBatch(batchCore);
  assert.match(canonical, /"durablePersistenceAllowed":true/u);
  assert.match(canonical, /"fingerprintPreimagesStored":false/u);
  assert.doesNotMatch(canonical, /"fingerprintPreimage":/u);
  assert.doesNotMatch(canonical, /"evidencePackIds":/u);
  assert.doesNotMatch(canonical, /"status":/u);
});

test('projects UNKNOWN location to an explicit empty path and rejects forged bindings', () => {
  const unknownSource = redactedFinding({
    location: {
      kind: 'UNKNOWN',
      reasonCode: 'SCANNER_LOCATION_OMITTED'
    }
  });
  const input = toSastFindingFingerprintInput(unknownSource);
  assert.equal(
    input.normalizedPath,
    SAST_FINDING_UNKNOWN_NORMALIZED_PATH
  );
  assert.match(
    buildFindingFingerprintPreimage(input),
    /0:/u
  );

  const sourceBatch = redactedBatch([unknownSource]);
  const finding = fingerprintedFinding(unknownSource);
  const batch = fingerprintedBatch(sourceBatch, [finding]);
  for (const forged of [
    {
      ...finding,
      fingerprint: {
        ...finding.fingerprint,
        stableFingerprint: `sha256:${'b'.repeat(64)}`
      }
    },
    {
      ...finding,
      fingerprint: {
        ...finding.fingerprint,
        normalizedPath: 'invented/path.ts'
      }
    },
    {
      ...finding,
      fingerprint: {
        ...finding.fingerprint,
        scannerMatchIdentityAuthoritative: true
      }
    }
  ]) {
    assert.equal(
      isSastFingerprintedFindingShapeValid(forged, digest),
      false
    );
  }
  assert.equal(
    isSastFingerprintedFindingBatchShapeValid(
      {
        ...batch,
        sourceRedactionBatchDigest:
          `sha256:${'b'.repeat(64)}`
      },
      digest
    ),
    false
  );
  assert.equal(
    isSastFingerprintedFindingBatchShapeValid(
      {
        ...batch,
        authority: {
          ...batch.authority,
          publicationAuthority: true
        }
      },
      digest
    ),
    false
  );
});

test('orders coarse rejection metadata and exposes only bounded audit fields', () => {
  assert.deepEqual(
    orderSastFindingIdentityRejectionReasons([
      'FINDING_IDENTITY_OUTPUT_INVALID',
      'FINDING_IDENTITY_INPUT_INVALID',
      'FINDING_IDENTITY_OUTPUT_INVALID'
    ]),
    [
      'FINDING_IDENTITY_INPUT_INVALID',
      'FINDING_IDENTITY_OUTPUT_INVALID'
    ]
  );
  assert.deepEqual(
    SAST_FINDING_IDENTITY_REJECTION_REASON_CODES.at(-1),
    'FINDING_IDENTITY_OUTPUT_INVALID'
  );

  const sourceBatch = redactedBatch([redactedFinding()]);
  const finding = fingerprintedFinding(sourceBatch.findings[0]);
  const batch = fingerprintedBatch(sourceBatch, [finding]);
  const acceptedAudit = toSastFindingIdentityAuditMetadata(
    { outcome: 'FINGERPRINTED', batch },
    digest
  );
  assert.deepEqual(Object.keys(acceptedAudit), [
    'version',
    'outcome',
    'batchDigest',
    'sourceRedactionBatchDigest',
    'artifactDigest',
    'dispositionDecisionDigest',
    'findingCount',
    'distinctFingerprintCount',
    'repeatedOccurrenceCount'
  ]);

  const rejectionCore = {
    version: SAST_FINDING_IDENTITY_VERSION,
    outcome: 'REJECTED',
    reasonCodes: ['FINDING_IDENTITY_FINGERPRINT_COLLISION'],
    sourceBatchDigestStored: false,
    fingerprintPreimageStored: false,
    sourceCandidateStored: false,
    secretValueStored: false
  };
  const rejection = {
    ...rejectionCore,
    rejectionDigest: digest(
      canonicalizeSastFindingIdentityRejection(rejectionCore)
    )
  };
  assert.equal(
    isSastFindingIdentityRejectionShapeValid(
      rejection,
      digest
    ),
    true
  );
  assert.deepEqual(
    toSastFindingIdentityAuditMetadata(rejection, digest),
    {
      version: SAST_FINDING_IDENTITY_VERSION,
      outcome: 'REJECTED',
      reasonCodes: ['FINDING_IDENTITY_FINGERPRINT_COLLISION'],
      rejectionDigest: rejection.rejectionDigest
    }
  );
  assert.doesNotMatch(
    canonicalizeSastFindingIdentityRejection(rejectionCore),
    /artifact|candidate|preimage":|stableFingerprint|secretValue":/u
  );
});

function fingerprintedFinding(source) {
  const input = toSastFindingFingerprintInput(source);
  const stableFingerprint = digest(
    buildFindingFingerprintPreimage(input)
  );
  const decisionCore = {
    version: SAST_FINDING_FINGERPRINT_VERSION,
    ...input,
    stableFingerprint,
    sourceRedactionDecisionDigest:
      source.redaction.decisionDigest,
    unstableCoordinatesIncluded: false,
    scannerMatchIdentityAuthoritative: false,
    fingerprintPreimageStored: false
  };
  const decisionDigest = digest(
    canonicalizeSastFindingFingerprintDecision(decisionCore)
  );
  return {
    ...source,
    cweIds: [...source.cweIds],
    cveIds: [...source.cveIds],
    location: { ...source.location },
    identityMaterial: { ...source.identityMaterial },
    provenance: { ...source.provenance },
    notes: [...source.notes],
    redaction: {
      ...source.redaction,
      redactedFields: [...source.redaction.redactedFields],
      detectorKinds: [...source.redaction.detectorKinds]
    },
    fingerprint: {
      ...decisionCore,
      decisionDigest,
      decisionRef:
        `fingerprint://${SAST_FINDING_FINGERPRINT_VERSION}/${decisionDigest.slice(
          'sha256:'.length
        )}`
    },
    durablePersistenceAllowed: true
  };
}

function fingerprintedBatch(source, findings) {
  const batchCore = {
    version: SAST_FINDING_IDENTITY_VERSION,
    outcome: 'FINGERPRINTED',
    sourceRedactionVersion: source.version,
    sourceAdapterVersion: source.sourceAdapterVersion,
    artifactSchema: source.artifactSchema,
    artifactSchemaVersion: source.artifactSchemaVersion,
    ingestionId: source.ingestionId,
    scope: { ...source.scope },
    scannerRunId: source.scannerRunId,
    scanner: source.scanner,
    scannerVersion: source.scannerVersion,
    scannerImageDigest: source.scannerImageDigest,
    ruleBundleDigest: source.ruleBundleDigest,
    planDigest: source.planDigest,
    canonicalScanKey: source.canonicalScanKey,
    preflightAttestationRef: source.preflightAttestationRef,
    preflightInventoryDigest: source.preflightInventoryDigest,
    lane: source.lane,
    commitSha: source.commitSha,
    envelopeDigest: source.envelopeDigest,
    artifactDigest: source.artifactDigest,
    schemaBundleDigest: source.schemaBundleDigest,
    normalizerBundleDigest: source.normalizerBundleDigest,
    validationResultDigest: source.validationResultDigest,
    dispositionDecisionDigest: source.dispositionDecisionDigest,
    retentionExpiresAt: source.retentionExpiresAt,
    sourceRedactionBatchDigest: source.batchDigest,
    findings,
    sourceRedaction: {
      ...source.redaction,
      detectorKinds: [...source.redaction.detectorKinds]
    },
    identity: {
      version: SAST_FINDING_IDENTITY_VERSION,
      fingerprintVersion: SAST_FINDING_FINGERPRINT_VERSION,
      findingCount: findings.length,
      distinctFingerprintCount:
        new Set(
          findings.map(
            (finding) => finding.fingerprint.stableFingerprint
          )
        ).size,
      repeatedOccurrenceCount: 0,
      fingerprintPreimagesStored: false,
      unstableCoordinatesIncluded: false,
      scannerMatchIdentityAuthoritative: false,
      rawSourceCandidatesStored: false,
      secretValuesStored: false
    },
    authority: {
      normalizedFindingPersistenceEligible: true,
      occurrenceAuthority: false,
      lifecycleAuthority: false,
      correlationAuthority: false,
      coverageAuthority: false,
      evidenceAuthority: false,
      policyAuthority: false,
      publicationAuthority: false,
      aiPayloadEligible: false
    },
    durablePersistenceAllowed: true
  };
  batchCore.identity.repeatedOccurrenceCount =
    findings.length -
    batchCore.identity.distinctFingerprintCount;
  return {
    ...batchCore,
    batchDigest: digest(
      canonicalizeSastFingerprintedFindingBatch(batchCore)
    )
  };
}

function redactedFinding(overrides = {}) {
  const finding = {
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
      decisionRef:
        `redaction://${SAST_SECRET_REDACTION_VERSION}/${'a'.repeat(64)}`
    },
    durablePersistenceAllowed: false,
    ...overrides
  };
  const {
    decisionDigest: _decisionDigest,
    decisionRef: _decisionRef,
    ...redactionCore
  } = finding.redaction;
  void _decisionDigest;
  void _decisionRef;
  const decisionDigest = digest(
    canonicalizeSastSecretRedactionDecision({
      ...finding,
      redaction: redactionCore
    })
  );
  finding.redaction.decisionDigest = decisionDigest;
  finding.redaction.decisionRef =
    `redaction://${SAST_SECRET_REDACTION_VERSION}/${decisionDigest.slice(
      'sha256:'.length
    )}`;
  return finding;
}

function redactedBatch(findings) {
  const redactedCandidateCount = findings.filter(
    (finding) => finding.redaction.replacementCount > 0
  ).length;
  const redactedFieldCount = findings.reduce(
    (sum, finding) =>
      sum + finding.redaction.redactedFields.length,
    0
  );
  const replacementCount = findings.reduce(
    (sum, finding) => sum + finding.redaction.replacementCount,
    0
  );
  const batch = {
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
    findings,
    redaction: {
      version: SAST_SECRET_REDACTION_VERSION,
      secretRedactionApplied: true,
      candidateCount: findings.length,
      batchInspectedFieldCount:
        SAST_SECRET_REDACTION_BATCH_INSPECTED_FIELD_COUNT,
      inspectedFieldCount:
        findings.reduce(
          (sum, finding) =>
            sum + finding.redaction.inspectedFieldCount,
          0
        ) + SAST_SECRET_REDACTION_BATCH_INSPECTED_FIELD_COUNT,
      redactedCandidateCount,
      redactedFieldCount,
      replacementCount,
      detectorKinds:
        redactedCandidateCount === 0 ? [] : ['GITHUB_TOKEN'],
      secretValuesStored: false,
      matchedValueDigestsStored: false,
      rawCandidatesStored: false,
      sourceCandidateDigestStored: false
    },
    durablePersistenceAllowed: false,
    batchDigest: DIGEST
  };
  const { batchDigest: _batchDigest, ...batchCore } = batch;
  void _batchDigest;
  batch.batchDigest = digest(
    canonicalizeSastSecretRedactionBatch(batchCore)
  );
  return batch;
}

function digest(value) {
  return `sha256:${createHash('sha256')
    .update(value, 'utf8')
    .digest('hex')}`;
}
