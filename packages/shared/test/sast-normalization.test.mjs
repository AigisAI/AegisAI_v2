import assert from 'node:assert/strict';
import test from 'node:test';

import {
  OPENGREP_SARIF_NORMALIZER_VERSION,
  SAST_NORMALIZATION_LIMITS,
  canonicalizeOpenGrepSarifNormalizationBatch,
  canonicalizeOpenGrepSarifNormalizationRejection,
  compareSastNormalizationIdentifiers,
  compareSastNormalizedFindingCandidates,
  isOpenGrepSarifNormalizationBatchShapeValid,
  isOpenGrepSarifNormalizationRejectionShapeValid,
  orderSastNormalizationNotes,
  orderSastNormalizationRejectionReasons
} from '../dist/index.js';

const DIGEST = `sha256:${'a'.repeat(64)}`;

test('pins the OpenGrep adapter version and normalized field limits', () => {
  assert.equal(
    OPENGREP_SARIF_NORMALIZER_VERSION,
    'opengrep-sarif-normalizer-v1'
  );
  assert.deepEqual(SAST_NORMALIZATION_LIMITS, {
    titleBytes: 512,
    descriptionBytes: 4096,
    normalizedPathBytes: 1024,
    symbolBytes: 512,
    ruleIdBytes: 256,
    ruleRevisionBytes: 256,
    scannerIdentityHintBytes: 512,
    vulnerabilityIdentifierBytes: 64,
    maximumRuleTags: 128,
    maximumCweIds: 25,
    maximumCveIds: 25
  });
});

test('orders and de-duplicates rejection reasons independently of discovery order', () => {
  assert.deepEqual(
    orderSastNormalizationRejectionReasons([
      'NORMALIZATION_TEXT_INVALID',
      'NORMALIZATION_ACCEPTANCE_INVALID',
      'NORMALIZATION_TEXT_INVALID',
      'NORMALIZATION_CONTENT_DIGEST_MISMATCH'
    ]),
    [
      'NORMALIZATION_ACCEPTANCE_INVALID',
      'NORMALIZATION_CONTENT_DIGEST_MISMATCH',
      'NORMALIZATION_TEXT_INVALID'
    ]
  );
  assert.deepEqual(
    orderSastNormalizationNotes([
      'UNKNOWN_CONFIDENCE',
      'UNKNOWN_SEVERITY',
      'UNKNOWN_CONFIDENCE'
    ]),
    ['UNKNOWN_SEVERITY', 'UNKNOWN_CONFIDENCE']
  );
});

test('uses runtime-independent natural identifier and finding order', () => {
  assert.deepEqual(
    ['CWE-10', 'CWE-2', 'CWE-1'].sort(
      compareSastNormalizationIdentifiers
    ),
    ['CWE-1', 'CWE-2', 'CWE-10']
  );

  const finding = batchCore().findings[0];
  const lineTwo = {
    ...finding,
    location: {
      kind: 'FILE',
      normalizedPath: 'src/App.java',
      lineStart: 2,
      columnStart: 1
    },
    identityMaterial: {
      ...finding.identityMaterial,
      structuralHash: 'hash-2',
      scannerMatchBasedId: 'match-2'
    }
  };
  const lineTen = {
    ...finding,
    location: {
      kind: 'FILE',
      normalizedPath: 'src/App.java',
      lineStart: 10,
      columnStart: 1
    },
    identityMaterial: {
      ...finding.identityMaterial,
      structuralHash: 'hash-10',
      scannerMatchBasedId: 'match-10'
    }
  };
  assert.deepEqual(
    [lineTen, lineTwo].sort(compareSastNormalizedFindingCandidates),
    [lineTwo, lineTen]
  );
});

test('canonicalizes transient candidates without inventing durable finding state', () => {
  const core = batchCore();
  const canonical = canonicalizeOpenGrepSarifNormalizationBatch(core);
  const reordered = {
    durablePersistenceAllowed: false,
    findings: core.findings,
    dispositionDecisionDigest: core.dispositionDecisionDigest,
    validationResultDigest: core.validationResultDigest,
    normalizerBundleDigest: core.normalizerBundleDigest,
    schemaBundleDigest: core.schemaBundleDigest,
    artifactDigest: core.artifactDigest,
    envelopeDigest: core.envelopeDigest,
    commitSha: core.commitSha,
    lane: core.lane,
    ruleBundleDigest: core.ruleBundleDigest,
    scannerImageDigest: core.scannerImageDigest,
    scannerVersion: core.scannerVersion,
    scanner: core.scanner,
    scannerRunId: core.scannerRunId,
    scope: {
      scannerRunId: core.scope.scannerRunId,
      attemptId: core.scope.attemptId,
      scanRequestId: core.scope.scanRequestId,
      repositoryBindingId: core.scope.repositoryBindingId,
      tenantId: core.scope.tenantId
    },
    ingestionId: core.ingestionId,
    artifactSchemaVersion: core.artifactSchemaVersion,
    artifactSchema: core.artifactSchema,
    adapterVersion: core.adapterVersion,
    version: core.version
  };

  assert.equal(
    canonical,
    canonicalizeOpenGrepSarifNormalizationBatch(reordered)
  );
  assert.doesNotMatch(canonical, /stableFingerprint/u);
  assert.doesNotMatch(canonical, /evidencePackIds/u);
  assert.doesNotMatch(canonical, /"status"/u);
  assert.match(canonical, /"durablePersistenceAllowed":false/u);
  assert.match(canonical, /"scannerMatchBasedId":"match-id"/u);
});

test('canonicalizes bounded rejection metadata only', () => {
  const canonical = canonicalizeOpenGrepSarifNormalizationRejection({
    version: OPENGREP_SARIF_NORMALIZER_VERSION,
    adapterVersion: OPENGREP_SARIF_NORMALIZER_VERSION,
    outcome: 'REJECTED',
    ingestionId: 'ingestion-1',
    reasonCodes: [
      'NORMALIZATION_ACCEPTANCE_INVALID',
      'NORMALIZATION_TEXT_INVALID'
    ]
  });

  assert.equal(
    canonical,
    '{"version":"opengrep-sarif-normalizer-v1","adapterVersion":"opengrep-sarif-normalizer-v1","outcome":"REJECTED","ingestionId":"ingestion-1","reasonCodes":["NORMALIZATION_ACCEPTANCE_INVALID","NORMALIZATION_TEXT_INVALID"]}'
  );
  assert.doesNotMatch(canonical, /source|snippet|payload|objectKey/iu);
});

test('shape validators preserve transient, scoped, and ordered invariants', () => {
  const core = batchCore();
  const batch = {
    ...core,
    batchDigest: DIGEST
  };
  assert.equal(
    isOpenGrepSarifNormalizationBatchShapeValid(batch),
    true
  );
  assert.equal(
    isOpenGrepSarifNormalizationBatchShapeValid({
      ...batch,
      durablePersistenceAllowed: true
    }),
    false
  );
  assert.equal(
    isOpenGrepSarifNormalizationBatchShapeValid({
      ...batch,
      findings: [
        {
          ...batch.findings[0],
          tenantId: 'another-tenant'
        }
      ]
    }),
    false
  );
  const finding = batch.findings[0];
  const earlier = {
    ...finding,
    location: {
      kind: 'FILE',
      normalizedPath: 'src/App.java',
      lineStart: 2,
      columnStart: 1
    },
    identityMaterial: {
      ...finding.identityMaterial,
      structuralHash: 'hash-2',
      scannerMatchBasedId: 'match-2'
    }
  };
  const later = {
    ...finding,
    location: {
      kind: 'FILE',
      normalizedPath: 'src/App.java',
      lineStart: 10,
      columnStart: 1
    },
    identityMaterial: {
      ...finding.identityMaterial,
      structuralHash: 'hash-10',
      scannerMatchBasedId: 'match-10'
    }
  };
  assert.equal(
    isOpenGrepSarifNormalizationBatchShapeValid({
      ...batch,
      findings: [earlier, later]
    }),
    true
  );
  assert.equal(
    isOpenGrepSarifNormalizationBatchShapeValid({
      ...batch,
      findings: [later, earlier]
    }),
    false
  );

  const rejection = {
    version: OPENGREP_SARIF_NORMALIZER_VERSION,
    adapterVersion: OPENGREP_SARIF_NORMALIZER_VERSION,
    outcome: 'REJECTED',
    ingestionId: 'ingestion-1',
    reasonCodes: [
      'NORMALIZATION_ACCEPTANCE_INVALID',
      'NORMALIZATION_TEXT_INVALID'
    ],
    rejectionDigest: DIGEST
  };
  assert.equal(
    isOpenGrepSarifNormalizationRejectionShapeValid(rejection),
    true
  );
  assert.equal(
    isOpenGrepSarifNormalizationRejectionShapeValid({
      ...rejection,
      reasonCodes: [
        'NORMALIZATION_TEXT_INVALID',
        'NORMALIZATION_ACCEPTANCE_INVALID'
      ]
    }),
    false
  );
});

function batchCore() {
  return {
    version: OPENGREP_SARIF_NORMALIZER_VERSION,
    adapterVersion: OPENGREP_SARIF_NORMALIZER_VERSION,
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
    lane: 'FAST',
    commitSha: 'a'.repeat(40),
    envelopeDigest: DIGEST,
    artifactDigest: DIGEST,
    schemaBundleDigest: DIGEST,
    normalizerBundleDigest: DIGEST,
    validationResultDigest: DIGEST,
    dispositionDecisionDigest: DIGEST,
    findings: [
      {
        tenantId: 'tenant-1',
        repositoryBindingId: 'repository-1',
        scanRequestId: 'scan-1',
        attemptId: 'attempt-1',
        scannerRunId: 'scanner-run-1',
        commitSha: 'a'.repeat(40),
        lane: 'FAST',
        capability: 'SAST',
        title: 'Finding',
        description: 'Plain text',
        severity: 'INFO',
        confidence: 'UNKNOWN',
        cweIds: [],
        cveIds: [],
        location: {
          kind: 'UNKNOWN',
          reasonCode: 'SCANNER_LOCATION_OMITTED'
        },
        identityMaterial: {
          ruleSemanticId: 'rule-1',
          symbolAnchor: '',
          sinkKind: '',
          structuralHash: DIGEST,
          scannerMatchBasedId: 'match-id'
        },
        provenance: {
          scanner: 'OPENGREP',
          scannerVersion: '1.22.0',
          scannerImageDigest: DIGEST,
          ruleId: 'rule-1',
          ruleRevision: '1',
          ruleBundleDigest: DIGEST,
          artifactDigest: DIGEST
        },
        notes: ['UNKNOWN_SEVERITY', 'UNKNOWN_CONFIDENCE'],
        durablePersistenceAllowed: false
      }
    ],
    durablePersistenceAllowed: false
  };
}
