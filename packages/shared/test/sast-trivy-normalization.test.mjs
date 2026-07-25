import assert from 'node:assert/strict';
import test from 'node:test';

import {
  TRIVY_JSON_NORMALIZER_VERSION,
  canonicalizeTrivyJsonNormalizationBatch,
  canonicalizeTrivyJsonNormalizationRejection,
  isTrivyJsonNormalizationBatchShapeValid,
  isTrivyJsonNormalizationRejectionShapeValid
} from '../dist/index.js';

const DIGEST = `sha256:${'a'.repeat(64)}`;

test('pins the Trivy JSON adapter and canonical capability-aware batch', () => {
  assert.equal(
    TRIVY_JSON_NORMALIZER_VERSION,
    'trivy-json-normalizer-v1'
  );
  const core = batchCore();
  const canonical = canonicalizeTrivyJsonNormalizationBatch(core);
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
    preflightInventoryDigest: core.preflightInventoryDigest,
    preflightAttestationRef: core.preflightAttestationRef,
    canonicalScanKey: core.canonicalScanKey,
    planDigest: core.planDigest,
    vulnerabilityDatabaseDigest: core.vulnerabilityDatabaseDigest,
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
    canonicalizeTrivyJsonNormalizationBatch(reordered)
  );
  assert.match(canonical, /"capability":"SECRET_DETECTION"/u);
  assert.match(canonical, /"platformPolicyAuthority":false/u);
  assert.match(canonical, /"secretValueStored":false/u);
  assert.doesNotMatch(canonical, /stableFingerprint|evidencePackIds/u);
});

test('validates exact Trivy provenance and denies scanner policy authority', () => {
  const core = batchCore();
  const batch = { ...core, batchDigest: DIGEST };
  assert.equal(isTrivyJsonNormalizationBatchShapeValid(batch), true);

  for (const finding of [
    {
      ...core.findings[0],
      scannerDisposition: {
        ...core.findings[0].scannerDisposition,
        platformPolicyAuthority: true
      }
    },
    {
      ...core.findings[0],
      scannerDisposition: {
        source: 'DIRECT',
        status: 'ignored',
        platformPolicyAuthority: false
      }
    },
    {
      ...core.findings[0],
      provenance: {
        ...core.findings[0].provenance,
        vulnerabilityDatabaseDigest: `sha256:${'b'.repeat(64)}`
      }
    },
    {
      ...core.findings[0],
      provenance: {
        ...core.findings[0].provenance,
        ruleSource: 'VULNERABILITY_DATABASE'
      }
    },
    {
      ...core.findings[0],
      trivy: {
        ...core.findings[0].trivy,
        secretValueStored: true
      }
    },
    {
      ...core.findings[0],
      confidence: 'HIGH'
    },
    {
      ...core.findings[0],
      notes: []
    },
    {
      ...core.findings[0],
      identityMaterial: {
        ...core.findings[0].identityMaterial,
        sinkKind: 'GITHUB'
      }
    },
    {
      ...core.findings[0],
      identityMaterial: {
        ...core.findings[0].identityMaterial,
        structuralHash: 'scanner-controlled'
      }
    }
  ]) {
    assert.equal(
      isTrivyJsonNormalizationBatchShapeValid({
        ...batch,
        findings: [finding]
      }),
      false
    );
  }
});

test('canonicalizes ordered bounded Trivy rejection metadata only', () => {
  const core = {
    version: TRIVY_JSON_NORMALIZER_VERSION,
    adapterVersion: TRIVY_JSON_NORMALIZER_VERSION,
    outcome: 'REJECTED',
    ingestionId: 'ingestion-1',
    reasonCodes: [
      'NORMALIZATION_TRIVY_SECRET_INVALID',
      'NORMALIZATION_TEXT_INVALID'
    ]
  };
  const canonical =
    canonicalizeTrivyJsonNormalizationRejection(core);
  assert.equal(
    canonical,
    '{"version":"trivy-json-normalizer-v1","adapterVersion":"trivy-json-normalizer-v1","outcome":"REJECTED","ingestionId":"ingestion-1","reasonCodes":["NORMALIZATION_TRIVY_SECRET_INVALID","NORMALIZATION_TEXT_INVALID"]}'
  );
  assert.doesNotMatch(
    canonical,
    /"(?:Match|Code|Statement|Source)":/u
  );
  assert.equal(
    isTrivyJsonNormalizationRejectionShapeValid({
      ...core,
      rejectionDigest: DIGEST
    }),
    true
  );
  assert.equal(
    isTrivyJsonNormalizationRejectionShapeValid({
      ...core,
      reasonCodes: [...core.reasonCodes].reverse(),
      rejectionDigest: DIGEST
    }),
    false
  );
});

function batchCore() {
  return {
    version: TRIVY_JSON_NORMALIZER_VERSION,
    adapterVersion: TRIVY_JSON_NORMALIZER_VERSION,
    artifactSchema: 'TRIVY_JSON',
    artifactSchemaVersion: '2',
    ingestionId: 'ingestion-1',
    scope: {
      tenantId: 'tenant-1',
      repositoryBindingId: 'repository-1',
      scanRequestId: 'scan-1',
      attemptId: 'attempt-1',
      scannerRunId: 'scanner-run-1'
    },
    scannerRunId: 'scanner-run-1',
    scanner: 'TRIVY',
    scannerVersion: '0.66.0',
    scannerImageDigest: DIGEST,
    ruleBundleDigest: DIGEST,
    vulnerabilityDatabaseDigest: DIGEST,
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
    findings: [
      {
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
        capability: 'SECRET_DETECTION',
        title: 'AWS Access Key ID',
        description:
          'Potential AWS Access Key ID detected. The secret value and scanner context were discarded.',
        severity: 'CRITICAL',
        confidence: 'UNKNOWN',
        cweIds: [],
        cveIds: [],
        location: {
          kind: 'FILE',
          normalizedPath: 'deploy.sh',
          lineStart: 3,
          lineEnd: 3
        },
        identityMaterial: {
          ruleSemanticId: 'secret.aws-access-key-id',
          symbolAnchor: '',
          sinkKind: 'AWS',
          structuralHash: DIGEST,
          scannerMatchBasedId: DIGEST
        },
        provenance: {
          scanner: 'TRIVY',
          scannerVersion: '0.66.0',
          scannerImageDigest: DIGEST,
          ruleId: 'aws-access-key-id',
          ruleRevision: '2026.07.1',
          ruleBundleDigest: DIGEST,
          artifactDigest: DIGEST,
          ruleSource: 'CHECK_BUNDLE',
          vulnerabilityDatabaseDigest: DIGEST
        },
        scannerDisposition: {
          source: 'DIRECT',
          status: 'active',
          platformPolicyAuthority: false
        },
        trivy: {
          kind: 'SECRET_DETECTION',
          category: 'AWS',
          secretValueStored: false,
          secretPayloadDiscarded: true
        },
        notes: ['UNKNOWN_CONFIDENCE'],
        durablePersistenceAllowed: false
      }
    ],
    durablePersistenceAllowed: false
  };
}
