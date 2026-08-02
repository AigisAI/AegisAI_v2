import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  SAST_FINDING_CORRELATION_PROVENANCE_VERSION,
  SAST_FINDING_CORRELATION_SOURCE_VERSION,
  SAST_FINDING_CORRELATION_VERSION,
  SAST_FINDING_FINGERPRINT_VERSION,
  buildSastFindingCorrelationBasisPreimage,
  buildSastFindingCorrelationSourceSetPreimage,
  canonicalizeSastFindingCorrelationEdge,
  canonicalizeSastFindingCorrelationProvenance,
  canonicalizeSastFindingCorrelationRejection,
  canonicalizeSastFindingCorrelationResult,
  canonicalizeSastFindingCorrelationSourceBinding,
  isSastFindingCorrelationEdgeShapeValid,
  isSastFindingCorrelationProvenanceShapeValid,
  isSastFindingCorrelationRejectionShapeValid,
  isSastFindingCorrelationResultShapeValid,
  isSastFindingCorrelationSourceBindingShapeValid,
  sastFindingCorrelationAuthority,
  sastFindingCorrelationSafety,
  toSastFindingCorrelationAuditMetadata
} from '../dist/index.js';

const CORRELATION_ID = id('finding-correlation', 1);
const OCCURRENCE_1 = id('finding-occurrence', 1);
const OCCURRENCE_2 = id('finding-occurrence', 2);

test('binds the complete durable T037 source set independently from replay result digests', () => {
  const first = sourceBinding(1);
  const second = sourceBinding(2);
  const preimage = buildSastFindingCorrelationSourceSetPreimage([
    first,
    second
  ]);

  assert.equal(
    preimage,
    `sast-finding-correlation-v1\0` +
      `71:${first.sourceBindingDigest}` +
      `71:${second.sourceBindingDigest}`
  );
  assert.equal(
    isSastFindingCorrelationSourceBindingShapeValid(first, digest),
    true
  );
  assert.equal(
    isSastFindingCorrelationSourceBindingShapeValid(
      { ...first, occurrenceCount: 0 },
      digest
    ),
    false
  );
});

test('pins dependency correlation to canonical ecosystem, package, version, and CVE fields', () => {
  const first = buildSastFindingCorrelationBasisPreimage({
    kind: 'SAME_DEPENDENCY_CVE',
    components: [
      'maven',
      'org.example:library',
      '1.2.3',
      'CVE-2026-12345'
    ]
  });
  const changedVersion = buildSastFindingCorrelationBasisPreimage({
    kind: 'SAME_DEPENDENCY_CVE',
    components: [
      'maven',
      'org.example:library',
      '1.2.4',
      'CVE-2026-12345'
    ]
  });

  assert.notEqual(digest(first), digest(changedVersion));
  assert.match(first, /^sast-finding-correlation-basis-v1\0/u);
});

test('validates provenance-preserving edges that cannot merge or inherit severity', () => {
  const source = provenance('SOURCE', OCCURRENCE_1, 'CRITICAL');
  const target = provenance('TARGET', OCCURRENCE_2, 'LOW');
  const core = {
    version: SAST_FINDING_CORRELATION_VERSION,
    correlationBatchId: CORRELATION_ID,
    kind: 'POSSIBLE_OVERLAP',
    sourceOccurrenceId: OCCURRENCE_1,
    targetOccurrenceId: OCCURRENCE_2,
    basisDigests: [digest('cve-overlap')],
    confidenceBasisPoints: 5_000,
    sourceProvenanceDigest: source.provenanceDigest,
    targetProvenanceDigest: target.provenanceDigest,
    safety: sastFindingCorrelationSafety(),
    decidedAt: '2026-08-02T00:00:00.000Z'
  };
  const edge = {
    ...core,
    edgeDigest: digest(canonicalizeSastFindingCorrelationEdge(core))
  };

  assert.equal(
    isSastFindingCorrelationProvenanceShapeValid(source, digest),
    true
  );
  assert.equal(
    isSastFindingCorrelationProvenanceShapeValid(target, digest),
    true
  );
  assert.equal(isSastFindingCorrelationEdgeShapeValid(edge, digest), true);
  assert.equal(
    isSastFindingCorrelationEdgeShapeValid(
      {
        ...edge,
        safety: { ...edge.safety, severityInheritanceAllowed: true },
        edgeDigest: digest('forged')
      },
      digest
    ),
    false
  );
});

test('binds exact edge counts and keeps every downstream authority false', () => {
  const core = {
    version: SAST_FINDING_CORRELATION_VERSION,
    outcome: 'CORRELATED',
    correlationBatchId: CORRELATION_ID,
    sourceSetDigest: digest('source-set'),
    lifecycleContextKey: digest('context'),
    sourceBatchCount: 2,
    occurrenceCount: 2,
    edgeCount: 1,
    exactFingerprintCount: 0,
    sameDependencyCveCount: 0,
    supportingEvidenceCount: 0,
    possibleOverlapCount: 1,
    replayed: false,
    correlatedAt: '2026-08-02T00:00:00.000Z',
    authority: sastFindingCorrelationAuthority()
  };
  const result = {
    ...core,
    resultDigest: digest(
      canonicalizeSastFindingCorrelationResult(core)
    )
  };

  assert.equal(
    isSastFindingCorrelationResultShapeValid(result, digest),
    true
  );
  const emptySourceCore = { ...core, sourceBatchCount: 0 };
  assert.equal(
    isSastFindingCorrelationResultShapeValid(
      {
        ...emptySourceCore,
        resultDigest: digest(
          canonicalizeSastFindingCorrelationResult(emptySourceCore)
        )
      },
      digest
    ),
    false
  );
  assert.deepEqual(result.authority, {
    correlationAuthority: true,
    provenancePreservationAuthority: true,
    findingMergeAuthority: false,
    severityAuthority: false,
    lifecycleAuthority: false,
    coverageCalculationAuthority: false,
    evidenceAuthority: false,
    policyAuthority: false,
    publicationAuthority: false,
    aiPayloadEligible: false
  });
  assert.deepEqual(toSastFindingCorrelationAuditMetadata(result, digest), {
    version: SAST_FINDING_CORRELATION_VERSION,
    outcome: 'CORRELATED',
    correlationBatchId: CORRELATION_ID,
    resultDigest: result.resultDigest,
    sourceBatchCount: 2,
    occurrenceCount: 2,
    edgeCount: 1,
    exactFingerprintCount: 0,
    sameDependencyCveCount: 0,
    supportingEvidenceCount: 0,
    possibleOverlapCount: 1,
    replayed: false
  });
});

test('keeps correlation rejections coarse and identifier-free', () => {
  const core = {
    version: SAST_FINDING_CORRELATION_VERSION,
    outcome: 'REJECTED',
    reasonCodes: ['FINDING_CORRELATION_SOURCE_SET_INCOMPLETE'],
    observationBatchIdsStored: false,
    sourceResultDigestsStored: false,
    sourceFindingStored: false,
    correlationBasisStored: false,
    secretValueStored: false
  };
  const rejection = {
    ...core,
    rejectionDigest: digest(
      canonicalizeSastFindingCorrelationRejection(core)
    )
  };

  assert.equal(
    isSastFindingCorrelationRejectionShapeValid(rejection, digest),
    true
  );
  assert.equal(JSON.stringify(rejection).includes(OCCURRENCE_1), false);
});

function sourceBinding(index) {
  const core = {
    version: SAST_FINDING_CORRELATION_SOURCE_VERSION,
    observationBatchId: id('finding-observation', index),
    sourceIdentityBatchDigest: digest(`identity-${index}`),
    scannerRunId: `scanner-run-${index}`,
    scanner: index === 1 ? 'OPENGREP' : 'TRIVY',
    capabilities:
      index === 1 ? ['SAST'] : ['DEPENDENCY_VULNERABILITY'],
    lifecycleContextKey: digest('context'),
    findingCount: 1,
    occurrenceCount: 1,
    observedAt: `2026-08-02T00:00:0${index}.000Z`
  };
  return {
    ...core,
    sourceBindingDigest: digest(
      canonicalizeSastFindingCorrelationSourceBinding(core)
    )
  };
}

function provenance(side, occurrenceId, severity) {
  const core = {
    version: SAST_FINDING_CORRELATION_PROVENANCE_VERSION,
    side,
    occurrenceId,
    observationBatchId: id('finding-observation', 1),
    lineageId: id('finding-lineage', 1),
    normalizedFindingId: id('normalized-finding', 1),
    scannerRunId: 'scanner-run-1',
    scanner: 'OPENGREP',
    capability: 'SAST',
    authorityLevel: 'AUTHORITATIVE',
    severity,
    fingerprintVersion: SAST_FINDING_FINGERPRINT_VERSION,
    stableFingerprint: digest('fingerprint'),
    fingerprintDecisionDigest: digest('fingerprint-decision'),
    sourceFindingDigest: digest('source-finding'),
    scannerVersion: '1.22.0',
    scannerImageDigest: digest('scanner-image'),
    ruleId: 'java.sql-injection',
    ruleRevision: '2026.08.1',
    ruleBundleDigest: digest('rules'),
    artifactDigest: digest('artifact')
  };
  return {
    ...core,
    provenanceDigest: digest(
      canonicalizeSastFindingCorrelationProvenance(core)
    )
  };
}

function id(prefix, value) {
  return `${prefix}://${value.toString(16).padStart(64, '0')}`;
}

function digest(value) {
  return `sha256:${createHash('sha256')
    .update(value, 'utf8')
    .digest('hex')}`;
}
