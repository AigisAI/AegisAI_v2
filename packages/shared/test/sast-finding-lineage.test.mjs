import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  SAST_FINDING_FINGERPRINT_VERSION,
  SAST_FINDING_LIFECYCLE_COVERAGE_VERSION,
  SAST_FINDING_LINEAGE_REJECTION_REASON_CODES,
  SAST_FINDING_LINEAGE_VERSION,
  SAST_FINDING_RENAME_ATTESTATION_VERSION,
  buildFindingFingerprintPreimage,
  buildSastFindingLifecycleContextPreimage,
  buildSastFindingLineageKeyPreimage,
  canonicalizeSastFindingLifecycleCoverageDecision,
  canonicalizeSastFindingLifecycleReconciliationResult,
  canonicalizeSastFindingLineageRejection,
  canonicalizeSastFindingRenameAttestation,
  isSastFindingLifecycleCoverageDecisionShapeValid,
  isSastFindingLifecycleContextInputValid,
  isSastFindingLifecycleReconciliationResultShapeValid,
  isSastFindingLineageRejectionShapeValid,
  isSastFindingRenameAttestationShapeValid,
  orderSastFindingLineageRejectionReasons,
  projectRenamedSastFindingFingerprintInput
} from '../dist/index.js';

const DIGEST = `sha256:${'a'.repeat(64)}`;
const OTHER_DIGEST = `sha256:${'b'.repeat(64)}`;
const CONTEXT_KEY = digest(
  buildSastFindingLifecycleContextPreimage({
    tenantId: 'tenant-é',
    repositoryBindingId: 'repository-1',
    targetRef: 'refs/heads/café'
  })
);

test('pins target-context and lineage keys with NFC UTF-8 framing', () => {
  const context = {
    tenantId: 'tenant-é',
    repositoryBindingId: 'repository-1',
    targetRef: 'refs/heads/café'
  };
  const decomposed = {
    ...context,
    tenantId: 'tenant-e\u0301',
    targetRef: 'refs/heads/cafe\u0301'
  };
  const expectedContext =
    'sast-finding-lifecycle-context-v1\0' +
    '9:tenant-é12:repository-116:refs/heads/café';

  assert.equal(
    buildSastFindingLifecycleContextPreimage(context),
    expectedContext
  );
  assert.equal(
    buildSastFindingLifecycleContextPreimage(decomposed),
    expectedContext
  );
  assert.equal(
    isSastFindingLifecycleContextInputValid(context),
    true
  );
  assert.equal(
    isSastFindingLifecycleContextInputValid(decomposed),
    false
  );
  assert.equal(
    isSastFindingLifecycleContextInputValid({
      ...context,
      targetRef: `refs/heads/${'a'.repeat(2049)}`
    }),
    false
  );
  assert.notEqual(
    digest(buildSastFindingLifecycleContextPreimage(context)),
    digest(
      buildSastFindingLifecycleContextPreimage({
        ...context,
        targetRef: 'refs/heads/release'
      })
    ),
    'target lifecycle contexts must remain isolated'
  );
  assert.equal(
    buildSastFindingLineageKeyPreimage({
      tenantId: 'tenant-é',
      repositoryBindingId: 'repository-1',
      capability: 'SAST',
      fingerprintVersion: SAST_FINDING_FINGERPRINT_VERSION,
      stableFingerprint: DIGEST
    }),
    'sast-finding-lineage-v1\0' +
      '9:tenant-é12:repository-14:SAST19:sast-fingerprint-v1' +
      `71:${DIGEST}`
  );
});

test('validates a one-to-one, sorted, fixed-commit rename attestation', () => {
  const core = renameAttestationCore();
  const attestation = {
    ...core,
    attestationDigest: digest(
      canonicalizeSastFindingRenameAttestation(core)
    )
  };

  assert.equal(
    isSastFindingRenameAttestationShapeValid(attestation, digest),
    true
  );
  const sha256Core = {
    ...core,
    fromCommitSha: '0'.repeat(64),
    toCommitSha: '1'.repeat(64)
  };
  assert.equal(
    isSastFindingRenameAttestationShapeValid(
      {
        ...sha256Core,
        attestationDigest: digest(
          canonicalizeSastFindingRenameAttestation(sha256Core)
        )
      },
      digest
    ),
    true
  );
  assert.equal(
    isSastFindingRenameAttestationShapeValid(
      {
        ...attestation,
        entries: [...attestation.entries].reverse()
      },
      digest
    ),
    false
  );
  assert.equal(
    isSastFindingRenameAttestationShapeValid(
      {
        ...attestation,
        entries: [
          ...attestation.entries,
          {
            fromNormalizedPath: 'src/legacy.java',
            toNormalizedPath: 'src/renamed/A.java'
          }
        ]
      },
      digest
    ),
    false
  );
});

test('accepts a later canonical rename-back as a new fixed-commit attestation', () => {
  const forwardCore = {
    ...renameAttestationCore(),
    entries: [
      {
        fromNormalizedPath: 'src/A.java',
        toNormalizedPath: 'src/renamed/A.java'
      }
    ]
  };
  const forward = {
    ...forwardCore,
    attestationDigest: digest(
      canonicalizeSastFindingRenameAttestation(forwardCore)
    )
  };
  const reverseCore = {
    ...forwardCore,
    fromScanRequestId: forwardCore.toScanRequestId,
    fromCommitSha: forwardCore.toCommitSha,
    toScanRequestId: 'scan-2',
    toCommitSha: '2'.repeat(40),
    entries: [
      {
        fromNormalizedPath: 'src/renamed/A.java',
        toNormalizedPath: 'src/A.java'
      }
    ],
    issuedAt: '2026-07-30T03:00:00.000Z',
    attestationRef: 'rename-attestation://scan-1/scan-2',
    signatureRef: 'signature://rename/scan-2',
    provenanceRef: 'provenance://rename/scan-2'
  };
  const reverse = {
    ...reverseCore,
    attestationDigest: digest(
      canonicalizeSastFindingRenameAttestation(reverseCore)
    )
  };

  assert.equal(
    isSastFindingRenameAttestationShapeValid(forward, digest),
    true
  );
  assert.equal(
    isSastFindingRenameAttestationShapeValid(reverse, digest),
    true
  );
});

test('reconstructs only the path component for trusted rename lookup', () => {
  const current = {
    version: SAST_FINDING_FINGERPRINT_VERSION,
    repositoryBindingId: 'repository-1',
    capability: 'SAST',
    ruleSemanticId: 'java.sql-injection',
    normalizedPath: 'src/renamed/A.java',
    symbolAnchor: 'com.example.A#run',
    sinkKind: 'SQL_EXECUTE',
    structuralHash: DIGEST,
    stableFingerprint: OTHER_DIGEST,
    sourceRedactionDecisionDigest: DIGEST,
    unstableCoordinatesIncluded: false,
    scannerMatchIdentityAuthoritative: false,
    fingerprintPreimageStored: false,
    decisionDigest: DIGEST,
    decisionRef: `fingerprint://${SAST_FINDING_FINGERPRINT_VERSION}/${'a'.repeat(64)}`
  };

  const predecessor = projectRenamedSastFindingFingerprintInput(
    current,
    'src/original/A.java'
  );
  assert.deepEqual(predecessor, {
    repositoryBindingId: 'repository-1',
    capability: 'SAST',
    ruleSemanticId: 'java.sql-injection',
    normalizedPath: 'src/original/A.java',
    symbolAnchor: 'com.example.A#run',
    sinkKind: 'SQL_EXECUTE',
    structuralHash: DIGEST
  });
  assert.notEqual(
    buildFindingFingerprintPreimage(predecessor),
    buildFindingFingerprintPreimage(
      projectRenamedSastFindingFingerprintInput(
        current,
        current.normalizedPath
      )
    )
  );
});

test('accepts only complete non-stale comparable lifecycle authority', () => {
  const core = coverageDecisionCore();
  const decision = {
    ...core,
    decisionDigest: digest(
      canonicalizeSastFindingLifecycleCoverageDecision(core)
    )
  };

  assert.equal(
    isSastFindingLifecycleCoverageDecisionShapeValid(decision, digest),
    true
  );
  for (const mutation of [
    { ...decision, state: 'PARTIAL' },
    { ...decision, stale: true },
    { ...decision, comparable: false },
    { ...decision, sequence: 0 },
    {
      ...decision,
      eligibleLineageIds: [
        decision.eligibleLineageIds[0],
        decision.eligibleLineageIds[0]
      ]
    },
    {
      ...decision,
      expectedObservationBatchDigests: [
        OTHER_DIGEST,
        DIGEST
      ]
    }
  ]) {
    assert.equal(
      isSastFindingLifecycleCoverageDecisionShapeValid(
        mutation,
        digest
      ),
      false
    );
  }
});

test('orders bounded zero-payload lineage rejection metadata', () => {
  assert.deepEqual(
    orderSastFindingLineageRejectionReasons([
      'FINDING_LINEAGE_PERSISTENCE_FAILED',
      'FINDING_LINEAGE_INPUT_INVALID',
      'FINDING_LINEAGE_INPUT_INVALID'
    ]),
    [
      'FINDING_LINEAGE_INPUT_INVALID',
      'FINDING_LINEAGE_PERSISTENCE_FAILED'
    ]
  );
  assert.deepEqual(
    SAST_FINDING_LINEAGE_REJECTION_REASON_CODES,
    [
      'FINDING_LINEAGE_INPUT_INVALID',
      'FINDING_LINEAGE_RETENTION_INVALID',
      'FINDING_LINEAGE_RETENTION_EXPIRED',
      'FINDING_LINEAGE_DURABLE_SCOPE_INVALID',
      'FINDING_LINEAGE_RENAME_ATTESTATION_INVALID',
      'FINDING_LINEAGE_RENAME_AUTHORITY_UNAVAILABLE',
      'FINDING_LINEAGE_RENAME_AMBIGUOUS',
      'FINDING_LINEAGE_REPLAY_CONFLICT',
      'FINDING_LINEAGE_COVERAGE_AUTHORITY_UNAVAILABLE',
      'FINDING_LINEAGE_COVERAGE_DECISION_INVALID',
      'FINDING_LINEAGE_SCAN_NOT_COMPARABLE',
      'FINDING_LINEAGE_SCAN_STALE',
      'FINDING_LINEAGE_SCAN_INCOMPLETE',
      'FINDING_LINEAGE_RECONCILIATION_OUT_OF_ORDER',
      'FINDING_LINEAGE_OBSERVATION_INCOMPLETE',
      'FINDING_LINEAGE_PERSISTENCE_FAILED'
    ]
  );

  const core = {
    version: SAST_FINDING_LINEAGE_VERSION,
    outcome: 'REJECTED',
    operation: 'OBSERVE',
    reasonCodes: [
      'FINDING_LINEAGE_INPUT_INVALID'
    ],
    sourceBatchDigestStored: false,
    sourceFindingStored: false,
    renamePathsStored: false,
    eligibleLineageIdsStored: false,
    secretValueStored: false
  };
  const rejection = {
    ...core,
    rejectionDigest: digest(
      canonicalizeSastFindingLineageRejection(core)
    )
  };
  assert.equal(
    isSastFindingLineageRejectionShapeValid(rejection, digest),
    true
  );
  assert.doesNotMatch(
    JSON.stringify(rejection),
    /repository|scan-1|src\/|fingerprint|artifact|secret-value/u
  );
});

test('binds reconciliation transition counts to the observed set', () => {
  const core = {
    version: SAST_FINDING_LINEAGE_VERSION,
    outcome: 'RECONCILED',
    operation: 'RECONCILE',
    reconciliationId:
      `finding-reconciliation://${'3'.repeat(64)}`,
    coverageDecisionDigest: DIGEST,
    lifecycleContextKey: CONTEXT_KEY,
    sequence: 1,
    eligibleLineageCount: 4,
    observedLineageCount: 2,
    fixedCount: 1,
    reopenedCount: 1,
    unchangedOpenCount: 1,
    unchangedFixedCount: 1,
    replayed: false,
    reconciledAt: '2026-07-30T02:07:00.000Z',
    authority: {
      normalizedFindingPersistenceAuthority: true,
      occurrenceAuthority: true,
      lifecycleAuthority: true,
      renameAuthority: true,
      correlationAuthority: false,
      coverageCalculationAuthority: false,
      evidenceAuthority: false,
      policyAuthority: false,
      publicationAuthority: false,
      aiPayloadEligible: false
    }
  };
  const result = {
    ...core,
    resultDigest: digest(
      canonicalizeSastFindingLifecycleReconciliationResult(core)
    )
  };
  assert.equal(
    isSastFindingLifecycleReconciliationResultShapeValid(
      result,
      digest
    ),
    true
  );
  const invalidCore = {
    ...core,
    observedLineageCount: 1
  };
  assert.equal(
    isSastFindingLifecycleReconciliationResultShapeValid(
      {
        ...invalidCore,
        resultDigest: digest(
          canonicalizeSastFindingLifecycleReconciliationResult(
            invalidCore
          )
        )
      },
      digest
    ),
    false
  );
  const overLimitCore = {
    ...core,
    eligibleLineageCount: 25_001,
    observedLineageCount: 0,
    fixedCount: 25_001,
    reopenedCount: 0,
    unchangedOpenCount: 0,
    unchangedFixedCount: 0
  };
  assert.equal(
    isSastFindingLifecycleReconciliationResultShapeValid(
      {
        ...overLimitCore,
        resultDigest: digest(
          canonicalizeSastFindingLifecycleReconciliationResult(
            overLimitCore
          )
        )
      },
      digest
    ),
    false
  );
});

function renameAttestationCore() {
  return {
    version: SAST_FINDING_RENAME_ATTESTATION_VERSION,
    tenantId: 'tenant-1',
    repositoryBindingId: 'repository-1',
    lifecycleContextKey: CONTEXT_KEY,
    fromScanRequestId: 'scan-0',
    fromCommitSha: '0'.repeat(40),
    toScanRequestId: 'scan-1',
    toCommitSha: '1'.repeat(40),
    profileId: 'JAVA_DEEP_V1',
    profileDigest: DIGEST,
    entries: [
      {
        fromNormalizedPath: 'src/A.java',
        toNormalizedPath: 'src/renamed/A.java'
      },
      {
        fromNormalizedPath: 'src/B.java',
        toNormalizedPath: 'src/renamed/B.java'
      }
    ],
    issuedAt: '2026-07-30T02:00:00.000Z',
    attestationRef: 'rename-attestation://scan-0/scan-1',
    signatureRef: 'signature://rename/scan-1',
    provenanceRef: 'provenance://rename/scan-1'
  };
}

function coverageDecisionCore() {
  return {
    version: SAST_FINDING_LIFECYCLE_COVERAGE_VERSION,
    tenantId: 'tenant-1',
    repositoryBindingId: 'repository-1',
    scanRequestId: 'scan-1',
    attemptId: 'attempt-1',
    canonicalScanKey: DIGEST,
    planDigest: OTHER_DIGEST,
    commitSha: '1'.repeat(40),
    lifecycleContextKey: CONTEXT_KEY,
    profileId: 'JAVA_DEEP_V1',
    profileDigest: DIGEST,
    state: 'COMPLETE',
    stale: false,
    comparable: true,
    sequence: 2,
    previousScanRequestId: 'scan-0',
    previousCommitSha: '0'.repeat(40),
    completeCapabilities: [
      'SAST',
      'DEPENDENCY_VULNERABILITY',
      'SECRET_DETECTION',
      'IAC_MISCONFIGURATION'
    ],
    eligibleLineageIds: [
      `finding-lineage://${'1'.repeat(64)}`,
      `finding-lineage://${'2'.repeat(64)}`
    ],
    expectedObservationBatchDigests: [
      DIGEST,
      OTHER_DIGEST
    ],
    sourceCoverageDecisionDigest: DIGEST,
    sourceCoverageDecisionRef: 'coverage://scan-1/decision',
    completedAt: '2026-07-30T02:05:00.000Z',
    decidedAt: '2026-07-30T02:06:00.000Z'
  };
}

function digest(value) {
  return `sha256:${createHash('sha256')
    .update(value, 'utf8')
    .digest('hex')}`;
}
