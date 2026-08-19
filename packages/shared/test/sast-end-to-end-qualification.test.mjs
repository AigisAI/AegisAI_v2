import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  SAST_END_TO_END_QUALIFICATION_APPROVAL_ROLES,
  SAST_END_TO_END_QUALIFICATION_ARTIFACT_KEYS,
  SAST_END_TO_END_QUALIFICATION_ENTRY_ATTESTATION_VERSION,
  SAST_END_TO_END_QUALIFICATION_PIPELINE_PHASES,
  SAST_END_TO_END_QUALIFICATION_RECEIPT_SIGNATURE_ROLES,
  SAST_END_TO_END_QUALIFICATION_SIGNATURE_VERSION,
  SAST_ISOLATED_QUALIFICATION_CLEANUP_CONTROLS,
  SAST_ISOLATED_QUALIFICATION_RESULT_VERSION,
  buildSastEndToEndQualificationAttempt,
  buildSastEndToEndQualificationDependencySet,
  buildSastEndToEndQualificationEntryAttestation,
  buildSastEndToEndQualificationExecutionPlan,
  buildSastEndToEndQualificationReceipt,
  evaluateSastEndToEndQualificationEvidence,
  isSastEndToEndQualificationManifestValid,
  isSastEndToEndQualificationResultValid,
  isSastIsolatedQualificationResultValid
} from '../dist/index.js';
import { createEndToEndQualificationAssets } from '../../../tools/sast-qualification/end-to-end-qualification-assets.mjs';

const manifest = createEndToEndQualificationAssets().manifest;
const ZERO_COUNTS = Object.freeze({
  crossTenantLeakCount: 0,
  secretLeakCount: 0,
  sandboxEscapeCount: 0,
  staleExternalPublicationCount: 0,
  unauthorizedEgressCount: 0,
  missingDestructionEvidenceCount: 0,
  evidencePolicyViolationCount: 0,
  unsignedArtifactExecutionCount: 0
});
const SIGNATURE_BYTES = Buffer.alloc(64).toString('base64');

test('T054 manifest deterministically binds the exact 3,462-cell denominator', () => {
  assert.equal(isSastEndToEndQualificationManifestValid(manifest, digest), true);
  assert.equal(manifest.executionCellCount, 3462);
  assert.equal(manifest.goldenCandidateCellCount, 1880);
  assert.equal(manifest.goldenNegativeBaselineCellCount, 940);
  assert.equal(manifest.endToEndCandidateCellCount, 102);
  assert.equal(manifest.performanceCellCount, 540);
  assert.equal(manifest.performanceBucketCount, 9);
  assert.equal(manifest.requiredPerformanceRunsPerArmBucket, 30);
  assert.equal(manifest.aggregateMetricsRecomputedFromReceipts, true);
  assert.equal(manifest.productionReadinessAuthority, false);
});

test('T054 remains blocked without a cryptographically qualified T053 pass', () => {
  const result = evaluateSastEndToEndQualificationEvidence(
    {
      manifest,
      t053Result: null,
      entryAttestation: null,
      dependencySet: null,
      plan: null,
      approvals: [],
      signedReceipts: [],
      trustedEvaluatedAt: '2026-08-20T00:10:00.000Z',
      verifySignature: () => false
    },
    digest
  );
  assert.ok(result);
  assert.equal(result.status, 'BLOCKED_T053_QUALIFICATION');
  assert.equal(result.t055EntryAuthorized, false);
  assert.equal(result.productionReadinessAuthority, false);
  assert.equal(isSastEndToEndQualificationResultValid(result, digest), true);
});

test('T054 recomputes every gate from all signed receipts and grants only T055 entry', () => {
  const bundle = createExecutionBundle(0);
  const result = evaluateBundle(bundle);
  assert.ok(result);
  assert.equal(result.status, 'PASSED');
  assert.equal(result.validReceiptCount, 3462);
  assert.equal(result.measurements?.eligibleAttemptCount, 3462);
  assert.equal(result.measurements?.goldenCorpusPassRate, 1);
  assert.equal(result.measurements?.mustDetectRecall, 1);
  assert.equal(result.measurements?.criticalHighPrecision, 1);
  assert.equal(result.measurements?.priorMustDetectRegressionRecall, 1);
  assert.equal(result.measurements?.fingerprintFixturePassRate, 1);
  assert.equal(result.measurements?.evidencePrivacyPassRate, 1);
  assert.equal(result.measurements?.capacityPassRate, 1);
  assert.equal(result.measurements?.performanceBuckets.length, 9);
  assert.equal(result.t055EntryAuthorized, true);
  assert.equal(result.findingAuthority, false);
  assert.equal(result.policyAuthority, false);
  assert.equal(result.publicationAuthority, false);
  assert.equal(result.deploymentAuthority, false);
  assert.equal(result.productionReadinessAuthority, false);
  assert.equal(isSastEndToEndQualificationResultValid(result, digest), true);
});

test('T054 keeps infrastructure retries in reliability metrics and fails above 2%', () => {
  const bundle = createExecutionBundle(71);
  const result = evaluateBundle(bundle);
  assert.ok(result);
  assert.equal(result.status, 'FAILED');
  assert.ok(result.measurements);
  assert.equal(result.measurements.eligibleAttemptCount, 3533);
  assert.ok(result.measurements.scannerFailureRate > 0.02);
  assert.ok(result.failureReasons.includes('SCANNER_FAILURE_RATE_EXCEEDED'));
  assert.equal(result.t055EntryAuthorized, false);
});

test('T054 rejects duplicate global identities and retroactive approvals', () => {
  const bundle = createExecutionBundle(0);
  const first = bundle.signedReceipts[0];
  const duplicate = evaluateSastEndToEndQualificationEvidence(
    {
      ...bundle.evaluationInput,
      signedReceipts: [first, first]
    },
    digest
  );
  assert.ok(duplicate);
  assert.equal(duplicate.status, 'FAILED');
  assert.ok(duplicate.failureReasons.includes('RECEIPT_DUPLICATE'));
  assert.ok(duplicate.failureReasons.includes('IDENTITY_REUSED'));

  const retroactive = evaluateSastEndToEndQualificationEvidence(
    {
      ...bundle.evaluationInput,
      approvals: SAST_END_TO_END_QUALIFICATION_APPROVAL_ROLES.map((role) =>
        signature(role, bundle.plan.planDigest, '2026-08-20T00:02:00.000Z')
      ),
      signedReceipts: [first]
    },
    digest
  );
  assert.ok(retroactive);
  assert.equal(retroactive.status, 'FAILED');
  assert.ok(retroactive.failureReasons.includes('APPROVAL_SET_INVALID'));
});

function createExecutionBundle(retryCount) {
  const t053Result = passedT053Result();
  const dependencySet = dependencySetForManifest();
  const entryCoreInput = {
    t053ManifestId: manifest.t053ManifestId,
    t053ManifestDigest: manifest.t053ManifestDigest,
    t053ResultId: t053Result.resultId,
    t053ResultDigest: t053Result.resultDigest,
    t053DependencySetDigest: t053Result.dependencySetDigest,
    verifiedAt: '2026-08-20T00:00:30.000Z',
    verifierRef: digestRef(
      'qualification-verifier://aegisai/t054-entry',
      't054-entry-verifier'
    )
  };
  const entryDigest = digest(
    stableJson({
      version: SAST_END_TO_END_QUALIFICATION_ENTRY_ATTESTATION_VERSION,
      ...entryCoreInput,
      t054EntryAuthorized: true,
      findingAuthority: false,
      policyAuthority: false,
      publicationAuthority: false,
      deploymentAuthority: false,
      productionReadinessAuthority: false
    })
  );
  const entryAttestation = buildSastEndToEndQualificationEntryAttestation(
    entryCoreInput,
    signature(
      'QUALIFICATION_AUTHORITY',
      entryDigest,
      entryCoreInput.verifiedAt
    ),
    digest
  );
  assert.ok(entryAttestation);
  const plan = buildSastEndToEndQualificationExecutionPlan(
    {
      manifest,
      dependencySet,
      t053Result,
      entryAttestation,
      plannedAt: '2026-08-20T00:01:00.000Z',
      verifySignature: () => true
    },
    digest
  );
  assert.ok(plan);
  const approvals = SAST_END_TO_END_QUALIFICATION_APPROVAL_ROLES.map((role) =>
    signature(role, plan.planDigest, '2026-08-20T00:01:30.000Z')
  );
  const signedReceipts = manifest.cells.map((cell, index) =>
    signedReceipt(cell, plan, dependencySet, index < retryCount)
  );
  return {
    plan,
    signedReceipts,
    evaluationInput: {
      manifest,
      t053Result,
      entryAttestation,
      dependencySet,
      plan,
      approvals,
      signedReceipts,
      trustedEvaluatedAt: '2026-08-20T00:10:00.000Z',
      verifySignature: () => true
    }
  };
}

function evaluateBundle(bundle) {
  return evaluateSastEndToEndQualificationEvidence(bundle.evaluationInput, digest);
}

function passedT053Result() {
  const dependencySetDigest = digest('t053-live-dependency-set');
  const planDigest = digest('t053-live-plan');
  const core = {
    version: SAST_ISOLATED_QUALIFICATION_RESULT_VERSION,
    manifestId: manifest.t053ManifestId,
    manifestDigest: manifest.t053ManifestDigest,
    dependencySetDigest,
    planDigest,
    status: 'PASSED',
    expectedCellCount: 123,
    receivedReceiptCount: 123,
    validatedReceiptCount: 123,
    missingCellCount: 0,
    missingCellSetDigest: digest('[]'),
    failureReasons: [],
    evaluatedAt: '2026-08-20T00:00:00.000Z',
    t053Complete: true,
    t054EntryAuthorized: true,
    findingAuthority: false,
    policyAuthority: false,
    publicationAuthority: false,
    productionReadinessAuthority: false,
    immutable: true
  };
  const resultDigest = digest(stableJson(core));
  const result = {
    ...core,
    resultId:
      `sast-isolated-qualification-result://${resultDigest.slice('sha256:'.length)}`,
    resultDigest
  };
  assert.equal(isSastIsolatedQualificationResultValid(result, digest), true);
  return result;
}

function dependencySetForManifest() {
  const candidateScannerSetDigest = digest('candidate-scanner-set');
  const baselineScannerSetDigest = digest('baseline-scanner-set');
  const performanceCell = manifest.cells.find((cell) =>
    cell.cellKind.startsWith('PERFORMANCE_')
  );
  assert.ok(performanceCell?.hardwareClassRef);
  assert.ok(performanceCell.hardwareClassDigest);
  const artifacts = SAST_END_TO_END_QUALIFICATION_ARTIFACT_KEYS.map(
    (artifactKey) => {
      const artifactDigest =
        artifactKey === 'CANDIDATE_SCANNER_SET'
          ? candidateScannerSetDigest
          : artifactKey === 'BASELINE_SCANNER_SET'
            ? baselineScannerSetDigest
            : digest(`artifact:${artifactKey}`);
      return {
        artifactKey,
        artifactRef:
          `qualification-artifact://aegisai/t054/${artifactKey.toLowerCase()}/${artifactDigest}`,
        artifactDigest,
        signatureRef: digestRef(
          `artifact-signature://aegisai/t054/${artifactKey.toLowerCase()}`,
          `signature:${artifactKey}`
        ),
        provenanceRef: digestRef(
          `artifact-provenance://aegisai/t054/${artifactKey.toLowerCase()}`,
          `provenance:${artifactKey}`
        )
      };
    }
  );
  const value = buildSastEndToEndQualificationDependencySet(
    {
      revision: '1.0.0',
      providerId: 'microvm-provider://aegisai/production-equivalent/t054',
      providerAdapterRef: digestRef(
        'provider-adapter://aegisai/t054',
        'provider-adapter'
      ),
      validFrom: '2026-08-20T00:00:00.000Z',
      validUntil: '2026-08-21T00:00:00.000Z',
      candidateScannerSetDigest,
      baselineScannerSetDigest,
      performanceHardwareClassRef: performanceCell.hardwareClassRef,
      performanceHardwareClassDigest: performanceCell.hardwareClassDigest,
      artifacts
    },
    digest
  );
  assert.ok(value);
  return value;
}

function signedReceipt(cell, plan, dependencySet, retry) {
  const attempts = [];
  if (retry) {
    attempts.push(
      attempt(cell, 1, 'INFRASTRUCTURE_FAILURE', {
        startedAt: '2026-08-20T00:02:00.000Z',
        completedAt: '2026-08-20T00:02:00.500Z',
        cleanupCompletedAt: '2026-08-20T00:02:01.000Z'
      })
    );
    attempts.push(
      attempt(cell, 2, 'COMPLETED', {
        startedAt: '2026-08-20T00:02:01.000Z',
        completedAt: '2026-08-20T00:02:02.000Z',
        cleanupCompletedAt: '2026-08-20T00:02:03.000Z'
      })
    );
  } else {
    attempts.push(
      attempt(cell, 1, 'COMPLETED', {
        startedAt: '2026-08-20T00:02:00.000Z',
        completedAt: '2026-08-20T00:02:01.000Z',
        cleanupCompletedAt: '2026-08-20T00:02:02.000Z'
      })
    );
  }
  const expectedFindingCount =
    cell.cellKind === 'GOLDEN_CANDIDATE'
      ? cell.expectedFindingCount
      : 0;
  const criticalHighMatch =
    cell.cellKind === 'GOLDEN_CANDIDATE' &&
    cell.expectedOutcome === 'DETECT' &&
    (cell.severity === 'CRITICAL' || cell.severity === 'HIGH')
      ? 1
      : 0;
  const receipt = buildSastEndToEndQualificationReceipt(
    {
      manifestId: manifest.manifestId,
      manifestDigest: manifest.manifestDigest,
      dependencySetId: dependencySet.dependencySetId,
      dependencySetDigest: dependencySet.dependencySetDigest,
      planId: plan.planId,
      planDigest: plan.planDigest,
      cellId: cell.cellId,
      cellDigest: cell.cellDigest,
      cellKind: cell.cellKind,
      arm: cell.arm,
      caseId: cell.caseId,
      caseDigest: cell.caseDigest,
      profileId: cell.profileId,
      profileDigest: cell.profileDigest,
      providerId: dependencySet.providerId,
      candidateScannerSetDigest: dependencySet.candidateScannerSetDigest,
      baselineScannerSetDigest: dependencySet.baselineScannerSetDigest,
      hardwareClassRef: cell.hardwareClassRef,
      hardwareClassDigest: cell.hardwareClassDigest,
      attempts,
      attemptSetDigest: digest(
        stableJson(
          attempts.map((item) => ({
            attemptId: item.attemptId,
            attemptDigest: item.attemptDigest
          }))
        )
      ),
      phaseObservations: SAST_END_TO_END_QUALIFICATION_PIPELINE_PHASES.map(
        (phase) => ({
          phase,
          status: 'PASSED',
          evidenceDigest: digest(`${cell.cellId}:${phase}`)
        })
      ),
      observedControlOutcome: cell.expectedOutcome,
      observedFindingCount: expectedFindingCount ?? 0,
      matchedExpectedFindingCount: expectedFindingCount ?? 0,
      observedCriticalHighFindingCount: criticalHighMatch,
      matchedCriticalHighFindingCount: criticalHighMatch,
      normalizedOutputDigest: digest(`${cell.cellId}:normalized`),
      fingerprintDigest: digest(`${cell.cellId}:fingerprint`),
      correlationDigest: digest(`${cell.cellId}:correlation`),
      coverageDecisionDigest: digest(`${cell.cellId}:coverage`),
      policyDecisionDigest: digest(`${cell.cellId}:policy`),
      evidenceDecisionDigest: digest(`${cell.cellId}:evidence`),
      externalPublicationAttempted: false,
      customerContentObserved: false,
      customerCodeExecuted: false,
      packageInstallObserved: false,
      repositoryBuildObserved: false,
      dynamicTestObserved: false,
      publicInternetEgressObserved: false,
      completedAt: attempts.at(-1).cleanupCompletedAt
    },
    digest
  );
  assert.ok(receipt);
  return {
    receipt,
    signatures: SAST_END_TO_END_QUALIFICATION_RECEIPT_SIGNATURE_ROLES.map(
      (role) => signature(role, receipt.receiptDigest, '2026-08-20T00:02:04.000Z')
    )
  };
}

function attempt(cell, ordinal, outcome, timestamps) {
  const identity = `${cell.cellId}:${ordinal}`;
  const value = buildSastEndToEndQualificationAttempt(
    {
      attemptId: digestRef('qualification-attempt://aegisai/t054', identity),
      sandboxId: digestRef('qualification-sandbox://aegisai/t054', identity),
      workloadId: digestRef('qualification-workload://aegisai/t054', identity),
      providerAttestationRef: digestRef(
        'provider-attestation://aegisai/t054',
        identity
      ),
      runtimeAttestationRef: digestRef(
        'runtime-attestation://aegisai/t054',
        identity
      ),
      telemetryAttestationRef: digestRef(
        'telemetry-attestation://aegisai/t054',
        identity
      ),
      ...timestamps,
      outcome,
      latencyMilliseconds:
        Date.parse(timestamps.completedAt) - Date.parse(timestamps.startedAt),
      cpuMilliseconds: 100,
      peakMemoryBytes: 1024,
      peakDiskBytes: 1024,
      phaseEgressCount: 0,
      zeroToleranceCounts: { ...ZERO_COUNTS },
      cleanupControls: [...SAST_ISOLATED_QUALIFICATION_CLEANUP_CONTROLS],
      cleanupComplete: true
    },
    digest
  );
  assert.ok(value);
  return value;
}

function signature(role, payloadDigest, signedAt) {
  return {
    version: SAST_END_TO_END_QUALIFICATION_SIGNATURE_VERSION,
    role,
    keyId: digestRef(
      `qualification-key://aegisai/t054/${role.toLowerCase()}`,
      role
    ),
    payloadDigest,
    signedAt,
    algorithm: 'ED25519',
    valueBase64: SIGNATURE_BYTES
  };
}

function digestRef(prefix, seed) {
  return `${prefix}/${digest(seed)}`;
}

function digest(value) {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}

function stableJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'number') {
    return JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`)
    .join(',')}}`;
}
