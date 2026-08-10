import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  SAST_LATEST_TARGET_OBSERVATION_VERSION,
  SAST_SCAN_FRESHNESS_VERSION,
  buildSastScanFreshnessDecision,
  buildSastScanRetryDecision,
  canonicalizeSastLatestTargetObservation,
  canonicalizeSastScanFreshnessDecision,
  evaluateSastScanFreshness,
  evaluateSastScanRetry,
  isSastLatestTargetObservationShapeValid,
  isSastScanFreshnessDecisionShapeValid,
  isSastScanRetryDecisionShapeValid
} from '../dist/index.js';

test('grants only eligibility for independently verified fresh comparable coverage', () => {
  const scope = freshnessScope();
  const observation = targetObservation(scope.commitSha);
  const comparison = comparisonSource();
  const decision = buildSastScanFreshnessDecision({
    freshnessDecisionId: id('sast-freshness', 'decision'),
    coverageComplete: true,
    scope,
    observation,
    observationAuthority: 'VERIFIED',
    observationMonotonic: true,
    comparison,
    decidedAt: '2026-08-10T03:00:01.000Z',
    digestCanonical: digest
  });

  assert.equal(decision.version, SAST_SCAN_FRESHNESS_VERSION);
  assert.equal(decision.staleStatus, 'FRESH');
  assert.equal(decision.comparabilityStatus, 'COMPARABLE');
  assert.equal(decision.externalCommentEligible, true);
  assert.equal(decision.blockingStatusEligible, true);
  assert.equal(decision.lifecycleMutationAllowed, true);
  assert.equal(decision.aiAdvisoryAllowed, false);
  assert.equal(decision.publicationAttempted, false);
  assert.deepEqual(decision.reasonCodes, []);
  assert.equal(
    isSastScanFreshnessDecisionShapeValid(decision, digest),
    true
  );

  const { decisionDigest: _digest, ...core } = decision;
  const forgedCore = {
    ...core,
    observationId: null,
    observationDigest: null,
    observedHeadCommitSha: null,
    observationSequence: null
  };
  assert.equal(
    isSastScanFreshnessDecisionShapeValid(
      {
        ...forgedCore,
        decisionDigest: digest(
          canonicalizeSastScanFreshnessDecision(forgedCore)
        )
      },
      digest
    ),
    false
  );
});

test('fails closed for stale, unavailable, non-monotonic, or incomparable scans', () => {
  const scope = freshnessScope();
  const stale = evaluateSastScanFreshness({
    coverageComplete: true,
    scope,
    observation: targetObservation('c'.repeat(40)),
    observationAuthority: 'VERIFIED',
    observationMonotonic: true,
    comparison: comparisonSource()
  });
  assert.equal(stale.staleStatus, 'STALE');
  assert.equal(stale.authorityEligible, false);
  assert.deepEqual(stale.reasonCodes, [
    'TARGET_HEAD_MISMATCH',
    'PUBLICATION_FAIL_CLOSED'
  ]);

  const unavailable = evaluateSastScanFreshness({
    coverageComplete: true,
    scope,
    observation: null,
    observationAuthority: 'UNAVAILABLE',
    observationMonotonic: false,
    comparison: null
  });
  assert.equal(unavailable.staleStatus, 'UNKNOWN');
  assert.equal(unavailable.comparabilityStatus, 'UNKNOWN');
  assert.equal(unavailable.authorityEligible, false);
  assert.deepEqual(unavailable.reasonCodes, [
    'LATEST_TARGET_AUTHORITY_UNAVAILABLE',
    'COMPARISON_SOURCE_UNAVAILABLE',
    'PUBLICATION_FAIL_CLOSED'
  ]);

  const incomparable = evaluateSastScanFreshness({
    coverageComplete: true,
    scope,
    observation: targetObservation(scope.commitSha),
    observationAuthority: 'VERIFIED',
    observationMonotonic: false,
    comparison: {
      ...comparisonSource(),
      requiredCapabilities: ['SAST']
    }
  });
  assert.equal(incomparable.latestTargetAuthority, 'INVALID');
  assert.equal(incomparable.comparabilityStatus, 'INCOMPARABLE');
  assert.deepEqual(incomparable.reasonCodes, [
    'LATEST_TARGET_OBSERVATION_NON_MONOTONIC',
    'REQUIRED_CAPABILITY_SET_INCOMPATIBLE',
    'PUBLICATION_FAIL_CLOSED'
  ]);
});

test('accepts exactly one infrastructure-only retry with a fresh sandbox', () => {
  const evaluation = retryEvaluation();
  assert.deepEqual(evaluateSastScanRetry(evaluation), []);
  const decision = buildSastScanRetryDecision({
    retryDecisionId: id('sast-retry', 'allowed'),
    evaluation,
    decidedAt: '2026-08-10T03:05:00.000Z',
    digestCanonical: digest
  });
  assert.equal(decision.retryAllowed, true);
  assert.equal(
    isSastScanRetryDecisionShapeValid(decision, digest),
    true
  );
});

test('rejects attempt three, non-infrastructure failure, missing audit, kill switch, and sandbox reuse', () => {
  const base = retryEvaluation();
  const reasons = evaluateSastScanRetry({
    ...base,
    scope: {
      ...base.scope,
      requestedAttemptId: base.scope.previousAttemptId,
      requestedAttemptNumber: 3,
      requestedSandboxId: base.scope.previousSandboxId
    },
    previousFailureClass: 'SCANNER_DEFECT',
    previousFinalAuditValid: false,
    killSwitchStatus: 'ACTIVE'
  });
  assert.deepEqual(reasons, [
    'RETRY_ATTEMPT_LIMIT_EXCEEDED',
    'PREVIOUS_ATTEMPT_NOT_IMMEDIATE',
    'FAILURE_NOT_RETRYABLE_INFRASTRUCTURE',
    'FINAL_AUDIT_BINDING_MISSING',
    'KILL_SWITCH_ACTIVE',
    'SANDBOX_IDENTITY_REUSED'
  ]);

  assert.deepEqual(
    evaluateSastScanRetry({
      ...base,
      killSwitchSnapshotDigest: null
    }),
    ['KILL_SWITCH_AUTHORITY_UNAVAILABLE']
  );
});

test('recomputes observation and decision digests instead of trusting shaped values', () => {
  const observation = targetObservation('b'.repeat(40));
  assert.equal(
    isSastLatestTargetObservationShapeValid(observation, digest),
    true
  );
  assert.equal(
    isSastLatestTargetObservationShapeValid(
      { ...observation, headCommitSha: 'c'.repeat(40) },
      digest
    ),
    false
  );
});

function freshnessScope() {
  return {
    tenantId: 'tenant-1',
    repositoryBindingId: 'repository-1',
    provider: 'GITHUB',
    targetRef: 'refs/heads/main',
    commitSha: 'b'.repeat(40),
    scanRequestId: 'scan-current',
    attemptId: 'attempt-current',
    attemptNumber: 1,
    coverageDecisionId: id('sast-coverage', 'current'),
    coverageDecisionDigest: digest('current-coverage'),
    lifecycleContextKey: digest('lifecycle'),
    canonicalScanKey: digest('canonical'),
    planDigest: digest('plan'),
    profileId: 'JAVA_DEEP_V1',
    profileDigest: digest('profile'),
    profileFamily: 'JAVA',
    requiredCapabilities: [
      'SAST',
      'DEPENDENCY_VULNERABILITY',
      'SECRET_DETECTION',
      'IAC_MISCONFIGURATION',
      'SBOM'
    ],
    fingerprintVersion: 'sast-fingerprint-v1',
    lifecycleEligibilityScope: digest('eligibility')
  };
}

function comparisonSource() {
  return {
    coverageDecisionId: id('sast-coverage', 'previous'),
    coverageDecisionDigest: digest('previous-coverage'),
    scanRequestId: 'scan-previous',
    commitSha: 'a'.repeat(40),
    tenantId: 'tenant-1',
    repositoryBindingId: 'repository-1',
    targetRef: 'refs/heads/main',
    profileId: 'JAVA_DEEP_V1',
    profileDigest: digest('previous-profile'),
    profileFamily: 'JAVA',
    requiredCapabilities: [
      'SAST',
      'DEPENDENCY_VULNERABILITY',
      'SECRET_DETECTION',
      'IAC_MISCONFIGURATION',
      'SBOM'
    ],
    fingerprintVersion: 'sast-fingerprint-v1',
    lifecycleEligibilityScope: digest('eligibility'),
    completedAt: '2026-08-09T03:00:00.000Z'
  };
}

function targetObservation(headCommitSha) {
  const core = {
    version: SAST_LATEST_TARGET_OBSERVATION_VERSION,
    observationId: id('sast-target-observation', headCommitSha),
    tenantId: 'tenant-1',
    repositoryBindingId: 'repository-1',
    provider: 'GITHUB',
    targetRef: 'refs/heads/main',
    headCommitSha,
    sequence: 2,
    observerRef: 'scm-head-authority://github-app',
    observedAt: '2026-08-10T03:00:00.000Z'
  };
  return {
    ...core,
    observationDigest: digest(
      canonicalizeSastLatestTargetObservation(core)
    )
  };
}

function retryEvaluation() {
  return {
    scope: {
      tenantId: 'tenant-1',
      repositoryBindingId: 'repository-1',
      scanRequestId: 'scan-1',
      canonicalScanKey: digest('canonical'),
      planDigest: digest('plan'),
      originalScannerSetDigest: digest('scanner-set'),
      previousAttemptId: 'attempt-1',
      previousAttemptNumber: 1,
      previousSandboxId: 'sandbox-1',
      previousWorkloadIdentityRef: 'spiffe://aegis/attempt-1',
      requestedAttemptId: 'attempt-2',
      requestedAttemptNumber: 2,
      requestedSandboxId: 'sandbox-2',
      requestedWorkloadIdentityRef: 'spiffe://aegis/attempt-2'
    },
    previousStage: 'FAILED',
    previousFailureClass: 'RETRYABLE_INFRASTRUCTURE',
    previousRetryEligible: true,
    previousCompletedAt: '2026-08-10T03:04:00.000Z',
    previousFinalAuditEventId: 'audit-attempt-1',
    previousFinalAuditValid: true,
    durableCanonicalScanKey: digest('canonical'),
    durablePlanDigest: digest('plan'),
    currentScannerSetDigest: digest('scanner-set'),
    scannerSetAvailable: true,
    killSwitchStatus: 'CLEAR',
    killSwitchSnapshotDigest: digest('kill-switch-snapshot')
  };
}

function digest(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function id(prefix, value) {
  return `${prefix}://${createHash('sha256').update(value).digest('hex')}`;
}
