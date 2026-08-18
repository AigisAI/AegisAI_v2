import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import test from 'node:test';

import {
  SAST_RULE_BUNDLE_CANARY_STEPS,
  buildSastCanaryMembershipHmacPreimage,
  buildSastRuleBundleCanaryAssignmentReceipt,
  buildSastRuleBundleCanaryEligibilityDecision,
  buildSastRuleBundleCanaryMembership,
  buildSastRuleBundleCanaryObservationReceipt,
  buildSastRuleBundleCanaryRollout,
  buildSastRuleBundleCanaryScanObservation,
  buildSastRuleBundleCanaryStepDecision,
  findSastRuleBundleCanaryGateReasonCodes,
  isSastRuleBundleCanaryAssignmentReceiptShapeValid,
  isSastRuleBundleCanaryEligibilityDecisionShapeValid,
  isSastRuleBundleCanaryMembershipShapeValid,
  isSastRuleBundleCanaryObservationReceiptShapeValid,
  isSastRuleBundleCanaryRolloutShapeValid,
  isSastRuleBundleCanaryScanObservationShapeValid,
  isSastRuleBundleCanaryStepDecisionShapeValid,
  isVerifiedSastRuleBundleCanaryAssignmentDescriptorValid,
  nextSastRuleBundleCanaryStep,
  toVerifiedSastRuleBundleCanaryAssignmentDescriptor
} from '../dist/index.js';

test('T048 fixes one immutable rollout to candidate, baseline, evidence, transition, profile, and policy', () => {
  const value = rollout();

  assert.equal(isSastRuleBundleCanaryRolloutShapeValid(value, digest), true);
  assert.deepEqual(value.progression, SAST_RULE_BUNDLE_CANARY_STEPS);
  assert.equal(value.customerInputAccepted, false);
  assert.equal(value.repositoryContentStored, false);
  assert.equal(value.findingContentStored, false);
  assert.equal(value.secretKeyMaterialStored, false);
  assert.equal(
    buildSastRuleBundleCanaryRollout({ ...rolloutInput(), source: 'repo' }, digest),
    null
  );
});

test('T048 derives stable tenant-safe membership from one length-framed keyed-hash input', () => {
  const currentRollout = rollout();
  const first = membership(currentRollout, {
    tenantId: 'tenant-1',
    repositoryBindingId: 'repository-1'
  });
  const replay = membership(currentRollout, {
    tenantId: 'tenant-1',
    repositoryBindingId: 'repository-1'
  });
  const otherRepository = membership(currentRollout, {
    tenantId: 'tenant-1',
    repositoryBindingId: 'repository-2'
  });

  assert.equal(first.membershipDigest, replay.membershipDigest);
  assert.equal(first.bucketBasisPoints, replay.bucketBasisPoints);
  assert.notEqual(first.assignmentHmacDigest, otherRepository.assignmentHmacDigest);
  assert.equal(isSastRuleBundleCanaryMembershipShapeValid(first, digest), true);
  assert.equal(first.repositoryContentUsed, false);
  assert.equal(first.findingOrSeverityUsed, false);
  assert.equal(first.secretKeyMaterialStored, false);

  const hostile = structuredClone(first);
  hostile.tenantId = Symbol('hostile');
  assert.equal(isSastRuleBundleCanaryMembershipShapeValid(hostile, digest), false);
});

test('T048 keeps memberships stable while deterministic step selection expands monotonically', () => {
  const currentRollout = rollout();
  const internal = membership(currentRollout, {
    eligibilityClass: 'INTERNAL_REPOSITORY'
  });
  const production = membership(currentRollout, {
    eligibilityClass: 'ELIGIBLE_PRODUCTION'
  });
  const selectedSteps = [];

  for (const step of SAST_RULE_BUNDLE_CANARY_STEPS) {
    const receipt = assignment(currentRollout, production, step);
    assert.equal(
      isSastRuleBundleCanaryAssignmentReceiptShapeValid(receipt, digest),
      true
    );
    if (receipt.selection === 'CANDIDATE') selectedSteps.push(step);
  }
  assert.equal(selectedSteps.at(-1), 'PERCENT_100');
  const firstSelectedIndex = SAST_RULE_BUNDLE_CANARY_STEPS.indexOf(
    selectedSteps[0]
  );
  assert.deepEqual(
    selectedSteps,
    SAST_RULE_BUNDLE_CANARY_STEPS.slice(firstSelectedIndex)
  );
  assert.equal(
    assignment(currentRollout, internal, 'INTERNAL_CORPUS').selection,
    'BASELINE'
  );
  assert.equal(
    assignment(currentRollout, internal, 'INTERNAL_REPOSITORIES').selection,
    'CANDIDATE'
  );

  const excluded = membership(currentRollout, { excluded: true });
  assert.equal(
    assignment(currentRollout, excluded, 'PERCENT_100').selection,
    'EXCLUDED'
  );
});

test('T048 produces a plan descriptor only for an exact candidate assignment', () => {
  const currentRollout = rollout();
  const currentMembership = membership(currentRollout);
  const receipt = assignment(currentRollout, currentMembership, 'PERCENT_100');
  const descriptor = toVerifiedSastRuleBundleCanaryAssignmentDescriptor(
    currentMembership,
    receipt
  );

  assert.ok(descriptor);
  assert.equal(
    isVerifiedSastRuleBundleCanaryAssignmentDescriptorValid(descriptor),
    true
  );
  assert.equal(descriptor.candidateAssigned, true);

  const baseline = assignment(currentRollout, currentMembership, 'PERCENT_1');
  if (baseline.selection === 'BASELINE') {
    assert.equal(
      toVerifiedSastRuleBundleCanaryAssignmentDescriptor(
        currentMembership,
        baseline
      ),
      null
    );
  }
});

test('T048 accepts only content-free terminal observations with exact assignment binding', () => {
  const currentRollout = rollout();
  const currentMembership = membership(currentRollout);
  const currentAssignment = forceCandidateAssignment(
    currentRollout,
    currentMembership
  );
  const candidate = observation(
    currentRollout,
    currentAssignment,
    'CANDIDATE',
    'candidate'
  );
  const baseline = observation(
    currentRollout,
    null,
    'BASELINE',
    'baseline'
  );

  assert.equal(
    isSastRuleBundleCanaryScanObservationShapeValid(candidate, digest),
    true
  );
  assert.equal(
    isSastRuleBundleCanaryScanObservationShapeValid(baseline, digest),
    true
  );
  assert.equal(candidate.sourceOrFindingContentStored, false);
  assert.equal(candidate.secretValueStored, false);

  const incompleteTelemetry = buildSastRuleBundleCanaryScanObservation(
    {
      ...observationInput(currentRollout, currentAssignment, 'CANDIDATE', 'incomplete'),
      telemetryComplete: false
    },
    digest
  );
  assert.ok(incompleteTelemetry);
  assert.equal(incompleteTelemetry.telemetryComplete, false);

  const incompleteCoverageInput = observationInput(
    currentRollout,
    currentAssignment,
    'CANDIDATE',
    'incomplete-coverage'
  );
  incompleteCoverageInput.coverageComplete = false;
  incompleteCoverageInput.measurements.incompleteCoverageCount = 1;
  const incompleteCoverage = buildSastRuleBundleCanaryScanObservation(
    incompleteCoverageInput,
    digest
  );
  assert.ok(incompleteCoverage);
  assert.equal(incompleteCoverage.coverageComplete, false);
  assert.equal(incompleteCoverage.measurements.incompleteCoverageCount, 1);

  const missingAssignment = observationInput(
    currentRollout,
    null,
    'CANDIDATE',
    'missing'
  );
  assert.equal(
    buildSastRuleBundleCanaryScanObservation(missingAssignment, digest),
    null
  );
});

test('T048 enforces time, per-arm sample, false-positive, failure, latency, volume, and zero-event gates', () => {
  const currentRollout = rollout();
  const passing = stepDecisionInput(currentRollout);
  const decision = buildSastRuleBundleCanaryStepDecision(passing, digest);

  assert.ok(decision);
  assert.equal(decision.outcome, 'PASSED');
  assert.deepEqual(decision.reasonCodes, []);
  assert.equal(
    isSastRuleBundleCanaryStepDecisionShapeValid(decision, digest),
    true
  );
  const callerCutoff = stepDecisionInput(currentRollout);
  callerCutoff.evaluatedAt = '2026-08-15T07:00:00.001Z';
  assert.equal(buildSastRuleBundleCanaryStepDecision(callerCutoff, digest), null);

  const cases = [
    [
      (input) => {
        input.windowEndedAt = '2026-08-15T06:59:59.999Z';
        input.evaluatedAt = input.windowEndedAt;
      },
      'OBSERVATION_WINDOW_INSUFFICIENT',
      'PENDING'
    ],
    [
      (input) => {
        input.measurements.candidateCompletedScans = 199;
        input.measurements.candidateCriticalHighFindingCount = 119;
      },
      'CANDIDATE_SAMPLE_INSUFFICIENT',
      'PENDING'
    ],
    [
      (input) => {
        input.telemetryComplete = false;
      },
      'TELEMETRY_MISSING',
      'PAUSED'
    ],
    [
      (input) => {
        input.measurements.candidateIncompleteCoverageCount = 1;
      },
      'COVERAGE_INCOMPLETE',
      'PAUSED'
    ],
    [
      (input) => {
        input.measurements.candidateFalsePositiveCount = 31;
      },
      'FALSE_POSITIVE_GATE_FAILED',
      'PAUSED'
    ],
    [
      (input) => {
        input.measurements.candidateScannerFailureCount = 5;
      },
      'SCANNER_FAILURE_GATE_FAILED',
      'PAUSED'
    ],
    [
      (input) => {
        input.measurements.candidateP95LatencyMilliseconds = 600_001;
      },
      'LATENCY_GATE_FAILED',
      'PAUSED'
    ],
    [
      (input) => {
        input.measurements.candidateCriticalHighFindingCount = 121;
      },
      'CRITICAL_HIGH_VOLUME_GATE_FAILED',
      'PAUSED'
    ],
    [
      (input) => {
        input.measurements.unauthorizedEgressEvents = 1;
      },
      'ZERO_TOLERANCE_EVENT_RECORDED',
      'PAUSED'
    ]
  ];

  for (const [mutate, reason, outcome] of cases) {
    const input = stepDecisionInput(currentRollout);
    mutate(input);
    assert.equal(
      findSastRuleBundleCanaryGateReasonCodes(input).includes(reason),
      true,
      reason
    );
    assert.equal(
      buildSastRuleBundleCanaryStepDecision(input, digest)?.outcome,
      outcome,
      reason
    );
  }

  const unequalArmsAtBoundary = stepDecisionInput(currentRollout);
  unequalArmsAtBoundary.measurements.candidateCompletedScans = 400;
  unequalArmsAtBoundary.measurements.candidateCriticalHighFindingCount = 240;
  assert.equal(
    findSastRuleBundleCanaryGateReasonCodes(unequalArmsAtBoundary).includes(
      'CRITICAL_HIGH_VOLUME_GATE_FAILED'
    ),
    false
  );
  unequalArmsAtBoundary.measurements.candidateCriticalHighFindingCount = 241;
  assert.equal(
    findSastRuleBundleCanaryGateReasonCodes(unequalArmsAtBoundary).includes(
      'CRITICAL_HIGH_VOLUME_GATE_FAILED'
    ),
    true
  );
});

test('T048 requires 1,000 scans per arm and 48 hours at 25% and 100%', () => {
  for (const step of ['PERCENT_25', 'PERCENT_100']) {
    const input = stepDecisionInput(rollout());
    input.step = step;
    input.measurements.candidateCompletedScans = 999;
    input.measurements.baselineCompletedScans = 999;
    assert.deepEqual(findSastRuleBundleCanaryGateReasonCodes(input), [
      'OBSERVATION_WINDOW_INSUFFICIENT',
      'CANDIDATE_SAMPLE_INSUFFICIENT',
      'BASELINE_SAMPLE_INSUFFICIENT'
    ]);

    input.windowEndedAt = '2026-08-16T07:00:00.000Z';
    input.evaluatedAt = '2026-08-16T07:00:00.000Z';
    input.measurements.candidateCompletedScans = 1_000;
    input.measurements.baselineCompletedScans = 1_000;
    assert.deepEqual(findSastRuleBundleCanaryGateReasonCodes(input), []);
  }
});

test('T048 issues a lifecycle authority receipt only over all six passed steps in order', () => {
  const currentRollout = rollout();
  const passedSteps = SAST_RULE_BUNDLE_CANARY_STEPS.map((step, index) => {
    const decisionDigest = digest(`decision-${step}`);
    return {
      step,
      decisionId: `sast-rule-bundle-canary-step-decision://${decisionDigest.slice('sha256:'.length)}`,
      decisionDigest
    };
  });
  const receipt = buildSastRuleBundleCanaryObservationReceipt(
    observationReceiptInput(currentRollout, passedSteps),
    digest
  );

  assert.ok(receipt);
  assert.equal(
    isSastRuleBundleCanaryObservationReceiptShapeValid(receipt, digest),
    true
  );
  assert.equal(receipt.receiptRef.endsWith(receipt.receiptDigest), true);
  assert.equal(receipt.thresholdsWaived, false);

  const incomplete = passedSteps.slice(0, 5);
  assert.equal(
    buildSastRuleBundleCanaryObservationReceipt(
      observationReceiptInput(currentRollout, incomplete),
      digest
    ),
    null
  );
});

test('T048 exposes a strict, non-skippable rollout progression', () => {
  assert.equal(nextSastRuleBundleCanaryStep('INTERNAL_CORPUS'), 'INTERNAL_REPOSITORIES');
  assert.equal(nextSastRuleBundleCanaryStep('PERCENT_25'), 'PERCENT_100');
  assert.equal(nextSastRuleBundleCanaryStep('PERCENT_100'), null);
});

function rolloutInput() {
  const candidateManifestDigest = digest('candidate-manifest');
  const baselineManifestDigest = digest('baseline-manifest');
  const evidenceDigest = digest('promotion-evidence');
  const transitionDigest = digest('canary-transition');
  const eligibilityPolicyDigest = digest('eligibility-policy');
  const observationSourceDigest = digest('observation-source');
  return {
    candidateManifestId: `sast-rule-bundle-manifest://${candidateManifestDigest.slice('sha256:'.length)}`,
    candidateManifestDigest,
    candidateBundleId: 'sast-rule-bundle://opengrep/java-core',
    candidateBundleDigest: digest('candidate-bundle'),
    baselineManifestId: `sast-rule-bundle-manifest://${baselineManifestDigest.slice('sha256:'.length)}`,
    baselineManifestDigest,
    baselineBundleDigest: digest('baseline-bundle'),
    profileId: 'JAVA_FAST_V1',
    profileDigest: digest('profile'),
    promotionEvidenceId: `sast-rule-bundle-promotion-evidence://${evidenceDigest.slice('sha256:'.length)}`,
    promotionEvidenceDigest: evidenceDigest,
    canaryTransitionId: `sast-rule-bundle-lifecycle-transition://${transitionDigest.slice('sha256:'.length)}`,
    canaryTransitionDigest: transitionDigest,
    cohortKeyRef: reference('cohort-key-v1'),
    cohortKeyVersion: 'cohort-key-v1',
    eligibilityPolicyRef: reference('eligibility-policy'),
    eligibilityPolicyDigest,
    observationSourceRef: reference('observation-source'),
    observationSourceDigest,
    createdAt: '2026-08-14T07:00:00.000Z'
  };
}

function rollout() {
  const value = buildSastRuleBundleCanaryRollout(rolloutInput(), digest);
  assert.ok(value);
  return value;
}

function membership(
  currentRollout,
  {
    tenantId = 'tenant-1',
    repositoryBindingId = 'repository-1',
    eligibilityClass = 'ELIGIBLE_PRODUCTION',
    excluded = false
  } = {}
) {
  const preimage = buildSastCanaryMembershipHmacPreimage({
    tenantId,
    repositoryBindingId,
    profileId: currentRollout.profileId,
    rolloutId: currentRollout.rolloutId
  });
  assert.ok(preimage);
  const assignmentHmacDigest = `sha256:${createHmac('sha256', Buffer.alloc(32, 7))
    .update(preimage, 'utf8')
    .digest('hex')}`;
  const eligibilityDecision = buildSastRuleBundleCanaryEligibilityDecision(
    {
      rolloutId: currentRollout.rolloutId,
      rolloutDigest: currentRollout.rolloutDigest,
      tenantId,
      repositoryBindingId,
      profileId: currentRollout.profileId,
      profileDigest: currentRollout.profileDigest,
      eligibilityClass,
      excluded,
      exclusionRef: excluded ? reference('contract-exclusion') : null,
      eligibilityPolicyRef: currentRollout.eligibilityPolicyRef,
      eligibilityPolicyDigest: currentRollout.eligibilityPolicyDigest,
      actorRef: 'actor://sast-canary/eligibility-policy',
      auditRef: reference(`eligibility-${tenantId}-${repositoryBindingId}`),
      evaluatedAt: '2026-08-14T07:01:00.000Z'
    },
    digest
  );
  assert.ok(eligibilityDecision);
  assert.equal(
    isSastRuleBundleCanaryEligibilityDecisionShapeValid(
      eligibilityDecision,
      digest
    ),
    true
  );
  const value = buildSastRuleBundleCanaryMembership(
    {
      rolloutId: currentRollout.rolloutId,
      rolloutDigest: currentRollout.rolloutDigest,
      tenantId,
      repositoryBindingId,
      profileId: currentRollout.profileId,
      profileDigest: currentRollout.profileDigest,
      eligibilityDecisionId: eligibilityDecision.eligibilityDecisionId,
      eligibilityDecisionDigest:
        eligibilityDecision.eligibilityDecisionDigest,
      eligibilityClass,
      excluded,
      exclusionRef: excluded ? reference('contract-exclusion') : null,
      eligibilityPolicyRef: currentRollout.eligibilityPolicyRef,
      eligibilityPolicyDigest: currentRollout.eligibilityPolicyDigest,
      cohortKeyRef: currentRollout.cohortKeyRef,
      cohortKeyVersion: currentRollout.cohortKeyVersion,
      assignmentHmacDigest,
      evaluatedAt: '2026-08-14T07:01:00.000Z'
    },
    digest
  );
  assert.ok(value);
  return value;
}

function assignment(currentRollout, currentMembership, step) {
  const value = buildSastRuleBundleCanaryAssignmentReceipt(
    {
      rolloutId: currentRollout.rolloutId,
      rolloutDigest: currentRollout.rolloutDigest,
      membershipId: currentMembership.membershipId,
      membershipDigest: currentMembership.membershipDigest,
      tenantId: currentMembership.tenantId,
      repositoryBindingId: currentMembership.repositoryBindingId,
      profileId: currentMembership.profileId,
      profileDigest: currentMembership.profileDigest,
      eligibilityClass: currentMembership.eligibilityClass,
      excluded: currentMembership.excluded,
      bucketBasisPoints: currentMembership.bucketBasisPoints,
      step,
      stepHeadDecisionId: null,
      stepHeadDecisionDigest: null,
      candidateManifestId: currentRollout.candidateManifestId,
      candidateManifestDigest: currentRollout.candidateManifestDigest,
      candidateBundleDigest: currentRollout.candidateBundleDigest,
      baselineManifestId: currentRollout.baselineManifestId,
      baselineManifestDigest: currentRollout.baselineManifestDigest,
      baselineBundleDigest: currentRollout.baselineBundleDigest,
      evaluatedAt: '2026-08-14T07:02:00.000Z'
    },
    digest
  );
  assert.ok(value);
  return value;
}

function forceCandidateAssignment(currentRollout, currentMembership) {
  const value = assignment(currentRollout, currentMembership, 'PERCENT_100');
  assert.equal(value.selection, 'CANDIDATE');
  return value;
}

function observationInput(currentRollout, currentAssignment, role, slug) {
  const candidate = role === 'CANDIDATE';
  const selectedManifestId = candidate
    ? currentRollout.candidateManifestId
    : currentRollout.baselineManifestId;
  const selectedManifestDigest = candidate
    ? currentRollout.candidateManifestDigest
    : currentRollout.baselineManifestDigest;
  const selectedBundleDigest = candidate
    ? currentRollout.candidateBundleDigest
    : currentRollout.baselineBundleDigest;
  const coverageDecisionDigest = digest(`coverage-${slug}`);
  const publicationDecisionDigest = digest(`publication-${slug}`);
  const telemetrySourceDigest = digest(`telemetry-${slug}`);
  return {
    rolloutId: currentRollout.rolloutId,
    rolloutDigest: currentRollout.rolloutDigest,
    step: 'PERCENT_100',
    cohortRole: role,
    tenantId: `tenant-${slug}`,
    repositoryBindingId: `repository-${slug}`,
    scanRequestId: `scan-${slug}`,
    attemptId: `attempt-${slug}`,
    assignmentReceiptId: currentAssignment?.assignmentReceiptId ?? null,
    assignmentReceiptDigest:
      currentAssignment?.assignmentReceiptDigest ?? null,
    selectedManifestId,
    selectedManifestDigest,
    selectedBundleDigest,
    profileId: currentRollout.profileId,
    profileDigest: currentRollout.profileDigest,
    lane: 'FAST',
    repositorySizeBucket: 'MEDIUM',
    coverageDecisionId: `coverage-decision-${slug}`,
    coverageDecisionDigest,
    publicationDecisionId: `publication-decision-${slug}`,
    publicationDecisionDigest,
    observationSourceRef: currentRollout.observationSourceRef,
    observationSourceDigest: currentRollout.observationSourceDigest,
    telemetrySourceRef: `sast-canary-telemetry://${slug}/${telemetrySourceDigest}`,
    telemetrySourceDigest,
    startedAt: '2026-08-15T07:00:00.000Z',
    completedAt: '2026-08-15T07:10:00.000Z',
    coverageComplete: true,
    telemetryComplete: true,
    measurements: observationMeasurements()
  };
}

function observation(currentRollout, currentAssignment, role, slug) {
  const value = buildSastRuleBundleCanaryScanObservation(
    observationInput(currentRollout, currentAssignment, role, slug),
    digest
  );
  assert.ok(value);
  return value;
}

function observationMeasurements() {
  return {
    findingCount: 1_000,
    criticalHighFindingCount: 100,
    falsePositiveCount: 10,
    feedbackEligibleFindingCount: 1_000,
    waiverCount: 0,
    suppressionCount: 0,
    scannerFailureCount: 4,
    scannerTimeoutCount: 0,
    eligibleScannerAttemptCount: 200,
    artifactRejectionCount: 0,
    latencyMilliseconds: 500_000,
    cpuMilliseconds: 10_000,
    peakMemoryBytes: 1_000_000,
    diskBytes: 2_000_000,
    incompleteCoverageCount: 0,
    publicationDenialCount: 0,
    egressDenialCount: 0,
    cleanupLagMilliseconds: 1_000,
    quarantineCount: 0,
    killSwitchSignalCount: 0,
    crossTenantEvents: 0,
    secretLeakEvents: 0,
    sandboxEscapeEvents: 0,
    stalePublicationEvents: 0,
    unauthorizedEgressEvents: 0,
    missingDestructionEvidenceEvents: 0,
    evidencePolicyViolationEvents: 0,
    unsignedArtifactExecutionEvents: 0
  };
}

function stepDecisionInput(currentRollout) {
  const candidateDigest = digest('candidate-observation');
  const baselineDigest = digest('baseline-observation');
  return {
    rolloutId: currentRollout.rolloutId,
    rolloutDigest: currentRollout.rolloutDigest,
    candidateManifestId: currentRollout.candidateManifestId,
    candidateManifestDigest: currentRollout.candidateManifestDigest,
    candidateBundleDigest: currentRollout.candidateBundleDigest,
    baselineManifestId: currentRollout.baselineManifestId,
    baselineManifestDigest: currentRollout.baselineManifestDigest,
    baselineBundleDigest: currentRollout.baselineBundleDigest,
    profileId: currentRollout.profileId,
    profileDigest: currentRollout.profileDigest,
    sequence: 1,
    step: 'PERCENT_5',
    previousDecisionId: null,
    previousDecisionDigest: null,
    windowStartedAt: '2026-08-14T07:00:00.000Z',
    windowEndedAt: '2026-08-15T07:00:00.000Z',
    observations: [
      {
        observationId: `sast-rule-bundle-canary-observation://${baselineDigest.slice('sha256:'.length)}`,
        observationDigest: baselineDigest
      },
      {
        observationId: `sast-rule-bundle-canary-observation://${candidateDigest.slice('sha256:'.length)}`,
        observationDigest: candidateDigest
      }
    ].sort((left, right) =>
      left.observationId.localeCompare(right.observationId)
    ),
    measurements: stepMeasurements(),
    telemetryComplete: true,
    allProfileSizeBucketsCompared: true,
    evaluatorRef: 'actor://sast-canary/evaluator',
    auditRef: reference('step-audit'),
    evaluatedAt: '2026-08-15T07:00:00.000Z'
  };
}

function stepMeasurements() {
  return {
    candidateCompletedScans: 200,
    baselineCompletedScans: 200,
    candidateFindingCount: 1_000,
    baselineFindingCount: 1_000,
    candidateCriticalHighFindingCount: 120,
    baselineCriticalHighFindingCount: 100,
    candidateFalsePositiveCount: 30,
    candidateFeedbackEligibleFindingCount: 1_000,
    baselineFalsePositiveCount: 10,
    baselineFeedbackEligibleFindingCount: 1_000,
    candidateWaiverCount: 0,
    baselineWaiverCount: 0,
    candidateSuppressionCount: 0,
    baselineSuppressionCount: 0,
    candidateScannerFailureCount: 4,
    candidateEligibleScannerAttemptCount: 200,
    baselineScannerFailureCount: 2,
    baselineEligibleScannerAttemptCount: 200,
    candidateScannerTimeoutCount: 0,
    baselineScannerTimeoutCount: 0,
    candidateP50LatencyMilliseconds: 300_000,
    candidateP95LatencyMilliseconds: 600_000,
    baselineP50LatencyMilliseconds: 280_000,
    baselineP95LatencyMilliseconds: 500_000,
    candidateP95CpuMilliseconds: 20_000,
    baselineP95CpuMilliseconds: 18_000,
    candidateP95PeakMemoryBytes: 1_000_000,
    baselineP95PeakMemoryBytes: 900_000,
    candidateP95DiskBytes: 2_000_000,
    baselineP95DiskBytes: 1_800_000,
    candidateArtifactRejectionCount: 0,
    baselineArtifactRejectionCount: 0,
    candidateIncompleteCoverageCount: 0,
    baselineIncompleteCoverageCount: 0,
    candidatePublicationDenialCount: 0,
    baselinePublicationDenialCount: 0,
    candidateEgressDenialCount: 0,
    baselineEgressDenialCount: 0,
    candidateP95CleanupLagMilliseconds: 1_000,
    baselineP95CleanupLagMilliseconds: 1_000,
    candidateQuarantineCount: 0,
    baselineQuarantineCount: 0,
    candidateKillSwitchSignalCount: 0,
    baselineKillSwitchSignalCount: 0,
    crossTenantEvents: 0,
    secretLeakEvents: 0,
    sandboxEscapeEvents: 0,
    stalePublicationEvents: 0,
    unauthorizedEgressEvents: 0,
    missingDestructionEvidenceEvents: 0,
    evidencePolicyViolationEvents: 0,
    unsignedArtifactExecutionEvents: 0
  };
}

function observationReceiptInput(currentRollout, passedSteps) {
  return {
    rolloutId: currentRollout.rolloutId,
    rolloutDigest: currentRollout.rolloutDigest,
    candidateManifestId: currentRollout.candidateManifestId,
    candidateManifestDigest: currentRollout.candidateManifestDigest,
    candidateBundleId: currentRollout.candidateBundleId,
    candidateBundleDigest: currentRollout.candidateBundleDigest,
    baselineManifestId: currentRollout.baselineManifestId,
    baselineManifestDigest: currentRollout.baselineManifestDigest,
    baselineBundleDigest: currentRollout.baselineBundleDigest,
    profileId: currentRollout.profileId,
    profileDigest: currentRollout.profileDigest,
    promotionEvidenceId: currentRollout.promotionEvidenceId,
    promotionEvidenceDigest: currentRollout.promotionEvidenceDigest,
    passedSteps,
    observedFrom: '2026-08-01T00:00:00.000Z',
    observedThrough: '2026-08-15T00:00:00.000Z',
    issuedAt: '2026-08-15T00:00:00.000Z'
  };
}

function reference(label) {
  return `sast-reference://canary/${label}/${digest(label)}`;
}

function digest(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}
