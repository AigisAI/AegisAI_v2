import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  buildSastRuleBundleLifecycleSelectionReceipt,
  buildSastRuleBundleLifecycleTransition,
  buildSastRuleBundlePromotionApproval,
  buildSastRuleBundlePromotionEvidence,
  findSastRuleBundlePromotionEvidenceReasonCodes,
  isSastRuleBundleLifecycleSelectionReceiptShapeValid,
  isSastRuleBundleLifecycleTransitionShapeValid,
  isSastRuleBundlePromotionApprovalShapeValid,
  isSastRuleBundlePromotionEvidenceShapeValid,
  isVerifiedSastRuleBundleLifecycleDescriptorValid,
  toVerifiedSastRuleBundleLifecycleDescriptor
} from '../dist/index.js';

test('T047 binds passing quantitative evidence to one verified candidate and baseline', () => {
  const evidence = promotionEvidence();

  assert.equal(
    isSastRuleBundlePromotionEvidenceShapeValid(evidence, digest),
    true
  );
  assert.deepEqual(
    findSastRuleBundlePromotionEvidenceReasonCodes(evidenceInput()),
    []
  );
  assert.equal(evidence.gatesPassed, true);
  assert.equal(evidence.automatedEvidenceOnly, true);
  assert.equal(evidence.approvalGranted, false);
  assert.equal(evidence.customerInputAccepted, false);
  assert.equal(evidence.executableRuleContentStored, false);
  assert.equal(JSON.stringify(evidence).includes('sourceContent'), false);
});

test('T047 rejects every quantitative gate independently and in stable order', () => {
  const cases = [
    ['positiveCases', 199, 'SAMPLE_INSUFFICIENT'],
    ['goldenPassedCases', 199, 'CORPUS_GATE_FAILED'],
    ['mustDetectTruePositiveCases', 189, 'RECALL_GATE_FAILED'],
    ['criticalHighTruePositiveCases', 179, 'PRECISION_GATE_FAILED'],
    [
      'falsePositiveIncreaseBasisPoints',
      201,
      'FALSE_POSITIVE_GATE_FAILED'
    ],
    ['scannerFailureRateBasisPoints', 201, 'FAILURE_RATE_GATE_FAILED'],
    ['p95LatencyIncreaseBasisPoints', 2_001, 'LATENCY_GATE_FAILED'],
    ['crossTenantEvents', 1, 'SECURITY_EVENT_RECORDED']
  ];

  for (const [field, value, reason] of cases) {
    const input = evidenceInput();
    input.measurements[field] = value;
    assert.equal(
      findSastRuleBundlePromotionEvidenceReasonCodes(input).includes(reason),
      true,
      field
    );
    assert.equal(buildSastRuleBundlePromotionEvidence(input, digest), null);
  }

  const combined = evidenceInput();
  combined.measurements.positiveCases = 199;
  combined.measurements.goldenPassedCases = 199;
  combined.measurements.crossTenantEvents = 1;
  assert.deepEqual(findSastRuleBundlePromotionEvidenceReasonCodes(combined), [
    'SAMPLE_INSUFFICIENT',
    'CORPUS_GATE_FAILED',
    'SECURITY_EVENT_RECORDED'
  ]);
});

test('T047 keeps automated evidence separate from role-bound human approvals', () => {
  const evidence = promotionEvidence();
  const security = approval(evidence, 'SECURITY_ENGINEERING', 'security');
  const platform = approval(evidence, 'SCAN_PLATFORM', 'platform');

  assert.equal(
    isSastRuleBundlePromotionApprovalShapeValid(security, digest),
    true
  );
  assert.equal(
    isSastRuleBundlePromotionApprovalShapeValid(platform, digest),
    true
  );
  assert.equal(security.humanApproval, true);
  assert.equal(security.automatedApproval, false);
  assert.equal(
    buildSastRuleBundlePromotionApproval(
      {
        ...approvalInput(evidence, 'SECURITY_ENGINEERING', 'security'),
        approverRef: evidence.candidateAuthorRef
      },
      digest
    ),
    null
  );
});

test('T047 permits only the append-only lifecycle graph and required authorities', () => {
  const evidence = promotionEvidence();
  const security = approval(evidence, 'SECURITY_ENGINEERING', 'security');
  const platform = approval(evidence, 'SCAN_PLATFORM', 'platform');
  const validated = transition({
    evidence,
    approvals: [security],
    sequence: 1,
    fromState: 'DRAFT',
    toState: 'VALIDATED'
  });
  const canary = transition({
    evidence,
    approvals: [security],
    sequence: 2,
    fromState: 'VALIDATED',
    toState: 'CANARY',
    previous: validated
  });
  const active = transition({
    evidence,
    approvals: [security, platform],
    sequence: 3,
    fromState: 'CANARY',
    toState: 'ACTIVE',
    previous: canary,
    externalAuthority: 'CANARY_OBSERVATION',
    externalAuthorityReceiptDigest: digest('canary-observation')
  });

  for (const item of [validated, canary, active]) {
    assert.equal(
      isSastRuleBundleLifecycleTransitionShapeValid(item, digest),
      true
    );
  }
  assert.equal(
    buildSastRuleBundleLifecycleTransition(
      transitionInput({
        evidence,
        approvals: [security],
        sequence: 1,
        fromState: 'DRAFT',
        toState: 'ACTIVE'
      }),
      digest
    ),
    null
  );
  assert.equal(
    buildSastRuleBundleLifecycleTransition(
      transitionInput({
        evidence,
        approvals: [security],
        sequence: 3,
        fromState: 'CANARY',
        toState: 'ACTIVE',
        previous: canary,
        externalAuthority: 'CANARY_OBSERVATION',
        externalAuthorityReceiptDigest: digest('canary-observation')
      }),
      digest
    ),
    null
  );
});

test('T047 issues selection receipts only for the latest CANARY or ACTIVE transition', () => {
  const evidence = promotionEvidence();
  const security = approval(evidence, 'SECURITY_ENGINEERING', 'security');
  const platform = approval(evidence, 'SCAN_PLATFORM', 'platform');
  const validated = transition({
    evidence,
    approvals: [security],
    sequence: 1,
    fromState: 'DRAFT',
    toState: 'VALIDATED'
  });
  const canary = transition({
    evidence,
    approvals: [security],
    sequence: 2,
    fromState: 'VALIDATED',
    toState: 'CANARY',
    previous: validated
  });
  const active = transition({
    evidence,
    approvals: [security, platform],
    sequence: 3,
    fromState: 'CANARY',
    toState: 'ACTIVE',
    previous: canary,
    externalAuthority: 'CANARY_OBSERVATION',
    externalAuthorityReceiptDigest: digest('canary-observation')
  });
  const receipt = selectionReceipt(active);
  const descriptor = toVerifiedSastRuleBundleLifecycleDescriptor(receipt);

  assert.equal(
    isSastRuleBundleLifecycleSelectionReceiptShapeValid(receipt, digest),
    true
  );
  assert.equal(isVerifiedSastRuleBundleLifecycleDescriptorValid(descriptor), true);
  assert.equal(descriptor.lifecycleState, 'ACTIVE');
  assert.equal(descriptor.lifecycleTransitionDigest, active.transitionDigest);
  assert.equal(
    buildSastRuleBundleLifecycleSelectionReceipt(
      { ...selectionInput(active), lifecycleState: 'SUSPENDED' },
      digest
    ),
    null
  );
});

test('T047 validators return false for hostile nested shapes without throwing', () => {
  const evidence = promotionEvidence();
  const security = approval(evidence, 'SECURITY_ENGINEERING', 'security');
  const validated = transition({
    evidence,
    approvals: [security],
    sequence: 1,
    fromState: 'DRAFT',
    toState: 'VALIDATED'
  });

  assert.equal(
    isSastRuleBundlePromotionEvidenceShapeValid(
      { ...evidence, measurements: null },
      digest
    ),
    false
  );
  assert.equal(
    isSastRuleBundleLifecycleTransitionShapeValid(
      { ...validated, approvals: null },
      digest
    ),
    false
  );
});

function evidenceInput() {
  return {
    manifestId: `sast-rule-bundle-manifest://${'1'.repeat(64)}`,
    manifestDigest: digest('candidate-manifest'),
    verificationId: `sast-rule-bundle-verification://${'2'.repeat(64)}`,
    verificationDigest: digest('candidate-verification'),
    bundleId: 'sast-rule-bundle://opengrep/java-core',
    bundleDigest: digest('candidate-bundle'),
    profileId: 'JAVA_FAST_V1',
    candidateAuthorRef: 'sast-actor://rule-authors/alice',
    baselineManifestId: `sast-rule-bundle-manifest://${'3'.repeat(64)}`,
    baselineManifestDigest: digest('baseline-manifest'),
    baselineBundleDigest: digest('baseline-bundle'),
    rollbackTargetDigest: digest('baseline-bundle'),
    environmentRef: reference('qualification-environment'),
    corpusReferences: {
      goldenCorpusRef: reference('golden'),
      priorMustDetectCorpusRef: reference('prior-must-detect'),
      maliciousCorpusRef: reference('malicious'),
      parserCorpusRef: reference('parser'),
      fingerprintCorpusRef: reference('fingerprint'),
      coverageCorpusRef: reference('coverage'),
      performanceCorpusRef: reference('performance')
    },
    measurements: {
      positiveCases: 200,
      negativeCases: 200,
      performanceRuns: 30,
      goldenPassedCases: 200,
      goldenTotalCases: 200,
      priorMustDetectPassedCases: 200,
      priorMustDetectTotalCases: 200,
      mustDetectTruePositiveCases: 190,
      mustDetectExpectedCases: 200,
      criticalHighTruePositiveCases: 180,
      criticalHighReportedCases: 200,
      maliciousPassedCases: 40,
      maliciousTotalCases: 40,
      parserRejectedCases: 50,
      parserExpectedRejectCases: 50,
      fingerprintPassedCases: 20,
      fingerprintTotalCases: 20,
      coveragePassedCases: 20,
      coverageTotalCases: 20,
      falsePositiveIncreaseBasisPoints: 200,
      scannerFailureRateBasisPoints: 200,
      p95LatencyIncreaseBasisPoints: 2_000,
      crossTenantEvents: 0,
      secretLeakEvents: 0,
      sandboxEscapeEvents: 0,
      stalePublicationEvents: 0
    },
    measuredAt: '2026-08-14T07:00:00.000Z'
  };
}

function promotionEvidence() {
  const value = buildSastRuleBundlePromotionEvidence(evidenceInput(), digest);
  assert.ok(value);
  return value;
}

function approvalInput(evidence, role, slug) {
  return {
    evidenceId: evidence.evidenceId,
    evidenceDigest: evidence.evidenceDigest,
    manifestId: evidence.manifestId,
    manifestDigest: evidence.manifestDigest,
    bundleDigest: evidence.bundleDigest,
    candidateAuthorRef: evidence.candidateAuthorRef,
    role,
    approverRef: `sast-approver://rule-governance/${slug}`,
    approvalRef: reference(`approval-${slug}`),
    approvedAt: '2026-08-14T07:05:00.000Z'
  };
}

function approval(evidence, role, slug) {
  const value = buildSastRuleBundlePromotionApproval(
    approvalInput(evidence, role, slug),
    digest
  );
  assert.ok(value);
  return value;
}

function transitionInput({
  evidence,
  approvals,
  sequence,
  fromState,
  toState,
  previous = null,
  externalAuthority = 'NONE',
  externalAuthorityReceiptDigest = null
}) {
  return {
    manifestId: evidence.manifestId,
    manifestDigest: evidence.manifestDigest,
    bundleId: evidence.bundleId,
    bundleDigest: evidence.bundleDigest,
    sequence,
    fromState,
    toState,
    previousTransitionId: previous?.transitionId ?? null,
    previousTransitionDigest: previous?.transitionDigest ?? null,
    promotionEvidenceId: evidence.evidenceId,
    promotionEvidenceDigest: evidence.evidenceDigest,
    candidateAuthorRef: evidence.candidateAuthorRef,
    approvals: approvals.map((item) => ({
      approvalId: item.approvalId,
      approvalDigest: item.approvalDigest,
      role: item.role,
      approverRef: item.approverRef,
      approvedAt: item.approvedAt
    })),
    externalAuthority,
    externalAuthorityReceiptRef: externalAuthorityReceiptDigest
      ? `sast-authority://${externalAuthority.toLowerCase()}/${externalAuthorityReceiptDigest}`
      : null,
    externalAuthorityReceiptDigest,
    actorRef: 'sast-actor://rule-governance/release-manager',
    reasonRef: reference(`transition-${sequence}-reason`),
    auditRef: reference(`transition-${sequence}-audit`),
    transitionedAt: `2026-08-14T07:${String(10 + sequence).padStart(2, '0')}:00.000Z`
  };
}

function transition(options) {
  const value = buildSastRuleBundleLifecycleTransition(
    transitionInput(options),
    digest
  );
  assert.ok(value);
  return value;
}

function selectionInput(transitionValue) {
  return {
    manifestId: transitionValue.manifestId,
    manifestDigest: transitionValue.manifestDigest,
    bundleId: transitionValue.bundleId,
    bundleDigest: transitionValue.bundleDigest,
    lifecycleState: transitionValue.toState,
    lifecycleSequence: transitionValue.sequence,
    transitionId: transitionValue.transitionId,
    transitionDigest: transitionValue.transitionDigest,
    promotionEvidenceId: transitionValue.promotionEvidenceId,
    promotionEvidenceDigest: transitionValue.promotionEvidenceDigest,
    approvalSetDigest: transitionValue.approvalSetDigest,
    evaluatedAt: '2026-08-14T07:20:00.000Z'
  };
}

function selectionReceipt(transitionValue) {
  const value = buildSastRuleBundleLifecycleSelectionReceipt(
    selectionInput(transitionValue),
    digest
  );
  assert.ok(value);
  return value;
}

function reference(label) {
  return `sast-reference://rule-governance/${label}/${digest(label)}`;
}

function digest(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}
