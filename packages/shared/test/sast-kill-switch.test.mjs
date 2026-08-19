import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  SAST_KILL_SWITCH_GATES,
  buildApplicableSastKillSwitchSelectors,
  buildSastKillSwitchCanarySuspensionSignal,
  buildSastKillSwitchDecision,
  buildSastKillSwitchEmergencySuspensionReceipt,
  buildSastKillSwitchEvaluation,
  buildSastKillSwitchEvaluationContext,
  buildSastKillSwitchHeadBinding,
  buildSastKillSwitchVerification,
  isSastKillSwitchDecisionShapeValid,
  isSastKillSwitchCanarySuspensionRequestValid,
  isSastKillSwitchCanarySuspensionSignalValid,
  isSastKillSwitchEmergencySuspensionReceiptValid,
  isSastKillSwitchEvaluationContextValid,
  isSastKillSwitchEvaluationReceiptValid,
  isSastKillSwitchPlanningDescriptorValid,
  isSastKillSwitchSelectorValid,
  isSastKillSwitchVerificationShapeValid,
  toSastKillSwitchPlanningDescriptor
} from '../dist/index.js';

test('T049 canonicalizes one content-free multi-scope runtime context', () => {
  const value = context();

  assert.equal(isSastKillSwitchEvaluationContextValid(value, digest), true);
  assert.deepEqual(
    value.scanners.map((entry) => entry.scanner),
    ['OPENGREP', 'SYFT', 'TRIVY']
  );
  assert.equal(value.repositoryContentStored, false);
  assert.equal(value.findingContentStored, false);
  assert.equal(value.secretValueStored, false);
  assert.equal(value.arbitraryPayloadStored, false);

  const changed = structuredClone(value);
  changed.requiredCapabilities.reverse();
  assert.equal(isSastKillSwitchEvaluationContextValid(changed, digest), false);
  const hostile = { ...value, payload: { source: 'secret' } };
  assert.equal(isSastKillSwitchEvaluationContextValid(hostile, digest), false);
});

test('T049 derives all runtime selectors and only adds publication selectors at external boundaries', () => {
  const planning = buildApplicableSastKillSwitchSelectors(
    context(),
    'PLANNING',
    digest
  );
  const publication = buildApplicableSastKillSwitchSelectors(
    context(),
    'EXTERNAL_PUBLICATION',
    digest
  );
  const scopes = new Set(planning.map((entry) => entry.selector.scope));

  assert.deepEqual(
    [...scopes].sort(),
    [
      'CAPABILITY',
      'GLOBAL',
      'PROFILE',
      'REPOSITORY_BINDING',
      'RULE_BUNDLE',
      'SCANNER_VERSION',
      'SEMANTIC_RULE',
      'TENANT'
    ]
  );
  assert.equal(
    planning.some((entry) => entry.selector.scope === 'EXTERNAL_PUBLICATION'),
    false
  );
  assert.equal(
    publication.filter(
      (entry) => entry.selector.scope === 'EXTERNAL_PUBLICATION'
    ).length,
    3
  );
  assert.equal(
    new Set(publication.map((entry) => entry.selectorKey)).size,
    publication.length
  );
  assert.deepEqual(
    [...publication].map((entry) => entry.selectorKey),
    [...publication]
      .map((entry) => entry.selectorKey)
      .sort()
  );
  assert.deepEqual(SAST_KILL_SWITCH_GATES, [
    'PLANNING',
    'QUEUE_ADMISSION',
    'SCANNER_START',
    'ARTIFACT_ACCEPTANCE',
    'RETRY_ADMISSION',
    'COVERAGE',
    'EXTERNAL_PUBLICATION',
    'AI_ADVISORY'
  ]);
});

test('T049 requires an exact signed append-only activation or deactivation decision', () => {
  const activation = decision();
  assert.ok(activation);
  assert.equal(isSastKillSwitchDecisionShapeValid(activation, digest), true);
  assert.equal(activation.action, 'ACTIVATE');
  assert.equal(activation.customerInputAccepted, false);
  assert.equal(activation.arbitraryPayloadStored, false);

  const deactivation = decision({
    sequence: 2,
    previousDecisionId: activation.decisionId,
    previousDecisionDigest: activation.decisionDigest,
    action: 'DEACTIVATE',
    effectiveAt: '2026-08-19T01:00:00.000Z',
    reviewBy: '2026-08-20T01:00:00.000Z',
    expiresAt: '2026-08-21T01:00:00.000Z'
  });
  assert.ok(deactivation);
  assert.equal(isSastKillSwitchDecisionShapeValid(deactivation, digest), true);

  assert.equal(decision({ sequence: 2 }), null);
  assert.equal(
    decision({ reviewBy: '2026-08-21T00:00:00.000Z' }),
    null
  );
  assert.equal(
    decision({ signatureRef: 'https://example.test/signature' }),
    null
  );
  const mutated = { ...activation, rawPayload: 'forbidden' };
  assert.equal(isSastKillSwitchDecisionShapeValid(mutated, digest), false);
});

test('T049 stores only content-free signature and provenance verification facts', () => {
  const activation = decision();
  const verification = buildSastKillSwitchVerification(
    {
      decisionId: activation.decisionId,
      decisionDigest: activation.decisionDigest,
      selectorKey: activation.selectorKey,
      signerIdentity: 'security-signer-v1',
      signatureRef: activation.signatureRef,
      provenanceRef: activation.provenanceRef,
      verifiedAt: activation.effectiveAt
    },
    digest
  );

  assert.ok(verification);
  assert.equal(
    isSastKillSwitchVerificationShapeValid(verification, digest),
    true
  );
  assert.equal(verification.signatureBytesStored, false);
  assert.equal(verification.provenancePayloadStored, false);
  assert.equal(verification.repositoryContentStored, false);
  assert.equal(verification.secretValueStored, false);
});

test('T049 binds clear and active evaluations to every lockable selector head', () => {
  const currentContext = context();
  const selectors = buildApplicableSastKillSwitchSelectors(
    currentContext,
    'PLANNING',
    digest
  );
  const clearHeads = selectors.map(({ selectorKey, selector }) =>
    buildSastKillSwitchHeadBinding(
      {
        selectorKey,
        scope: selector.scope,
        sequence: 0,
        decisionId: null,
        decisionDigest: null,
        action: null,
        active: false,
        effectiveAt: null,
        expiresAt: null
      },
      digest
    )
  );
  assert.equal(clearHeads.every(Boolean), true);
  const clear = buildSastKillSwitchEvaluation(
    {
      context: currentContext,
      gate: 'PLANNING',
      heads: clearHeads,
      evaluatedAt: '2026-08-19T00:01:00.000Z'
    },
    digest
  );
  assert.ok(clear);
  assert.equal(clear.receipt.outcome, 'CLEAR');
  assert.equal(clear.receipt.matchedDecisionCount, 0);
  assert.equal(clear.receipt.coverageEffect, 'UNCHANGED');
  assert.equal(
    isSastKillSwitchEvaluationReceiptValid(clear.receipt, digest),
    true
  );
  const planning = toSastKillSwitchPlanningDescriptor(clear.receipt);
  assert.ok(planning);
  assert.equal(isSastKillSwitchPlanningDescriptorValid(planning), true);

  const activation = decision();
  const activeHeads = clearHeads.map((head) =>
    head.selectorKey === activation.selectorKey
      ? buildSastKillSwitchHeadBinding(
          {
            selectorKey: activation.selectorKey,
            scope: activation.selector.scope,
            sequence: activation.sequence,
            decisionId: activation.decisionId,
            decisionDigest: activation.decisionDigest,
            action: activation.action,
            active: true,
            effectiveAt: activation.effectiveAt,
            expiresAt: activation.expiresAt
          },
          digest
        )
      : head
  );
  const active = buildSastKillSwitchEvaluation(
    {
      context: currentContext,
      gate: 'PLANNING',
      heads: activeHeads,
      evaluatedAt: '2026-08-19T00:01:00.000Z'
    },
    digest
  );
  assert.ok(active);
  assert.equal(active.receipt.outcome, 'ACTIVE');
  assert.equal(active.receipt.matchedDecisionCount, 1);
  assert.equal(active.receipt.coverageEffect, 'FAILED');
  assert.equal(toSastKillSwitchPlanningDescriptor(active.receipt), null);

  assert.equal(
    buildSastKillSwitchEvaluation(
      {
        context: currentContext,
        gate: 'PLANNING',
        heads: activeHeads,
        evaluatedAt: activation.expiresAt
      },
      digest
    ),
    null
  );
});

test('T049 validates a content-free emergency suspension receipt against one active decision', () => {
  const activation = decision();
  const receipt = buildSastKillSwitchEmergencySuspensionReceipt({
    manifestId: 'manifest-1',
    manifestDigest: sha('manifest'),
    bundleId: 'opengrep-java',
    bundleDigest: sha('bundle'),
    fromState: 'ACTIVE',
    toState: 'SUSPENDED',
    lifecycleSequence: 4,
    lifecycleTransitionId: 'transition-4',
    lifecycleTransitionDigest: sha('transition'),
    promotionEvidenceId: 'evidence-1',
    promotionEvidenceDigest: sha('evidence'),
    triggerSelectorKey: activation.selectorKey,
    triggerDecisionId: activation.decisionId,
    triggerDecisionDigest: activation.decisionDigest,
    activeDecisionCount: 1,
    activeDecisionSetDigest: sha('active-set'),
    requestedAt: '2026-08-19T00:01:00.000Z',
    verifiedAt: '2026-08-19T00:01:00.000Z'
  }, digest);
  assert.ok(receipt);

  assert.equal(
    isSastKillSwitchEmergencySuspensionReceiptValid(receipt, digest),
    true
  );
  assert.equal(
    isSastKillSwitchEmergencySuspensionReceiptValid(
      { ...receipt, source: 'repository' },
      digest
    ),
    false
  );
  assert.equal(receipt.receiptRef.endsWith(receipt.receiptDigest), true);
  assert.match(
    receipt.receiptRef,
    /^sast-kill-switch-suspension:\/\/authority\/sha256:[a-f0-9]{64}$/u
  );
  assert.equal(
    isSastKillSwitchEmergencySuspensionReceiptValid(
      { ...receipt, receiptRef: receipt.receiptRef.replace('authority', 'other') },
      digest
    ),
    false
  );
});

test('T049 derives a non-forgeable content-free suspension signal from one T048 decision reference', () => {
  const request = {
    version: 'sast-kill-switch-canary-suspension-request-v1',
    canaryDecisionId:
      `sast-rule-bundle-canary-step-decision://${hex('canary-decision')}`,
    canaryDecisionDigest: sha('canary-decision')
  };
  assert.equal(isSastKillSwitchCanarySuspensionRequestValid(request), true);
  assert.equal(
    isSastKillSwitchCanarySuspensionRequestValid({
      ...request,
      candidateBundleDigest: sha('forged-target')
    }),
    false
  );

  const signal = buildSastKillSwitchCanarySuspensionSignal(
    {
      canaryDecisionId: request.canaryDecisionId,
      canaryDecisionDigest: request.canaryDecisionDigest,
      rolloutId: `sast-rule-bundle-canary-rollout://${hex('rollout')}`,
      rolloutDigest: sha('rollout'),
      candidateManifestId: 'manifest-1',
      candidateManifestDigest: sha('manifest'),
      candidateBundleId: 'bundle-1',
      candidateBundleDigest: sha('bundle'),
      profileId: 'JAVA_DEEP_V1',
      profileDigest: sha('profile'),
      lifecycleTransitionId: 'transition-3',
      lifecycleTransitionDigest: sha('transition'),
      lifecycleState: 'CANARY',
      reasonCodes: [
        'SCANNER_FAILURE_GATE_FAILED',
        'ZERO_TOLERANCE_EVENT_RECORDED'
      ],
      observedAt: '2026-08-19T00:00:00.000Z'
    },
    digest
  );
  assert.ok(signal);
  assert.equal(signal.trigger, 'ZERO_TOLERANCE');
  assert.equal(signal.customerTargetAccepted, false);
  assert.equal(
    isSastKillSwitchCanarySuspensionSignalValid(signal, digest),
    true
  );
  assert.equal(
    isSastKillSwitchCanarySuspensionSignalValid(
      { ...signal, candidateBundleDigest: sha('forged-target') },
      digest
    ),
    false
  );
});

test('T049 selector contracts reject cross-scope and malformed targets', () => {
  assert.equal(
    isSastKillSwitchSelectorValid({
      scope: 'REPOSITORY_BINDING',
      tenantId: 'tenant-1',
      repositoryBindingId: 'repo-1'
    }),
    true
  );
  assert.equal(
    isSastKillSwitchSelectorValid({
      scope: 'TENANT',
      tenantId: 'tenant-1',
      repositoryBindingId: 'repo-1'
    }),
    false
  );
  assert.equal(
    isSastKillSwitchSelectorValid({
      scope: 'EXTERNAL_PUBLICATION',
      targetScope: 'TENANT',
      tenantId: 'tenant-1',
      repositoryBindingId: 'repo-1'
    }),
    false
  );
});

function context() {
  const value = buildSastKillSwitchEvaluationContext(
    {
      tenantId: 'tenant-1',
      repositoryBindingId: 'repository-1',
      scanRequestId: 'scan-1',
      profileId: 'JAVA_DEEP_V1',
      profileDigest: sha('profile'),
      scannerSetDigest: sha('scanner-set'),
      scanners: [
        { scanner: 'OPENGREP', scannerVersion: '1.2.3' },
        { scanner: 'SYFT', scannerVersion: '1.44.0' },
        { scanner: 'TRIVY', scannerVersion: '0.60.0' }
      ],
      ruleBundles: [
        {
          bundleDigest: sha('opengrep-bundle'),
          ruleSemanticIds: ['java.command-injection', 'java.sql-injection']
        },
        {
          bundleDigest: sha('trivy-bundle'),
          ruleSemanticIds: ['iac.public-ingress']
        }
      ],
      requiredCapabilities: [
        'SAST',
        'DEPENDENCY_VULNERABILITY',
        'SECRET_DETECTION',
        'IAC_MISCONFIGURATION',
        'SBOM'
      ]
    },
    digest
  );
  assert.ok(value);
  return value;
}

function decision(overrides = {}) {
  return buildSastKillSwitchDecision(
    {
      selector: { scope: 'GLOBAL', runtime: 'SAST' },
      sequence: 1,
      previousDecisionId: null,
      previousDecisionDigest: null,
      action: 'ACTIVATE',
      reasonCode: 'SECURITY_INCIDENT',
      incidentRef: reference('incident'),
      actorRef: reference('actor'),
      actorRole: 'SECURITY_ON_CALL',
      effectiveAt: '2026-08-19T00:00:00.000Z',
      reviewBy: '2026-08-20T00:00:00.000Z',
      expiresAt: '2026-08-21T00:00:00.000Z',
      rollbackTargetRef: reference('rollback'),
      signatureRef: reference('signature'),
      provenanceRef: reference('provenance'),
      auditRef: reference('audit'),
      ...overrides
    },
    digest
  );
}

function reference(seed) {
  return `immutable://${seed}/sha256:${hex(seed)}`;
}

function sha(seed) {
  return `sha256:${hex(seed)}`;
}

function hex(seed) {
  return createHash('sha256').update(seed).digest('hex');
}

function digest(value) {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}
