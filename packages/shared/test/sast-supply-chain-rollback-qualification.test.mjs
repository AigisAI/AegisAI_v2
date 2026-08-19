import assert from 'node:assert/strict';
import test from 'node:test';

import {
  SAST_END_TO_END_QUALIFICATION_APPROVAL_ROLES,
  SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LIMITS,
  evaluateSastSupplyChainRollbackQualificationEvidence,
  isSastSupplyChainRollbackQualificationManifestValid,
  isSastSupplyChainRollbackQualificationResultValid
} from '../dist/index.js';
import {
  createT055QualificationBundle,
  digest,
  rebuildT055Receipt,
  signReceipt,
  signature,
  stableJson
} from './helpers/t055-qualification-fixture.mjs';

const bundle = createT055QualificationBundle();

test('T055 manifest pins the exact 169-cell supply-chain and rollback denominator', () => {
  assert.equal(
    isSastSupplyChainRollbackQualificationManifestValid(
      bundle.manifest,
      bundle.t054Manifest,
      digest
    ),
    true
  );
  assert.equal(bundle.manifest.cells.length, 169);
  assert.equal(bundle.manifest.artifactKeys.length, 36);
  assert.equal(bundle.manifest.artifactSupplyChainDrillCount, 144);
  assert.equal(bundle.manifest.allowlistDrillCount, 1);
  assert.equal(bundle.manifest.databaseDrillCount, 6);
  assert.equal(bundle.manifest.schemaDrillCount, 3);
  assert.equal(bundle.manifest.rollbackDrillCount, 15);
  assert.equal(bundle.manifest.preExecutionRejectionCount, 115);
  assert.equal(bundle.manifest.customerCodeExecutionAllowed, false);
  assert.equal(bundle.manifest.productionReadinessAuthority, false);
});

test('T055 remains blocked without T054 and rejects downstream evidence before entry', () => {
  const blockedInput = {
    manifest: bundle.manifest,
    t054Manifest: bundle.t054Manifest,
    t054Result: null,
    t054DependencySet: null,
    t054ArtifactVerificationSet: null,
    t054Plan: null,
    entryAttestation: null,
    plan: null,
    approvals: [],
    signedReceipts: [],
    trustedEvaluatedAt: '2026-08-20T01:00:00.000Z',
    verifySignature: () => false
  };
  const blocked = evaluateSastSupplyChainRollbackQualificationEvidence(
    blockedInput,
    digest
  );
  assert.ok(blocked);
  assert.equal(blocked.status, 'BLOCKED_T054_QUALIFICATION');
  assert.equal(blocked.t056EntryAuthorized, false);
  assert.equal(blocked.productionReadinessAuthority, false);
  assert.equal(
    isSastSupplyChainRollbackQualificationResultValid(blocked, digest),
    true
  );

  const injected = evaluateSastSupplyChainRollbackQualificationEvidence(
    {
      ...blockedInput,
      signedReceipts: [bundle.signedReceipts[0]]
    },
    digest
  );
  assert.ok(injected);
  assert.equal(injected.status, 'FAILED');
  assert.deepEqual(injected.failureReasons, ['T054_ENTRY_INVALID']);
});

test('T055 recomputes all 169 drills and grants only T056 entry', () => {
  const result = evaluateSastSupplyChainRollbackQualificationEvidence(
    bundle.evaluationInput,
    digest
  );
  assert.ok(result);
  assert.equal(result.status, 'PASSED');
  assert.equal(result.validReceiptCount, 169);
  assert.equal(result.measurements?.artifactSupplyChainDrillCount, 144);
  assert.equal(result.measurements?.preExecutionRejectionCount, 115);
  assert.equal(
    result.measurements?.artifactInvocationCount,
    SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LIMITS.expectedArtifactInvocationCount
  );
  assert.equal(result.measurements?.networkEgressCount, 0);
  assert.equal(result.measurements?.productionMutationCount, 0);
  assert.equal(result.t056EntryAuthorized, true);
  assert.equal(result.findingAuthority, false);
  assert.equal(result.policyAuthority, false);
  assert.equal(result.publicationAuthority, false);
  assert.equal(result.deploymentAuthority, false);
  assert.equal(result.productionReadinessAuthority, false);
  assert.equal(
    isSastSupplyChainRollbackQualificationResultValid(result, digest),
    true
  );
});

test('T055 accepts a strict valid subset only as pending', () => {
  const result = evaluateSastSupplyChainRollbackQualificationEvidence(
    {
      ...bundle.evaluationInput,
      signedReceipts: [bundle.signedReceipts[0]]
    },
    digest
  );
  assert.ok(result);
  assert.equal(result.status, 'PENDING_DRILL_EXECUTION');
  assert.equal(result.validReceiptCount, 1);
  assert.equal(result.measurements, null);
  assert.equal(result.t056EntryAuthorized, false);
});

test('T055 rejects envelope drift, provider transfer, and untrusted signatures', () => {
  const first = bundle.signedReceipts[0].receipt;
  const envelopeDrift = signReceipt(
    rebuildT055Receipt(first, {
      observedSignatureEnvelopeDigest: digest('unexpected-signature-envelope')
    })
  );
  const envelopeResult = evaluateSastSupplyChainRollbackQualificationEvidence(
    {
      ...bundle.evaluationInput,
      signedReceipts: [envelopeDrift]
    },
    digest
  );
  assert.ok(envelopeResult);
  assert.equal(envelopeResult.status, 'FAILED');
  assert.ok(envelopeResult.failureReasons.includes('DRILL_OUTCOME_MISMATCH'));

  const providerDrift = signReceipt(
    rebuildT055Receipt(first, {
      providerId: 'microvm-provider://aegisai/unqualified/t055'
    })
  );
  const providerResult = evaluateSastSupplyChainRollbackQualificationEvidence(
    {
      ...bundle.evaluationInput,
      signedReceipts: [providerDrift]
    },
    digest
  );
  assert.ok(providerResult);
  assert.ok(providerResult.failureReasons.includes('PROVIDER_MISMATCH'));

  const untrusted = evaluateSastSupplyChainRollbackQualificationEvidence(
    {
      ...bundle.evaluationInput,
      signedReceipts: [],
      approvals: [],
      verifySignature: () => false
    },
    digest
  );
  assert.ok(untrusted);
  assert.equal(untrusted.status, 'FAILED');
  assert.ok(untrusted.failureReasons.includes('ARTIFACT_VERIFICATION_INVALID'));
});

test('T055 rejects duplicate identities and retroactive approval', () => {
  const first = bundle.signedReceipts[0];
  const duplicate = evaluateSastSupplyChainRollbackQualificationEvidence(
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

  const overCount = evaluateSastSupplyChainRollbackQualificationEvidence(
    {
      ...bundle.evaluationInput,
      signedReceipts: Array.from(
        { length: bundle.manifest.executionCellCount + 1 },
        () => first
      )
    },
    digest
  );
  assert.ok(overCount);
  assert.equal(overCount.status, 'FAILED');
  assert.deepEqual(overCount.failureReasons, ['RECEIPT_INVALID']);
  assert.equal(overCount.validReceiptCount, 0);

  const retroactive = evaluateSastSupplyChainRollbackQualificationEvidence(
    {
      ...bundle.evaluationInput,
      signedReceipts: [first],
      approvals: SAST_END_TO_END_QUALIFICATION_APPROVAL_ROLES.map((role) =>
        signature(role, bundle.plan.planDigest, first.receipt.startedAt)
      )
    },
    digest
  );
  assert.ok(retroactive);
  assert.equal(retroactive.status, 'FAILED');
  assert.ok(retroactive.failureReasons.includes('APPROVAL_SET_INVALID'));
});

test('T055 requires ordered rollback phases and fail-closed cleanup evidence', () => {
  const queueFence = bundle.signedReceipts.find(
    ({ receipt }) => receipt.drillKind === 'ROLLBACK_QUEUE_ADMISSION_FENCE'
  );
  assert.ok(queueFence);
  const outOfOrder = evaluateSastSupplyChainRollbackQualificationEvidence(
    {
      ...bundle.evaluationInput,
      signedReceipts: [queueFence]
    },
    digest
  );
  assert.ok(outOfOrder);
  assert.equal(outOfOrder.status, 'FAILED');
  assert.ok(outOfOrder.failureReasons.includes('ROLLBACK_SEQUENCE_INVALID'));

  const activation = bundle.signedReceipts.find(
    ({ receipt }) =>
      receipt.drillKind === 'ROLLBACK_ACTIVATE_BASELINE_APPEND_ONLY'
  );
  assert.ok(activation);
  const arbitraryPriorHead = signReceipt(
    rebuildT055Receipt(activation.receipt, {
      rollbackLedgerPreviousDigest: digest('attacker-selected-ledger-head')
    })
  );
  const arbitraryPriorHeadResult =
    evaluateSastSupplyChainRollbackQualificationEvidence(
      {
        ...bundle.evaluationInput,
        signedReceipts: [arbitraryPriorHead]
      },
      digest
    );
  assert.ok(arbitraryPriorHeadResult);
  assert.equal(arbitraryPriorHeadResult.status, 'FAILED');
  assert.ok(
    arbitraryPriorHeadResult.failureReasons.includes('DRILL_OUTCOME_MISMATCH')
  );

  const first = bundle.signedReceipts[0].receipt;
  const cleanupLate = signReceipt(
    rebuildT055Receipt(first, {
      cleanupCompletedAt: '2026-08-19T20:04:02.000Z'
    })
  );
  const cleanupResult = evaluateSastSupplyChainRollbackQualificationEvidence(
    {
      ...bundle.evaluationInput,
      signedReceipts: [cleanupLate]
    },
    digest
  );
  assert.ok(cleanupResult);
  assert.ok(cleanupResult.failureReasons.includes('CLEANUP_SLO_EXCEEDED'));

  const forbiddenExecution = signReceipt(
    rebuildT055Receipt(first, { customerCodeExecuted: true })
  );
  const forbiddenResult = evaluateSastSupplyChainRollbackQualificationEvidence(
    {
      ...bundle.evaluationInput,
      signedReceipts: [forbiddenExecution]
    },
    digest
  );
  assert.ok(forbiddenResult);
  assert.ok(forbiddenResult.failureReasons.includes('ZERO_TOLERANCE_EVENT'));
});

test('T055 result validation rejects caller-forged aggregate success', () => {
  const passed = evaluateSastSupplyChainRollbackQualificationEvidence(
    bundle.evaluationInput,
    digest
  );
  assert.ok(passed?.measurements);
  const { measurementsDigest, ...measurementCore } = passed.measurements;
  assert.ok(measurementsDigest);
  const forgedMeasurementCore = {
    ...measurementCore,
    artifactInvocationCount: 0
  };
  const forgedMeasurements = {
    ...forgedMeasurementCore,
    measurementsDigest: digest(stableJson(forgedMeasurementCore))
  };
  const { resultId, resultDigest, ...resultCore } = passed;
  assert.ok(resultId);
  assert.ok(resultDigest);
  const forgedCore = { ...resultCore, measurements: forgedMeasurements };
  const forgedDigest = digest(stableJson(forgedCore));
  const forged = {
    ...forgedCore,
    resultId:
      `sast-supply-chain-rollback-qualification-result://${forgedDigest.slice('sha256:'.length)}`,
    resultDigest: forgedDigest
  };
  assert.equal(
    isSastSupplyChainRollbackQualificationResultValid(forged, digest),
    false
  );
});
