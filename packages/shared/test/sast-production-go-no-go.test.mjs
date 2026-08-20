import assert from 'node:assert/strict';
import test from 'node:test';

import {
  SAST_PRODUCTION_GO_NO_GO_EVIDENCE_KINDS,
  SAST_PRODUCTION_GO_NO_GO_GATE_IDS,
  buildSastProductionGoNoGoEvidenceAttestation,
  buildSastProductionGoNoGoPlan,
  evaluateSastProductionGoNoGoEvidence,
  isSastProductionGoNoGoManifestValid,
  isSastProductionGoNoGoRecordValid
} from '../dist/index.js';
import { createT056GoNoGoBundle, digest } from './helpers/t056-go-no-go-fixture.mjs';

test('T056 manifest fixes one exact 54-gate catalog and zero production authority', () => {
  const bundle = createT056GoNoGoBundle();
  const { manifest, t054Manifest, t055Manifest } = bundle.assets;
  assert.equal(
    isSastProductionGoNoGoManifestValid(
      manifest,
      t055Manifest,
      t054Manifest,
      digest
    ),
    true
  );
  assert.equal(manifest.requiredGateCount, 54);
  assert.deepEqual(manifest.gates.map((item) => item.gateId), SAST_PRODUCTION_GO_NO_GO_GATE_IDS);
  assert.equal(new Set(manifest.gates.map((item) => item.gateDigest)).size, 54);
  assert.equal(manifest.gates.every((item) => item.notApplicableAllowed === false), true);
  assert.equal(manifest.aggregateDecisionAcceptedFromCaller, false);
  assert.equal(manifest.deploymentAuthority, false);
  assert.equal(manifest.kubernetesExecutionAuthority, false);
  assert.equal(manifest.productionReadinessAuthority, false);
});

test('T056 repository validation remains blocked without the exact external T055 pass', () => {
  const bundle = createT056GoNoGoBundle();
  const record = evaluateSastProductionGoNoGoEvidence(
    {
      ...bundle.evaluationInput,
      upstream: null,
      entryAttestation: null,
      evidenceAttestations: [],
      plan: null,
      approvals: []
    },
    digest
  );
  assert.ok(record);
  assert.equal(record.status, 'BLOCKED_T055_QUALIFICATION');
  assert.equal(record.deploymentOperationsEntryAuthorized, false);
  assert.equal(record.kubernetesExecutionAuthority, false);

  const blockedWithUpstream = evaluateSastProductionGoNoGoEvidence(
    {
      ...bundle.evaluationInput,
      upstream: {
        ...bundle.upstream,
        t055Result: {
          ...bundle.upstream.t055Result,
          status: 'FAILED',
          t056EntryAuthorized: false
        }
      }
    },
    digest
  );
  assert.equal(blockedWithUpstream?.status, 'BLOCKED_T055_QUALIFICATION');
  assert.equal(isSastProductionGoNoGoRecordValid(blockedWithUpstream, digest), true);
});

test('T056 recomputes all gates and GO authorizes only entry to deployment operations', () => {
  const bundle = createT056GoNoGoBundle();
  const record = evaluateSastProductionGoNoGoEvidence(bundle.evaluationInput, digest);
  assert.ok(record);
  assert.equal(isSastProductionGoNoGoRecordValid(record, digest), true);
  assert.equal(record.status, 'GO');
  assert.equal(record.evaluatedGateCount, 54);
  assert.equal(record.passedGateCount, 54);
  assert.equal(record.failedGateCount, 0);
  assert.equal(record.notApplicableGateCount, 0);
  assert.equal(record.deploymentOperationsEntryAuthorized, true);
  assert.equal(record.findingAuthority, false);
  assert.equal(record.policyAuthority, false);
  assert.equal(record.publicationAuthority, false);
  assert.equal(record.scmMutationAuthority, false);
  assert.equal(record.aiAuthority, false);
  assert.equal(record.deploymentAuthority, false);
  assert.equal(record.kubernetesExecutionAuthority, false);
  assert.equal(record.productionMutationAuthority, false);
  assert.equal(record.productionReadinessAuthority, false);
  assert.equal(bundle.plan.repositoryCommitSha, 'a'.repeat(40));
  assert.equal(record.repositoryCommitSha, bundle.plan.repositoryCommitSha);
  assert.equal(record.rollbackTargetDigest, bundle.entryAttestation.rollbackTargetDigest);
  assert.equal(
    record.killSwitchEvidenceAttestationDigest,
    bundle.evidenceAttestations.find(
      (item) => item.evidenceKind === 'KILL_SWITCH_PROPAGATION'
    ).attestationDigest
  );
});

test('T056 rejects mixed repository commits and digest-detached evidence references', () => {
  const bundle = createT056GoNoGoBundle();
  const source = bundle.evidenceAttestations[1];
  const mixedCommitEvidence = rebuildEvidenceAttestation(source, {
    repositoryCommitSha: 'b'.repeat(40)
  });
  const mixedEvidenceSet = [...bundle.evidenceAttestations];
  mixedEvidenceSet[1] = mixedCommitEvidence;
  const mixedPlan = buildSastProductionGoNoGoPlan(
    {
      manifest: bundle.assets.manifest,
      entryAttestation: bundle.entryAttestation,
      evidenceAttestations: mixedEvidenceSet,
      decisionActorRef: bundle.plan.decisionActorRef,
      decidedAt: bundle.plan.decidedAt,
      verifySignature: () => true
    },
    digest
  );
  assert.equal(mixedPlan, null);
  const mixedRecord = evaluateSastProductionGoNoGoEvidence(
    { ...bundle.evaluationInput, evidenceAttestations: mixedEvidenceSet },
    digest
  );
  assert.equal(mixedRecord?.status, 'NO_GO');
  assert.ok(mixedRecord?.failureReasons.includes('EVIDENCE_INVALID'));

  const mismatchedDigest = digest('mismatched-reference');
  const evidenceInput = pickEvidenceInput(source);
  assert.equal(
    buildSastProductionGoNoGoEvidenceAttestation(
      {
        ...evidenceInput,
        evidenceRef: evidenceInput.evidenceRef.replace(
          /sha256:[a-f0-9]{64}$/u,
          mismatchedDigest
        )
      },
      [],
      digest
    ),
    null
  );
  assert.equal(
    buildSastProductionGoNoGoEvidenceAttestation(
      {
        ...evidenceInput,
        observations: evidenceInput.observations.map((item, index) =>
          index === 0
            ? {
                ...item,
                evidenceRef: item.evidenceRef.replace(
                  /sha256:[a-f0-9]{64}$/u,
                  mismatchedDigest
                )
              }
            : item
        )
      },
      [],
      digest
    ),
    null
  );
});

test('T056 treats a valid missing category or final approval as pending', () => {
  const bundle = createT056GoNoGoBundle();
  const missingEvidence = evaluateSastProductionGoNoGoEvidence(
    {
      ...bundle.evaluationInput,
      evidenceAttestations: bundle.evidenceAttestations.slice(0, -1),
      plan: null,
      approvals: []
    },
    digest
  );
  assert.equal(missingEvidence?.status, 'PENDING_FINAL_EVIDENCE');
  assert.equal(isSastProductionGoNoGoRecordValid(missingEvidence, digest), true);
  const contradictoryMissingEvidence = evaluateSastProductionGoNoGoEvidence(
    {
      ...bundle.evaluationInput,
      evidenceAttestations: bundle.evidenceAttestations.slice(0, -1)
    },
    digest
  );
  assert.equal(contradictoryMissingEvidence?.status, 'NO_GO');
  assert.ok(contradictoryMissingEvidence?.failureReasons.includes('PLAN_INVALID'));
  assert.ok(
    contradictoryMissingEvidence?.failureReasons.includes('APPROVALS_INVALID')
  );
  const missingApproval = evaluateSastProductionGoNoGoEvidence(
    {
      ...bundle.evaluationInput,
      approvals: bundle.approvals.slice(0, 1)
    },
    digest
  );
  assert.equal(missingApproval?.status, 'PENDING_FINAL_EVIDENCE');
  assert.equal(isSastProductionGoNoGoRecordValid(missingApproval, digest), true);
  assert.deepEqual(SAST_PRODUCTION_GO_NO_GO_EVIDENCE_KINDS, [
    'UPSTREAM_QUALIFICATION',
    'REPOSITORY_VALIDATION',
    'CANARY_TELEMETRY_REPLAY',
    'KILL_SWITCH_PROPAGATION',
    'ROLLBACK_READINESS',
    'DEPLOYMENT_HANDOFF_BOUNDARY'
  ]);
});

test('T056 never lets incomplete inputs hide malformed or breached evidence', () => {
  const breached = createT056GoNoGoBundle({
    overrides: { CANARY_SAMPLE_SUFFICIENCY: 999 }
  });
  const incompleteBreach = evaluateSastProductionGoNoGoEvidence(
    {
      ...breached.evaluationInput,
      evidenceAttestations: breached.evidenceAttestations.slice(0, -1),
      approvals: []
    },
    digest
  );
  assert.equal(incompleteBreach?.status, 'NO_GO');
  assert.ok(incompleteBreach?.failureReasons.includes('GATE_THRESHOLD_BREACH'));

  const bundle = createT056GoNoGoBundle();
  const malformedEvidence = structuredClone(bundle.evidenceAttestations.slice(0, 1));
  malformedEvidence[0].signatures[0].payloadDigest = digest('wrong-evidence');
  const incompleteMalformed = evaluateSastProductionGoNoGoEvidence(
    {
      ...bundle.evaluationInput,
      evidenceAttestations: malformedEvidence,
      plan: null,
      approvals: []
    },
    digest
  );
  assert.equal(incompleteMalformed?.status, 'NO_GO');
  assert.ok(incompleteMalformed?.failureReasons.includes('EVIDENCE_INVALID'));

  const hostileShape = evaluateSastProductionGoNoGoEvidence(
    {
      ...bundle.evaluationInput,
      evidenceAttestations: [null],
      plan: null,
      approvals: []
    },
    digest
  );
  assert.equal(hostileShape?.status, 'NO_GO');
  assert.ok(hostileShape?.failureReasons.includes('EVIDENCE_INVALID'));

  const malformedApproval = structuredClone(bundle.approvals.slice(0, 1));
  malformedApproval[0].payloadDigest = digest('wrong-plan');
  const incompleteMalformedApproval = evaluateSastProductionGoNoGoEvidence(
    { ...bundle.evaluationInput, approvals: malformedApproval },
    digest
  );
  assert.equal(incompleteMalformedApproval?.status, 'NO_GO');
  assert.ok(
    incompleteMalformedApproval?.failureReasons.includes('APPROVALS_INVALID')
  );
});

test('T056 rejects future evidence and future-dated decision authority', () => {
  const futureEvidence = createT056GoNoGoBundle({
    evidenceObservedAtBase: '2026-08-20T20:31:00.000Z',
    decidedAt: '2026-08-20T20:32:00.000Z',
    approvalSignedAt: '2026-08-20T20:32:00.000Z',
    trustedEvaluatedAt: '2026-08-20T20:30:00.000Z'
  });
  const futureEvidenceRecord = evaluateSastProductionGoNoGoEvidence(
    futureEvidence.evaluationInput,
    digest
  );
  assert.equal(futureEvidenceRecord?.status, 'NO_GO');
  assert.ok(futureEvidenceRecord?.failureReasons.includes('EVIDENCE_STALE'));

  const futurePlan = createT056GoNoGoBundle({
    decidedAt: '2026-08-20T20:31:00.000Z',
    approvalSignedAt: '2026-08-20T20:31:00.000Z',
    trustedEvaluatedAt: '2026-08-20T20:30:00.000Z'
  });
  const futurePlanRecord = evaluateSastProductionGoNoGoEvidence(
    futurePlan.evaluationInput,
    digest
  );
  assert.equal(futurePlanRecord?.status, 'NO_GO');
  assert.ok(futurePlanRecord?.failureReasons.includes('APPROVALS_INVALID'));
});

test('T056 returns NO_GO for threshold breach, stale evidence, or v1 N/A substitution', () => {
  const breached = createT056GoNoGoBundle({
    overrides: { CANARY_SAMPLE_SUFFICIENCY: 999 }
  });
  const breachedRecord = evaluateSastProductionGoNoGoEvidence(
    breached.evaluationInput,
    digest
  );
  assert.equal(breachedRecord?.status, 'NO_GO');
  assert.ok(breachedRecord?.failureReasons.includes('GATE_THRESHOLD_BREACH'));

  const stale = createT056GoNoGoBundle({
    staleEvidenceKind: 'CANARY_TELEMETRY_REPLAY'
  });
  const staleRecord = evaluateSastProductionGoNoGoEvidence(stale.evaluationInput, digest);
  assert.equal(staleRecord?.status, 'NO_GO');
  assert.ok(staleRecord?.failureReasons.includes('EVIDENCE_STALE'));

  const notApplicable = createT056GoNoGoBundle({
    notApplicableGateId: 'DEPLOYMENT_OPERATIONS_REFERENCE_ONLY'
  });
  const notApplicableRecord = evaluateSastProductionGoNoGoEvidence(
    notApplicable.evaluationInput,
    digest
  );
  assert.equal(notApplicableRecord?.status, 'NO_GO');
  assert.ok(
    notApplicableRecord?.failureReasons.includes('NOT_APPLICABLE_PROHIBITED')
  );
});

test('T056 rejects a favorable caller aggregate that differs from upstream measurements', () => {
  const bundle = createT056GoNoGoBundle({
    overrides: { MUST_DETECT_RECALL: 9_999 }
  });
  const record = evaluateSastProductionGoNoGoEvidence(bundle.evaluationInput, digest);
  assert.equal(record?.status, 'NO_GO');
  assert.ok(record?.failureReasons.includes('UPSTREAM_MEASUREMENT_MISMATCH'));
});

test('T056 fails closed on signature failure and record mutation', () => {
  const bundle = createT056GoNoGoBundle();
  const rejected = evaluateSastProductionGoNoGoEvidence(
    { ...bundle.evaluationInput, verifySignature: () => false },
    digest
  );
  assert.equal(rejected?.status, 'NO_GO');
  assert.ok(rejected?.failureReasons.includes('UPSTREAM_BINDING_INVALID'));

  const tamperedPlanRecord = evaluateSastProductionGoNoGoEvidence(
    {
      ...bundle.evaluationInput,
      plan: { ...bundle.plan, repositoryCommitSha: 'b'.repeat(40) }
    },
    digest
  );
  assert.equal(tamperedPlanRecord?.status, 'NO_GO');
  assert.ok(tamperedPlanRecord?.failureReasons.includes('PLAN_INVALID'));

  const record = evaluateSastProductionGoNoGoEvidence(bundle.evaluationInput, digest);
  assert.ok(record);
  assert.equal(
    isSastProductionGoNoGoRecordValid(
      { ...record, deploymentOperationsEntryAuthorized: false },
      digest
    ),
    false
  );
});

function rebuildEvidenceAttestation(source, overrides) {
  const input = { ...pickEvidenceInput(source), ...overrides };
  const unsigned = buildSastProductionGoNoGoEvidenceAttestation(input, [], digest);
  assert.ok(unsigned);
  const signed = buildSastProductionGoNoGoEvidenceAttestation(
    input,
    source.signatures.map((item) => ({
      ...item,
      payloadDigest: unsigned.attestationDigest
    })),
    digest
  );
  assert.ok(signed);
  return signed;
}

function pickEvidenceInput(source) {
  return {
    manifestId: source.manifestId,
    manifestDigest: source.manifestDigest,
    entryAttestationId: source.entryAttestationId,
    entryAttestationDigest: source.entryAttestationDigest,
    evidenceKind: source.evidenceKind,
    providerId: source.providerId,
    providerAdapterRef: source.providerAdapterRef,
    repositoryCommitSha: source.repositoryCommitSha,
    candidateScannerSetDigest: source.candidateScannerSetDigest,
    baselineScannerSetDigest: source.baselineScannerSetDigest,
    profileSetDigest: source.profileSetDigest,
    t051SnapshotDigest: source.t051SnapshotDigest,
    t051PriorReleaseManifestDigest: source.t051PriorReleaseManifestDigest,
    t052SnapshotDigest: source.t052SnapshotDigest,
    t054MeasurementsDigest: source.t054MeasurementsDigest,
    t055MeasurementsDigest: source.t055MeasurementsDigest,
    evidenceRef: source.evidenceRef,
    evidenceDigest: source.evidenceDigest,
    observedAt: source.observedAt,
    validUntil: source.validUntil,
    observations: source.observations.map((item) => ({
      gateId: item.gateId,
      disposition: item.disposition,
      observedValue: item.observedValue,
      unit: item.unit,
      evidenceRef: item.evidenceRef,
      evidenceDigest: item.evidenceDigest
    })),
    externalEvidence: source.externalEvidence
  };
}
