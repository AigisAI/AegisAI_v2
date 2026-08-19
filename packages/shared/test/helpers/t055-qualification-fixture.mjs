import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import {
  SAST_END_TO_END_QUALIFICATION_APPROVAL_ROLES,
  SAST_END_TO_END_QUALIFICATION_ARTIFACT_KEYS,
  SAST_END_TO_END_QUALIFICATION_ARTIFACT_PROVENANCE_VERSION,
  SAST_END_TO_END_QUALIFICATION_ARTIFACT_VERIFICATION_SET_VERSION,
  SAST_END_TO_END_QUALIFICATION_ENTRY_ATTESTATION_VERSION,
  SAST_END_TO_END_QUALIFICATION_RESULT_VERSION,
  SAST_END_TO_END_QUALIFICATION_SIGNATURE_VERSION,
  SAST_ISOLATED_QUALIFICATION_ARTIFACT_KINDS,
  SAST_ISOLATED_QUALIFICATION_RESULT_VERSION,
  SAST_PROFILE_IDS,
  SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_ENTRY_ATTESTATION_VERSION,
  SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LEDGER_ENTRY_VERSION,
  SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LEDGER_HEAD_ATTESTATION_VERSION,
  SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LEDGER_HEAD_SIGNATURE_ROLES,
  SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_RECEIPT_SIGNATURE_ROLES,
  buildSastEndToEndQualificationArtifactProvenance,
  buildSastEndToEndQualificationArtifactVerificationSet,
  buildSastEndToEndQualificationDependencySet,
  buildSastEndToEndQualificationEntryAttestation,
  buildSastEndToEndQualificationExecutionPlan,
  buildSastIsolatedQualificationDependencySet,
  buildSastSupplyChainRollbackQualificationEntryAttestation,
  buildSastSupplyChainRollbackQualificationLedgerHeadAttestation,
  buildSastSupplyChainRollbackQualificationManifest,
  buildSastSupplyChainRollbackQualificationPlan,
  buildSastSupplyChainRollbackQualificationReceipt,
  isSastEndToEndQualificationResultValid,
  isSastIsolatedQualificationResultValid
} from '../../dist/index.js';
import { createEndToEndQualificationAssets } from '../../../../tools/sast-qualification/end-to-end-qualification-assets.mjs';

const SIGNATURE_BYTES = Buffer.alloc(64).toString('base64');
const T054_MANIFEST = createEndToEndQualificationAssets().manifest;

export function createT055QualificationBundle(options = {}) {
  const signatureFactory = options.signatureFactory ?? signature;
  const t054 = createT054Prerequisite(
    signatureFactory,
    options.trustPolicyText
  );
  const manifest = options.manifest ?? buildSastSupplyChainRollbackQualificationManifest(
    {
      revision: '1.0.0',
      publishedAt: '2026-08-19T20:00:40.000Z',
      ownerRef: digestRef(
        'qualification-owner://aegisai/t055/supply-chain-platform',
        't055-owner'
      ),
      drillPolicyRef: digestRef(
        'repository-file://qualification/t055-v1/drill-policy.json',
        't055-drill-policy'
      ),
      drillPolicyDigest: digest('t055-drill-policy'),
      t054Manifest: T054_MANIFEST
    },
    digest
  );
  assert.ok(manifest);

  const entryInput = {
    manifestId: manifest.manifestId,
    manifestDigest: manifest.manifestDigest,
    t054ResultId: t054.result.resultId,
    t054ResultDigest: t054.result.resultDigest,
    t054DependencySetId: t054.dependencySet.dependencySetId,
    t054DependencySetDigest: t054.dependencySet.dependencySetDigest,
    t054ArtifactVerificationSetId:
      t054.artifactVerificationSet.verificationSetId,
    t054ArtifactVerificationSetDigest:
      t054.artifactVerificationSet.verificationSetDigest,
    t054PlanId: t054.plan.planId,
    t054PlanDigest: t054.plan.planDigest,
    verifiedAt: '2026-08-19T20:01:00.000Z',
    verifierRef: digestRef(
      'qualification-verifier://aegisai/t055-entry',
      't055-entry-verifier'
    )
  };
  const entryDigest = digest(
    stableJson({
      version:
        SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_ENTRY_ATTESTATION_VERSION,
      ...entryInput,
      t055EntryAuthorized: true,
      findingAuthority: false,
      policyAuthority: false,
      publicationAuthority: false,
      deploymentAuthority: false,
      productionReadinessAuthority: false
    })
  );
  const entryAttestation =
    buildSastSupplyChainRollbackQualificationEntryAttestation(
      entryInput,
      signatureFactory(
        'QUALIFICATION_AUTHORITY',
        entryDigest,
        entryInput.verifiedAt,
        't055'
      ),
      digest
    );
  assert.ok(entryAttestation);

  const rollbackLedgerHeadAttestations = createRollbackLedgerHeadAttestations(
    manifest,
    t054.dependencySet,
    signatureFactory
  );

  const plan = buildSastSupplyChainRollbackQualificationPlan(
    {
      manifest,
      t054Manifest: T054_MANIFEST,
      t054Result: t054.result,
      t054DependencySet: t054.dependencySet,
      t054ArtifactVerificationSet: t054.artifactVerificationSet,
      t054Plan: t054.plan,
      entryAttestation,
      rollbackLedgerHeadAttestations,
      plannedAt: '2026-08-19T20:01:30.000Z',
      verifySignature: () => true
    },
    digest
  );
  assert.ok(plan);

  const approvals = SAST_END_TO_END_QUALIFICATION_APPROVAL_ROLES.map((role) =>
    signatureFactory(role, plan.planDigest, '2026-08-19T20:02:00.000Z', 't055')
  );
  const signedReceipts = manifest.cells.map((cell, index) =>
    signedT055Receipt(
      cell,
      index,
      manifest,
      plan,
      t054.dependencySet,
      t054.artifactVerificationSet,
      signatureFactory
    )
  );
  const evaluationInput = {
    manifest,
    t054Manifest: T054_MANIFEST,
    t054Result: t054.result,
    t054DependencySet: t054.dependencySet,
    t054ArtifactVerificationSet: t054.artifactVerificationSet,
    t054Plan: t054.plan,
    entryAttestation,
    plan,
    approvals,
    signedReceipts,
    trustedEvaluatedAt: '2026-08-19T21:00:00.000Z',
    verifySignature: () => true
  };
  return {
    ...t054,
    t054Plan: t054.plan,
    t054Manifest: T054_MANIFEST,
    manifest,
    entryAttestation,
    rollbackLedgerHeadAttestations,
    plan,
    approvals,
    signedReceipts,
    evaluationInput
  };
}

function createRollbackLedgerHeadAttestations(
  manifest,
  dependencySet,
  signatureFactory
) {
  const candidateReleaseSetDigest = releaseSetDigest(dependencySet, 'CANDIDATE');
  const baselineReleaseSetDigest = releaseSetDigest(dependencySet, 'BASELINE');
  return SAST_PROFILE_IDS.map((profileId, index) => {
    const ledgerHeadDigest = digest(`trusted-rollback-ledger-head:${profileId}`);
    const input = {
      manifestId: manifest.manifestId,
      manifestDigest: manifest.manifestDigest,
      dependencySetId: dependencySet.dependencySetId,
      dependencySetDigest: dependencySet.dependencySetDigest,
      providerId: dependencySet.providerId,
      providerAdapterRef: dependencySet.providerAdapterRef,
      profileId,
      candidateReleaseSetDigest,
      baselineReleaseSetDigest,
      ledgerHeadDigest,
      ledgerHeadSequence: 100 + index,
      ledgerHeadRef:
        `rollback-ledger-head://aegisai/t055/${profileId.toLowerCase()}/${ledgerHeadDigest}`,
      observedAt: '2026-08-19T20:01:10.000Z'
    };
    const attestationDigest = digest(
      stableJson({
        version:
          SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LEDGER_HEAD_ATTESTATION_VERSION,
        ...input,
        appendOnlyLedgerVerified: true,
        productionMutationAuthority: false
      })
    );
    const attestation =
      buildSastSupplyChainRollbackQualificationLedgerHeadAttestation(
        input,
        SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LEDGER_HEAD_SIGNATURE_ROLES.map(
          (role) =>
            signatureFactory(
              role,
              attestationDigest,
              input.observedAt,
              `t055-ledger-head-${profileId}`
            )
        ),
        digest
      );
    assert.ok(attestation);
    return attestation;
  });
}

function createT054Prerequisite(signatureFactory, trustPolicyText) {
  const t053 = createT053Pass();
  const { dependencySet, verifications } = createT054DependencySet(
    t053.dependencySet,
    signatureFactory,
    trustPolicyText
  );
  const t054EntryInput = {
    t053ManifestId: T054_MANIFEST.t053ManifestId,
    t053ManifestDigest: T054_MANIFEST.t053ManifestDigest,
    t053ResultId: t053.result.resultId,
    t053ResultDigest: t053.result.resultDigest,
    t053DependencySetDigest: t053.result.dependencySetDigest,
    verifiedAt: '2026-08-19T20:00:05.000Z',
    verifierRef: digestRef(
      'qualification-verifier://aegisai/t054-entry',
      't054-entry-verifier'
    )
  };
  const t054EntryDigest = digest(
    stableJson({
      version: SAST_END_TO_END_QUALIFICATION_ENTRY_ATTESTATION_VERSION,
      ...t054EntryInput,
      t054EntryAuthorized: true,
      findingAuthority: false,
      policyAuthority: false,
      publicationAuthority: false,
      deploymentAuthority: false,
      productionReadinessAuthority: false
    })
  );
  const entryAttestation = buildSastEndToEndQualificationEntryAttestation(
    t054EntryInput,
    signatureFactory(
      'QUALIFICATION_AUTHORITY',
      t054EntryDigest,
      t054EntryInput.verifiedAt,
      't054'
    ),
    digest
  );
  assert.ok(entryAttestation);

  const verificationInput = {
    dependencySet,
    verifications,
    verifiedAt: '2026-08-19T20:00:10.000Z',
    verifierRef: digestRef(
      'supply-chain-verifier://aegisai/t054',
      't054-artifact-verifier'
    )
  };
  const verificationDigest = digest(
    stableJson({
      version:
        SAST_END_TO_END_QUALIFICATION_ARTIFACT_VERIFICATION_SET_VERSION,
      dependencySetId: dependencySet.dependencySetId,
      dependencySetDigest: dependencySet.dependencySetDigest,
      verifications,
      verifiedAt: verificationInput.verifiedAt,
      verifierRef: verificationInput.verifierRef,
      everyArtifactSignatureVerified: true,
      everyArtifactProvenanceVerified: true,
      immutable: true
    })
  );
  const artifactVerificationSet =
    buildSastEndToEndQualificationArtifactVerificationSet(
      verificationInput,
      signatureFactory(
        'SUPPLY_CHAIN_AUTHORITY',
        verificationDigest,
        verificationInput.verifiedAt,
        't054'
      ),
      digest
    );
  assert.ok(artifactVerificationSet);

  const plan = buildSastEndToEndQualificationExecutionPlan(
    {
      manifest: T054_MANIFEST,
      t053DependencySet: t053.dependencySet,
      dependencySet,
      artifactVerificationSet,
      t053Result: t053.result,
      entryAttestation,
      plannedAt: '2026-08-19T20:00:20.000Z',
      verifySignature: () => true
    },
    digest
  );
  assert.ok(plan);
  const result = createT054PassedResult(t053.result, dependencySet, plan);
  return { dependencySet, artifactVerificationSet, plan, result };
}

function createT053Pass() {
  const providerId = 'microvm-provider://aegisai/production-equivalent/t055';
  const providerAdapterRef = digestRef(
    'provider-adapter://aegisai/t055',
    'provider-adapter'
  );
  const dependencySet = buildSastIsolatedQualificationDependencySet(
    {
      revision: '1.0.0',
      providerId,
      providerAdapterRef,
      validFrom: '2026-08-19T20:00:00.000Z',
      validUntil: '2026-08-20T20:00:00.000Z',
      artifacts: SAST_ISOLATED_QUALIFICATION_ARTIFACT_KINDS.map((kind) => {
        const artifactDigest = digest(`t053-artifact:${kind}`);
        return {
          kind,
          artifactRef:
            `qualification-artifact://aegisai/t053/${kind.toLowerCase()}/${artifactDigest}`,
          artifactDigest,
          signatureRef: digestRef(
            `artifact-signature://aegisai/t053/${kind.toLowerCase()}`,
            `t053-signature:${kind}`
          ),
          provenanceRef: digestRef(
            `artifact-provenance://aegisai/t053/${kind.toLowerCase()}`,
            `t053-provenance:${kind}`
          )
        };
      })
    },
    digest
  );
  assert.ok(dependencySet);
  const planDigest = digest('t053-live-plan');
  const core = {
    version: SAST_ISOLATED_QUALIFICATION_RESULT_VERSION,
    manifestId: T054_MANIFEST.t053ManifestId,
    manifestDigest: T054_MANIFEST.t053ManifestDigest,
    dependencySetDigest: dependencySet.dependencySetDigest,
    planDigest,
    status: 'PASSED',
    expectedCellCount: 123,
    receivedReceiptCount: 123,
    validatedReceiptCount: 123,
    missingCellCount: 0,
    missingCellSetDigest: digest('[]'),
    failureReasons: [],
    evaluatedAt: '2026-08-19T20:00:00.000Z',
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
  return { dependencySet, result };
}

function createT054DependencySet(
  t053DependencySet,
  signatureFactory,
  trustPolicyText
) {
  const candidateScannerSetDigest = digest('candidate-scanner-set');
  const baselineScannerSetDigest = digest('baseline-scanner-set');
  const performanceCell = T054_MANIFEST.cells.find((cell) =>
    cell.cellKind.startsWith('PERFORMANCE_')
  );
  assert.ok(performanceCell?.hardwareClassRef);
  assert.ok(performanceCell.hardwareClassDigest);
  const verifications = [];
  const artifacts = SAST_END_TO_END_QUALIFICATION_ARTIFACT_KEYS.map(
    (artifactKey) => {
      const artifactDigest =
        artifactKey === 'TRUST_POLICY' && typeof trustPolicyText === 'string'
          ? digest(trustPolicyText)
          : artifactKey === 'CANDIDATE_SCANNER_SET'
          ? candidateScannerSetDigest
          : artifactKey === 'BASELINE_SCANNER_SET'
            ? baselineScannerSetDigest
            : digest(`artifact:${artifactKey}`);
      const artifactRef =
        `qualification-artifact://aegisai/t054/${artifactKey.toLowerCase()}/${artifactDigest}`;
      const artifactSignature = signatureFactory(
        'SUPPLY_CHAIN_AUTHORITY',
        artifactDigest,
        '2026-08-19T20:00:01.000Z',
        't054'
      );
      const signatureEnvelopeDigest = digest(stableJson(artifactSignature));
      const sourceDigest = digest(`source:${artifactKey}`);
      const provenanceInput = {
        artifactKey,
        artifactRef,
        artifactDigest,
        builderRef: digestRef(
          'supply-chain-builder://aegisai/t054',
          `builder:${artifactKey}`
        ),
        sourceRef:
          `source-snapshot://aegisai/t054/${artifactKey.toLowerCase()}/${sourceDigest}`,
        sourceDigest,
        materialsDigest: digest(`materials:${artifactKey}`),
        generatedAt: '2026-08-19T20:00:02.000Z'
      };
      const provenanceDigest = digest(
        stableJson({
          version:
            SAST_END_TO_END_QUALIFICATION_ARTIFACT_PROVENANCE_VERSION,
          ...provenanceInput,
          customerContentIncluded: false,
          immutable: true
        })
      );
      const provenance = buildSastEndToEndQualificationArtifactProvenance(
        provenanceInput,
        signatureFactory(
          'SUPPLY_CHAIN_AUTHORITY',
          provenanceDigest,
          provenanceInput.generatedAt,
          't054'
        ),
        digest
      );
      assert.ok(provenance);
      const provenanceEnvelopeDigest = digest(stableJson(provenance));
      const signatureRef =
        `artifact-signature://aegisai/t054/${artifactKey.toLowerCase()}/${signatureEnvelopeDigest}`;
      const provenanceRef =
        `artifact-provenance://aegisai/t054/${artifactKey.toLowerCase()}/${provenanceEnvelopeDigest}`;
      verifications.push({
        artifactKey,
        artifactDigest,
        signatureRef,
        signatureEnvelopeDigest,
        artifactSignature,
        provenanceRef,
        provenanceEnvelopeDigest,
        provenance
      });
      return {
        artifactKey,
        artifactRef,
        artifactDigest,
        signatureRef,
        provenanceRef
      };
    }
  );
  const dependencySet = buildSastEndToEndQualificationDependencySet(
    {
      revision: '1.0.0',
      providerId: t053DependencySet.providerId,
      providerAdapterRef: t053DependencySet.providerAdapterRef,
      validFrom: '2026-08-19T20:00:00.000Z',
      validUntil: '2026-08-20T20:00:00.000Z',
      candidateScannerSetDigest,
      baselineScannerSetDigest,
      performanceHardwareClassRef: performanceCell.hardwareClassRef,
      performanceHardwareClassDigest: performanceCell.hardwareClassDigest,
      artifacts
    },
    digest
  );
  assert.ok(dependencySet);
  return { dependencySet, verifications };
}

function createT054PassedResult(t053Result, dependencySet, plan) {
  const performanceBucketMap = new Map();
  for (const cell of T054_MANIFEST.cells.filter((candidate) =>
    candidate.cellKind.startsWith('PERFORMANCE_')
  )) {
    performanceBucketMap.set(`${cell.profileId}:${cell.scenario}`, {
      profileId: cell.profileId,
      scenario: cell.scenario,
      candidateRunCount: 30,
      baselineRunCount: 30,
      candidateP50Milliseconds: 100,
      candidateP95Milliseconds: 100,
      baselineP50Milliseconds: 100,
      baselineP95Milliseconds: 100,
      p95LatencyIncrease: 0,
      candidateMaximumCpuMilliseconds: 100,
      candidateMaximumMemoryBytes: 1_024,
      candidateMaximumDiskBytes: 1_024
    });
  }
  const measurementCore = {
    eligibleAttemptCount: 3_462,
    completedCellCount: 3_462,
    performanceRunsPerArmProfileSizeBucket: 30,
    goldenCorpusPassRate: 1,
    criticalHighPrecision: 1,
    mustDetectRecall: 1,
    priorMustDetectRegressionRecall: 1,
    candidateFalsePositiveRate: 0,
    baselineFalsePositiveRate: 0,
    falsePositiveIncrease: 0,
    scannerFailureRate: 0,
    fingerprintFixturePassRate: 1,
    evidencePrivacyPassRate: 1,
    capacityPassRate: 1,
    fastLaneP95Milliseconds: 100,
    deepLaneP95Milliseconds: 100,
    zeroToleranceCounts: {
      crossTenantLeakCount: 0,
      secretLeakCount: 0,
      sandboxEscapeCount: 0,
      staleExternalPublicationCount: 0,
      unauthorizedEgressCount: 0,
      missingDestructionEvidenceCount: 0,
      evidencePolicyViolationCount: 0,
      unsignedArtifactExecutionCount: 0
    },
    performanceBuckets: [...performanceBucketMap.values()]
  };
  const measurements = {
    ...measurementCore,
    measurementsDigest: digest(stableJson(measurementCore))
  };
  const core = {
    version: SAST_END_TO_END_QUALIFICATION_RESULT_VERSION,
    status: 'PASSED',
    manifestId: T054_MANIFEST.manifestId,
    manifestDigest: T054_MANIFEST.manifestDigest,
    t053ResultId: t053Result.resultId,
    t053ResultDigest: t053Result.resultDigest,
    dependencySetId: dependencySet.dependencySetId,
    dependencySetDigest: dependencySet.dependencySetDigest,
    planId: plan.planId,
    planDigest: plan.planDigest,
    expectedReceiptCount: 3_462,
    observedReceiptCount: 3_462,
    validReceiptCount: 3_462,
    measurements,
    failureReasons: [],
    evaluatedAt: '2026-08-19T20:00:30.000Z',
    t055EntryAuthorized: true,
    findingAuthority: false,
    policyAuthority: false,
    publicationAuthority: false,
    deploymentAuthority: false,
    productionReadinessAuthority: false
  };
  const resultDigest = digest(stableJson(core));
  const result = {
    ...core,
    resultId:
      `sast-end-to-end-qualification-result://${resultDigest.slice('sha256:'.length)}`,
    resultDigest
  };
  assert.equal(isSastEndToEndQualificationResultValid(result, digest), true);
  return result;
}

function signedT055Receipt(
  cell,
  index,
  manifest,
  plan,
  dependencySet,
  artifactVerificationSet,
  signatureFactory
) {
  const { startedAt, completedAt, cleanupCompletedAt } = receiptTimes(cell);
  const artifact = cell.artifactKey
    ? dependencySet.artifacts.find((item) => item.artifactKey === cell.artifactKey)
    : null;
  const verification = cell.artifactKey
    ? artifactVerificationSet.verifications.find(
        (item) => item.artifactKey === cell.artifactKey
      )
    : null;
  const identitySeed = `${cell.cellId}:${index}`;
  const input = {
    manifestId: manifest.manifestId,
    manifestDigest: manifest.manifestDigest,
    planId: plan.planId,
    planDigest: plan.planDigest,
    dependencySetId: dependencySet.dependencySetId,
    dependencySetDigest: dependencySet.dependencySetDigest,
    cellId: cell.cellId,
    cellDigest: cell.cellDigest,
    drillKind: cell.drillKind,
    artifactKey: cell.artifactKey,
    profileId: cell.profileId,
    providerId: dependencySet.providerId,
    providerAdapterRef: dependencySet.providerAdapterRef,
    attemptId: digestRef('qualification-attempt://aegisai/t055', identitySeed),
    sandboxId: digestRef('qualification-sandbox://aegisai/t055', identitySeed),
    workloadId: digestRef('qualification-workload://aegisai/t055', identitySeed),
    startedAt,
    completedAt,
    cleanupCompletedAt,
    observedDecision: cell.expectedDecision,
    observedArtifactDigest: null,
    mountRehashDigest: null,
    observedSignatureEnvelopeDigest: null,
    observedProvenanceEnvelopeDigest: null,
    artifactMountedReadOnly: null,
    signatureVerified: null,
    provenanceVerified: null,
    allowlisted: null,
    internalMirrorUsed: null,
    databaseFresh: null,
    networkEgressAttempted: false,
    schemaCompatible: null,
    candidateStateBefore: null,
    candidateStateAfter: null,
    baselineStateBefore: null,
    baselineStateAfter: null,
    queueFenceApplied: false,
    rollbackTargetDerived: false,
    baselineReverified: false,
    candidateInvocationsAfterFence: 0,
    candidateReleaseSetDigest: null,
    baselineReleaseSetDigest: null,
    rollbackTargetDigest: null,
    inFlightCandidateWorkloadCountBefore: 0,
    inFlightCandidateWorkloadCountAfter: 0,
    inFlightAbortConfirmed: false,
    rollbackLedgerHeadAttestationId: null,
    rollbackLedgerHeadAttestationDigest: null,
    rollbackLedgerPreviousDigest: null,
    rollbackLedgerEntrySequence: null,
    rollbackLedgerEntryDigest: null,
    rollbackLedgerAppendVerified: false,
    preExecutionRejected: cell.preExecutionRejectionRequired,
    artifactInvocationCount: cell.artifactInvocationAllowed ? 1 : 0,
    networkEgressCount: 0,
    productionMutationCount: 0,
    customerContentObserved: false,
    customerCodeExecuted: false,
    packageInstallObserved: false,
    repositoryBuildObserved: false,
    dynamicTestObserved: false,
    cleanupComplete: true,
    providerAttestationRef: digestRef(
      'provider-attestation://aegisai/t055',
      identitySeed
    ),
    runtimeAttestationRef: digestRef(
      'runtime-attestation://aegisai/t055',
      identitySeed
    ),
    telemetryAttestationRef: digestRef(
      'telemetry-attestation://aegisai/t055',
      identitySeed
    ),
    auditRef: digestRef('qualification-audit://aegisai/t055', identitySeed)
  };
  applyDrillObservation(
    input,
    cell,
    artifact,
    verification,
    dependencySet,
    plan
  );
  const receipt = buildSastSupplyChainRollbackQualificationReceipt(input, digest);
  assert.ok(receipt, `expected receipt for ${cell.drillKind}`);
  return signReceipt(receipt, signatureFactory);
}

function applyDrillObservation(
  input,
  cell,
  artifact,
  verification,
  dependencySet,
  plan
) {
  const canonical = () => {
    assert.ok(artifact);
    assert.ok(verification);
    Object.assign(input, {
      observedArtifactDigest: artifact.artifactDigest,
      mountRehashDigest: artifact.artifactDigest,
      observedSignatureEnvelopeDigest: verification.signatureEnvelopeDigest,
      observedProvenanceEnvelopeDigest: verification.provenanceEnvelopeDigest,
      artifactMountedReadOnly: true
    });
  };
  const substituted = (kind) => {
    const substitutedArtifactDigest = digest(`${kind}:artifact:${cell.cellId}`);
    Object.assign(input, {
      observedArtifactDigest: substitutedArtifactDigest,
      mountRehashDigest: substitutedArtifactDigest,
      observedSignatureEnvelopeDigest: digest(`${kind}:signature:${cell.cellId}`),
      observedProvenanceEnvelopeDigest: digest(`${kind}:provenance:${cell.cellId}`),
      artifactMountedReadOnly: true
    });
  };

  switch (cell.drillKind) {
    case 'ARTIFACT_MOUNT_REHASH_ACCEPT':
      canonical();
      Object.assign(input, {
        signatureVerified: true,
        provenanceVerified: true,
        allowlisted: true
      });
      return;
    case 'ARTIFACT_DIGEST_SUBSTITUTION_REJECT':
      assert.ok(verification);
      substituted('digest-substitution');
      Object.assign(input, {
        observedSignatureEnvelopeDigest: verification.signatureEnvelopeDigest,
        observedProvenanceEnvelopeDigest: verification.provenanceEnvelopeDigest,
        signatureVerified: false,
        provenanceVerified: false,
        allowlisted: false
      });
      return;
    case 'ARTIFACT_SIGNATURE_SUBSTITUTION_REJECT':
      canonical();
      Object.assign(input, {
        observedSignatureEnvelopeDigest: digest(
          `signature-substitution:${cell.cellId}`
        ),
        signatureVerified: false,
        provenanceVerified: true,
        allowlisted: false
      });
      return;
    case 'ARTIFACT_PROVENANCE_SUBSTITUTION_REJECT':
      canonical();
      Object.assign(input, {
        observedProvenanceEnvelopeDigest: digest(
          `provenance-substitution:${cell.cellId}`
        ),
        signatureVerified: true,
        provenanceVerified: false,
        allowlisted: false
      });
      return;
    case 'UNLISTED_COMPONENT_REJECT':
      substituted('unlisted');
      Object.assign(input, {
        signatureVerified: true,
        provenanceVerified: true,
        allowlisted: false
      });
      return;
    case 'DATABASE_INTERNAL_MIRROR_ACCEPT':
      canonical();
      Object.assign(input, {
        signatureVerified: true,
        provenanceVerified: true,
        allowlisted: true,
        internalMirrorUsed: true,
        databaseFresh: true
      });
      return;
    case 'DATABASE_STALE_SNAPSHOT_REJECT':
      substituted('stale-database');
      Object.assign(input, {
        signatureVerified: true,
        provenanceVerified: true,
        allowlisted: false,
        internalMirrorUsed: true,
        databaseFresh: false
      });
      return;
    case 'DATABASE_NETWORK_ENRICHMENT_REJECT':
      canonical();
      Object.assign(input, {
        signatureVerified: true,
        provenanceVerified: true,
        allowlisted: true,
        internalMirrorUsed: true,
        databaseFresh: true,
        networkEgressAttempted: true
      });
      return;
    case 'SCHEMA_CANONICAL_ACCEPT':
      canonical();
      Object.assign(input, {
        signatureVerified: true,
        provenanceVerified: true,
        allowlisted: true,
        schemaCompatible: true
      });
      return;
    case 'SCHEMA_INCOMPATIBLE_VERSION_REJECT':
    case 'SCHEMA_MALFORMED_OR_OVERSIZED_REJECT':
      substituted(cell.drillKind.toLowerCase());
      Object.assign(input, {
        signatureVerified: true,
        provenanceVerified: true,
        allowlisted: false,
        schemaCompatible: false
      });
      return;
    default:
      applyRollbackObservation(input, cell, dependencySet, plan);
  }
}

function applyRollbackObservation(input, cell, dependencySet, plan) {
  const candidateReleaseSetDigest = releaseSetDigest(
    dependencySet,
    'CANDIDATE'
  );
  const baselineReleaseSetDigest = releaseSetDigest(dependencySet, 'BASELINE');
  Object.assign(input, {
    candidateReleaseSetDigest,
    baselineReleaseSetDigest,
    baselineStateBefore: 'STANDBY',
    baselineStateAfter: 'STANDBY'
  });
  switch (cell.drillKind) {
    case 'ROLLBACK_CANDIDATE_SUSPEND':
      Object.assign(input, {
        candidateStateBefore: 'ACTIVE',
        candidateStateAfter: 'SUSPENDED'
      });
      return;
    case 'ROLLBACK_QUEUE_ADMISSION_FENCE':
      Object.assign(input, {
        candidateStateBefore: 'SUSPENDED',
        candidateStateAfter: 'SUSPENDED',
        queueFenceApplied: true
      });
      return;
    case 'ROLLBACK_IN_FLIGHT_ABORT_AND_CLEANUP':
      Object.assign(input, {
        candidateStateBefore: 'SUSPENDED',
        candidateStateAfter: 'SUSPENDED',
        queueFenceApplied: true,
        inFlightCandidateWorkloadCountBefore: 1,
        inFlightCandidateWorkloadCountAfter: 0,
        inFlightAbortConfirmed: true
      });
      return;
    case 'ROLLBACK_DERIVE_AND_REVERIFY_LAST_KNOWN_GOOD':
      Object.assign(input, {
        candidateStateBefore: 'SUSPENDED',
        candidateStateAfter: 'SUSPENDED',
        queueFenceApplied: true,
        rollbackTargetDerived: true,
        baselineReverified: true,
        rollbackTargetDigest: baselineReleaseSetDigest
      });
      return;
    case 'ROLLBACK_ACTIVATE_BASELINE_APPEND_ONLY': {
      const ledgerHeadAttestation = plan.rollbackLedgerHeadAttestations.find(
        (attestation) => attestation.profileId === cell.profileId
      );
      assert.ok(ledgerHeadAttestation);
      const rollbackLedgerEntrySequence =
        ledgerHeadAttestation.ledgerHeadSequence + 1;
      const rollbackLedgerEntryDigest = digest(
        stableJson({
          version:
            SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LEDGER_ENTRY_VERSION,
          headAttestationDigest: ledgerHeadAttestation.attestationDigest,
          previousDigest: ledgerHeadAttestation.ledgerHeadDigest,
          previousSequence: ledgerHeadAttestation.ledgerHeadSequence,
          sequence: rollbackLedgerEntrySequence,
          profileId: cell.profileId,
          candidateReleaseSetDigest,
          baselineReleaseSetDigest,
          rollbackTargetDigest: baselineReleaseSetDigest,
          action: 'ACTIVATE_BASELINE',
          activatedAt: input.completedAt
        })
      );
      Object.assign(input, {
        candidateStateBefore: 'SUSPENDED',
        candidateStateAfter: 'ROLLED_BACK',
        baselineStateAfter: 'ACTIVE',
        queueFenceApplied: true,
        rollbackTargetDerived: true,
        baselineReverified: true,
        rollbackTargetDigest: baselineReleaseSetDigest,
        rollbackLedgerHeadAttestationId: ledgerHeadAttestation.attestationId,
        rollbackLedgerHeadAttestationDigest:
          ledgerHeadAttestation.attestationDigest,
        rollbackLedgerPreviousDigest: ledgerHeadAttestation.ledgerHeadDigest,
        rollbackLedgerEntrySequence,
        rollbackLedgerEntryDigest,
        rollbackLedgerAppendVerified: true,
        auditRef:
          `qualification-audit://aegisai/t055/rollback/${rollbackLedgerEntryDigest}`
      });
      return;
    }
    default:
      throw new Error(`unsupported drill kind: ${cell.drillKind}`);
  }
}

function receiptTimes(cell) {
  if (!cell.drillKind.startsWith('ROLLBACK_')) {
    return {
      startedAt: '2026-08-19T20:03:00.000Z',
      completedAt: '2026-08-19T20:03:01.000Z',
      cleanupCompletedAt: '2026-08-19T20:03:02.000Z'
    };
  }
  const profiles = ['JAVA_FAST_V1', 'JAVA_DEEP_V1', 'COMMON_DEEP_V1'];
  const sequence = [
    'ROLLBACK_CANDIDATE_SUSPEND',
    'ROLLBACK_QUEUE_ADMISSION_FENCE',
    'ROLLBACK_IN_FLIGHT_ABORT_AND_CLEANUP',
    'ROLLBACK_DERIVE_AND_REVERIFY_LAST_KNOWN_GOOD',
    'ROLLBACK_ACTIVATE_BASELINE_APPEND_ONLY'
  ];
  const profileIndex = profiles.indexOf(cell.profileId);
  const phaseIndex = sequence.indexOf(cell.drillKind);
  assert.notEqual(profileIndex, -1);
  assert.notEqual(phaseIndex, -1);
  const startedAtMs = Date.parse('2026-08-19T20:05:00.000Z') +
    profileIndex * 30_000 + phaseIndex * 4_000;
  return {
    startedAt: new Date(startedAtMs).toISOString(),
    completedAt: new Date(startedAtMs + 1_000).toISOString(),
    cleanupCompletedAt: new Date(startedAtMs + 2_000).toISOString()
  };
}

function releaseSetDigest(dependencySet, arm) {
  const excludedPrefix = arm === 'CANDIDATE' ? 'BASELINE_' : 'CANDIDATE_';
  const artifacts = dependencySet.artifacts
    .filter((artifact) => !artifact.artifactKey.startsWith(excludedPrefix))
    .map((artifact) => ({
      artifactKey: artifact.artifactKey,
      artifactDigest: artifact.artifactDigest
    }));
  return digest(stableJson({ arm, artifacts }));
}

export function rebuildT055Receipt(receipt, changes = {}) {
  const { version, receiptId, receiptDigest, ...input } = receipt;
  assert.ok(version);
  assert.ok(receiptId);
  assert.ok(receiptDigest);
  const rebuilt = buildSastSupplyChainRollbackQualificationReceipt(
    { ...input, ...changes },
    digest
  );
  assert.ok(rebuilt);
  return rebuilt;
}

export function signReceipt(receipt, signatureFactory = signature) {
  const signedAt = new Date(
    Date.parse(receipt.cleanupCompletedAt) + 1_000
  ).toISOString();
  return {
    receipt,
    signatures:
      SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_RECEIPT_SIGNATURE_ROLES.map(
        (role) => signatureFactory(role, receipt.receiptDigest, signedAt, 't055')
      )
  };
}

export function signature(role, payloadDigest, signedAt, stage = 't055') {
  return {
    version: SAST_END_TO_END_QUALIFICATION_SIGNATURE_VERSION,
    role,
    keyId: digestRef(
      `qualification-key://aegisai/${stage}/${role.toLowerCase()}`,
      `${stage}:${role}`
    ),
    payloadDigest,
    signedAt,
    algorithm: 'ED25519',
    valueBase64: SIGNATURE_BYTES
  };
}

export function digestRef(prefix, seed) {
  return `${prefix}/${digest(seed)}`;
}

export function digest(value) {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}

export function stableJson(value) {
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
