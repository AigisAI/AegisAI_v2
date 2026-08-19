import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  SAST_ISOLATED_QUALIFICATION_ARTIFACT_KINDS,
  SAST_ISOLATED_QUALIFICATION_APPROVAL_ROLES,
  SAST_ISOLATED_QUALIFICATION_CLEANUP_CONTROLS,
  SAST_ISOLATED_QUALIFICATION_LIMITS,
  SAST_ISOLATED_QUALIFICATION_PHASES,
  SAST_ISOLATED_QUALIFICATION_RECEIPT_SIGNATURE_ROLES,
  SAST_ISOLATED_QUALIFICATION_SIGNATURE_VERSION,
  SAST_PROFILE_IDS,
  buildSastIsolatedQualificationDependencySet,
  buildSastIsolatedQualificationExecutionPlan,
  buildSastIsolatedQualificationManifest,
  buildSastIsolatedQualificationReceipt,
  evaluateSastIsolatedQualificationEvidence,
  isSastIsolatedQualificationDependencySetValid,
  isSastIsolatedQualificationExecutionPlanValid,
  isSastIsolatedQualificationManifestValid,
  isSastIsolatedQualificationReceiptValid,
  isSastIsolatedQualificationResultValid
} from '../dist/index.js';

const corpusRoot = new URL(
  '../../../qualification/corpora/t052-v1/',
  import.meta.url
);
const sourceSnapshot = JSON.parse(
  readFileSync(new URL('multi-class-corpus.snapshot.json', corpusRoot), 'utf8')
);
const sourceFixtures = sourceSnapshot.cases.map((item) =>
  JSON.parse(readFileSync(new URL(item.fixturePath, corpusRoot), 'utf8'))
);
const provisioningContract = readFileSync(
  new URL('../../../deploy/scanner-sandbox/provisioning-contract.json', import.meta.url),
  'utf8'
);
const provisioningContractDigest = digest(provisioningContract);
const materializationPolicyDigest = digest('t053-materialization-policy-v1');

const manifest = buildSastIsolatedQualificationManifest(
  {
    revision: '1.0.0',
    publishedAt: '2026-08-20T00:00:00.000Z',
    ownerRef: 'team://security-engineering/sast-qualification',
    sourceSnapshot,
    sourceFixtures,
    provisioningContractRef:
      `repository-file://deploy/scanner-sandbox/provisioning-contract.json/${provisioningContractDigest}`,
    provisioningContractDigest,
    materializationPolicyRef:
      `repository-file://qualification/t053-v1/materialization-policy.json/${materializationPolicyDigest}`,
    materializationPolicyDigest
  },
  digest
);

test('T053 manifest expands the exact 41-case by three-profile matrix', () => {
  assert.ok(manifest);
  assert.equal(isSastIsolatedQualificationManifestValid(manifest, digest), true);
  assert.equal(manifest.sourceCorpusRevision, '1.0.2');
  assert.equal(
    manifest.caseCount,
    SAST_ISOLATED_QUALIFICATION_LIMITS.expectedCaseCount
  );
  assert.equal(
    manifest.executionCellCount,
    SAST_ISOLATED_QUALIFICATION_LIMITS.expectedCellCount
  );
  assert.equal(manifest.cells.length, 123);
  assert.deepEqual(manifest.profiles.map((item) => item.profileId), [
    ...SAST_PROFILE_IDS
  ]);
  assert.equal(new Set(manifest.cells.map((item) => item.cellId)).size, 123);
  assert.equal(new Set(manifest.cells.map((item) => item.cellKey)).size, 123);
  assert.ok(manifest.cells.every((item) => item.freshMicroVmRequired === true));
  assert.ok(manifest.cells.every((item) => item.sandboxReuseAllowed === false));
  assert.equal(manifest.providerExecutionStatus, 'PENDING_PROVIDER_EXECUTION');
  assert.equal(manifest.productionReadinessAuthority, false);
});

test('T053 cells consume exact selected-profile and shared-parser boundaries', () => {
  const artifactFast = cell('ARTIFACT_BYTES_LIMIT_PLUS_ONE', 'JAVA_FAST_V1');
  const recordFast = cell('RECORD_COUNT_LIMIT_PLUS_ONE', 'JAVA_FAST_V1');
  const nesting = cell('NESTING_DEPTH_LIMIT_PLUS_ONE', 'JAVA_FAST_V1');
  const string = cell('STRING_BYTES_LIMIT_PLUS_ONE', 'JAVA_FAST_V1');

  assert.equal(artifactFast.expectedMaterialization.bytes, 67_108_865);
  assert.equal(recordFast.expectedMaterialization.entries, 25_001);
  assert.equal(nesting.expectedMaterialization.jsonDepth, 65);
  assert.equal(string.expectedMaterialization.maximumStringBytes, 4_097);
  assert.equal(
    artifactFast.materializationSelectionSource,
    'CASE_PROFILE_DECLARATION'
  );
  assert.equal(recordFast.scenarioNameBranchingAllowed, false);
});

test('T053 manifest identity is stable when fixture inputs are reordered', () => {
  const rebuilt = buildSastIsolatedQualificationManifest(
    {
      revision: manifest.revision,
      publishedAt: manifest.publishedAt,
      ownerRef: manifest.ownerRef,
      sourceSnapshot,
      sourceFixtures: [...sourceFixtures].reverse(),
      provisioningContractRef: manifest.provisioningContractRef,
      provisioningContractDigest: manifest.provisioningContractDigest,
      materializationPolicyRef: manifest.materializationPolicyRef,
      materializationPolicyDigest: manifest.materializationPolicyDigest
    },
    digest
  );
  assert.ok(rebuilt);
  assert.equal(rebuilt.manifestDigest, manifest.manifestDigest);
  assert.deepEqual(rebuilt.cells, manifest.cells);
});

test('T053 dependency set and execution plan bind every live provider artifact', () => {
  const dependencySet = dependencySetFixture();
  assert.ok(dependencySet);
  assert.equal(
    isSastIsolatedQualificationDependencySetValid(dependencySet, digest),
    true
  );
  assert.deepEqual(
    dependencySet.artifacts.map((item) => item.kind),
    [...SAST_ISOLATED_QUALIFICATION_ARTIFACT_KINDS]
  );
  const plan = buildSastIsolatedQualificationExecutionPlan(
    { manifest, dependencySet },
    digest
  );
  assert.ok(plan);
  assert.equal(
    isSastIsolatedQualificationExecutionPlanValid(
      plan,
      manifest,
      dependencySet,
      digest
    ),
    true
  );
  assert.equal(plan.executionCellCount, 123);
  assert.equal(plan.cleanupSloSeconds, 60);
  assert.equal(plan.oneFreshMicroVmPerCell, true);
  assert.equal(plan.executionAuthority, 'DETACHED_DUAL_APPROVAL_REQUIRED');
});

test('T053 cannot report a pass before live provider inputs exist', () => {
  const result = evaluateSastIsolatedQualificationEvidence(
    {
      manifest,
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
  assert.equal(result.status, 'PENDING_PROVIDER_EXECUTION');
  assert.equal(result.t053Complete, false);
  assert.equal(result.t054EntryAuthorized, false);
  assert.equal(result.productionReadinessAuthority, false);
  assert.equal(result.missingCellCount, 123);
});

test('T053 rejects dependency omissions and authority widening', () => {
  const dependencySet = dependencySetFixture();
  assert.ok(dependencySet);
  assert.equal(
    buildSastIsolatedQualificationDependencySet(
      {
        ...dependencySetInput(dependencySet),
        artifacts: dependencySet.artifacts.slice(1)
      },
      digest
    ),
    null
  );
  assert.equal(
    isSastIsolatedQualificationManifestValid(
      { ...manifest, productionReadinessAuthority: true },
      digest
    ),
    false
  );
});

test('T053 passes only an exact 123-cell dual-signed provider receipt set', () => {
  const bundle = completeEvidenceBundle();
  const result = evaluateSastIsolatedQualificationEvidence(
    {
      manifest,
      dependencySet: bundle.dependencySet,
      plan: bundle.plan,
      approvals: bundle.approvals,
      signedReceipts: bundle.signedReceipts,
      trustedEvaluatedAt: '2026-08-20T00:10:00.000Z',
      verifySignature: () => true
    },
    digest
  );
  assert.ok(result);
  assert.equal(isSastIsolatedQualificationResultValid(result, digest), true);
  assert.equal(result.status, 'PASSED');
  assert.equal(result.receivedReceiptCount, 123);
  assert.equal(result.validatedReceiptCount, 123);
  assert.equal(result.missingCellCount, 0);
  assert.equal(result.t053Complete, true);
  assert.equal(result.t054EntryAuthorized, true);
  assert.equal(result.productionReadinessAuthority, false);
});

test('T053 keeps a valid partial provider run pending without inventing completion', () => {
  const bundle = completeEvidenceBundle();
  const result = evaluateSastIsolatedQualificationEvidence(
    {
      manifest,
      dependencySet: bundle.dependencySet,
      plan: bundle.plan,
      approvals: bundle.approvals,
      signedReceipts: bundle.signedReceipts.slice(0, 17),
      trustedEvaluatedAt: '2026-08-20T00:10:00.000Z',
      verifySignature: () => true
    },
    digest
  );
  assert.ok(result);
  assert.equal(result.status, 'PENDING_PROVIDER_EXECUTION');
  assert.equal(result.validatedReceiptCount, 17);
  assert.equal(result.missingCellCount, 106);
  assert.equal(result.t054EntryAuthorized, false);
});

test('T053 requires both detached approvals strictly before execution starts', () => {
  const bundle = completeEvidenceBundle();
  const retroactiveApprovals = SAST_ISOLATED_QUALIFICATION_APPROVAL_ROLES.map(
    (role) => signature(role, bundle.plan.planDigest, '2026-08-20T00:01:00.000Z')
  );
  const result = evaluateSastIsolatedQualificationEvidence(
    {
      manifest,
      dependencySet: bundle.dependencySet,
      plan: bundle.plan,
      approvals: retroactiveApprovals,
      signedReceipts: bundle.signedReceipts.slice(0, 1),
      trustedEvaluatedAt: '2026-08-20T00:10:00.000Z',
      verifySignature: () => true
    },
    digest
  );
  assert.ok(result);
  assert.equal(result.status, 'FAILED');
  assert.deepEqual(result.failureReasons, ['APPROVAL_SET_INVALID']);
  assert.equal(result.validatedReceiptCount, 0);
});

test('T053 rejects stale replay against the trusted evaluation instant', () => {
  const bundle = completeEvidenceBundle();
  const result = evaluateSastIsolatedQualificationEvidence(
    {
      manifest,
      dependencySet: bundle.dependencySet,
      plan: bundle.plan,
      approvals: bundle.approvals,
      signedReceipts: bundle.signedReceipts.slice(0, 1),
      trustedEvaluatedAt: '2026-08-22T00:10:00.000Z',
      verifySignature: () => true
    },
    digest
  );
  assert.ok(result);
  assert.equal(result.status, 'FAILED');
  assert.deepEqual(result.failureReasons, ['EVIDENCE_STALE']);
  assert.equal(result.t054EntryAuthorized, false);
});

test('T053 fails closed on duplicate cells and sandbox or attestation reuse', () => {
  const bundle = completeEvidenceBundle();
  const duplicated = evaluateSastIsolatedQualificationEvidence(
    {
      manifest,
      dependencySet: bundle.dependencySet,
      plan: bundle.plan,
      approvals: bundle.approvals,
      signedReceipts: [bundle.signedReceipts[0], bundle.signedReceipts[0]],
      trustedEvaluatedAt: '2026-08-20T00:10:00.000Z',
      verifySignature: () => true
    },
    digest
  );
  assert.ok(duplicated);
  assert.equal(duplicated.status, 'FAILED');
  assert.ok(duplicated.failureReasons.includes('RECEIPT_DUPLICATE'));
  assert.ok(duplicated.failureReasons.includes('ATTEMPT_REUSED'));
  assert.ok(duplicated.failureReasons.includes('SANDBOX_REUSED'));
  assert.ok(duplicated.failureReasons.includes('WORKLOAD_REUSED'));
  assert.ok(duplicated.failureReasons.includes('ATTESTATION_REUSED'));
});

test('T053 reports outcome, egress, cleanup, and signature violations', () => {
  const bundle = completeEvidenceBundle();
  const base = bundle.signedReceipts[0].receipt;
  const violatedReceipt = buildSastIsolatedQualificationReceipt(
    {
      ...receiptInput(base),
      actualOutcome:
        base.expectedOutcome === 'SAFE_SUCCESS' ? 'REJECT' : 'SAFE_SUCCESS',
      phaseEgress: base.phaseEgress.map((item) =>
        item.phase === 'EXECUTION'
          ? {
              ...item,
              publicInternetConnections: 1,
              bytesSent: 64,
              dnsQueries: 1,
              destinations: [
                digestRef('network-destination://blocked/observed', 'blocked-host')
              ]
            }
          : item
      ),
      cleanupEvidence: base.cleanupEvidence.slice(0, -1),
      cleanupCompletedAt: '2026-08-20T00:04:00.000Z',
      cleanupDurationSeconds: 120
    },
    digest
  );
  assert.ok(violatedReceipt);
  const result = evaluateSastIsolatedQualificationEvidence(
    {
      manifest,
      dependencySet: bundle.dependencySet,
      plan: bundle.plan,
      approvals: bundle.approvals,
      signedReceipts: [
        {
          receipt: violatedReceipt,
          signatures: receiptSignatures(violatedReceipt.receiptDigest, '2026-08-20T00:05:00.000Z')
        }
      ],
      trustedEvaluatedAt: '2026-08-20T00:10:00.000Z',
      verifySignature: (signatureValue) =>
        SAST_ISOLATED_QUALIFICATION_APPROVAL_ROLES.includes(signatureValue.role)
    },
    digest
  );
  assert.ok(result);
  assert.equal(result.status, 'FAILED');
  assert.deepEqual(result.failureReasons, [
    'RECEIPT_SIGNATURE_INVALID',
    'OUTCOME_MISMATCH',
    'EGRESS_VIOLATION',
    'CLEANUP_INCOMPLETE',
    'CLEANUP_SLO_EXCEEDED'
  ]);
});

test('T053 rejects provider drift and every prohibited side effect', () => {
  const bundle = completeEvidenceBundle();
  const base = bundle.signedReceipts[0].receipt;
  const violatedReceipt = buildSastIsolatedQualificationReceipt(
    {
      ...receiptInput(base),
      providerId: 'microvm-provider://qualification/unapproved-region',
      prohibitedEffects: {
        ...base.prohibitedEffects,
        customerCodeExecutions: 1
      }
    },
    digest
  );
  assert.ok(violatedReceipt);
  const result = evaluateSastIsolatedQualificationEvidence(
    {
      manifest,
      dependencySet: bundle.dependencySet,
      plan: bundle.plan,
      approvals: bundle.approvals,
      signedReceipts: [
        {
          receipt: violatedReceipt,
          signatures: receiptSignatures(
            violatedReceipt.receiptDigest,
            '2026-08-20T00:03:00.000Z'
          )
        }
      ],
      trustedEvaluatedAt: '2026-08-20T00:10:00.000Z',
      verifySignature: () => true
    },
    digest
  );
  assert.ok(result);
  assert.equal(result.status, 'FAILED');
  assert.deepEqual(result.failureReasons, [
    'PROVIDER_MISMATCH',
    'PROHIBITED_EFFECT'
  ]);
});

test('T053 receipt digest and authority fields reject tampering', () => {
  const bundle = completeEvidenceBundle();
  const receipt = bundle.signedReceipts[0].receipt;
  assert.equal(isSastIsolatedQualificationReceiptValid(receipt, digest), true);
  assert.equal(
    isSastIsolatedQualificationReceiptValid(
      { ...receipt, productionReadinessAuthority: true },
      digest
    ),
    false
  );
  assert.equal(
    isSastIsolatedQualificationReceiptValid(
      { ...receipt, materializationOutputDigest: digest('tampered') },
      digest
    ),
    false
  );
});

function cell(scenario, profileId) {
  const value = manifest?.cells.find(
    (item) => item.scenario === scenario && item.profileId === profileId
  );
  assert.ok(value, `${scenario}:${profileId}`);
  return value;
}

function dependencySetFixture() {
  return buildSastIsolatedQualificationDependencySet(
    {
      revision: '1.0.0',
      providerId: 'microvm-provider://qualification/eu-west-1',
      providerAdapterRef: digestRef(
        'provider-adapter://aegisai/qualification-v1',
        'provider-adapter'
      ),
      validFrom: '2026-08-20T00:00:00.000Z',
      validUntil: '2026-08-21T00:00:00.000Z',
      artifacts: [...SAST_ISOLATED_QUALIFICATION_ARTIFACT_KINDS]
        .reverse()
        .map((kind) => {
          const artifactDigest = digest(`artifact:${kind}`);
          return {
            kind,
            artifactRef: `qualification-artifact://aegisai/${kind.toLowerCase()}/${artifactDigest}`,
            artifactDigest,
            signatureRef: digestRef(
              `signature://aegisai/${kind.toLowerCase()}`,
              `signature:${kind}`
            ),
            provenanceRef: digestRef(
              `provenance://aegisai/${kind.toLowerCase()}`,
              `provenance:${kind}`
            )
          };
        })
    },
    digest
  );
}

function completeEvidenceBundle() {
  const dependencySet = dependencySetFixture();
  assert.ok(dependencySet);
  const plan = buildSastIsolatedQualificationExecutionPlan(
    { manifest, dependencySet },
    digest
  );
  assert.ok(plan);
  const approvals = SAST_ISOLATED_QUALIFICATION_APPROVAL_ROLES.map((role) =>
    signature(role, plan.planDigest, '2026-08-20T00:00:30.000Z')
  );
  const signedReceipts = manifest.cells.map((item) => {
    const receipt = receiptFixture(item, plan, dependencySet);
    return {
      receipt,
      signatures: receiptSignatures(
        receipt.receiptDigest,
        '2026-08-20T00:03:00.000Z'
      )
    };
  });
  return { dependencySet, plan, approvals, signedReceipts };
}

function receiptFixture(item, plan, dependencySet) {
  const providerAttestationDigest = digest(`provider-attestation:${item.cellId}`);
  const runtimeAttestationDigest = digest(`runtime-attestation:${item.cellId}`);
  const receipt = buildSastIsolatedQualificationReceipt(
    {
      planId: plan.planId,
      planDigest: plan.planDigest,
      manifestDigest: manifest.manifestDigest,
      dependencySetDigest: dependencySet.dependencySetDigest,
      providerId: dependencySet.providerId,
      cellId: item.cellId,
      cellDigest: item.cellDigest,
      caseId: item.caseId,
      caseDigest: item.caseDigest,
      fixtureId: item.fixtureId,
      fixtureDigest: item.fixtureDigest,
      profileId: item.profileId,
      profileDigest: item.profileDigest,
      attemptId: digestRef('qualification-attempt://aegisai/t053', item.cellId),
      sandboxId: digestRef('qualification-sandbox://aegisai/t053', item.cellId),
      workloadId: digestRef('qualification-workload://aegisai/t053', item.cellId),
      providerAttestationRef:
        `provider-attestation://aegisai/t053/${providerAttestationDigest}`,
      providerAttestationDigest,
      runtimeAttestationRef:
        `runtime-attestation://aegisai/t053/${runtimeAttestationDigest}`,
      runtimeAttestationDigest,
      materializationInputDigest: item.materializationInputDigest,
      recipeActionDigest: item.recipeActionDigest,
      materializationProjectionDigest:
        item.expectedMaterialization.projectionDigest,
      materializationOutputDigest: digest(`materialization-output:${item.cellId}`),
      materialized: expectedMaterializationCore(item.expectedMaterialization),
      executionTarget: item.executionTarget,
      isolationClass: item.isolationClass,
      expectedOutcome: item.expectedOutcome,
      actualOutcome: item.expectedOutcome,
      startedAt: '2026-08-20T00:01:00.000Z',
      executionCompletedAt: '2026-08-20T00:02:00.000Z',
      cleanupStartedAt: '2026-08-20T00:02:00.000Z',
      cleanupCompletedAt: '2026-08-20T00:02:30.000Z',
      cleanupDurationSeconds: 30,
      phaseEgress: SAST_ISOLATED_QUALIFICATION_PHASES.map((phase) => ({
        phase,
        publicInternetConnections: 0,
        bytesSent: 0,
        dnsQueries: 0,
        destinations: []
      })),
      prohibitedEffects: {
        customerCodeExecutions: 0,
        packageInstalls: 0,
        repositoryBuilds: 0,
        dynamicTests: 0,
        publicInternetConnections: 0,
        scmCredentialPersistences: 0,
        hostMutations: 0,
        unauthorizedResultWrites: 0
      },
      cleanupEvidence: SAST_ISOLATED_QUALIFICATION_CLEANUP_CONTROLS.map(
        (control) => {
          const evidenceDigest = digest(`cleanup:${control}:${item.cellId}`);
          return {
            control,
            status: 'VERIFIED',
            observedAt: '2026-08-20T00:02:30.000Z',
            evidenceRef:
              `cleanup-evidence://aegisai/t053/${control.toLowerCase()}/${evidenceDigest}`,
            evidenceDigest
          };
        }
      ),
      freshMicroVmObserved: true,
      sandboxReuseObserved: false,
      platformOwnedFixtureObserved: true,
      repositoryCredentialIssued: false,
      customerContentObserved: false,
      findingAuthority: false,
      policyAuthority: false,
      publicationAuthority: false,
      productionReadinessAuthority: false,
      immutable: true
    },
    digest
  );
  assert.ok(receipt);
  return receipt;
}

function receiptSignatures(payloadDigest, signedAt) {
  return SAST_ISOLATED_QUALIFICATION_RECEIPT_SIGNATURE_ROLES.map((role) =>
    signature(role, payloadDigest, signedAt)
  );
}

function signature(role, payloadDigest, signedAt) {
  return {
    version: SAST_ISOLATED_QUALIFICATION_SIGNATURE_VERSION,
    role,
    keyId: digestRef(
      `qualification-key://aegisai/${role.toLowerCase().replaceAll('_', '-')}`,
      `key:${role}`
    ),
    payloadDigest,
    signedAt,
    algorithm: 'ED25519',
    valueBase64: Buffer.alloc(64).toString('base64')
  };
}

function receiptInput(value) {
  const { receiptId: _receiptId, receiptDigest: _receiptDigest, version: _version, ...input } = value;
  return input;
}

function expectedMaterializationCore(value) {
  return {
    bytes: value.bytes,
    entries: value.entries,
    pathDepth: value.pathDepth,
    simulatedDurationSeconds: value.simulatedDurationSeconds,
    jsonDepth: value.jsonDepth,
    maximumStringBytes: value.maximumStringBytes
  };
}

function dependencySetInput(value) {
  return {
    revision: value.revision,
    providerId: value.providerId,
    providerAdapterRef: value.providerAdapterRef,
    validFrom: value.validFrom,
    validUntil: value.validUntil,
    artifacts: value.artifacts
  };
}

function digestRef(prefix, value) {
  return `${prefix}/${digest(value)}`;
}

function digest(value) {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}
