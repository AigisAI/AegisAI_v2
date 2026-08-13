import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  buildSastAiAdvisoryAuthorityProof,
  buildSastAiAdvisoryAuthorityStateSnapshot,
  buildSastAiAdvisoryPolicyReference,
  isSastAiAdvisoryAuthorityProofIntentShapeValid,
  isSastAiAdvisoryAuthorityProofShapeValid,
  isSastAiAdvisoryPolicyReferenceShapeValid
} from '../dist/index.js';

test('T044 binds identical authoritative state before and after advisory consumption', () => {
  const snapshot = authoritySnapshot();
  const proof = buildSastAiAdvisoryAuthorityProof({
    scope: authorityScope(),
    before: snapshot,
    after: snapshot,
    verifiedAt: '2026-08-11T05:30:00.000Z',
    digestCanonical: digest
  });

  assert.ok(proof);
  assert.equal(
    isSastAiAdvisoryAuthorityProofShapeValid(proof, digest),
    true
  );
  assert.equal(proof.before.stateDigest, proof.after.stateDigest);
  assert.deepEqual(proof.authority, {
    findingCreateAuthority: false,
    findingStatusMutationAuthority: false,
    findingSeverityMutationAuthority: false,
    lifecycleMutationAuthority: false,
    waiverMutationAuthority: false,
    suppressionMutationAuthority: false,
    policyOverrideAuthority: false,
    blockDecisionAuthority: false,
    publicationAuthority: false,
    scmWriteAuthority: false,
    advisoryOnly: true
  });
  assert.equal(proof.audit.proofLedgerWritten, true);
  assert.equal(proof.audit.authoritativeFindingWritten, false);
  assert.equal(proof.audit.policyDecisionWritten, false);
  assert.equal(proof.audit.waiverWritten, false);
  assert.equal(proof.audit.suppressionWritten, false);
});

test('T044 policy references expose only immutable advisory and proof identity', () => {
  const snapshot = authoritySnapshot();
  const proof = buildSastAiAdvisoryAuthorityProof({
    scope: authorityScope(),
    before: snapshot,
    after: snapshot,
    verifiedAt: '2026-08-11T05:30:00.000Z',
    digestCanonical: digest
  });
  assert.ok(proof);
  const reference = buildSastAiAdvisoryPolicyReference(proof, digest);
  assert.ok(reference);
  assert.equal(
    isSastAiAdvisoryPolicyReferenceShapeValid(reference),
    true
  );
  assert.deepEqual(Object.keys(reference).sort(), [
    'advisoryId',
    'advisoryOnly',
    'authorityProofDigest',
    'authorityProofId',
    'version'
  ]);
  assert.equal(
    isSastAiAdvisoryPolicyReferenceShapeValid({
      ...reference,
      suggestedAction: 'BLOCK'
    }),
    false
  );
});

test('T044 rejects state drift, caller authority, and non-exact proof intent', () => {
  const before = authoritySnapshot();
  const after = buildSastAiAdvisoryAuthorityStateSnapshot({
    normalizedFindingDigests: [digest('finding-a')],
    targetFindingDigest: digest('finding-a'),
    lifecycleStateDigests: [digest('lifecycle-fixed')],
    policyDecisionDigests: [],
    waiverDigests: [],
    suppressionDigests: [],
    digestCanonical: digest
  });
  assert.ok(after);
  assert.equal(
    buildSastAiAdvisoryAuthorityProof({
      scope: authorityScope(),
      before,
      after,
      verifiedAt: '2026-08-11T05:30:00.000Z',
      digestCanonical: digest
    }),
    null
  );
  assert.equal(
    isSastAiAdvisoryAuthorityProofIntentShapeValid({
      tenantId: 'tenant-ai',
      advisoryId: authorityScope().advisoryId,
      policyOverride: true
    }),
    false
  );
  const proof = buildSastAiAdvisoryAuthorityProof({
    scope: authorityScope(),
    before,
    after: before,
    verifiedAt: '2026-08-11T05:30:00.000Z',
    digestCanonical: digest
  });
  assert.ok(proof);
  assert.equal(
    isSastAiAdvisoryAuthorityProofShapeValid(
      {
        ...proof,
        authority: {
          ...proof.authority,
          policyOverrideAuthority: true
        }
      },
      digest
    ),
    false
  );
});

test('T044 rejects tampered proof identity, scope, and digest', () => {
  const snapshot = authoritySnapshot();
  const proof = buildSastAiAdvisoryAuthorityProof({
    scope: authorityScope(),
    before: snapshot,
    after: snapshot,
    verifiedAt: '2026-08-11T05:30:00.000Z',
    digestCanonical: digest
  });
  assert.ok(proof);

  for (const tampered of [
    {
      ...proof,
      proofId: `sast-ai-authority-proof://${'0'.repeat(64)}`
    },
    {
      ...proof,
      scope: { ...proof.scope, tenantId: 'foreign-tenant' }
    },
    { ...proof, proofDigest: `sha256:${'0'.repeat(64)}` }
  ]) {
    assert.equal(
      isSastAiAdvisoryAuthorityProofShapeValid(tampered, digest),
      false
    );
  }
});

test('T044 rejects empty, duplicate, unsorted, and target-missing digest sets', () => {
  const findingA = digest('finding-a');
  const findingB = digest('finding-b');
  const sorted = [findingA, findingB].sort();
  const common = {
    targetFindingDigest: sorted[0],
    lifecycleStateDigests: [digest('lifecycle-open')],
    policyDecisionDigests: [],
    waiverDigests: [],
    suppressionDigests: [],
    digestCanonical: digest
  };

  for (const normalizedFindingDigests of [
    [],
    [findingA, findingA],
    [...sorted].reverse()
  ]) {
    assert.equal(
      buildSastAiAdvisoryAuthorityStateSnapshot({
        ...common,
        normalizedFindingDigests
      }),
      null
    );
  }
  assert.equal(
    buildSastAiAdvisoryAuthorityStateSnapshot({
      ...common,
      normalizedFindingDigests: sorted,
      targetFindingDigest: digest('missing-target')
    }),
    null
  );
});

function authoritySnapshot() {
  const snapshot = buildSastAiAdvisoryAuthorityStateSnapshot({
    normalizedFindingDigests: [digest('finding-a')],
    targetFindingDigest: digest('finding-a'),
    lifecycleStateDigests: [digest('lifecycle-open')],
    policyDecisionDigests: [digest('policy-warn')],
    waiverDigests: [],
    suppressionDigests: [],
    digestCanonical: digest
  });
  if (!snapshot) throw new Error('authority snapshot fixture is invalid');
  return snapshot;
}

function authorityScope() {
  return {
    tenantId: 'tenant-ai',
    repositoryBindingId: 'repository-ai',
    scanRequestId: 'scan-ai',
    attemptId: 'attempt-ai',
    advisoryId: contractId('sast-ai-advisory', 'advisory'),
    handoffId: contractId('sast-ai-handoff', 'handoff'),
    requestDigest: digest('request'),
    handoffDigest: digest('handoff'),
    normalizedFindingId: 'normalized-finding-ai',
    occurrenceId: contractId('finding-occurrence', 'occurrence'),
    findingFingerprint: digest('finding-fingerprint')
  };
}

function digest(value) {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}

function contractId(prefix, seed) {
  return `${prefix}://${createHash('sha256').update(seed, 'utf8').digest('hex')}`;
}
