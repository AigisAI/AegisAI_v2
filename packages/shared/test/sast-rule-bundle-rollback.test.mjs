import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  SAST_RULE_BUNDLE_ROLLBACK_REQUEST_VERSION,
  buildSastRuleBundleRollbackApproval,
  buildSastRuleBundleRollbackCommand,
  buildSastRuleBundleRollbackReceipt,
  buildSastRuleBundleRollbackVerification,
  isSastRuleBundleRollbackApprovalValid,
  isSastRuleBundleRollbackCommandValid,
  isSastRuleBundleRollbackReceiptValid,
  isSastRuleBundleRollbackRequestValid,
  isSastRuleBundleRollbackVerificationValid
} from '../dist/index.js';

test('T050 accepts only a candidate suspension request and never a caller-selected target', () => {
  const value = request();

  assert.equal(isSastRuleBundleRollbackRequestValid(value), true);
  assert.equal('baselineManifestId' in value, false);
  assert.equal(
    isSastRuleBundleRollbackRequestValid({
      ...value,
      baselineManifestId: manifestId('attacker-target')
    }),
    false
  );
  assert.equal(
    isSastRuleBundleRollbackRequestValid({
      ...value,
      incidentRef: 'https://customer.example/incident'
    }),
    false
  );
});

test('T050 binds an immutable command to the evidence-derived active baseline', () => {
  const value = command();

  assert.ok(value);
  assert.equal(isSastRuleBundleRollbackCommandValid(value, digest), true);
  assert.equal(value.rollbackTargetDerived, true);
  assert.equal(value.customerTargetAccepted, false);
  assert.equal(value.baselineState, 'ACTIVE');
  assert.equal(value.baselineManifestId, manifestId('baseline'));

  const tampered = { ...value, baselineManifestId: manifestId('other') };
  assert.equal(isSastRuleBundleRollbackCommandValid(tampered, digest), false);
});

test('T050 validates content-free command signature facts', () => {
  const currentCommand = command();
  const value = verification(currentCommand);

  assert.ok(value);
  assert.equal(isSastRuleBundleRollbackVerificationValid(value, digest), true);
  assert.equal(value.signatureBytesStored, false);
  assert.equal(value.provenancePayloadStored, false);

  const hostile = { ...value, signatureBytes: 'forbidden' };
  assert.equal(
    isSastRuleBundleRollbackVerificationValid(hostile, digest),
    false
  );
});

test('T050 requires fresh independent Security Engineering and platform-side approvals', () => {
  const currentCommand = command();
  const currentVerification = verification(currentCommand);
  const security = approval(currentCommand, {
    role: 'SECURITY_ENGINEERING',
    approverRef: 'staff://security/alice'
  });
  const platform = approval(currentCommand, {
    role: 'SCAN_PLATFORM',
    approverRef: 'staff://platform/bob',
    approvalRef: ref('platform-approval'),
    approvedAt: '2026-08-19T02:03:00.000Z'
  });
  const value = receipt(currentCommand, currentVerification, [platform, security]);

  assert.ok(value);
  assert.equal(isSastRuleBundleRollbackReceiptValid(value, digest), true);
  assert.deepEqual(
    value.approvals.map((entry) => entry.role),
    ['SECURITY_ENGINEERING', 'SCAN_PLATFORM']
  );
  assert.equal(value.baselineMutationAuthorized, false);
  assert.equal(value.historicalMutationAuthorized, false);
  assert.equal(value.scannerSetMutationAuthorized, false);
  assert.equal(value.findingAuthority, false);
  assert.equal(value.policyAuthority, false);
  assert.equal(value.publicationAuthority, false);
  assert.equal(value.scmWriteAuthority, false);

  assert.equal(
    receipt(currentCommand, currentVerification, [security]),
    null
  );
  assert.equal(
    receipt(currentCommand, currentVerification, [
      security,
      approval(currentCommand, {
        role: 'SECURITY_OPERATIONS',
        approverRef: 'staff://security/alice',
        approvalRef: ref('duplicate-approver')
      })
    ]),
    null
  );
  assert.equal(
    receipt(currentCommand, currentVerification, [
      security,
      approval(currentCommand, {
        role: 'SCAN_PLATFORM',
        approverRef: currentCommand.actorRef,
        approvalRef: ref('self-approval')
      })
    ]),
    null
  );
  assert.equal(
    receipt(currentCommand, currentVerification, [
      security,
      approval(currentCommand, {
        role: 'SCAN_PLATFORM',
        approverRef: 'staff://platform/bob',
        approvalRef: ref('stale-approval'),
        approvedAt: '2026-08-19T01:59:59.999Z'
      })
    ]),
    null
  );
});

test('T050 validators reject malformed hostile shapes without throwing', () => {
  const currentCommand = command();
  const currentVerification = verification(currentCommand);
  const value = receipt(currentCommand, currentVerification, [
    approval(currentCommand, {
      role: 'SECURITY_ENGINEERING',
      approverRef: 'staff://security/alice'
    }),
    approval(currentCommand, {
      role: 'SECURITY_OPERATIONS',
      approverRef: 'staff://operations/bob',
      approvalRef: ref('operations-approval')
    })
  ]);
  assert.ok(value);

  for (const hostile of [
    null,
    [],
    { ...value, receiptDigest: null },
    { ...value, approvals: null },
    { ...value, approvalCount: 3 },
    { ...value, rawPayload: { source: 'forbidden' } }
  ]) {
    assert.doesNotThrow(() =>
      isSastRuleBundleRollbackReceiptValid(hostile, digest)
    );
    assert.equal(isSastRuleBundleRollbackReceiptValid(hostile, digest), false);
  }

  const mutated = structuredClone(value);
  mutated.approvals[0].approvedAt = '2026-08-19T02:05:00.001Z';
  assert.equal(isSastRuleBundleRollbackReceiptValid(mutated, digest), false);
});

function request(overrides = {}) {
  return {
    version: SAST_RULE_BUNDLE_ROLLBACK_REQUEST_VERSION,
    candidateManifestId: manifestId('candidate'),
    suspendedTransitionId: transitionId('candidate-suspended'),
    suspendedTransitionDigest: sha('candidate-suspended-transition'),
    incidentRef: ref('incident'),
    actorRef: 'staff://security/on-call',
    actorRole: 'SECURITY_ON_CALL',
    reasonRef: ref('reason'),
    auditRef: ref('audit'),
    signatureRef: ref('signature'),
    provenanceRef: ref('provenance'),
    commandedAt: '2026-08-19T02:00:00.000Z',
    ...overrides
  };
}

function command(overrides = {}) {
  const { version: _version, ...currentRequest } = request();
  return buildSastRuleBundleRollbackCommand(
    {
      ...currentRequest,
      candidateManifestDigest: sha('candidate-manifest'),
      candidateVerificationId: verificationId('candidate'),
      candidateVerificationDigest: sha('candidate-verification'),
      candidateBundleId: 'java-default',
      candidateBundleDigest: sha('candidate-bundle'),
      suspendedSequence: 4,
      suspendedTransitionedAt: '2026-08-19T01:30:00.000Z',
      suspensionAuthorityReceiptRef: ref('suspension-receipt'),
      suspensionAuthorityReceiptDigest: sha('suspension-receipt'),
      promotionEvidenceId: evidenceId('promotion'),
      promotionEvidenceDigest: sha('promotion-evidence'),
      profileId: 'JAVA_DEEP_V1',
      baselineManifestId: manifestId('baseline'),
      baselineManifestDigest: sha('baseline-manifest'),
      baselineVerificationId: verificationId('baseline'),
      baselineVerificationDigest: sha('baseline-verification'),
      baselineBundleId: 'java-default',
      baselineBundleDigest: sha('baseline-bundle'),
      baselineTransitionId: transitionId('baseline-active'),
      baselineTransitionDigest: sha('baseline-active-transition'),
      baselineSequence: 2,
      baselineTransitionedAt: '2026-08-18T20:00:00.000Z',
      ...overrides
    },
    digest
  );
}

function verification(currentCommand, overrides = {}) {
  return buildSastRuleBundleRollbackVerification(
    {
      commandId: currentCommand.commandId,
      commandDigest: currentCommand.commandDigest,
      signerIdentity: 'kms://aegis/rollback-signer',
      signatureRef: currentCommand.signatureRef,
      provenanceRef: currentCommand.provenanceRef,
      verifiedAt: '2026-08-19T02:01:00.000Z',
      ...overrides
    },
    digest
  );
}

function approval(currentCommand, overrides = {}) {
  const value = buildSastRuleBundleRollbackApproval(
    {
      commandId: currentCommand.commandId,
      commandDigest: currentCommand.commandDigest,
      role: 'SECURITY_ENGINEERING',
      approverRef: 'staff://security/alice',
      approvalRef: ref('security-approval'),
      approvedAt: '2026-08-19T02:02:00.000Z',
      ...overrides
    },
    digest
  );
  assert.ok(value);
  assert.equal(isSastRuleBundleRollbackApprovalValid(value, digest), true);
  return value;
}

function receipt(currentCommand, currentVerification, approvals) {
  return buildSastRuleBundleRollbackReceipt(
    {
      command: currentCommand,
      verification: currentVerification,
      approvals,
      requestedAt: '2026-08-19T02:05:00.000Z',
      issuedAt: '2026-08-19T02:05:00.000Z'
    },
    digest
  );
}

function digest(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function sha(value) {
  return digest(value);
}

function suffix(value) {
  return createHash('sha256').update(value).digest('hex');
}

function manifestId(value) {
  return `sast-rule-bundle-manifest://${suffix(value)}`;
}

function verificationId(value) {
  return `sast-rule-bundle-verification://${suffix(value)}`;
}

function transitionId(value) {
  return `sast-rule-bundle-lifecycle-transition://${suffix(value)}`;
}

function evidenceId(value) {
  return `sast-rule-bundle-promotion-evidence://${suffix(value)}`;
}

function ref(value) {
  return `aegis-audit://${value}/${sha(value)}`;
}
