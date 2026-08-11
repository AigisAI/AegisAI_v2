import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  SAST_AI_PAYLOAD_MAX_RETENTION_SECONDS,
  buildSastAiAdvisoryHandoff,
  buildSastEvidenceAccessDecision,
  buildSastEvidenceDeletionProof,
  buildSastEvidenceDeletionSchedule,
  isSafeNormalizedPath,
  isSastAiAdvisoryHandoffShapeValid,
  isSastAiAdvisoryIntentShapeValid,
  isSastEvidenceAccessDecisionShapeValid,
  isSastEvidenceDeletionProofShapeValid,
  isSastEvidenceDeletionScheduleShapeValid,
  isSastEvidenceSafeFragmentShapeValid
} from '../dist/index.js';

const CREATED_AT = '2026-08-10T04:40:00.000Z';
const DECIDED_AT = '2026-08-10T05:00:00.000Z';
const EXPIRES_AT = '2026-08-17T04:40:00.000Z';

test('dashboard and AI access decisions keep purpose authority independent', () => {
  const schedule = deletionSchedule();
  const dashboard = accessDecision(schedule, 'DASHBOARD');
  const ai = accessDecision(schedule, 'AI_ADVISORY');

  assert.equal(
    isSastEvidenceAccessDecisionShapeValid(dashboard, digest),
    true
  );
  assert.equal(
    dashboard.authority.dashboardReadAllowed,
    true
  );
  assert.equal(
    dashboard.authority.reducedEvidenceReferenceAllowed,
    false
  );
  assert.equal(dashboard.reducedEvidenceRef, null);
  assert.equal(dashboard.aiPayloadExpiresAt, null);

  assert.equal(
    isSastEvidenceAccessDecisionShapeValid(ai, digest),
    true
  );
  assert.equal(ai.authority.dashboardReadAllowed, false);
  assert.equal(
    ai.authority.reducedEvidenceReferenceAllowed,
    true
  );
  assert.equal(ai.authority.aiPayloadAllowed, false);
  assert.equal(ai.authority.aiProviderCallAllowed, false);
  assert.equal(ai.audit.aiPayloadCreated, false);
  assert.ok(
    Date.parse(ai.aiPayloadExpiresAt) - Date.parse(ai.decidedAt) <=
      SAST_AI_PAYLOAD_MAX_RETENTION_SECONDS * 1000
  );
});

test('access validators reject authority widening and retention extension', () => {
  const schedule = deletionSchedule();
  assert.equal(
    isSastEvidenceDeletionScheduleShapeValid(schedule, digest),
    true
  );
  const dashboard = accessDecision(schedule, 'DASHBOARD');
  const widened = {
    ...dashboard,
    authority: {
      ...dashboard.authority,
      reducedEvidenceReferenceAllowed: true
    }
  };
  assert.equal(
    isSastEvidenceAccessDecisionShapeValid(widened, digest),
    false
  );
  assert.equal(
    isSastEvidenceAccessDecisionShapeValid({
      ...dashboard,
      redactedFragmentCount: 6,
      redactedTotalBytes: 32_769,
      redactionCount: 32_769
    }),
    false
  );
  assert.equal(
    isSastEvidenceSafeFragmentShapeValid({
      fragmentId: contractId('sast-evidence-fragment', 'fragment'),
      ordinal: 0,
      role: 'PRIMARY',
      normalizedPath: 'src/Main.java',
      startLine: 1,
      endLine: 1,
      redactedContent: 'a'.repeat(8193),
      byteSize: 8193,
      contentDigest: digest('a'.repeat(8193))
    }),
    false
  );
  const extended = {
    ...schedule,
    deleteAfter: '2026-08-17T04:40:00.001Z'
  };
  assert.equal(
    isSastEvidenceDeletionScheduleShapeValid(extended, digest),
    false
  );
});

test('denied decisions keep AI-only fields null and never parse unused expiry', () => {
  const schedule = deletionSchedule();
  assert.doesNotThrow(() =>
    buildSastEvidenceAccessDecision({
      purpose: 'DASHBOARD',
      scope: schedule.scope,
      schedule,
      secretRegistryVersion: 'not-checked-v1',
      outcome: 'DENIED',
      reasonCodes: ['EVIDENCE_ACCESS_INPUT_INVALID'],
      redactedProjectionDigest: null,
      redactedFragmentCount: 0,
      redactedTotalBytes: 0,
      redactionCount: 0,
      evidenceExpiresAt: 'invalid-expiry',
      decidedAt: 'invalid-decision-time',
      digestCanonical: digest
    })
  );

  const denied = buildSastEvidenceAccessDecision({
    purpose: 'AI_ADVISORY',
    scope: schedule.scope,
    schedule,
    secretRegistryVersion: 'not-checked-v1',
    outcome: 'DENIED',
    reasonCodes: ['EVIDENCE_ACCESS_EXPIRED'],
    redactedProjectionDigest: null,
    redactedFragmentCount: 0,
    redactedTotalBytes: 0,
    redactionCount: 0,
    evidenceExpiresAt: EXPIRES_AT,
    decidedAt: DECIDED_AT,
    digestCanonical: digest
  });
  assert.equal(
    isSastEvidenceAccessDecisionShapeValid(denied, digest),
    true
  );
  assert.equal(
    isSastEvidenceAccessDecisionShapeValid({
      ...denied,
      secondPassRedactionDecisionRef: 'invalid',
      reducedEvidenceRef: 'invalid',
      aiPayloadExpiresAt: 'invalid'
    }),
    false
  );
});

test('deletion proof binds the deterministic operation and bounded provider receipt', () => {
  const schedule = deletionSchedule();
  const proof = buildSastEvidenceDeletionProof({
    schedule,
    receipt: {
      operationId: schedule.operationId,
      providerReceiptRef: contractId(
        'sast-evidence-delete-receipt',
        'receipt'
      ),
      providerReceiptDigest: digest('receipt'),
      completedAt: EXPIRES_AT
    },
    digestCanonical: digest
  });
  assert.equal(
    isSastEvidenceDeletionProofShapeValid(proof, digest),
    true
  );
  assert.equal(proof.contentDeleted, true);
  assert.equal(proof.fragmentsDeleted, true);
  assert.equal(proof.buildDecisionRetained, true);
  assert.equal(proof.accessAuthorityRevoked, true);

  assert.equal(
    isSastEvidenceDeletionProofShapeValid(
      { ...proof, providerReceiptRef: 'unbounded-receipt' },
      digest
    ),
    false
  );
});

test('dashboard path classification rejects traversal and repository metadata', () => {
  assert.equal(isSafeNormalizedPath('src/main/App.java'), true);
  assert.equal(isSafeNormalizedPath('../secret.env'), false);
  assert.equal(isSafeNormalizedPath('.git/config'), false);
  assert.equal(isSafeNormalizedPath('C:\\repo\\secret.env'), false);
});

test('T043 handoff binds normalized findings to an opaque reduced reference', () => {
  const decision = accessDecision(
    deletionSchedule(),
    'AI_ADVISORY'
  );
  const reference = reducedReference(decision);
  const normalizedFinding = advisoryFinding(decision);
  const handoff = buildSastAiAdvisoryHandoff({
    decision,
    reducedEvidenceReference: reference,
    normalizedFinding,
    modelVersion: 'detector-planner-runtime-v1',
    createdAt: '2026-08-10T05:00:01.000Z',
    digestCanonical: digest
  });

  assert.ok(handoff);
  assert.equal(
    isSastAiAdvisoryHandoffShapeValid(handoff, digest),
    true
  );
  assert.equal(handoff.createdAt, decision.decidedAt);
  assert.deepEqual(handoff.authority, {
    normalizedFindingAllowed: true,
    reducedEvidenceReferenceAllowed: true,
    aiPayloadAllowed: true,
    aiProviderCallAllowed: true,
    retrievalAllowed: false,
    toolsAllowed: false,
    policyAuthority: false,
    publicationAuthority: false,
    lifecycleMutationAuthority: false,
    scmWriteAuthority: false,
    advisoryOnly: true
  });
  assert.equal(handoff.audit.requestPayloadStored, false);
  assert.equal(handoff.audit.rawSourceStored, false);
  assert.equal(handoff.audit.evidenceFragmentStored, false);
});

test('T043 retries are deterministic and reject caller fields or authority widening', () => {
  const decision = accessDecision(
    deletionSchedule(),
    'AI_ADVISORY'
  );
  const input = {
    decision,
    reducedEvidenceReference: reducedReference(decision),
    normalizedFinding: advisoryFinding(decision),
    modelVersion: 'detector-planner-runtime-v1',
    digestCanonical: digest
  };
  const first = buildSastAiAdvisoryHandoff({
    ...input,
    createdAt: '2026-08-10T05:00:01.000Z'
  });
  const retry = buildSastAiAdvisoryHandoff({
    ...input,
    createdAt: '2026-08-10T05:00:02.000Z'
  });

  assert.ok(first);
  assert.deepEqual(retry, first);
  assert.equal(
    isSastAiAdvisoryHandoffShapeValid({
      ...first,
      authority: { ...first.authority, toolsAllowed: true }
    }, digest),
    false
  );
  assert.equal(
    isSastAiAdvisoryHandoffShapeValid({
      ...first,
      requestDigest: digest('tampered-request')
    }, digest),
    false
  );
  assert.equal(
    isSastAiAdvisoryHandoffShapeValid({
      ...first,
      handoffDigest: digest('tampered-handoff')
    }, digest),
    false
  );
  assert.equal(buildSastAiAdvisoryHandoff({
    ...input,
    createdAt: decision.aiPayloadExpiresAt
  }), null);
  assert.equal(buildSastAiAdvisoryHandoff({
    ...input,
    normalizedFinding: {
      ...input.normalizedFinding,
      title: 'Unsafe\ndeserialization'
    },
    createdAt: '2026-08-10T05:00:01.000Z'
  }), null);

  const withUndefinedLocation = buildSastAiAdvisoryHandoff({
    ...input,
    normalizedFinding: {
      ...input.normalizedFinding,
      location: {
        ...input.normalizedFinding.location,
        lineEnd: undefined
      }
    },
    createdAt: '2026-08-10T05:00:01.000Z'
  });
  assert.ok(withUndefinedLocation);
  const roundTripped = JSON.parse(JSON.stringify(withUndefinedLocation));
  assert.equal(
    isSastAiAdvisoryHandoffShapeValid(roundTripped, digest),
    true
  );
  assert.equal(roundTripped.requestDigest, withUndefinedLocation.requestDigest);
  assert.equal(roundTripped.handoffDigest, withUndefinedLocation.handoffDigest);
  assert.equal(isSastAiAdvisoryIntentShapeValid({
    tenantId: decision.scope.tenantId,
    repositoryBindingId: decision.scope.repositoryBindingId,
    evidencePackId: decision.scope.evidencePackId,
    modelVersion: 'detector-planner-runtime-v1'
  }), true);
  assert.equal(isSastAiAdvisoryIntentShapeValid({
    tenantId: decision.scope.tenantId,
    repositoryBindingId: decision.scope.repositoryBindingId,
    evidencePackId: decision.scope.evidencePackId,
    modelVersion: 'detector-planner-runtime-v1',
    normalizedFinding: { title: 'caller supplied' }
  }), false);
});

function accessDecision(schedule, purpose) {
  return buildSastEvidenceAccessDecision({
    purpose,
    scope: schedule.scope,
    schedule,
    secretRegistryVersion: 'platform-secret-registry-v1',
    outcome: 'ALLOWED',
    reasonCodes: [],
    redactedProjectionDigest: digest('projection'),
    redactedFragmentCount: 1,
    redactedTotalBytes: 12,
    redactionCount: 1,
    evidenceExpiresAt: EXPIRES_AT,
    decidedAt: DECIDED_AT,
    digestCanonical: digest
  });
}

function reducedReference(decision) {
  return {
    version: 'sast-reduced-evidence-reference-v1',
    reducedEvidenceRef: decision.reducedEvidenceRef,
    accessDecisionId: decision.accessDecisionId,
    accessDecisionDigest: decision.decisionDigest,
    evidencePackId: decision.scope.evidencePackId,
    findingFingerprint: decision.scope.findingFingerprint,
    redactedProjectionDigest: decision.redactedProjectionDigest,
    fragmentCount: decision.redactedFragmentCount,
    payloadExpiresAt: decision.aiPayloadExpiresAt,
    aiPayloadCreated: false,
    aiProviderCalled: false,
    retrievalAllowed: false,
    toolsAllowed: false,
    advisoryOnly: true
  };
}

function advisoryFinding(decision) {
  return {
    normalizedFindingId: 'normalized-finding-1',
    occurrenceId: decision.scope.occurrenceId,
    tenantId: decision.scope.tenantId,
    repositoryBindingId: decision.scope.repositoryBindingId,
    scanRequestId: decision.scope.scanRequestId,
    attemptId: decision.scope.attemptId,
    scannerRunId: 'scanner-run-1',
    findingFingerprint: decision.scope.findingFingerprint,
    capability: 'SAST',
    title: 'Unsafe deserialization',
    severity: 'HIGH',
    confidence: 'HIGH',
    cweIds: ['CWE-502', 'CWE-79'],
    cveIds: ['CVE-2025-0001', 'CVE-2026-0002'],
    location: {
      kind: 'FILE',
      normalizedPath: 'src/App.java',
      lineStart: 42,
      lineEnd: 42
    },
    scanner: 'OPENGREP',
    ruleSemanticId: 'java.unsafe-deserialization',
    ruleRevision: '1.0.0',
    secretRedactionApplied: true
  };
}

function deletionSchedule() {
  return buildSastEvidenceDeletionSchedule({
    scope: {
      tenantId: 'tenant-1',
      repositoryBindingId: 'repository-1',
      scanRequestId: 'scan-1',
      attemptId: 'attempt-1',
      occurrenceId: contractId('finding-occurrence', 'occurrence'),
      buildDecisionId: contractId(
        'sast-evidence-build',
        'build'
      ),
      evidencePackId: contractId('sast-evidence-pack', 'pack'),
      findingFingerprint: digest('finding'),
      profileId: 'JAVA_FAST_V1',
      profileDigest:
        'sha256:19743211685c76ac7c63cb8c829823c45bf458da3aee5dac4f5eaba2b44bbe74',
      freshnessDecisionId: contractId('sast-freshness', 'freshness'),
      freshnessDecisionDigest: digest('freshness-decision'),
      coverageDecisionId: contractId('sast-coverage', 'coverage'),
      coverageDecisionDigest: digest('coverage-decision'),
      sourcePackDigest: digest('pack-digest')
    },
    scheduledAt: CREATED_AT,
    deleteAfter: EXPIRES_AT,
    digestCanonical: digest
  });
}

function contractId(prefix, seed) {
  return `${prefix}://${createHash('sha256').update(seed).digest('hex')}`;
}

function digest(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}
