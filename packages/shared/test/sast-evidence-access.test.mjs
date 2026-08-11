import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  SAST_AI_PAYLOAD_MAX_RETENTION_SECONDS,
  buildSastEvidenceAccessDecision,
  buildSastEvidenceDeletionProof,
  buildSastEvidenceDeletionSchedule,
  isSafeNormalizedPath,
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
