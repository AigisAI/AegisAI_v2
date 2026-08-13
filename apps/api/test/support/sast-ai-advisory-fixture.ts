import { createHash } from 'node:crypto';

import {
  buildSastAiAdvisoryHandoff,
  buildSastAiAdvisoryAuthorityProof,
  buildSastAiAdvisoryAuthorityStateSnapshot,
  buildSastAiAdvisoryPolicyReference,
  buildSastEvidenceAccessDecision,
  buildSastEvidenceDeletionSchedule,
  type SastAiAdvisoryHandoff,
  type SastAiAdvisoryAuthorityProof,
  type SastAiAdvisoryIntent,
  type SastAiAdvisoryNormalizedFinding,
  type SastEvidenceAccessDecision,
  type SastReducedEvidenceReference
} from '@aegisai/shared';

export const AI_FIXTURE_DECIDED_AT =
  '2026-08-11T04:00:00.000Z';
export const AI_FIXTURE_PAYLOAD_EXPIRES_AT =
  '2026-08-12T04:00:00.000Z';
export const AI_FIXTURE_EVIDENCE_EXPIRES_AT =
  '2026-08-18T03:40:00.000Z';

export function aiAdvisoryIntent(): SastAiAdvisoryIntent {
  return {
    tenantId: 'tenant-ai',
    repositoryBindingId: 'repository-ai',
    evidencePackId: contractId('sast-evidence-pack', 'pack-ai'),
    modelVersion: 'detector-planner-runtime-v1'
  };
}

export function aiAccessDecision(): SastEvidenceAccessDecision {
  const intent = aiAdvisoryIntent();
  const schedule = buildSastEvidenceDeletionSchedule({
    scope: {
      tenantId: intent.tenantId,
      repositoryBindingId: intent.repositoryBindingId,
      scanRequestId: 'scan-ai',
      attemptId: 'attempt-ai',
      occurrenceId: contractId('finding-occurrence', 'occurrence-ai'),
      buildDecisionId: contractId('sast-evidence-build', 'build-ai'),
      evidencePackId: intent.evidencePackId,
      findingFingerprint: digest('finding-ai'),
      profileId: 'JAVA_FAST_V1',
      profileDigest:
        'sha256:19743211685c76ac7c63cb8c829823c45bf458da3aee5dac4f5eaba2b44bbe74',
      freshnessDecisionId: contractId('sast-freshness', 'fresh-ai'),
      freshnessDecisionDigest: digest('fresh-ai'),
      coverageDecisionId: contractId('sast-coverage', 'coverage-ai'),
      coverageDecisionDigest: digest('coverage-ai'),
      sourcePackDigest: digest('pack-ai')
    },
    scheduledAt: '2026-08-11T03:40:00.000Z',
    deleteAfter: AI_FIXTURE_EVIDENCE_EXPIRES_AT,
    digestCanonical: digest
  });
  return buildSastEvidenceAccessDecision({
    purpose: 'AI_ADVISORY',
    scope: schedule.scope,
    schedule,
    secretRegistryVersion: 'platform-secret-registry-v1',
    outcome: 'ALLOWED',
    reasonCodes: [],
    redactedProjectionDigest: digest('projection-ai'),
    redactedFragmentCount: 1,
    redactedTotalBytes: 32,
    redactionCount: 0,
    evidenceExpiresAt: AI_FIXTURE_EVIDENCE_EXPIRES_AT,
    decidedAt: AI_FIXTURE_DECIDED_AT,
    digestCanonical: digest
  });
}

export function aiReducedReference(
  decision: SastEvidenceAccessDecision = aiAccessDecision()
): SastReducedEvidenceReference {
  if (
    !decision.reducedEvidenceRef ||
    !decision.redactedProjectionDigest ||
    !decision.aiPayloadExpiresAt
  ) {
    throw new Error('AI access decision fixture is incomplete.');
  }
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

export function aiNormalizedFinding(
  decision: SastEvidenceAccessDecision = aiAccessDecision()
): SastAiAdvisoryNormalizedFinding {
  return {
    normalizedFindingId: 'normalized-finding-ai',
    occurrenceId: decision.scope.occurrenceId,
    tenantId: decision.scope.tenantId,
    repositoryBindingId: decision.scope.repositoryBindingId,
    scanRequestId: decision.scope.scanRequestId,
    attemptId: decision.scope.attemptId,
    scannerRunId: 'scanner-run-ai',
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

export function aiHandoff(
  createdAt = '2026-08-11T04:00:01.000Z'
): SastAiAdvisoryHandoff {
  const decision = aiAccessDecision();
  const handoff = buildSastAiAdvisoryHandoff({
    decision,
    reducedEvidenceReference: aiReducedReference(decision),
    normalizedFinding: aiNormalizedFinding(decision),
    modelVersion: aiAdvisoryIntent().modelVersion,
    createdAt,
    digestCanonical: digest
  });
  if (!handoff) throw new Error('AI handoff fixture is invalid.');
  return handoff;
}

export function aiAuthorityProof(): SastAiAdvisoryAuthorityProof {
  const handoff = aiHandoff();
  const snapshot = buildSastAiAdvisoryAuthorityStateSnapshot({
    normalizedFindingDigests: [digest('authority-finding')],
    targetFindingDigest: digest('authority-finding'),
    lifecycleStateDigests: [digest('authority-lifecycle')],
    policyDecisionDigests: [digest('authority-policy')],
    waiverDigests: [],
    suppressionDigests: [],
    digestCanonical: digest
  });
  if (!snapshot) throw new Error('AI authority snapshot fixture is invalid.');
  const proof = buildSastAiAdvisoryAuthorityProof({
    scope: {
      tenantId: handoff.tenantId,
      repositoryBindingId: handoff.repositoryBindingId,
      scanRequestId: handoff.scanRequestId,
      attemptId: handoff.attemptId,
      advisoryId: handoff.advisoryId,
      handoffId: handoff.handoffId,
      requestDigest: handoff.requestDigest,
      handoffDigest: handoff.handoffDigest,
      normalizedFindingId:
        handoff.normalizedFinding.normalizedFindingId,
      occurrenceId: handoff.normalizedFinding.occurrenceId,
      findingFingerprint:
        handoff.normalizedFinding.findingFingerprint
    },
    before: snapshot,
    after: snapshot,
    verifiedAt: '2026-08-11T05:30:00.000Z',
    digestCanonical: digest
  });
  if (!proof) throw new Error('AI authority proof fixture is invalid.');
  return proof;
}

export function aiPolicyReference() {
  const reference = buildSastAiAdvisoryPolicyReference(
    aiAuthorityProof(),
    digest
  );
  if (!reference) throw new Error('AI policy reference fixture is invalid.');
  return reference;
}

export function allowedAiAccess() {
  const decision = aiAccessDecision();
  return {
    outcome: 'ALLOWED' as const,
    decision,
    replayed: false,
    dashboardEvidence: null,
    reducedEvidenceReference: aiReducedReference(decision)
  };
}

export function digest(value: string): `sha256:${string}` {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}

function contractId(prefix: string, seed: string): string {
  return `${prefix}://${createHash('sha256').update(seed, 'utf8').digest('hex')}`;
}
