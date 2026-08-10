import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  SAST_ACCEPTED_EVIDENCE_POLICY,
  buildSastAcceptedEvidence,
  canonicalizeSastAcceptedEvidencePack,
  canonicalizeSastEvidenceCandidate,
  canonicalizeSastEvidenceBuildDecision,
  isSastAcceptedEvidenceBuildResultShapeValid,
  isSastAcceptedEvidencePackShapeValid,
  isSastEvidenceBuildDecisionShapeValid,
  isSastRedactedEvidenceCandidateShapeValid
} from '../dist/index.js';

test('builds only bounded internal evidence with no dashboard, AI, or publication authority', () => {
  const scope = evidenceScope();
  const candidates = [
    candidate({
      seed: 'primary',
      role: 'PRIMARY',
      normalizedPath: scope.normalizedPath,
      startLine: 9,
      endLine: 13,
      anchorStartLine: 11,
      anchorEndLine: 11,
      sourceFileLineCount: 100
    }),
    candidate({
      seed: 'related',
      role: 'RELATED',
      normalizedPath: 'src/main/java/Helper.java',
      startLine: 20,
      endLine: 22,
      anchorStartLine: 21,
      anchorEndLine: 21,
      sourceFileLineCount: 120
    })
  ];

  const result = buildSastAcceptedEvidence({
    scope,
    candidates,
    decidedAt: '2026-08-10T04:40:00.000Z',
    digestCanonical: digest
  });

  assert.equal(result.decision.outcome, 'ACCEPTED');
  assert.deepEqual(result.decision.reasonCodes, []);
  assert.equal(
    result.decision.authority.evidenceConstructionAuthority,
    true
  );
  assert.equal(result.decision.authority.dashboardAccessAllowed, false);
  assert.equal(result.decision.authority.aiPayloadAllowed, false);
  assert.equal(result.decision.audit.rawSourceStored, false);
  assert.equal(result.decision.audit.secretValuesStored, false);
  assert.ok(result.pack);
  assert.equal(result.pack.fragments.length, 2);
  assert.equal(result.pack.dashboardSafe, false);
  assert.equal(result.pack.aiSafe, false);
  assert.equal(result.pack.classificationDecisionRef, null);
  assert.equal(result.pack.deletionScheduleRef, null);
  assert.equal(
    Date.parse(result.pack.expiresAt) -
      Date.parse(result.pack.createdAt),
    7 * 24 * 60 * 60 * 1000
  );
  assert.equal(
    isSastEvidenceBuildDecisionShapeValid(
      result.decision,
      digest
    ),
    true
  );
  assert.equal(
    isSastAcceptedEvidencePackShapeValid(result.pack, digest),
    true
  );
  assert.equal(
    isSastAcceptedEvidenceBuildResultShapeValid(result, digest),
    true
  );
  assert.equal(
    isSastEvidenceBuildDecisionShapeValid(
      result.decision,
      digest,
      {
        ...SAST_ACCEPTED_EVIDENCE_POLICY,
        maxFragmentCount: 1
      }
    ),
    false
  );
});

test('rejects a non-canonical decision timestamp without throwing', () => {
  const scope = evidenceScope();
  const result = buildSastAcceptedEvidence({
    scope,
    candidates: [
      candidate({
        seed: 'invalid-time-primary',
        role: 'PRIMARY',
        normalizedPath: scope.normalizedPath,
        startLine: 10,
        endLine: 12,
        anchorStartLine: 11,
        anchorEndLine: 11,
        sourceFileLineCount: 100
      })
    ],
    decidedAt: 'not-a-timestamp',
    digestCanonical: digest
  });

  assert.equal(result.pack, null);
  assert.equal(result.decision.outcome, 'REJECTED');
  assert.deepEqual(result.decision.reasonCodes, [
    'EVIDENCE_INPUT_INVALID'
  ]);
  assert.equal(result.decision.decidedAt, '1970-01-01T00:00:00.000Z');
  assert.equal(
    isSastAcceptedEvidenceBuildResultShapeValid(result, digest),
    true
  );
});

test('canonical ordering produces the same pack for an exact reordered replay', () => {
  const scope = evidenceScope();
  const primary = candidate({
    seed: 'primary',
    role: 'PRIMARY',
    normalizedPath: scope.normalizedPath,
    startLine: 10,
    endLine: 12,
    anchorStartLine: 11,
    anchorEndLine: 11,
    sourceFileLineCount: 100
  });
  const related = candidate({
    seed: 'related',
    role: 'RELATED',
    normalizedPath: 'src/main/java/Zed.java',
    startLine: 30,
    endLine: 32,
    anchorStartLine: 31,
    anchorEndLine: 31,
    sourceFileLineCount: 100
  });
  const input = {
    scope,
    decidedAt: '2026-08-10T04:40:00.000Z',
    digestCanonical: digest
  };
  const first = buildSastAcceptedEvidence({
    ...input,
    candidates: [primary, related]
  });
  const replay = buildSastAcceptedEvidence({
    ...input,
    candidates: [related, primary]
  });

  assert.equal(
    replay.decision.decisionDigest,
    first.decision.decisionDigest
  );
  assert.equal(replay.pack?.packDigest, first.pack?.packDigest);
});

test('rejects full-file, overlapping, adjacent, and substantial reconstruction sets', () => {
  const scope = evidenceScope();
  const fullFile = buildSastAcceptedEvidence({
    scope,
    candidates: [
      candidate({
        seed: 'full',
        role: 'PRIMARY',
        normalizedPath: scope.normalizedPath,
        startLine: 1,
        endLine: 20,
        anchorStartLine: 11,
        anchorEndLine: 11,
        sourceFileLineCount: 20
      })
    ],
    decidedAt: '2026-08-10T04:40:00.000Z',
    digestCanonical: digest
  });
  assert.equal(fullFile.pack, null);
  assert.ok(
    fullFile.decision.reasonCodes.includes(
      'EVIDENCE_FULL_FILE_FORBIDDEN'
    )
  );

  const primary = candidate({
    seed: 'primary',
    role: 'PRIMARY',
    normalizedPath: scope.normalizedPath,
    startLine: 10,
    endLine: 12,
    anchorStartLine: 11,
    anchorEndLine: 11,
    sourceFileLineCount: 100
  });
  const overlapping = buildSastAcceptedEvidence({
    scope,
    candidates: [
      primary,
      candidate({
        seed: 'overlap',
        role: 'RELATED',
        normalizedPath: scope.normalizedPath,
        startLine: 12,
        endLine: 14,
        anchorStartLine: 13,
        anchorEndLine: 13,
        sourceFileLineCount: 100
      })
    ],
    decidedAt: '2026-08-10T04:40:00.000Z',
    digestCanonical: digest
  });
  assert.ok(
    overlapping.decision.reasonCodes.includes(
      'EVIDENCE_RECONSTRUCTION_OVERLAP'
    )
  );
  assert.equal(overlapping.pack, null);
  assert.equal(overlapping.decision.reconstruction.status, 'RISK');

  const adjacent = buildSastAcceptedEvidence({
    scope,
    candidates: [
      primary,
      candidate({
        seed: 'adjacent',
        role: 'RELATED',
        normalizedPath: scope.normalizedPath,
        startLine: 13,
        endLine: 15,
        anchorStartLine: 14,
        anchorEndLine: 14,
        sourceFileLineCount: 100
      })
    ],
    decidedAt: '2026-08-10T04:40:00.000Z',
    digestCanonical: digest
  });
  assert.ok(
    adjacent.decision.reasonCodes.includes(
      'EVIDENCE_RECONSTRUCTION_ADJACENT'
    )
  );
  assert.equal(adjacent.pack, null);
  assert.equal(adjacent.decision.reconstruction.status, 'RISK');

  const substantialScope = {
    ...scope,
    findingStartLine: 4,
    findingEndLine: 4
  };
  const substantial = buildSastAcceptedEvidence({
    scope: substantialScope,
    candidates: [
      candidate({
        seed: 'substantial',
        role: 'PRIMARY',
        normalizedPath: scope.normalizedPath,
        startLine: 2,
        endLine: 6,
        anchorStartLine: 4,
        anchorEndLine: 4,
        sourceFileLineCount: 20
      })
    ],
    decidedAt: '2026-08-10T04:40:00.000Z',
    digestCanonical: digest
  });
  assert.ok(
    substantial.decision.reasonCodes.includes(
      'EVIDENCE_RECONSTRUCTION_COVERAGE'
    )
  );
  assert.equal(substantial.pack, null);
  assert.equal(substantial.decision.reconstruction.status, 'RISK');
});

test('rejects more than two fragments per file and an invalid primary fragment', () => {
  const scope = evidenceScope();
  const excessivePerFile = buildSastAcceptedEvidence({
    scope,
    candidates: [
      candidate({
        seed: 'primary-per-file',
        role: 'PRIMARY',
        normalizedPath: scope.normalizedPath,
        startLine: 10,
        endLine: 12,
        anchorStartLine: 11,
        anchorEndLine: 11,
        sourceFileLineCount: 100
      }),
      candidate({
        seed: 'related-per-file-1',
        role: 'RELATED',
        normalizedPath: scope.normalizedPath,
        startLine: 20,
        endLine: 22,
        anchorStartLine: 21,
        anchorEndLine: 21,
        sourceFileLineCount: 100
      }),
      candidate({
        seed: 'related-per-file-2',
        role: 'RELATED',
        normalizedPath: scope.normalizedPath,
        startLine: 30,
        endLine: 32,
        anchorStartLine: 31,
        anchorEndLine: 31,
        sourceFileLineCount: 100
      })
    ],
    decidedAt: '2026-08-10T04:40:00.000Z',
    digestCanonical: digest
  });
  assert.equal(excessivePerFile.pack, null);
  assert.equal(
    excessivePerFile.decision.reconstruction.status,
    'RISK'
  );
  assert.ok(
    excessivePerFile.decision.reasonCodes.includes(
      'EVIDENCE_RECONSTRUCTION_FRAGMENT_COUNT'
    )
  );

  const invalidPrimary = buildSastAcceptedEvidence({
    scope,
    candidates: [
      candidate({
        seed: 'misbound-primary',
        role: 'PRIMARY',
        normalizedPath: 'src/main/java/Other.java',
        startLine: 10,
        endLine: 12,
        anchorStartLine: 11,
        anchorEndLine: 11,
        sourceFileLineCount: 100
      })
    ],
    decidedAt: '2026-08-10T04:40:00.000Z',
    digestCanonical: digest
  });
  assert.equal(invalidPrimary.pack, null);
  assert.equal(
    invalidPrimary.decision.reconstruction.status,
    'NOT_CHECKED'
  );
  assert.ok(
    invalidPrimary.decision.reasonCodes.includes(
      'EVIDENCE_PRIMARY_FRAGMENT_INVALID'
    )
  );
});

test('truncates deterministically at five fragments and rejects content tampering', () => {
  const scope = evidenceScope();
  const candidates = [
    candidate({
      seed: 'primary',
      role: 'PRIMARY',
      normalizedPath: scope.normalizedPath,
      startLine: 10,
      endLine: 12,
      anchorStartLine: 11,
      anchorEndLine: 11,
      sourceFileLineCount: 100
    }),
    ...Array.from({ length: 5 }, (_, index) =>
      candidate({
        seed: 'related-' + index,
        role: 'RELATED',
        normalizedPath:
          'src/main/java/Related' + index + '.java',
        startLine: 20,
        endLine: 22,
        anchorStartLine: 21,
        anchorEndLine: 21,
        sourceFileLineCount: 100
      })
    )
  ];
  const result = buildSastAcceptedEvidence({
    scope,
    candidates,
    decidedAt: '2026-08-10T04:40:00.000Z',
    digestCanonical: digest
  });

  assert.ok(result.pack);
  assert.equal(result.pack.fragments.length, 5);
  assert.equal(result.pack.truncated, true);
  assert.equal(result.pack.suppressedFragmentCount, 1);

  const forged = {
    ...candidates[0],
    redactedContent: 'tampered\nline\nvalue'
  };
  assert.equal(
    isSastRedactedEvidenceCandidateShapeValid(forged, digest),
    false
  );

  const packCore = omit(result.pack, 'packDigest');
  const forgedPackCore = {
    ...packCore,
    reconstructionRiskDecisionRef: id(
      'sast-evidence-reconstruction',
      'forged-reconstruction'
    )
  };
  const forgedPack = {
    ...forgedPackCore,
    packDigest: digest(
      canonicalizeSastAcceptedEvidencePack(forgedPackCore)
    )
  };
  assert.equal(
    isSastAcceptedEvidencePackShapeValid(forgedPack, digest),
    false
  );

  const decisionCore = omit(result.decision, 'decisionDigest');
  const forgedDecisionCore = {
    ...decisionCore,
    evidencePackDigest: digest('different-pack')
  };
  const forgedDecision = {
    ...forgedDecisionCore,
    decisionDigest: digest(
      canonicalizeSastEvidenceBuildDecision(
        forgedDecisionCore
      )
    )
  };
  assert.equal(
    isSastEvidenceBuildDecisionShapeValid(
      forgedDecision,
      digest
    ),
    true
  );
  assert.equal(
    isSastAcceptedEvidenceBuildResultShapeValid(
      { decision: forgedDecision, pack: result.pack },
      digest
    ),
    false
  );
});

function evidenceScope() {
  return {
    tenantId: 'tenant-1',
    repositoryBindingId: 'repository-1',
    scanRequestId: 'scan-1',
    attemptId: 'attempt-1',
    targetRef: 'refs/pull/1/head',
    commitSha: 'a'.repeat(40),
    canonicalScanKey: digest('canonical-scan'),
    planDigest: digest('plan'),
    profileId: 'JAVA_FAST_V1',
    profileDigest: digest('profile'),
    freshnessDecisionId: id('sast-freshness', 'freshness'),
    freshnessDecisionDigest: digest('freshness-decision'),
    coverageDecisionId: id('sast-coverage', 'coverage'),
    coverageDecisionDigest: digest('coverage-decision'),
    occurrenceId: id('finding-occurrence', 'occurrence'),
    observationBatchId: id(
      'finding-observation',
      'observation'
    ),
    normalizedFindingId: 'normalized-finding-1',
    lineageId: id('finding-lineage', 'lineage'),
    findingFingerprint: digest('fingerprint'),
    fingerprintVersion: 'sast-fingerprint-v1',
    capability: 'SAST',
    normalizedPath: 'src/main/java/App.java',
    findingStartLine: 11,
    findingEndLine: 11,
    policyVersion: 'sast-evidence-policy-v1'
  };
}

function candidate(input) {
  const lineCount = input.endLine - input.startLine + 1;
  const redactedContent = Array.from(
    { length: lineCount },
    (_, index) => 'safe-' + input.seed + '-' + index
  ).join('\n');
  const core = {
    candidateId: id(
      'sast-evidence-candidate',
      input.seed
    ),
    role: input.role,
    normalizedPath: input.normalizedPath,
    startLine: input.startLine,
    endLine: input.endLine,
    anchorStartLine: input.anchorStartLine,
    anchorEndLine: input.anchorEndLine,
    sourceFileLineCount: input.sourceFileLineCount,
    redactedContent,
    byteSize: Buffer.byteLength(redactedContent, 'utf8'),
    sourceContentDigest: digest('source-' + input.seed),
    contentDigest: digest(redactedContent),
    sourceAttestationRef: 'source-attestation://' + input.seed,
    scannerRedactionDecisionRef:
      'scanner-redaction://' + input.seed,
    platformRedactionDecisionRef:
      'platform-redaction://' + input.seed,
    secretRedactionApplied: true,
    rawSourceStored: false
  };
  return {
    ...core,
    candidateDigest: digest(
      canonicalizeSastEvidenceCandidate(core)
    )
  };
}

function id(prefix, value) {
  return prefix + '://' + hex(value);
}

function digest(value) {
  return 'sha256:' + hex(value);
}

function hex(value) {
  return createHash('sha256').update(value).digest('hex');
}

function omit(value, key) {
  return Object.fromEntries(
    Object.entries(value).filter(([entryKey]) => entryKey !== key)
  );
}
