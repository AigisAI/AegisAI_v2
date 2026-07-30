import { createHash } from 'node:crypto';

import {
  OPENGREP_SARIF_NORMALIZER_VERSION,
  SAST_FINDING_FINGERPRINT_VERSION,
  SAST_FINDING_IDENTITY_LIMITS,
  SAST_FINDING_IDENTITY_VERSION,
  SAST_FINDING_UNKNOWN_NORMALIZED_PATH,
  SAST_SECRET_REDACTION_BATCH_INSPECTED_FIELD_COUNT,
  SAST_SECRET_REDACTION_TOKEN,
  SAST_SECRET_REDACTION_VERSION,
  TRIVY_JSON_NORMALIZER_VERSION,
  buildFindingFingerprintPreimage,
  canonicalizeSastFingerprintedFindingBatch,
  canonicalizeSastSecretRedactionBatch,
  canonicalizeSastSecretRedactionDecision,
  compareSastNormalizedFindingCandidates,
  isSastFingerprintedFindingBatchShapeValid,
  toSastFindingFingerprintInput,
  toSastFindingIdentityAuditMetadata,
  type FindingFingerprintInput,
  type SastFindingLocation,
  type SastSecretRedactedFindingCandidate,
  type SastSecretRedactionBatch,
  type SastSecretRedactionBatchCore
} from '@aegisai/shared';

import {
  SastFindingIdentityService
} from '../../src/scan-plane/sast-finding-identity.service';

const CONSTRUCTED_AT = '2026-07-29T00:00:00.000Z';
const RETENTION_EXPIRES_AT = '2026-08-01T00:00:00.000Z';
const DIGEST = digest('fixture');

type OpenGrepRedactedFinding = Extract<
  SastSecretRedactedFindingCandidate,
  { capability: 'SAST' }
>;

type TrivySecretRedactedFinding = Extract<
  SastSecretRedactedFindingCandidate,
  { capability: 'SECRET_DETECTION' }
>;

describe('SastFindingIdentityService', () => {
  const service = new SastFindingIdentityService();

  it('constructs a deterministic durable handoff without mutating the T035 batch', async () => {
    const source = redactedBatch([redactedFinding()]);
    const snapshot = structuredClone(source);

    const first = await service.construct(
      { batch: source },
      fixedClock
    );
    const second = await service.construct(
      { batch: source },
      fixedClock
    );

    expect(first).toEqual(second);
    expect(source).toEqual(snapshot);
    expect(first.outcome).toBe('FINGERPRINTED');
    if (first.outcome !== 'FINGERPRINTED') return;

    expect(
      isSastFingerprintedFindingBatchShapeValid(
        first.batch,
        digest
      )
    ).toBe(true);
    expect(first.batch).toMatchObject({
      version: SAST_FINDING_IDENTITY_VERSION,
      outcome: 'FINGERPRINTED',
      sourceRedactionVersion: SAST_SECRET_REDACTION_VERSION,
      sourceRedactionBatchDigest: source.batchDigest,
      durablePersistenceAllowed: true,
      identity: {
        fingerprintVersion: SAST_FINDING_FINGERPRINT_VERSION
      },
      authority: {
        normalizedFindingPersistenceEligible: true,
        occurrenceAuthority: false,
        lifecycleAuthority: false,
        correlationAuthority: false,
        coverageAuthority: false,
        evidenceAuthority: false,
        policyAuthority: false,
        publicationAuthority: false,
        aiPayloadEligible: false
      }
    });
    expect(first.batch.findings[0]).not.toBe(source.findings[0]);
    expect(first.batch.findings[0]?.location).not.toBe(
      source.findings[0]?.location
    );
    expect(first.batch.findings[0]?.identityMaterial).not.toBe(
      source.findings[0]?.identityMaterial
    );
    expect(first.batch.findings[0]?.redaction).not.toBe(
      source.findings[0]?.redaction
    );
    expect(first.batch.findings[0]?.durablePersistenceAllowed).toBe(
      true
    );

    const { batchDigest, ...batchCore } = first.batch;
    expect(
      digest(canonicalizeSastFingerprintedFindingBatch(batchCore))
    ).toBe(batchDigest);
    expect(
      Object.keys(toSastFindingIdentityAuditMetadata(first, digest))
    ).toEqual([
      'version',
      'outcome',
      'batchDigest',
      'sourceRedactionBatchDigest',
      'artifactDigest',
      'dispositionDecisionDigest',
      'findingCount',
      'distinctFingerprintCount',
      'repeatedOccurrenceCount'
    ]);
  });

  it('excludes unstable observation and display fields from stable identity', async () => {
    const base = redactedFinding();
    const drifted = redactedFinding({
      commitSha: 'b'.repeat(40),
      title: `${SAST_SECRET_REDACTION_TOKEN} exposure moved`,
      description: 'The sanitized display text changed.',
      severity: 'LOW',
      confidence: 'LOW',
      location: {
        kind: 'FILE',
        normalizedPath: 'src/config.ts',
        lineStart: 400,
        lineEnd: 402,
        columnStart: 9,
        columnEnd: 21
      },
      identityMaterial: {
        ...base.identityMaterial,
        scannerMatchBasedId: 'rules.secret:moved-match'
      }
    });

    const originalResult = await service.construct(
      { batch: redactedBatch([base]) },
      fixedClock
    );
    const driftedResult = await service.construct(
      { batch: redactedBatch([drifted]) },
      fixedClock
    );
    expect(originalResult.outcome).toBe('FINGERPRINTED');
    expect(driftedResult.outcome).toBe('FINGERPRINTED');
    if (
      originalResult.outcome !== 'FINGERPRINTED' ||
      driftedResult.outcome !== 'FINGERPRINTED'
    ) {
      return;
    }

    expect(
      driftedResult.batch.findings[0]?.fingerprint.stableFingerprint
    ).toBe(
      originalResult.batch.findings[0]?.fingerprint.stableFingerprint
    );
    expect(
      driftedResult.batch.findings[0]?.fingerprint.decisionDigest
    ).not.toBe(
      originalResult.batch.findings[0]?.fingerprint.decisionDigest
    );
  });

  it('changes the fingerprint when any canonical identity component changes', () => {
    const input = toSastFindingFingerprintInput(redactedFinding());
    const baseline = digest(
      buildFindingFingerprintPreimage(input)
    );
    const mutations: FindingFingerprintInput[] = [
      { ...input, repositoryBindingId: 'repository-2' },
      { ...input, capability: 'SECRET_DETECTION' },
      { ...input, ruleSemanticId: 'javascript.other-rule' },
      { ...input, normalizedPath: 'src/other.ts' },
      { ...input, symbolAnchor: 'configure()' },
      { ...input, sinkKind: 'CONFIG_WRITE' },
      { ...input, structuralHash: digest('other-structure') }
    ];

    for (const mutation of mutations) {
      expect(
        digest(buildFindingFingerprintPreimage(mutation))
      ).not.toBe(baseline);
    }
    expect(
      buildFindingFingerprintPreimage({
        ...input,
        normalizedPath: 'src/Cafe\u0301.ts'
      })
    ).toBe(
      buildFindingFingerprintPreimage({
        ...input,
        normalizedPath: 'src/Café.ts'
      })
    );
  });

  it('retains repeated observations with one stable fingerprint', async () => {
    const first = redactedFinding({
      location: {
        kind: 'FILE',
        normalizedPath: 'src/config.ts',
        lineStart: 4,
        lineEnd: 4
      }
    });
    const second = redactedFinding({
      location: {
        kind: 'FILE',
        normalizedPath: 'src/config.ts',
        lineStart: 40,
        lineEnd: 40
      },
      identityMaterial: {
        ...first.identityMaterial,
        scannerMatchBasedId: 'rules.secret:match-2'
      }
    });

    const result = await service.construct(
      { batch: redactedBatch([second, first]) },
      fixedClock
    );
    expect(result.outcome).toBe('FINGERPRINTED');
    if (result.outcome !== 'FINGERPRINTED') return;
    expect(result.batch.identity).toMatchObject({
      findingCount: 2,
      distinctFingerprintCount: 1,
      repeatedOccurrenceCount: 1
    });
    expect(
      result.batch.findings.map(
        (finding) => finding.fingerprint.stableFingerprint
      )
    ).toEqual([
      result.batch.findings[0]?.fingerprint.stableFingerprint,
      result.batch.findings[0]?.fingerprint.stableFingerprint
    ]);
  });

  it('maps every UNKNOWN location reason to the explicit empty path component', async () => {
    const first = redactedFinding({
      location: {
        kind: 'UNKNOWN',
        reasonCode: 'SCANNER_LOCATION_OMITTED'
      }
    });
    const second = redactedFinding({
      location: {
        kind: 'UNKNOWN',
        reasonCode: 'LOCATION_NOT_MAPPABLE'
      }
    });

    const firstResult = await service.construct(
      { batch: redactedBatch([first]) },
      fixedClock
    );
    const secondResult = await service.construct(
      { batch: redactedBatch([second]) },
      fixedClock
    );
    expect(firstResult.outcome).toBe('FINGERPRINTED');
    expect(secondResult.outcome).toBe('FINGERPRINTED');
    if (
      firstResult.outcome !== 'FINGERPRINTED' ||
      secondResult.outcome !== 'FINGERPRINTED'
    ) {
      return;
    }

    const firstFingerprint =
      firstResult.batch.findings[0]?.fingerprint;
    const secondFingerprint =
      secondResult.batch.findings[0]?.fingerprint;
    expect(firstFingerprint?.normalizedPath).toBe(
      SAST_FINDING_UNKNOWN_NORMALIZED_PATH
    );
    expect(secondFingerprint?.normalizedPath).toBe(
      SAST_FINDING_UNKNOWN_NORMALIZED_PATH
    );
    expect(secondFingerprint?.stableFingerprint).toBe(
      firstFingerprint?.stableFingerprint
    );
  });

  it('preserves Trivy capability and database provenance without granting scanner authority', async () => {
    const source = trivyRedactedBatch();
    const sourceFinding =
      source.findings[0] as TrivySecretRedactedFinding;

    const result = await service.construct(
      { batch: source },
      fixedClock
    );
    expect(result.outcome).toBe('FINGERPRINTED');
    if (result.outcome !== 'FINGERPRINTED') return;
    const finding =
      result.batch.findings[0] as typeof result.batch.findings[0] & {
        capability: 'SECRET_DETECTION';
        scannerDisposition: { platformPolicyAuthority: false };
        trivy: { secretValueStored: false };
      };

    expect(result.batch).toMatchObject({
      scanner: 'TRIVY',
      vulnerabilityDatabaseDigest:
        source.vulnerabilityDatabaseDigest
    });
    expect(finding).toMatchObject({
      capability: 'SECRET_DETECTION',
      scannerDisposition: {
        platformPolicyAuthority: false
      },
      trivy: {
        secretValueStored: false
      },
      fingerprint: {
        capability: 'SECRET_DETECTION'
      }
    });
    expect(finding.scannerDisposition).not.toBe(
      sourceFinding.scannerDisposition
    );
    expect(finding.trivy).not.toBe(sourceFinding.trivy);
    expect(
      isSastFingerprintedFindingBatchShapeValid(
        result.batch,
        digest
      )
    ).toBe(true);
  });

  it('rejects a digest collision across different preimages without leaking either candidate', async () => {
    const collisionService =
      new CollisionSastFindingIdentityService();
    const first = redactedFinding();
    const second = redactedFinding({
      location: {
        kind: 'FILE',
        normalizedPath: 'src/other.ts',
        lineStart: 1,
        lineEnd: 1
      },
      identityMaterial: {
        ...redactedFinding().identityMaterial,
        scannerMatchBasedId: 'rules.secret:match-2'
      }
    });
    const source = redactedBatch([first, second]);

    const result = await collisionService.construct(
      { batch: source },
      fixedClock
    );
    expect(result).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: [
        'FINDING_IDENTITY_FINGERPRINT_COLLISION'
      ],
      sourceBatchDigestStored: false,
      fingerprintPreimageStored: false,
      sourceCandidateStored: false,
      secretValueStored: false
    });
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain(source.batchDigest);
    expect(serialized).not.toContain('src/config.ts');
    expect(serialized).not.toContain('src/other.ts');
  });

  it('rejects forged T035 digests and oversized batches before construction', async () => {
    const source = redactedBatch([redactedFinding()]);
    const forged = {
      ...source,
      batchDigest: digest('forged')
    } as SastSecretRedactionBatch;
    const oversized = {
      ...source,
      findings: Array.from(
        {
          length:
            SAST_FINDING_IDENTITY_LIMITS.maximumFindings + 1
        },
        () => source.findings[0]
      )
    } as SastSecretRedactionBatch;

    await expect(
      service.construct({ batch: forged }, fixedClock)
    ).resolves.toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: ['FINDING_IDENTITY_INPUT_INVALID']
    });
    await expect(
      service.construct({ batch: oversized }, fixedClock)
    ).resolves.toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: ['FINDING_IDENTITY_INPUT_INVALID']
    });
  });

  it.each([
    {
      name: 'invalid clock',
      clock: () => new Date(Number.NaN),
      reasonCode: 'FINDING_IDENTITY_RETENTION_INVALID'
    },
    {
      name: 'already expired',
      clock: () => new Date(RETENTION_EXPIRES_AT),
      reasonCode: 'FINDING_IDENTITY_RETENTION_EXPIRED'
    },
    {
      name: 'clock rollback',
      clock: sequenceClock([
        CONSTRUCTED_AT,
        '2026-07-28T23:59:59.999Z'
      ]),
      reasonCode: 'FINDING_IDENTITY_RETENTION_INVALID'
    },
    {
      name: 'expiry crossed during construction',
      clock: sequenceClock([
        CONSTRUCTED_AT,
        RETENTION_EXPIRES_AT
      ]),
      reasonCode: 'FINDING_IDENTITY_RETENTION_EXPIRED'
    }
  ])('fails closed for $name', async ({ clock, reasonCode }) => {
    const result = await service.construct(
      { batch: redactedBatch([redactedFinding()]) },
      clock
    );
    expect(result).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: [reasonCode]
    });
  });

  it('handles an empty batch deterministically and yields during bounded large batches', async () => {
    const empty = await service.construct(
      { batch: redactedBatch([]) },
      fixedClock
    );
    expect(empty.outcome).toBe('FINGERPRINTED');
    if (empty.outcome !== 'FINGERPRINTED') return;
    expect(empty.batch.identity).toMatchObject({
      findingCount: 0,
      distinctFingerprintCount: 0,
      repeatedOccurrenceCount: 0
    });

    const observingService =
      new YieldObservingSastFindingIdentityService();
    const findingCount =
      SAST_FINDING_IDENTITY_LIMITS.yieldFindingInterval + 1;
    const findings = Array.from(
      { length: findingCount },
      (_, index) =>
        redactedFinding({
          title: `${SAST_SECRET_REDACTION_TOKEN} exposure ${index}`,
          location: {
            kind: 'FILE',
            normalizedPath: `src/file-${index
              .toString()
              .padStart(3, '0')}.ts`,
            lineStart: 1,
            lineEnd: 1
          },
          identityMaterial: {
            ...redactedFinding().identityMaterial,
            scannerMatchBasedId: `rules.secret:match-${index}`
          }
        })
    );
    const result = await observingService.construct(
      { batch: redactedBatch(findings) },
      fixedClock
    );
    expect(result.outcome).toBe('FINGERPRINTED');
    expect(observingService.yieldCount).toBe(
      Math.floor(
        (findings.length - 1) /
          SAST_FINDING_IDENTITY_LIMITS.yieldFindingInterval
      )
    );
  });
});

class CollisionSastFindingIdentityService extends SastFindingIdentityService {
  protected override digestFingerprint(): `sha256:${string}` {
    return digest('forced-collision');
  }
}

class YieldObservingSastFindingIdentityService extends SastFindingIdentityService {
  yieldCount = 0;

  protected override async yieldEventLoop(): Promise<void> {
    this.yieldCount += 1;
  }
}

function redactedFinding(
  overrides: Partial<OpenGrepRedactedFinding> = {}
): OpenGrepRedactedFinding {
  const finding = {
    tenantId: 'tenant-1',
    repositoryBindingId: 'repository-1',
    scanRequestId: 'scan-1',
    attemptId: 'attempt-1',
    scannerRunId: 'scanner-run-1',
    planDigest: DIGEST,
    canonicalScanKey: DIGEST,
    preflightAttestationRef: 'preflight://attempt-1',
    preflightInventoryDigest: DIGEST,
    commitSha: 'a'.repeat(40),
    lane: 'FAST',
    capability: 'SAST',
    title: `${SAST_SECRET_REDACTION_TOKEN} exposure`,
    description: 'A credential-like value was removed.',
    severity: 'HIGH',
    confidence: 'HIGH',
    cweIds: ['CWE-798'],
    cveIds: [],
    location: {
      kind: 'FILE',
      normalizedPath: 'src/config.ts',
      lineStart: 4,
      lineEnd: 4
    } satisfies SastFindingLocation,
    identityMaterial: {
      ruleSemanticId: 'javascript.hardcoded-secret',
      symbolAnchor: '',
      sinkKind: '',
      structuralHash: digest('structure'),
      scannerMatchBasedId: 'rules.secret:match-1'
    },
    provenance: {
      scanner: 'OPENGREP',
      scannerVersion: '1.22.0',
      scannerImageDigest: DIGEST,
      ruleId: 'rules.secret',
      ruleRevision: '2026.07.1',
      ruleBundleDigest: DIGEST,
      artifactDigest: DIGEST
    },
    notes: [],
    redaction: {
      version: SAST_SECRET_REDACTION_VERSION,
      secretRedactionApplied: true,
      replacementToken: SAST_SECRET_REDACTION_TOKEN,
      inspectedFieldCount: 10,
      redactedFields: ['TITLE'],
      replacementCount: 1,
      detectorKinds: ['GITHUB_TOKEN'],
      secretValueStored: false,
      matchedValueDigestStored: false,
      rawCandidateStored: false,
      decisionDigest: DIGEST,
      decisionRef:
        `redaction://${SAST_SECRET_REDACTION_VERSION}/${'a'.repeat(64)}`
    },
    durablePersistenceAllowed: false,
    ...overrides
  } as OpenGrepRedactedFinding;
  const {
    decisionDigest: _decisionDigest,
    decisionRef: _decisionRef,
    ...redactionCore
  } = finding.redaction;
  void _decisionDigest;
  void _decisionRef;
  const decisionDigest = digest(
    canonicalizeSastSecretRedactionDecision({
      ...finding,
      redaction: redactionCore
    })
  );
  finding.redaction.decisionDigest = decisionDigest;
  finding.redaction.decisionRef =
    `redaction://${SAST_SECRET_REDACTION_VERSION}/${decisionDigest.slice(
      'sha256:'.length
    )}`;
  return finding;
}

function redactedBatch(
  sourceFindings: OpenGrepRedactedFinding[]
): SastSecretRedactionBatch {
  const findings = [...sourceFindings].sort((left, right) =>
    compareSastNormalizedFindingCandidates(left, right)
  );
  const first = findings[0];
  const redactedCandidateCount = findings.filter(
    (finding) => finding.redaction.replacementCount > 0
  ).length;
  const redactedFieldCount = findings.reduce(
    (sum, finding) =>
      sum + finding.redaction.redactedFields.length,
    0
  );
  const replacementCount = findings.reduce(
    (sum, finding) => sum + finding.redaction.replacementCount,
    0
  );
  const batchCore: SastSecretRedactionBatchCore = {
    version: SAST_SECRET_REDACTION_VERSION,
    outcome: 'REDACTED',
    sourceAdapterVersion: OPENGREP_SARIF_NORMALIZER_VERSION,
    artifactSchema: 'OPENGREP_SARIF',
    artifactSchemaVersion: '2.1.0',
    ingestionId: 'ingestion-1',
    scope: {
      tenantId: first?.tenantId ?? 'tenant-1',
      repositoryBindingId:
        first?.repositoryBindingId ?? 'repository-1',
      scanRequestId: first?.scanRequestId ?? 'scan-1',
      attemptId: first?.attemptId ?? 'attempt-1',
      scannerRunId: first?.scannerRunId ?? 'scanner-run-1'
    },
    scannerRunId: first?.scannerRunId ?? 'scanner-run-1',
    scanner: 'OPENGREP',
    scannerVersion: first?.provenance.scannerVersion ?? '1.22.0',
    scannerImageDigest:
      first?.provenance.scannerImageDigest ?? DIGEST,
    ruleBundleDigest:
      first?.provenance.ruleBundleDigest ?? DIGEST,
    planDigest: first?.planDigest ?? DIGEST,
    canonicalScanKey: first?.canonicalScanKey ?? DIGEST,
    preflightAttestationRef:
      first?.preflightAttestationRef ?? 'preflight://attempt-1',
    preflightInventoryDigest:
      first?.preflightInventoryDigest ?? DIGEST,
    lane: first?.lane ?? 'FAST',
    commitSha: first?.commitSha ?? 'a'.repeat(40),
    envelopeDigest: digest('envelope'),
    artifactDigest: first?.provenance.artifactDigest ?? DIGEST,
    schemaBundleDigest: digest('schema'),
    normalizerBundleDigest: digest('normalizer'),
    validationResultDigest: digest('validation'),
    dispositionDecisionDigest: digest('disposition'),
    retentionExpiresAt: RETENTION_EXPIRES_AT,
    findings,
    redaction: {
      version: SAST_SECRET_REDACTION_VERSION,
      secretRedactionApplied: true,
      candidateCount: findings.length,
      batchInspectedFieldCount:
        SAST_SECRET_REDACTION_BATCH_INSPECTED_FIELD_COUNT,
      inspectedFieldCount:
        findings.reduce(
          (sum, finding) =>
            sum + finding.redaction.inspectedFieldCount,
          0
        ) + SAST_SECRET_REDACTION_BATCH_INSPECTED_FIELD_COUNT,
      redactedCandidateCount,
      redactedFieldCount,
      replacementCount,
      detectorKinds:
        redactedCandidateCount === 0 ? [] : ['GITHUB_TOKEN'],
      secretValuesStored: false,
      matchedValueDigestsStored: false,
      rawCandidatesStored: false,
      sourceCandidateDigestStored: false
    },
    durablePersistenceAllowed: false
  };
  return {
    ...batchCore,
    batchDigest: digest(
      canonicalizeSastSecretRedactionBatch(batchCore)
    )
  };
}

function trivyRedactedFinding(): TrivySecretRedactedFinding {
  const vulnerabilityDatabaseDigest = digest(
    'vulnerability-database'
  );
  const finding = {
    tenantId: 'tenant-1',
    repositoryBindingId: 'repository-1',
    scanRequestId: 'scan-1',
    attemptId: 'attempt-1',
    scannerRunId: 'scanner-run-1',
    planDigest: DIGEST,
    canonicalScanKey: DIGEST,
    preflightAttestationRef: 'preflight://attempt-1',
    preflightInventoryDigest: DIGEST,
    commitSha: 'a'.repeat(40),
    lane: 'FAST',
    capability: 'SECRET_DETECTION',
    title: `${SAST_SECRET_REDACTION_TOKEN} exposure`,
    description: 'Potential API secret was removed.',
    severity: 'HIGH',
    confidence: 'UNKNOWN',
    cweIds: [],
    cveIds: [],
    location: {
      kind: 'FILE',
      normalizedPath: 'src/config.ts',
      lineStart: 7,
      lineEnd: 7
    },
    identityMaterial: {
      ruleSemanticId: 'secret.generic-api-key',
      symbolAnchor: '',
      sinkKind: 'API',
      structuralHash: digest('trivy-structure'),
      scannerMatchBasedId: digest('trivy-match')
    },
    provenance: {
      scanner: 'TRIVY',
      scannerVersion: '0.66.0',
      scannerImageDigest: digest('trivy-image'),
      ruleId: 'generic-api-key',
      ruleRevision: '2026.07.1',
      ruleBundleDigest: digest('trivy-rules'),
      artifactDigest: DIGEST,
      ruleSource: 'CHECK_BUNDLE',
      vulnerabilityDatabaseDigest
    },
    scannerDisposition: {
      source: 'DIRECT',
      status: 'active',
      platformPolicyAuthority: false
    },
    trivy: {
      kind: 'SECRET_DETECTION',
      category: 'API',
      secretValueStored: false,
      secretPayloadDiscarded: true
    },
    notes: ['UNKNOWN_CONFIDENCE'],
    redaction: {
      version: SAST_SECRET_REDACTION_VERSION,
      secretRedactionApplied: true,
      replacementToken: SAST_SECRET_REDACTION_TOKEN,
      inspectedFieldCount: 19,
      redactedFields: ['TITLE'],
      replacementCount: 1,
      detectorKinds: ['GITHUB_TOKEN'],
      secretValueStored: false,
      matchedValueDigestStored: false,
      rawCandidateStored: false,
      decisionDigest: DIGEST,
      decisionRef:
        `redaction://${SAST_SECRET_REDACTION_VERSION}/${'a'.repeat(64)}`
    },
    durablePersistenceAllowed: false
  } as TrivySecretRedactedFinding;
  const {
    decisionDigest: _decisionDigest,
    decisionRef: _decisionRef,
    ...redactionCore
  } = finding.redaction;
  void _decisionDigest;
  void _decisionRef;
  const decisionDigest = digest(
    canonicalizeSastSecretRedactionDecision({
      ...finding,
      redaction: redactionCore
    })
  );
  finding.redaction.decisionDigest = decisionDigest;
  finding.redaction.decisionRef =
    `redaction://${SAST_SECRET_REDACTION_VERSION}/${decisionDigest.slice(
      'sha256:'.length
    )}`;
  return finding;
}

function trivyRedactedBatch(): SastSecretRedactionBatch {
  const finding = trivyRedactedFinding();
  const batchCore: SastSecretRedactionBatchCore = {
    version: SAST_SECRET_REDACTION_VERSION,
    outcome: 'REDACTED',
    sourceAdapterVersion: TRIVY_JSON_NORMALIZER_VERSION,
    artifactSchema: 'TRIVY_JSON',
    artifactSchemaVersion: '2',
    ingestionId: 'ingestion-1',
    scope: {
      tenantId: finding.tenantId,
      repositoryBindingId: finding.repositoryBindingId,
      scanRequestId: finding.scanRequestId,
      attemptId: finding.attemptId,
      scannerRunId: finding.scannerRunId
    },
    scannerRunId: finding.scannerRunId,
    scanner: 'TRIVY',
    scannerVersion: finding.provenance.scannerVersion,
    scannerImageDigest: finding.provenance.scannerImageDigest,
    ruleBundleDigest: finding.provenance.ruleBundleDigest,
    vulnerabilityDatabaseDigest:
      finding.provenance.vulnerabilityDatabaseDigest,
    planDigest: finding.planDigest,
    canonicalScanKey: finding.canonicalScanKey,
    preflightAttestationRef: finding.preflightAttestationRef,
    preflightInventoryDigest: finding.preflightInventoryDigest,
    lane: finding.lane,
    commitSha: finding.commitSha,
    envelopeDigest: digest('trivy-envelope'),
    artifactDigest: finding.provenance.artifactDigest,
    schemaBundleDigest: digest('trivy-schema'),
    normalizerBundleDigest: digest('trivy-normalizer'),
    validationResultDigest: digest('trivy-validation'),
    dispositionDecisionDigest: digest('trivy-disposition'),
    retentionExpiresAt: RETENTION_EXPIRES_AT,
    findings: [finding],
    redaction: {
      version: SAST_SECRET_REDACTION_VERSION,
      secretRedactionApplied: true,
      candidateCount: 1,
      batchInspectedFieldCount:
        SAST_SECRET_REDACTION_BATCH_INSPECTED_FIELD_COUNT,
      inspectedFieldCount:
        finding.redaction.inspectedFieldCount +
        SAST_SECRET_REDACTION_BATCH_INSPECTED_FIELD_COUNT,
      redactedCandidateCount: 1,
      redactedFieldCount: 1,
      replacementCount: 1,
      detectorKinds: ['GITHUB_TOKEN'],
      secretValuesStored: false,
      matchedValueDigestsStored: false,
      rawCandidatesStored: false,
      sourceCandidateDigestStored: false
    },
    durablePersistenceAllowed: false
  };
  return {
    ...batchCore,
    batchDigest: digest(
      canonicalizeSastSecretRedactionBatch(batchCore)
    )
  };
}

function sequenceClock(values: readonly string[]): () => Date {
  let index = 0;
  return () => {
    const value = values[Math.min(index, values.length - 1)];
    index += 1;
    return new Date(value);
  };
}

function fixedClock(): Date {
  return new Date(CONSTRUCTED_AT);
}

function digest(value: string): `sha256:${string}` {
  return `sha256:${createHash('sha256')
    .update(value, 'utf8')
    .digest('hex')}`;
}
