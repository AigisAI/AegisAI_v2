import { createHash } from 'node:crypto';

import {
  OPENGREP_SARIF_NORMALIZER_VERSION,
  SAST_ARTIFACT_DISPOSITION_VERSION,
  SAST_SECRET_REDACTION_LIMITS,
  SAST_SECRET_REDACTION_TOKEN,
  SAST_SECRET_REDACTION_VERSION,
  TRIVY_JSON_NORMALIZER_VERSION,
  canonicalizeOpenGrepSarifNormalizationBatch,
  canonicalizeSastArtifactDispositionDecision,
  canonicalizeSastSecretRedactionBatch,
  canonicalizeSastSecretRedactionDecision,
  canonicalizeTrivyJsonNormalizationBatch,
  isSastSecretRedactionBatchShapeValid,
  toSastSecretRedactionAuditMetadata,
  type OpenGrepNormalizedFindingCandidate,
  type OpenGrepSarifNormalizationBatch,
  type OpenGrepSarifNormalizationBatchCore,
  type SastArtifactDispositionDecision,
  type SastArtifactDispositionDecisionCore,
  type TrivyJsonNormalizationBatch,
  type TrivyJsonNormalizationBatchCore,
  type TrivyNormalizedFindingCandidate
} from '@aegisai/shared';

import {
  SastSecretRedactionService
} from '../../src/scan-plane/sast-secret-redaction.service';

const DECIDED_AT = '2026-07-26T10:00:00.000Z';
const REDACTED_AT = '2026-07-26T10:01:00.000Z';
const RETENTION_EXPIRES_AT = '2026-08-01T10:00:00.000Z';
const VALIDATION_DIGEST = digest('validation');
const ARTIFACT_DIGEST = digest('artifact');
const REGISTERED_SECRET = 'platform-runtime-secret-0123456789';

describe('SastSecretRedactionService', () => {
  const service = new SastSecretRedactionService();

  it('redacts the known-format, entropy, and registered-value corpus deterministically', async () => {
    const secrets = {
      aws: 'AKIAIOSFODNN7EXAMPLE',
      github: `github_pat_${'A'.repeat(30)}`,
      gitlab: 'glpat-SYNTHETIC0123456789',
      slack: 'xoxb-1234567890-SYNTHETIC-TOKEN',
      google: `AIza${'B'.repeat(35)}`,
      stripe: `sk_test_${'C'.repeat(24)}`,
      sendgrid: `SG.${'D'.repeat(20)}.${'E'.repeat(24)}`,
      jwt: `eyJ${'F'.repeat(12)}.${'G'.repeat(16)}.${'H'.repeat(16)}`,
      authorization: `Authorization: Bearer ${'I'.repeat(32)}`,
      url: 'https://synthetic-user:synthetic-password@example.invalid/path',
      assignment: 'password=synthetic-password-value',
      entropy: 'aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW1xY',
      hexadecimalEntropy: '0123456789abcdef'.repeat(2),
      digestShapedSecret:
        `sha256:${'fedcba9876543210'.repeat(4)}`,
      privateKey:
        '-----BEGIN PRIVATE KEY-----\nSYNTHETICNOTAREALKEY1234567890\n-----END PRIVATE KEY-----'
    };
    const disposition = acceptedDisposition();
    const batch = openGrepBatch(disposition, {
      title: `Credential ${secrets.github}`,
      description: Object.values(secrets).join('\n'),
      location: {
        kind: 'FILE',
        normalizedPath: 'src/config.ts',
        lineStart: 7,
        lineEnd: 7,
        symbol: `configure-${REGISTERED_SECRET}`
      }
    });
    const input = {
      batch,
      disposition,
      platformSecretValues: [REGISTERED_SECRET]
    };

    const first = await service.redact(input, fixedClock);
    const second = await service.redact(input, fixedClock);
    expect(first).toEqual(second);
    expect(first.outcome).toBe('REDACTED');
    if (first.outcome !== 'REDACTED') return;

    expect(
      isSastSecretRedactionBatchShapeValid(
        first.batch,
        digest
      )
    ).toBe(true);
    expect(first.batch.version).toBe(
      SAST_SECRET_REDACTION_VERSION
    );
    expect(first.batch.durablePersistenceAllowed).toBe(false);
    expect(first.batch.redaction.secretRedactionApplied).toBe(true);
    expect(first.batch.redaction.redactedCandidateCount).toBe(1);
    expect(first.batch.redaction.redactedFieldCount).toBe(3);
    expect(first.batch.redaction.detectorKinds).toEqual(
      expect.arrayContaining([
        'PLATFORM_VALUE',
        'PRIVATE_KEY',
        'AUTHORIZATION_CREDENTIAL',
        'URL_CREDENTIAL',
        'AWS_ACCESS_KEY_ID',
        'GITHUB_TOKEN',
        'GITLAB_TOKEN',
        'SLACK_TOKEN',
        'GOOGLE_API_KEY',
        'STRIPE_KEY',
        'SENDGRID_KEY',
        'JWT',
        'SECRET_ASSIGNMENT',
        'HIGH_ENTROPY'
      ])
    );
    const { batchDigest, ...batchCore } = first.batch;
    void batchDigest;
    const canonical =
      canonicalizeSastSecretRedactionBatch(batchCore);
    expect(digest(canonical)).toBe(first.batch.batchDigest);

    const serialized = JSON.stringify(first);
    const leakSentinels = [
      ...Object.values(secrets),
      REGISTERED_SECRET,
      'synthetic-user',
      'synthetic-password',
      'SYNTHETICNOTAREALKEY1234567890',
      'I'.repeat(32)
    ];
    for (const secret of leakSentinels) {
      expect(serialized).not.toContain(secret);
      expect(serialized).not.toContain(digest(secret));
    }
    expect(serialized).not.toContain(batch.batchDigest);
    expect(serialized).not.toContain('sourceBatchDigest');
    expect(serialized).not.toContain('"matchedValueDigest":');
    expect(serialized).toContain(SAST_SECRET_REDACTION_TOKEN);
    const redactedFinding = first.batch.findings[0];
    const {
      decisionDigest,
      decisionRef,
      ...redactionCore
    } = redactedFinding.redaction;
    void decisionRef;
    expect(
      digest(
        canonicalizeSastSecretRedactionDecision({
          ...redactedFinding,
          redaction: redactionCore
        })
      )
    ).toBe(decisionDigest);
    expect(
      toSastSecretRedactionAuditMetadata(first, digest)
    ).not.toHaveProperty('findings');
  });

  it('redacts supported Trivy candidates without granting durable or policy authority', async () => {
    const disposition = acceptedDisposition();
    const secret = `github_pat_${'J'.repeat(30)}`;
    const batch = trivyBatch(disposition, {
      description: `Potential credential ${secret} was reported.`
    });

    const result = await service.redact(
      { batch, disposition },
      fixedClock
    );
    expect(result.outcome).toBe('REDACTED');
    if (result.outcome !== 'REDACTED') return;
    expect(result.batch.scanner).toBe('TRIVY');
    expect(result.batch.sourceAdapterVersion).toBe(
      TRIVY_JSON_NORMALIZER_VERSION
    );
    expect(result.batch.vulnerabilityDatabaseDigest).toBe(
      digest('vulnerability-database')
    );
    expect(result.batch.findings[0]).toMatchObject({
      capability: 'SECRET_DETECTION',
      scannerDisposition: {
        platformPolicyAuthority: false
      },
      trivy: {
        secretValueStored: false,
        secretPayloadDiscarded: true
      },
      durablePersistenceAllowed: false
    });
    expect(JSON.stringify(result)).not.toContain(secret);
  });

  it('merges overlapping detector matches into one fixed replacement', async () => {
    const disposition = acceptedDisposition();
    const secret = 'registered-password-1234567890';
    const batch = openGrepBatch(disposition, {
      description: `password=${secret}`
    });
    const result = await service.redact(
      {
        batch,
        disposition,
        platformSecretValues: [secret]
      },
      fixedClock
    );

    expect(result.outcome).toBe('REDACTED');
    if (result.outcome !== 'REDACTED') return;
    const finding = result.batch.findings[0];
    expect(finding.description).toBe(SAST_SECRET_REDACTION_TOKEN);
    expect(finding.redaction.replacementCount).toBe(1);
    expect(finding.redaction.detectorKinds).toEqual([
      'PLATFORM_VALUE',
      'SECRET_ASSIGNMENT',
      'HIGH_ENTROPY'
    ]);
  });

  it('redacts prefixed and quoted low-entropy secret assignments', async () => {
    const disposition = acceptedDisposition();
    const batch = openGrepBatch(disposition, {
      description:
        `DB_PASSWORD="hunter2"; "password": "swordfish"; config.client_secret: "abc"; serialized {${String.raw`\"password\": \"lowpass\"`}}`
    });
    const result = await service.redact(
      { batch, disposition },
      fixedClock
    );

    expect(result.outcome).toBe('REDACTED');
    if (result.outcome !== 'REDACTED') return;
    expect(result.batch.findings[0]?.description).toBe(
      `${SAST_SECRET_REDACTION_TOKEN}; ${SAST_SECRET_REDACTION_TOKEN}; ${SAST_SECRET_REDACTION_TOKEN}; serialized {${SAST_SECRET_REDACTION_TOKEN}}`
    );
    expect(
      result.batch.findings[0]?.redaction.detectorKinds
    ).toEqual(['SECRET_ASSIGNMENT']);
    expect(JSON.stringify(result)).not.toContain('hunter2');
    expect(JSON.stringify(result)).not.toContain('swordfish');
    expect(JSON.stringify(result)).not.toContain('"abc"');
    expect(JSON.stringify(result)).not.toContain('lowpass');
  });

  it('is invariant to registered-value ordering and redacts NFC Unicode values', async () => {
    const disposition = acceptedDisposition();
    const firstSecret = '플랫폼-비밀값-0123456789';
    const secondSecret = 'second-platform-secret-9876543210';
    const batch = openGrepBatch(disposition, {
      description: `${firstSecret} and ${secondSecret}`
    });
    const first = await service.redact(
      {
        batch,
        disposition,
        platformSecretValues: [firstSecret, secondSecret]
      },
      fixedClock
    );
    const second = await service.redact(
      {
        batch,
        disposition,
        platformSecretValues: [secondSecret, firstSecret]
      },
      fixedClock
    );

    expect(first).toEqual(second);
    expect(first.outcome).toBe('REDACTED');
    expect(JSON.stringify(first)).not.toContain(firstSecret);
    expect(JSON.stringify(first)).not.toContain(secondSecret);
  });

  it('redacts an entire registered value when its shorter suffix matches first', async () => {
    const disposition = acceptedDisposition();
    const shorterSecret = '12345678';
    const longerSecret = 'xx12345678yy';
    const batch = openGrepBatch(disposition, {
      description: longerSecret
    });
    const result = await service.redact(
      {
        batch,
        disposition,
        platformSecretValues: [shorterSecret, longerSecret]
      },
      fixedClock
    );

    expect(result.outcome).toBe('REDACTED');
    if (result.outcome !== 'REDACTED') return;
    expect(result.batch.findings[0]?.description).toBe(
      SAST_SECRET_REDACTION_TOKEN
    );
    expect(JSON.stringify(result)).not.toContain(longerSecret);
  });

  it('fails closed when an identity-bearing field contains a secret', async () => {
    const disposition = acceptedDisposition();
    const batch = openGrepBatch(disposition, {
      identityMaterial: {
        ...openGrepFinding().identityMaterial,
        symbolAnchor: REGISTERED_SECRET
      }
    });
    const result = await service.redact(
      {
        batch,
        disposition,
        platformSecretValues: [REGISTERED_SECRET]
      },
      fixedClock
    );

    expect(result).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: [
        'SECRET_REDACTION_IDENTITY_FIELD_BLOCKED'
      ],
      secretValuesStored: false,
      matchedValueDigestsStored: false,
      sourceCandidateDigestStored: false
    });
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain(REGISTERED_SECRET);
    expect(serialized).not.toContain(batch.batchDigest);
    expect(serialized).not.toContain(batch.artifactDigest);
  });

  it('rejects an unregistered high-entropy scanner identity instead of hashing it', async () => {
    const disposition = acceptedDisposition();
    const highEntropyIdentity =
      'aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW1xY';
    const batch = openGrepBatch(disposition, {
      identityMaterial: {
        ...openGrepFinding().identityMaterial,
        scannerMatchBasedId: highEntropyIdentity,
        structuralHash: digest(highEntropyIdentity)
      }
    });
    const result = await service.redact(
      { batch, disposition },
      fixedClock
    );

    expect(result).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: [
        'SECRET_REDACTION_IDENTITY_FIELD_BLOCKED'
      ]
    });
    expect(JSON.stringify(result)).not.toContain(
      highEntropyIdentity
    );
  });

  it('rejects low-entropy credential syntax in opaque identity fields', async () => {
    const disposition = acceptedDisposition();
    const credentialIdentity = 'DB_PASSWORD="hunter2"';
    const batch = openGrepBatch(disposition, {
      identityMaterial: {
        ...openGrepFinding().identityMaterial,
        scannerMatchBasedId: credentialIdentity
      }
    });
    const result = await service.redact(
      { batch, disposition },
      fixedClock
    );

    expect(result).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: [
        'SECRET_REDACTION_IDENTITY_FIELD_BLOCKED'
      ]
    });
    expect(JSON.stringify(result)).not.toContain(
      credentialIdentity
    );
    expect(JSON.stringify(result)).not.toContain('hunter2');
  });

  it('rejects a forged reserved marker before it can claim redaction', async () => {
    const disposition = acceptedDisposition();
    const batch = openGrepBatch(disposition, {
      description: `forged ${SAST_SECRET_REDACTION_TOKEN}`
    });
    expect(
      await service.redact({ batch, disposition }, fixedClock)
    ).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: [
        'SECRET_REDACTION_RESERVED_TOKEN_PRESENT'
      ]
    });
  });

  it('rejects source digest tamper and invalid registered-secret sets with bounded metadata', async () => {
    const disposition = acceptedDisposition();
    const batch = openGrepBatch(disposition);
    const tampered = {
      ...batch,
      batchDigest: digest('tampered')
    };
    expect(
      await service.redact(
        {
          batch: tampered,
          disposition
        },
        fixedClock
      )
    ).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: [
        'SECRET_REDACTION_SOURCE_DIGEST_MISMATCH'
      ]
    });
    expect(
      await service.redact(
        {
          batch: {
            ...batch,
            findings: Array.from(
              {
                length:
                  SAST_SECRET_REDACTION_LIMITS
                    .maximumCandidates + 1
              },
              () => batch.findings[0]
            )
          },
          disposition
        },
        fixedClock
      )
    ).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: ['SECRET_REDACTION_INPUT_INVALID']
    });
    expect(
      await service.redact(
        {
          batch: {
            ...batch,
            findings: [
              {
                ...batch.findings[0],
                description: 'x'.repeat(
                  SAST_SECRET_REDACTION_LIMITS
                    .maximumInspectedCodeUnits + 1
                )
              }
            ]
          },
          disposition
        },
        fixedClock
      )
    ).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: ['SECRET_REDACTION_INPUT_INVALID']
    });

    for (const platformSecretValues of [
      [REGISTERED_SECRET, REGISTERED_SECRET],
      ['short'],
      [SAST_SECRET_REDACTION_TOKEN],
      ['synthetic\u0001secret'],
      [`synthetic-${String.fromCharCode(0xd800)}-secret`],
      ['de\u0301composed-secret-value'],
      Array.from(
        { length: 65 },
        (_, index) => `synthetic-secret-${index.toString().padStart(3, '0')}`
      )
    ]) {
      expect(
        await service.redact(
          {
            batch,
            disposition,
            platformSecretValues
          },
          fixedClock
        )
      ).toMatchObject({
        outcome: 'REJECTED',
        reasonCodes: [
          'SECRET_REDACTION_PLATFORM_VALUES_INVALID'
        ]
      });
    }
  });

  it('revalidates the accepted disposition and retention on both sides of redaction', async () => {
    const disposition = acceptedDisposition();
    const batch = openGrepBatch(disposition);
    const tamperedDisposition = {
      ...disposition,
      storageReceiptDigest: digest('tampered-receipt')
    };
    expect(
      await service.redact(
        {
          batch,
          disposition: tamperedDisposition
        },
        fixedClock
      )
    ).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: [
        'SECRET_REDACTION_DISPOSITION_INVALID'
      ]
    });

    const times = [
      new Date(REDACTED_AT),
      new Date(RETENTION_EXPIRES_AT)
    ];
    expect(
      await service.redact(
        { batch, disposition },
        () => times.shift() as Date
      )
    ).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: [
        'SECRET_REDACTION_RETENTION_EXPIRED'
      ]
    });
  });

  it('emits a deterministic fully bound zero-finding redaction batch', async () => {
    const disposition = acceptedDisposition();
    const batch = openGrepBatch(disposition, undefined, []);
    const result = await service.redact(
      { batch, disposition },
      fixedClock
    );

    expect(result.outcome).toBe('REDACTED');
    if (result.outcome !== 'REDACTED') return;
    expect(result.batch.findings).toEqual([]);
    expect(result.batch.redaction).toMatchObject({
      candidateCount: 0,
      batchInspectedFieldCount: 8,
      inspectedFieldCount: 8,
      redactedCandidateCount: 0,
      redactedFieldCount: 0,
      replacementCount: 0,
      detectorKinds: []
    });
    expect(
      isSastSecretRedactionBatchShapeValid(
        result.batch,
        digest
      )
    ).toBe(true);
  });

  it('yields to the event loop at candidate and code-unit chunk bounds', async () => {
    const disposition = acceptedDisposition();
    const findings = Array.from({ length: 65 }, (_, index) => {
      const finding = openGrepFinding();
      const line = index + 1;
      return {
        ...finding,
        location: {
          ...finding.location,
          lineStart: line,
          lineEnd: line
        },
        identityMaterial: {
          ...finding.identityMaterial,
          scannerMatchBasedId:
            `rules.secret:match-${index
              .toString()
              .padStart(3, '0')}`
        }
      } as OpenGrepNormalizedFindingCandidate;
    });
    const batch = openGrepBatch(
      disposition,
      undefined,
      findings
    );
    const yieldingService =
      new YieldObservingSastSecretRedactionService();
    const result = await yieldingService.redact(
      { batch, disposition },
      fixedClock
    );

    expect(result.outcome).toBe('REDACTED');
    expect(yieldingService.yieldCount).toBe(1);
    if (result.outcome !== 'REDACTED') return;
    expect(result.batch.findings).toHaveLength(65);

    const wideBatch = openGrepBatch(
      disposition,
      undefined,
      findings.slice(0, 10).map((finding) => ({
        ...finding,
        description: 'x'.repeat(3_500)
      }))
    );
    yieldingService.yieldCount = 0;
    const wideResult = await yieldingService.redact(
      { batch: wideBatch, disposition },
      fixedClock
    );

    expect(wideResult.outcome).toBe('REDACTED');
    expect(yieldingService.yieldCount).toBe(1);
  });

  it('does not classify the pinned OpenGrep matchBasedId hex form as a secret', async () => {
    const disposition = acceptedDisposition();
    const scannerMatchBasedId = `${'0123456789abcdef'.repeat(
      8
    )}_0`;
    const batch = openGrepBatch(disposition, {
      identityMaterial: {
        ...openGrepFinding().identityMaterial,
        scannerMatchBasedId,
        structuralHash: digest(scannerMatchBasedId)
      }
    });
    const result = await service.redact(
      { batch, disposition },
      fixedClock
    );

    expect(result.outcome).toBe('REDACTED');
    if (result.outcome !== 'REDACTED') return;
    expect(
      result.batch.findings[0].identityMaterial
        .scannerMatchBasedId
    ).toBe(scannerMatchBasedId);
  });

  it('rejects secret-bearing batch bindings even when there are no findings', async () => {
    const disposition = acceptedDisposition();
    const original = openGrepBatch(
      disposition,
      undefined,
      []
    );
    const { batchDigest, ...originalCore } = original;
    void batchDigest;
    const core: OpenGrepSarifNormalizationBatchCore = {
      ...originalCore,
      scope: {
        ...originalCore.scope,
        tenantId: REGISTERED_SECRET
      }
    };
    const batch = {
      ...core,
      batchDigest: digest(
        canonicalizeOpenGrepSarifNormalizationBatch(core)
      )
    };

    const result = await service.redact(
      {
        batch,
        disposition,
        platformSecretValues: [REGISTERED_SECRET]
      },
      fixedClock
    );
    expect(result).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: [
        'SECRET_REDACTION_IDENTITY_FIELD_BLOCKED'
      ]
    });
    expect(JSON.stringify(result)).not.toContain(
      REGISTERED_SECRET
    );
  });
});

class YieldObservingSastSecretRedactionService extends SastSecretRedactionService {
  yieldCount = 0;

  protected override async yieldEventLoop(): Promise<void> {
    this.yieldCount += 1;
  }
}

function openGrepBatch(
  disposition: Readonly<SastArtifactDispositionDecision>,
  findingOverrides?: Partial<OpenGrepNormalizedFindingCandidate>,
  findings?: OpenGrepNormalizedFindingCandidate[]
): OpenGrepSarifNormalizationBatch {
  const core: OpenGrepSarifNormalizationBatchCore = {
    version: OPENGREP_SARIF_NORMALIZER_VERSION,
    adapterVersion: OPENGREP_SARIF_NORMALIZER_VERSION,
    artifactSchema: 'OPENGREP_SARIF',
    artifactSchemaVersion: '2.1.0',
    ingestionId: disposition.ingestionId,
    scope: scope(),
    scannerRunId: 'scanner-run-1',
    scanner: 'OPENGREP',
    scannerVersion: '1.22.0',
    scannerImageDigest: digest('opengrep-image'),
    ruleBundleDigest: digest('opengrep-rules'),
    planDigest: digest('plan'),
    canonicalScanKey: digest('canonical-scan'),
    preflightAttestationRef: 'preflight://attempt-1',
    preflightInventoryDigest: digest('inventory'),
    lane: 'FAST',
    commitSha: 'a'.repeat(40),
    envelopeDigest: digest('envelope'),
    artifactDigest: ARTIFACT_DIGEST,
    schemaBundleDigest: digest('schema'),
    normalizerBundleDigest: digest('normalizer'),
    validationResultDigest: VALIDATION_DIGEST,
    dispositionDecisionDigest: disposition.decisionDigest,
    findings:
      findings ??
      [
        {
          ...openGrepFinding(),
          ...findingOverrides
        }
      ],
    durablePersistenceAllowed: false
  };
  return {
    ...core,
    batchDigest: digest(
      canonicalizeOpenGrepSarifNormalizationBatch(core)
    )
  };
}

function openGrepFinding(): OpenGrepNormalizedFindingCandidate {
  return {
    tenantId: 'tenant-1',
    repositoryBindingId: 'repository-1',
    scanRequestId: 'scan-1',
    attemptId: 'attempt-1',
    scannerRunId: 'scanner-run-1',
    planDigest: digest('plan'),
    canonicalScanKey: digest('canonical-scan'),
    preflightAttestationRef: 'preflight://attempt-1',
    preflightInventoryDigest: digest('inventory'),
    commitSha: 'a'.repeat(40),
    lane: 'FAST',
    capability: 'SAST',
    title: 'Hardcoded credential',
    description: 'A credential-like value was detected.',
    severity: 'HIGH',
    confidence: 'HIGH',
    cweIds: ['CWE-798'],
    cveIds: [],
    location: {
      kind: 'FILE',
      normalizedPath: 'src/config.ts',
      lineStart: 7,
      lineEnd: 7
    },
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
      scannerImageDigest: digest('opengrep-image'),
      ruleId: 'rules.secret',
      ruleRevision: '2026.07.1',
      ruleBundleDigest: digest('opengrep-rules'),
      artifactDigest: ARTIFACT_DIGEST
    },
    notes: [],
    durablePersistenceAllowed: false
  };
}

function trivyBatch(
  disposition: Readonly<SastArtifactDispositionDecision>,
  findingOverrides?: Partial<TrivyNormalizedFindingCandidate>
): TrivyJsonNormalizationBatch {
  const core: TrivyJsonNormalizationBatchCore = {
    version: TRIVY_JSON_NORMALIZER_VERSION,
    adapterVersion: TRIVY_JSON_NORMALIZER_VERSION,
    artifactSchema: 'TRIVY_JSON',
    artifactSchemaVersion: '2',
    ingestionId: disposition.ingestionId,
    scope: scope(),
    scannerRunId: 'scanner-run-1',
    scanner: 'TRIVY',
    scannerVersion: '0.66.0',
    scannerImageDigest: digest('trivy-image'),
    ruleBundleDigest: digest('trivy-rules'),
    vulnerabilityDatabaseDigest: digest(
      'vulnerability-database'
    ),
    planDigest: digest('plan'),
    canonicalScanKey: digest('canonical-scan'),
    preflightAttestationRef: 'preflight://attempt-1',
    preflightInventoryDigest: digest('inventory'),
    lane: 'FAST',
    commitSha: 'a'.repeat(40),
    envelopeDigest: digest('envelope'),
    artifactDigest: ARTIFACT_DIGEST,
    schemaBundleDigest: digest('schema'),
    normalizerBundleDigest: digest('normalizer'),
    validationResultDigest: VALIDATION_DIGEST,
    dispositionDecisionDigest: disposition.decisionDigest,
    findings: [
      {
        ...trivyFinding(),
        ...findingOverrides
      } as TrivyNormalizedFindingCandidate
    ],
    durablePersistenceAllowed: false
  };
  return {
    ...core,
    batchDigest: digest(
      canonicalizeTrivyJsonNormalizationBatch(core)
    )
  };
}

function trivyFinding(): TrivyNormalizedFindingCandidate {
  const matchId = digest('trivy-match');
  return {
    tenantId: 'tenant-1',
    repositoryBindingId: 'repository-1',
    scanRequestId: 'scan-1',
    attemptId: 'attempt-1',
    scannerRunId: 'scanner-run-1',
    planDigest: digest('plan'),
    canonicalScanKey: digest('canonical-scan'),
    preflightAttestationRef: 'preflight://attempt-1',
    preflightInventoryDigest: digest('inventory'),
    commitSha: 'a'.repeat(40),
    lane: 'FAST',
    capability: 'SECRET_DETECTION',
    title: 'Secret detected: generic-api-key',
    description:
      'Potential API secret detected. The secret value and scanner context were discarded.',
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
      structuralHash: digest(`trivy-structure:${matchId}`),
      scannerMatchBasedId: matchId
    },
    provenance: {
      scanner: 'TRIVY',
      scannerVersion: '0.66.0',
      scannerImageDigest: digest('trivy-image'),
      ruleId: 'generic-api-key',
      ruleRevision: '2026.07.1',
      ruleBundleDigest: digest('trivy-rules'),
      artifactDigest: ARTIFACT_DIGEST,
      ruleSource: 'CHECK_BUNDLE',
      vulnerabilityDatabaseDigest: digest(
        'vulnerability-database'
      )
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
    durablePersistenceAllowed: false
  };
}

function acceptedDisposition(): SastArtifactDispositionDecision {
  const intentDigest = digest('intent');
  const core: SastArtifactDispositionDecisionCore = {
    version: SAST_ARTIFACT_DISPOSITION_VERSION,
    ingestionId: 'ingestion-1',
    disposition: 'ACCEPTED',
    storageAction: 'RETAIN_ACCEPTED',
    reasonCodes: ['ARTIFACT_VALIDATION_ACCEPTED'],
    validationReasonCodes: [],
    validationResultDigest: VALIDATION_DIGEST,
    normalizationEligible: true,
    retentionExpiresAt: RETENTION_EXPIRES_AT,
    acceptanceControlRef: 'acceptance://policy/allow',
    intentDigest,
    storageOperationId:
      `${SAST_ARTIFACT_DISPOSITION_VERSION}:${intentDigest.slice(
        'sha256:'.length
      )}`,
    storageReceiptRef: 'storage-receipt://accepted/ingestion-1',
    storageReceiptDigest: digest('receipt'),
    decidedAt: DECIDED_AT
  };
  return {
    ...core,
    decisionDigest: digest(
      canonicalizeSastArtifactDispositionDecision(core)
    )
  };
}

function scope() {
  return {
    tenantId: 'tenant-1',
    repositoryBindingId: 'repository-1',
    scanRequestId: 'scan-1',
    attemptId: 'attempt-1',
    scannerRunId: 'scanner-run-1'
  };
}

function fixedClock(): Date {
  return new Date(REDACTED_AT);
}

function digest(value: string): `sha256:${string}` {
  return `sha256:${createHash('sha256')
    .update(value)
    .digest('hex')}`;
}
