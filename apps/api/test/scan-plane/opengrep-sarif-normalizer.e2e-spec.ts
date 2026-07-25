import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import {
  SAST_APPROVED_PROFILE_DIGESTS,
  SAST_ARTIFACT_DISPOSITION_VERSION,
  SAST_ARTIFACT_SCHEMA_VERSIONS,
  SAST_ARTIFACT_VALIDATION_VERSION,
  SAST_FORBIDDEN_CAPABILITIES,
  SAST_SCAN_PROFILES,
  canonicalizeOpenGrepSarifNormalizationBatch,
  canonicalizeSastArtifactDispositionDecision,
  canonicalizeSastArtifactValidationResult,
  canonicalizeScannerArtifactEnvelope,
  type ExpectedScannerArtifactBinding,
  type SastArtifactDispositionDecision,
  type SastArtifactDispositionDecisionCore,
  type SastArtifactValidationResult,
  type SastArtifactValidationResultCore,
  type SastScanPlan,
  type ScannerArtifactEnvelope
} from '@aegisai/shared';

import {
  OpenGrepSarifNormalizer,
  type OpenGrepSarifNormalizationInput
} from '../../src/scan-plane/opengrep-sarif-normalizer';
import {
  SastArtifactStreamValidationSession
} from '../../src/scan-plane/sast-artifact-stream-validator';
import type {
  SastFileCoordinateAttestation
} from '../../src/scan-plane/sast-file-coordinate-attestation.provider';

const FIXED_COMMIT = 'a'.repeat(40);
const NORMALIZED_AT = '2026-07-26T12:02:00.000Z';
const DECIDED_AT = '2026-07-26T12:01:00.000Z';
const RETENTION_EXPIRES_AT = '2026-08-01T12:00:00.000Z';

interface FixtureRule {
  id: string;
  name: string;
  defaultConfiguration?: {
    level?: string;
  };
  shortDescription?: {
    text: string;
  };
  properties: {
    precision?: string;
    'security-severity'?: string | number;
    tags: string[];
  };
}

interface FixtureLocation {
  physicalLocation: {
    artifactLocation: {
      uri: string;
      uriBaseId: string;
    };
    region: {
      startLine: number;
      endLine?: number;
      startColumn?: number;
      endColumn?: number;
      snippet?: { text: string };
    };
  };
}

interface FixtureResult {
  ruleId: string;
  ruleIndex?: number;
  level?: string;
  fingerprints: Record<string, string>;
  locations: FixtureLocation[];
  message: {
    text: string;
  };
  properties: Record<string, string>;
}

interface FixtureSarif {
  $schema: string;
  version: string;
  runs: [
    {
      invocations: [
        {
          executionSuccessful: boolean;
          toolExecutionNotifications: object[];
        }
      ];
      results: FixtureResult[];
      tool: {
        driver: {
          name: string;
          semanticVersion: string;
          rules: FixtureRule[];
        };
      };
    }
  ];
}

describe('OpenGrepSarifNormalizer', () => {
  const normalizer = new OpenGrepSarifNormalizer();

  it('normalizes the upstream-compatible golden fixture byte-exactly across chunking', async () => {
    const fixture = loadSarifFixture('upstream-compatible.sarif.json');
    const context = buildContext(fixture);
    const first = await normalizeAt(
      normalizer,
      context.input,
      chunks(context.artifact, [1])
    );
    const second = await normalizeAt(
      normalizer,
      context.input,
      chunks(context.artifact, [4093, 2, 8191, 7])
    );
    const withEmptyChunks = await normalizeAt(
      normalizer,
      context.input,
      chunksWithEmptySegments(context.artifact, [3, 4093, 11])
    );

    expect(first).toEqual(second);
    expect(first).toEqual(withEmptyChunks);
    expect(first.outcome).toBe('NORMALIZED');
    if (first.outcome !== 'NORMALIZED') return;

    const semanticFindings = first.batch.findings.map((finding) => ({
      ruleId: finding.provenance.ruleId,
      title: finding.title,
      description: finding.description,
      severity: finding.severity,
      confidence: finding.confidence,
      cweIds: finding.cweIds,
      cveIds: finding.cveIds,
      location: finding.location,
      notes: finding.notes
    }));
    expect(semanticFindings).toEqual(
      loadJsonFixture('upstream-compatible.expected.json')
    );
    expect(first.batch.durablePersistenceAllowed).toBe(false);
    expect(first.batch).toMatchObject({
      scannerRunId: context.input.envelope.scannerRunId,
      scanner: 'OPENGREP',
      scannerVersion: context.input.envelope.scannerVersion,
      scannerImageDigest:
        context.input.envelope.scannerImageDigest,
      ruleBundleDigest: context.input.envelope.ruleBundleDigest
    });
    expect(
      first.batch.findings.every(
        (finding) =>
          finding.durablePersistenceAllowed === false &&
          finding.scannerRunId ===
            context.input.envelope.scannerRunId
      )
    ).toBe(true);
    const sqlResult = fixture.runs[0].results.find(
      (result) => result.ruleId === 'rules.sql-injection'
    );
    const sqlFinding = first.batch.findings.find(
      (finding) =>
        finding.provenance.ruleId === 'rules.sql-injection'
    );
    const scannerMatchBasedId =
      sqlResult?.fingerprints['matchBasedId/v1'];
    expect(sqlFinding?.identityMaterial).toMatchObject({
      scannerMatchBasedId,
      structuralHash: digest(
        `opengrep:matchBasedId/v1:${scannerMatchBasedId}`
      )
    });
    expect(JSON.stringify(first)).not.toContain('super-secret');
    expect(first.batch.findings[0]).not.toHaveProperty(
      'stableFingerprint'
    );
    expect(first.batch.findings[0]).not.toHaveProperty(
      'evidencePackIds'
    );
    expect(first.batch.findings[0]).not.toHaveProperty('status');
    const { batchDigest, ...batchCore } = first.batch;
    expect(batchDigest).toBe(
      digest(
        canonicalizeOpenGrepSarifNormalizationBatch(batchCore)
      )
    );
  });

  it('accepts the same official OpenGrep shape through T030 before T032', async () => {
    const fixture = loadSarifFixture(
      'upstream-compatible.sarif.json'
    );
    const context = buildContext(fixture);
    const session = new SastArtifactStreamValidationSession({
      envelope: context.input.envelope,
      plan: context.input.plan,
      expectedBinding: context.input.expectedBinding,
      envelopeDigest: context.input.envelopeDigest,
      coordinateAttestation:
        context.input.coordinateAttestation
    });
    for await (const _chunk of session.observe(
      chunks(context.artifact, [1, 4095, 11])
    )) {
      // T030 tees these bytes to immutable storage in production.
      void _chunk;
    }
    const validation = session.finish();
    expect(validation.outcome).toBe('PASSED');
    const disposition = buildAcceptedDisposition(validation);
    const result = await normalizeAt(
      normalizer,
      {
        ...context.input,
        validation,
        disposition
      },
      chunks(context.artifact, [7, 4089])
    );

    expect(result.outcome).toBe('NORMALIZED');
  });

  it('retains scanner provenance for an accepted zero-finding batch', async () => {
    const fixture = loadSarifFixture(
      'upstream-compatible.sarif.json'
    );
    fixture.runs[0].results = [];
    const result = await normalizeFixture(normalizer, fixture);

    expect(result.outcome).toBe('NORMALIZED');
    if (result.outcome !== 'NORMALIZED') return;
    expect(result.batch.findings).toEqual([]);
    expect(result.batch).toMatchObject({
      scanner: 'OPENGREP',
      scannerVersion: '1.22.0',
      scannerImageDigest: expect.stringMatching(/^sha256:/u),
      ruleBundleDigest: expect.stringMatching(/^sha256:/u)
    });
  });

  it('rejects a foreign driver and a driver-version rebinding', async () => {
    const foreign = loadSarifFixture(
      'upstream-compatible.sarif.json'
    );
    foreign.runs[0].tool.driver.name = 'Semgrep OSS';
    const foreignResult = await normalizeFixture(
      normalizer,
      foreign
    );
    expect(foreignResult).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: ['NORMALIZATION_OPENGREP_DRIVER_INVALID']
    });

    const drifted = loadSarifFixture(
      'upstream-compatible.sarif.json'
    );
    drifted.runs[0].tool.driver.semanticVersion = '1.21.0';
    const driftedResult = await normalizeFixture(
      normalizer,
      drifted
    );
    expect(driftedResult).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: ['NORMALIZATION_OPENGREP_DRIVER_INVALID']
    });
  });

  it('fails closed instead of discarding an ambiguous primary location', async () => {
    const fixture = loadSarifFixture(
      'malicious-ambiguous-location.sarif.json'
    );
    const result = await normalizeFixture(normalizer, fixture);

    expect(result.outcome).toBe('REJECTED');
    if (result.outcome !== 'REJECTED') return;
    expect(result.reasonCodes).toEqual(
      expect.arrayContaining([
        'NORMALIZATION_OPENGREP_RESULT_INVALID',
        'NORMALIZATION_OPENGREP_LOCATION_INVALID'
      ])
    );
  });

  it('rejects container-shaped scalar coordinates as location ambiguity', async () => {
    const fixture = loadSarifFixture(
      'upstream-compatible.sarif.json'
    );
    fixture.runs[0].results[1]!.locations[0]!.physicalLocation
      .region.startLine = {} as unknown as number;
    const result = await normalizeFixture(normalizer, fixture);

    expect(result).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: ['NORMALIZATION_OPENGREP_LOCATION_INVALID']
    });
  });

  it('does not read an artifact whose accepted disposition binding is invalid', async () => {
    const fixture = loadSarifFixture(
      'upstream-compatible.sarif.json'
    );
    const context = buildContext(fixture);
    const invalidDisposition = {
      ...context.input.disposition,
      normalizationEligible: false
    };
    let bodyRead = false;
    const forbiddenBody: AsyncIterable<Uint8Array> = {
      [Symbol.asyncIterator](): AsyncIterator<Uint8Array> {
        bodyRead = true;
        throw new Error('artifact body must not be read');
      }
    };

    const result = await normalizeAt(
      normalizer,
      {
        ...context.input,
        disposition: invalidDisposition
      },
      forbiddenBody
    );

    expect(bodyRead).toBe(false);
    expect(result).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: ['NORMALIZATION_ACCEPTANCE_INVALID']
    });
  });

  it('rejects normalization at or after the accepted artifact retention boundary', async () => {
    const fixture = loadSarifFixture(
      'upstream-compatible.sarif.json'
    );
    const context = buildContext(fixture);
    const result = await normalizeAt(
      normalizer,
      context.input,
      chunks(context.artifact, [17]),
      RETENTION_EXPIRES_AT
    );

    expect(result).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: ['NORMALIZATION_RETENTION_EXPIRED']
    });
  });

  it('rejects a trusted reference time before the disposition decision', async () => {
    const fixture = loadSarifFixture(
      'upstream-compatible.sarif.json'
    );
    const context = buildContext(fixture);
    let bodyRead = false;
    async function* forbiddenBody(): AsyncGenerator<Uint8Array> {
      bodyRead = true;
      yield context.artifact;
    }
    const result = await normalizeAt(
      normalizer,
      context.input,
      forbiddenBody(),
      '2026-07-26T12:00:59.999Z'
    );

    expect(bodyRead).toBe(false);
    expect(result).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: ['NORMALIZATION_ACCEPTANCE_INVALID']
    });
  });

  it('rechecks retention after streaming before emitting candidates', async () => {
    const fixture = loadSarifFixture(
      'upstream-compatible.sarif.json'
    );
    const context = buildContext(fixture);
    let clockReads = 0;
    const result = await normalizer.normalize(
      context.input,
      chunks(context.artifact, [13]),
      () => {
        clockReads += 1;
        return new Date(
          clockReads === 1
            ? NORMALIZED_AT
            : RETENTION_EXPIRES_AT
        );
      }
    );

    expect(clockReads).toBe(2);
    expect(result).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: ['NORMALIZATION_RETENTION_EXPIRED']
    });
  });

  it('recomputes the accepted artifact digest and byte count while streaming', async () => {
    const fixture = loadSarifFixture(
      'upstream-compatible.sarif.json'
    );
    const context = buildContext(fixture);
    const drifted = Buffer.from(
      context.artifact
        .toString('utf8')
        .replace('nullable', 'tainted!')
    );
    const result = await normalizeAt(
      normalizer,
      context.input,
      chunks(drifted, [3, 4096])
    );

    expect(result.outcome).toBe('REJECTED');
    if (result.outcome !== 'REJECTED') return;
    expect(result.reasonCodes).toContain(
      'NORMALIZATION_CONTENT_DIGEST_MISMATCH'
    );
  });

  it('rejects oversized streams with chunk-independent bounded metadata', async () => {
    const fixture = loadSarifFixture(
      'upstream-compatible.sarif.json'
    );
    const context = buildContext(fixture);
    const oversized = Buffer.concat([
      context.artifact,
      Buffer.from('untrusted trailing bytes', 'utf8')
    ]);
    const singleChunk = await normalizeAt(
      normalizer,
      context.input,
      chunks(oversized, [oversized.byteLength])
    );
    const byteChunks = await normalizeAt(
      normalizer,
      context.input,
      chunks(oversized, [1])
    );

    expect(singleChunk).toEqual(byteChunks);
    expect(singleChunk).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: [
        'NORMALIZATION_CONTENT_DIGEST_MISMATCH',
        'NORMALIZATION_BYTE_SIZE_MISMATCH'
      ]
    });
  });

  it('converts artifact source failures into bounded rejection metadata', async () => {
    const fixture = loadSarifFixture(
      'upstream-compatible.sarif.json'
    );
    const context = buildContext(fixture);
    async function* failingArtifact(): AsyncGenerator<Uint8Array> {
      yield context.artifact.subarray(0, 17);
      throw new Error('secret object-store detail');
    }

    const result = await normalizeAt(
      normalizer,
      context.input,
      failingArtifact()
    );

    expect(result.outcome).toBe('REJECTED');
    if (result.outcome !== 'REJECTED') return;
    expect(result.reasonCodes).toContain(
      'NORMALIZATION_ARTIFACT_STREAM_INVALID'
    );
    expect(JSON.stringify(result)).not.toContain(
      'secret object-store detail'
    );
  });

  it('maps a missing severity to INFO with an explicit note', async () => {
    const fixture = loadSarifFixture(
      'upstream-compatible.sarif.json'
    );
    delete fixture.runs[0].tool.driver.rules[0]!
      .defaultConfiguration;
    const result = await normalizeFixture(normalizer, fixture);

    expect(result.outcome).toBe('NORMALIZED');
    if (result.outcome !== 'NORMALIZED') return;
    const finding = result.batch.findings.find(
      (candidate) =>
        candidate.provenance.ruleId === 'rules.null-deref'
    );
    expect(finding).toMatchObject({
      severity: 'INFO',
      notes: ['UNKNOWN_SEVERITY', 'UNKNOWN_CONFIDENCE']
    });
  });

  it('rejects unknown explicit levels and duplicate rule descriptors', async () => {
    const unknownLevel = loadSarifFixture(
      'upstream-compatible.sarif.json'
    );
    unknownLevel.runs[0].tool.driver.rules[0]!
      .defaultConfiguration!.level = 'fatal';
    const unknownResult = await normalizeFixture(
      normalizer,
      unknownLevel
    );
    expect(unknownResult).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: ['NORMALIZATION_OPENGREP_RULE_INVALID']
    });

    const duplicateRule = loadSarifFixture(
      'upstream-compatible.sarif.json'
    );
    duplicateRule.runs[0].tool.driver.rules[1]!.id =
      'rules.null-deref';
    duplicateRule.runs[0].tool.driver.rules[1]!.name =
      'rules.null-deref';
    const duplicateResult = await normalizeFixture(
      normalizer,
      duplicateRule
    );
    expect(duplicateResult.outcome).toBe('REJECTED');
    if (duplicateResult.outcome !== 'REJECTED') return;
    expect(duplicateResult.reasonCodes).toContain(
      'NORMALIZATION_OPENGREP_RULE_INVALID'
    );
  });

  it('emits explicit UNKNOWN location when attested metadata is unavailable', async () => {
    const fixture = loadSarifFixture(
      'upstream-compatible.sarif.json'
    );
    const context = buildContext(fixture);
    const result = await normalizeAt(
      normalizer,
      {
        ...context.input,
        coordinateAttestation: null
      },
      chunks(context.artifact, [31])
    );

    expect(result.outcome).toBe('NORMALIZED');
    if (result.outcome !== 'NORMALIZED') return;
    const finding = result.batch.findings.find(
      (candidate) =>
        candidate.provenance.ruleId === 'rules.sql-injection'
    );
    expect(finding?.location).toEqual({
      kind: 'UNKNOWN',
      reasonCode: 'LOCATION_NOT_MAPPABLE'
    });
  });

  it('rejects scanner output with execution notifications or a missing match identity hint', async () => {
    const notified = loadSarifFixture(
      'upstream-compatible.sarif.json'
    );
    notified.runs[0].invocations[0]!
      .toolExecutionNotifications.push({
        message: { text: 'partial scan' }
      });
    const notifiedResult = await normalizeFixture(
      normalizer,
      notified
    );
    expect(notifiedResult).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: ['NORMALIZATION_OPENGREP_INVOCATION_INVALID']
    });

    const missingIdentity = loadSarifFixture(
      'upstream-compatible.sarif.json'
    );
    delete missingIdentity.runs[0].results[0]!.fingerprints[
      'matchBasedId/v1'
    ];
    const identityResult = await normalizeFixture(
      normalizer,
      missingIdentity
    );
    expect(identityResult).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: ['NORMALIZATION_OPENGREP_RESULT_INVALID']
    });
  });

  it('rejects over-limit normalized text rather than truncating it', async () => {
    const fixture = loadSarifFixture(
      'upstream-compatible.sarif.json'
    );
    fixture.runs[0].tool.driver.rules[0]!.shortDescription = {
      text: '가'.repeat(200)
    };
    const result = await normalizeFixture(normalizer, fixture);

    expect(result.outcome).toBe('REJECTED');
    if (result.outcome !== 'REJECTED') return;
    expect(result.reasonCodes).toContain(
      'NORMALIZATION_FIELD_LIMIT_EXCEEDED'
    );
  });

  it('rejects unpaired Unicode surrogates before canonicalization', async () => {
    const fixture = loadSarifFixture(
      'upstream-compatible.sarif.json'
    );
    fixture.runs[0].results[0]!.message.text =
      'invalid surrogate \ud800';
    const result = await normalizeFixture(normalizer, fixture);

    expect(result).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: ['NORMALIZATION_ARTIFACT_STREAM_INVALID']
    });
  });

  it('bounds raw rule tags and normalized vulnerability identifiers', async () => {
    const tagBomb = loadSarifFixture(
      'upstream-compatible.sarif.json'
    );
    tagBomb.runs[0].tool.driver.rules[0]!.properties.tags =
      Array.from({ length: 129 }, (_, index) => `tag-${index}`);
    const tagResult = await normalizeFixture(normalizer, tagBomb);
    expect(tagResult).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: ['NORMALIZATION_OPENGREP_RULE_INVALID']
    });

    const identifiers = loadSarifFixture(
      'upstream-compatible.sarif.json'
    );
    identifiers.runs[0].tool.driver.rules[0]!.properties.tags =
      Array.from(
        { length: 26 },
        (_, index) => `CWE-${index + 1}: bounded fixture`
      );
    const identifierResult = await normalizeFixture(
      normalizer,
      identifiers
    );
    expect(identifierResult).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: ['NORMALIZATION_IDENTIFIER_LIMIT_EXCEEDED']
    });

    const oversizedIdentifier = loadSarifFixture(
      'upstream-compatible.sarif.json'
    );
    oversizedIdentifier.runs[0].tool.driver.rules[0]!
      .properties.tags = [`CVE-2026-${'1'.repeat(65)}`];
    const oversizedIdentifierResult = await normalizeFixture(
      normalizer,
      oversizedIdentifier
    );
    expect(oversizedIdentifierResult).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: ['NORMALIZATION_IDENTIFIER_LIMIT_EXCEEDED']
    });
  });
});

function normalizeAt(
  normalizer: OpenGrepSarifNormalizer,
  input: Readonly<OpenGrepSarifNormalizationInput>,
  artifact: AsyncIterable<Uint8Array>,
  referenceTime = NORMALIZED_AT
) {
  return normalizer.normalize(
    input,
    artifact,
    () => new Date(referenceTime)
  );
}

async function normalizeFixture(
  normalizer: OpenGrepSarifNormalizer,
  fixture: FixtureSarif
) {
  const context = buildContext(fixture);
  return normalizeAt(
    normalizer,
    context.input,
    chunks(context.artifact, [5, 4091, 13])
  );
}

function buildContext(fixture: FixtureSarif): {
  input: OpenGrepSarifNormalizationInput;
  artifact: Buffer;
} {
  const artifact = Buffer.from(JSON.stringify(fixture), 'utf8');
  const plan = buildPlan();
  const envelope = buildEnvelope(
    plan,
    artifact,
    fixture.runs[0].results.length
  );
  const envelopeDigest = digest(
    canonicalizeScannerArtifactEnvelope(envelope)
  );
  const validation = buildValidation(
    envelope,
    envelopeDigest
  );
  const disposition = buildAcceptedDisposition(validation);
  const expectedBinding: ExpectedScannerArtifactBinding = {
    attemptId: envelope.attemptId,
    scannerRunId: envelope.scannerRunId,
    scanner: envelope.scanner,
    artifactRef: envelope.artifactRef,
    workloadIdentityRef: envelope.workloadIdentityRef,
    preflightAttestationRef: envelope.preflightAttestationRef,
    preflightInventoryDigest: envelope.preflightInventoryDigest
  };
  return {
    artifact,
    input: {
      ingestionId: disposition.ingestionId,
      envelope,
      envelopeDigest,
      plan,
      expectedBinding,
      validation,
      disposition,
      coordinateAttestation: coordinateAttestation()
    }
  };
}

function buildEnvelope(
  plan: Readonly<SastScanPlan>,
  artifact: Buffer,
  recordCount: number
): ScannerArtifactEnvelope {
  const scanner = plan.scannerSet.scanners.OPENGREP;
  const ruleBundle = plan.scannerSet.ruleBundles.find(
    (bundle) => bundle.scanner === 'OPENGREP'
  )!;
  return {
    tenantId: plan.tenantId,
    repositoryBindingId:
      plan.repositoryState.repositoryBindingId,
    scanRequestId: plan.scanRequestId,
    attemptId: 'attempt-1',
    scannerRunId: 'scanner-run-opengrep',
    workloadIdentityRef: 'spiffe://aegis/scan/attempt-1',
    scanner: 'OPENGREP',
    scannerVersion: scanner.version,
    scannerImageDigest: scanner.digest,
    wrapperDigest: scanner.wrapper.digest,
    ruleBundleDigest: ruleBundle.digest,
    scannerSetDigest: plan.scannerSet.scannerSetDigest,
    schemaBundleDigest: plan.scannerSet.schemaBundle.digest,
    normalizerBundleDigest:
      plan.scannerSet.normalizerBundle.digest,
    profileId: plan.profile.id,
    profileDigest: plan.profileDigest,
    preflightAttestationRef: 'preflight://attempt-1',
    preflightInventoryDigest: digest('inventory'),
    scannerWorkspaceInventoryDigest: digest('inventory'),
    inputCommitSha: plan.repositoryState.fixedCommitSha,
    artifactSchema: 'OPENGREP_SARIF',
    artifactSchemaVersion:
      SAST_ARTIFACT_SCHEMA_VERSIONS.OPENGREP_SARIF,
    artifactRef:
      'result-ingress://tenant-1/scan-1/opengrep',
    contentDigest: digest(artifact),
    byteSize: artifact.byteLength,
    recordCount,
    truncated: false,
    exitCode: 0,
    executionStatus: 'SUCCEEDED',
    producedAt: '2026-07-26T12:00:00.000Z'
  };
}

function buildValidation(
  envelope: Readonly<ScannerArtifactEnvelope>,
  envelopeDigest: `sha256:${string}`
): SastArtifactValidationResult {
  const core: SastArtifactValidationResultCore = {
    version: SAST_ARTIFACT_VALIDATION_VERSION,
    outcome: 'PASSED',
    artifactSchema: 'OPENGREP_SARIF',
    envelopeDigest,
    observedContentDigest: envelope.contentDigest,
    checks: {
      planBinding: true,
      schema: true,
      contentDigest: true,
      byteSize: true,
      recordCount: true,
      encoding: true,
      jsonStructure: true,
      path: true,
      coordinate: true
    },
    reasonCodes: [],
    statistics: {
      observedByteSize: envelope.byteSize,
      observedRecordCount: envelope.recordCount,
      maximumObservedDepth: 16,
      maximumObservedStringBytes: 4096,
      normalizedPathCount: 2,
      coordinateCount: 6
    }
  };
  return {
    ...core,
    resultDigest: digest(
      canonicalizeSastArtifactValidationResult(core)
    )
  };
}

function buildAcceptedDisposition(
  validation: Readonly<SastArtifactValidationResult>
): SastArtifactDispositionDecision {
  const intentDigest = digest('accepted-intent');
  const core: SastArtifactDispositionDecisionCore = {
    version: SAST_ARTIFACT_DISPOSITION_VERSION,
    ingestionId: 'ingestion-opengrep-1',
    disposition: 'ACCEPTED',
    storageAction: 'RETAIN_ACCEPTED',
    reasonCodes: ['ARTIFACT_VALIDATION_ACCEPTED'],
    validationReasonCodes: [],
    validationResultDigest: validation.resultDigest,
    normalizationEligible: true,
    retentionExpiresAt: RETENTION_EXPIRES_AT,
    acceptanceControlRef: 'acceptance://policy/allow',
    intentDigest,
    storageOperationId:
      `${SAST_ARTIFACT_DISPOSITION_VERSION}:${intentDigest.slice(
        'sha256:'.length
      )}`,
    storageReceiptRef:
      'storage-receipt://accepted/opengrep-1',
    storageReceiptDigest: digest('accepted-receipt'),
    decidedAt: DECIDED_AT
  };
  return {
    ...core,
    decisionDigest: digest(
      canonicalizeSastArtifactDispositionDecision(core)
    )
  };
}

function buildPlan(): SastScanPlan {
  const profile = SAST_SCAN_PROFILES.JAVA_FAST_V1;
  const signed = (value: string) => ({
    digest: digest(value),
    signatureRef: `signature://${value}`,
    provenanceRef: `provenance://${value}`
  });
  const scanner = (
    kind: 'OPENGREP' | 'TRIVY' | 'SYFT',
    version: string
  ) => ({
    ...signed(`scanner-${kind}`),
    scanner: kind,
    version,
    sbomRef: `sbom://${kind.toLowerCase()}`,
    wrapper: signed(`wrapper-${kind}`)
  });
  const rule = (kind: 'OPENGREP' | 'TRIVY') => ({
    ...signed(`rule-${kind}`),
    bundleId: `${kind.toLowerCase()}-rules`,
    version: '2026.07.0',
    state: 'ACTIVE' as const,
    compatibilityRef: `compatibility://${kind}`,
    rolloutPolicyRef: `rollout://${kind}`,
    killSwitchRef: `kill-switch://${kind}`,
    scanner: kind,
    source: 'PLATFORM_MANAGED' as const,
    immutable: true as const,
    customerExecutableConfigAllowed: false as const
  });
  return {
    tenantId: 'tenant-1',
    scanRequestId: 'scan-1',
    canonicalScanKey: digest('canonical'),
    profile,
    profileDigest: SAST_APPROVED_PROFILE_DIGESTS[profile.id],
    policyVersion: 'policy-v1',
    repositoryState: {
      repositoryBindingId: 'repository-1',
      fixedCommitSha: FIXED_COMMIT,
      targetRef: 'refs/heads/main',
      inventoryDigest: digest('inventory'),
      attestationRef: 'preflight://attempt-1',
      shallowFetchPreferred: true,
      submodulesEnabled: false,
      lfsObjectsFetched: false
    },
    scannerSet: {
      scannerSetVersion: 'scanner-set-v1',
      scannerSetDigest: digest('scanner-set'),
      signatureRef: 'signature://scanner-set',
      provenanceRef: 'provenance://scanner-set',
      scanners: {
        OPENGREP: scanner('OPENGREP', '1.22.0'),
        TRIVY: scanner('TRIVY', '0.66.0'),
        SYFT: scanner('SYFT', '1.30.0')
      },
      ruleBundles: [rule('OPENGREP'), rule('TRIVY')],
      vulnerabilityDatabase: {
        ...signed('trivy-db'),
        databaseVersion: '2026-07-24',
        publishedAt: '2026-07-24T00:00:00.000Z'
      },
      schemaBundle: signed('schema'),
      normalizerBundle: signed('normalizer'),
      sbomSchema: 'CYCLONEDX_JSON',
      rollbackRef: 'rollback://scanner-set-v0'
    },
    isolationClass: 'HARDENED',
    resultIngressRef: 'result-ingress://tenant-1/scan-1',
    evidenceOutputRef: 'evidence-output://tenant-1/scan-1',
    auditSinkRef: 'audit-sink://tenant-1/scan-1',
    forbiddenCapabilities: [...SAST_FORBIDDEN_CAPABILITIES],
    createdAt: '2026-07-26T11:00:00.000Z'
  };
}

function coordinateAttestation(): SastFileCoordinateAttestation {
  return {
    attestationRef: 'preflight://attempt-1',
    inventoryDigest: digest('inventory'),
    verified: true,
    files: [
      {
        normalizedPath: 'src/Café.java',
        lineCount: 10,
        maxColumnByLine: new Array<number>(10).fill(120)
      },
      {
        normalizedPath: 'src/Other.java',
        lineCount: 10,
        maxColumnByLine: new Array<number>(10).fill(120)
      }
    ]
  };
}

async function* chunks(
  artifact: Buffer,
  sizes: readonly number[]
): AsyncGenerator<Uint8Array> {
  let offset = 0;
  let index = 0;
  while (offset < artifact.byteLength) {
    const size = Math.max(sizes[index % sizes.length] ?? 1, 1);
    const end = Math.min(offset + size, artifact.byteLength);
    yield artifact.subarray(offset, end);
    offset = end;
    index += 1;
  }
}

async function* chunksWithEmptySegments(
  artifact: Buffer,
  sizes: readonly number[]
): AsyncGenerator<Uint8Array> {
  yield Buffer.alloc(0);
  for await (const chunk of chunks(artifact, sizes)) {
    yield chunk;
    yield Buffer.alloc(0);
  }
}

function loadSarifFixture(name: string): FixtureSarif {
  return loadJsonFixture(name) as FixtureSarif;
}

function loadJsonFixture(name: string): unknown {
  return JSON.parse(
    readFileSync(
      join(
        __dirname,
        '..',
        'fixtures',
        'opengrep-sarif',
        name
      ),
      'utf8'
    )
  ) as unknown;
}

function digest(value: string | Uint8Array): `sha256:${string}` {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}
