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
  buildSastScanPlanDigestPreimage,
  canonicalizeSastArtifactDispositionDecision,
  canonicalizeSastArtifactValidationResult,
  canonicalizeScannerArtifactEnvelope,
  canonicalizeTrivyJsonNormalizationBatch,
  isTrivyJsonNormalizationBatchShapeValid,
  type ExpectedScannerArtifactBinding,
  type SastArtifactDispositionDecision,
  type SastArtifactDispositionDecisionCore,
  type SastArtifactValidationResult,
  type SastArtifactValidationResultCore,
  type SastScanPlan,
  type ScannerArtifactEnvelope
} from '@aegisai/shared';

import {
  TrivyJsonNormalizer,
  type TrivyJsonNormalizationInput
} from '../../src/scan-plane/trivy-json-normalizer';
import {
  SastArtifactStreamValidationSession
} from '../../src/scan-plane/sast-artifact-stream-validator';
import type {
  SastFileCoordinateAttestation
} from '../../src/scan-plane/sast-file-coordinate-attestation.provider';

const FIXED_COMMIT = 'b'.repeat(40);
const NORMALIZED_AT = '2026-07-26T12:02:00.000Z';
const DECIDED_AT = '2026-07-26T12:01:00.000Z';
const RETENTION_EXPIRES_AT = '2026-08-01T12:00:00.000Z';

interface FixtureVulnerability {
  VulnerabilityID: string;
  VendorIDs?: string[];
  PkgName: string;
  PkgIdentifier?: { PURL?: string };
  InstalledVersion: string;
  FixedVersion?: string;
  Status?: string;
  Title?: string;
  Description?: string;
  Severity?: string;
  CweIDs?: string[];
}

interface FixtureMisconfiguration {
  Type: string;
  ID: string;
  AVDID?: string;
  Title: string;
  Description?: string;
  Message?: string;
  Severity: string;
  Status: string;
  CauseMetadata?: {
    StartLine?: number;
    EndLine?: number;
  };
}

interface FixtureSecret {
  RuleID: string;
  Category: string;
  Severity: string;
  Title: string;
  StartLine: number;
  EndLine: number;
  Match?: string;
  Code?: unknown;
}

interface FixtureModifiedFinding {
  Type: string;
  Status: string;
  Statement?: string;
  Source?: string;
  Finding: Record<string, unknown>;
}

interface FixtureResult {
  Target: string;
  Class: string;
  Type?: string;
  Vulnerabilities?: FixtureVulnerability[];
  Misconfigurations?: FixtureMisconfiguration[];
  Secrets?: FixtureSecret[];
  ExperimentalModifiedFindings?: FixtureModifiedFinding[];
}

interface FixtureTrivy {
  SchemaVersion: number;
  CreatedAt?: string;
  ArtifactName?: string;
  ArtifactType: string;
  Metadata?: unknown;
  Results: FixtureResult[];
}

describe('TrivyJsonNormalizer', () => {
  const normalizer = new TrivyJsonNormalizer();

  it('normalizes vulnerability, IaC, direct secret, and modified secret records byte-exactly across chunking', async () => {
    const fixture = loadTrivyFixture(
      'upstream-compatible.trivy.json'
    );
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

    expect(first.batch.findings.map((finding) => ({
      capability: finding.capability,
      ruleId: finding.provenance.ruleId,
      ruleSource: finding.provenance.ruleSource,
      severity: finding.severity,
      confidence: finding.confidence,
      cweIds: finding.cweIds,
      cveIds: finding.cveIds,
      location: finding.location,
      scannerDisposition: finding.scannerDisposition,
      trivy: finding.trivy
    }))).toEqual(
      loadJsonFixture('upstream-compatible.expected.json')
    );
    expect(
      isTrivyJsonNormalizationBatchShapeValid(first.batch)
    ).toBe(true);
    expect(first.batch).toMatchObject({
      scanner: 'TRIVY',
      scannerVersion: '0.66.0',
      scannerRunId: context.input.envelope.scannerRunId,
      scannerImageDigest:
        context.input.envelope.scannerImageDigest,
      ruleBundleDigest:
        context.input.envelope.ruleBundleDigest,
      vulnerabilityDatabaseDigest:
        context.input.envelope.vulnerabilityDatabaseDigest,
      planDigest: digest(
        buildSastScanPlanDigestPreimage(context.input.plan)
      ),
      canonicalScanKey: context.input.plan.canonicalScanKey,
      durablePersistenceAllowed: false
    });
    const serialized = JSON.stringify(first);
    for (const forbidden of [
      'AKIA_SYNTHETIC_NEVER_COPY',
      'ghp_SYNTHETIC_NEVER_COPY',
      'ghp_SECOND_SYNTHETIC_NEVER_COPY',
      'UNTRUSTED-MISCONFIG-MESSAGE-MUST-NOT-BE-COPIED',
      'UNTRUSTED-TRACE-MUST-NOT-BE-COPIED',
      'UNTRUSTED-SUPPRESSION-STATEMENT',
      'customer-controlled.trivyignore',
      'SHOULD-NOT-BE-COPIED',
      'Fixture dependency vulnerability',
      'A deterministic dependency vulnerability',
      'Image user should not be root',
      'Run the container as a non-root user',
      'AWS Access Key ID',
      'GitHub Personal Access Token'
    ]) {
      expect(serialized).not.toContain(forbidden);
    }
    expect(
      first.batch.findings.every(
        (finding) =>
          finding.durablePersistenceAllowed === false &&
          finding.scannerDisposition.platformPolicyAuthority ===
            false
      )
    ).toBe(true);
    expect(first.batch.findings[0]).not.toHaveProperty(
      'stableFingerprint'
    );
    expect(first.batch.findings[0]).not.toHaveProperty(
      'evidencePackIds'
    );
    expect(first.batch.findings[0]).not.toHaveProperty('status');
    const { batchDigest, ...batchCore } = first.batch;
    expect(batchDigest).toBe(
      digest(canonicalizeTrivyJsonNormalizationBatch(batchCore))
    );
  });

  it('keeps secret identity independent of Match, Code, Statement, and Source payloads', async () => {
    const original = loadTrivyFixture(
      'upstream-compatible.trivy.json'
    );
    const changed = structuredClone(original);
    const directSecret = changed.Results[2]!.Secrets![0]!;
    directSecret.Match = 'DIFFERENT_DIRECT_SECRET';
    const directCode = directSecret.Code as {
      Lines: Array<Record<string, unknown>>;
    };
    directCode.Lines[0]!.Content =
      'export OTHER_TOKEN=DIFFERENT_NEARBY_SECRET';
    directCode.Lines[0]!.Highlighted =
      'export OTHER_TOKEN=DIFFERENT_NEARBY_SECRET';
    const modified =
      changed.Results[2]!.ExperimentalModifiedFindings![0]!;
    modified.Statement = 'different scanner statement';
    modified.Source = './different-untrusted-source';
    modified.Finding.Match = 'DIFFERENT_MODIFIED_SECRET';
    const modifiedCode = modified.Finding.Code as {
      Lines: Array<Record<string, unknown>>;
    };
    modifiedCode.Lines[0]!.Content =
      'export GITHUB_TOKEN=DIFFERENT_CONTEXT_SECRET';

    const originalContext = buildContext(original);
    const changedContext = buildContext(changed);
    const originalResult = await normalizeAt(
      normalizer,
      originalContext.input,
      chunks(originalContext.artifact, [37])
    );
    const changedResult = await normalizeAt(
      normalizer,
      changedContext.input,
      chunks(changedContext.artifact, [4096, 3])
    );
    expect(originalResult.outcome).toBe('NORMALIZED');
    expect(changedResult.outcome).toBe('NORMALIZED');
    if (
      originalResult.outcome !== 'NORMALIZED' ||
      changedResult.outcome !== 'NORMALIZED'
    ) {
      return;
    }

    const projectSecrets = (
      result: typeof originalResult
    ) =>
      result.batch.findings
        .filter(
          (finding) => finding.capability === 'SECRET_DETECTION'
        )
        .map((finding) => ({
          ruleId: finding.provenance.ruleId,
          title: finding.title,
          description: finding.description,
          identityMaterial: finding.identityMaterial,
          trivy: finding.trivy
        }));
    expect(projectSecrets(changedResult)).toEqual(
      projectSecrets(originalResult)
    );
    expect(changedResult.batch.artifactDigest).not.toBe(
      originalResult.batch.artifactDigest
    );
    expect(changedResult.batch.batchDigest).not.toBe(
      originalResult.batch.batchDigest
    );
  });

  it('keeps secret and IaC structural identity line-independent while distinguishing ordered occurrences', async () => {
    const original = loadTrivyFixture(
      'upstream-compatible.trivy.json'
    );
    const secondSecret = structuredClone(
      original.Results[2]!.Secrets![0]!
    );
    secondSecret.StartLine = 5;
    secondSecret.EndLine = 5;
    secondSecret.Match = 'SECOND_SYNTHETIC_SECRET';
    original.Results[2]!.Secrets!.push(secondSecret);

    const shifted = structuredClone(original);
    const shiftedMisconfiguration =
      shifted.Results[1]!.Misconfigurations![0]!;
    shiftedMisconfiguration.CauseMetadata!.StartLine = 3;
    shiftedMisconfiguration.CauseMetadata!.EndLine = 3;
    shifted.Results[2]!.Secrets![0]!.StartLine = 4;
    shifted.Results[2]!.Secrets![0]!.EndLine = 4;
    shifted.Results[2]!.Secrets![1]!.StartLine = 6;
    shifted.Results[2]!.Secrets![1]!.EndLine = 6;
    const shiftedModified =
      shifted.Results[2]!.ExperimentalModifiedFindings![0]!
        .Finding;
    shiftedModified.StartLine = 8;
    shiftedModified.EndLine = 8;

    const originalContext = buildContext(original);
    const shiftedContext = buildContext(shifted);
    const originalResult = await normalizeAt(
      normalizer,
      originalContext.input,
      chunks(originalContext.artifact, [19, 4077])
    );
    const shiftedResult = await normalizeAt(
      normalizer,
      shiftedContext.input,
      chunks(shiftedContext.artifact, [4095, 1])
    );
    expect(originalResult.outcome).toBe('NORMALIZED');
    expect(shiftedResult.outcome).toBe('NORMALIZED');
    if (
      originalResult.outcome !== 'NORMALIZED' ||
      shiftedResult.outcome !== 'NORMALIZED'
    ) {
      return;
    }

    const projectIdentity = (
      result: typeof originalResult
    ) =>
      result.batch.findings
        .filter(
          (finding) =>
            finding.capability === 'SECRET_DETECTION' ||
            finding.capability === 'IAC_MISCONFIGURATION'
        )
        .map((finding) => ({
          ruleId: finding.provenance.ruleId,
          identityMaterial: finding.identityMaterial
        }));
    expect(projectIdentity(shiftedResult)).toEqual(
      projectIdentity(originalResult)
    );
    expect(
      shiftedResult.batch.findings.map(
        (finding) => finding.location
      )
    ).not.toEqual(
      originalResult.batch.findings.map(
        (finding) => finding.location
      )
    );
    const awsIdentities = projectIdentity(originalResult)
      .filter(({ ruleId }) => ruleId === 'aws-access-key-id')
      .map(({ identityMaterial }) =>
        identityMaterial.scannerMatchBasedId
      );
    expect(awsIdentities).toHaveLength(2);
    expect(new Set(awsIdentities).size).toBe(2);
  });

  it('distinguishes the same dependency advisory across canonical package targets', async () => {
    const fixture = loadTrivyFixture(
      'upstream-compatible.trivy.json'
    );
    const secondTarget = structuredClone(fixture.Results[0]!);
    fixture.Results[0]!.Target = 'apps/a/package-lock.json';
    secondTarget.Target = 'apps/b/package-lock.json';
    fixture.Results.push(secondTarget);

    const result = await normalizeFixture(normalizer, fixture);
    expect(result.outcome).toBe('NORMALIZED');
    if (result.outcome !== 'NORMALIZED') return;

    const dependencies = result.batch.findings.filter(
      (finding) =>
        finding.capability === 'DEPENDENCY_VULNERABILITY'
    );
    expect(dependencies).toHaveLength(2);
    expect(
      new Set(
        dependencies.map(
          (finding) =>
            finding.identityMaterial.scannerMatchBasedId
        )
      ).size
    ).toBe(2);
    expect(
      dependencies.every(
        (finding) =>
          finding.location.kind === 'UNKNOWN' &&
          finding.location.reasonCode ===
            'SCANNER_LOCATION_OMITTED'
      )
    ).toBe(true);
  });

  it('accepts the same pinned producer shape through T030 before T033', async () => {
    const fixture = loadTrivyFixture(
      'upstream-compatible.trivy.json'
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
      void _chunk;
    }
    const validation = session.finish();

    expect(validation.outcome).toBe('PASSED');
    expect(validation.statistics.observedRecordCount).toBe(4);
    const result = await normalizeAt(
      normalizer,
      {
        ...context.input,
        validation,
        disposition: buildAcceptedDisposition(validation)
      },
      chunks(context.artifact, [7, 4089])
    );
    expect(result.outcome).toBe('NORMALIZED');
  });

  it('retains modified scanner status only as non-authoritative provenance', async () => {
    const result = await normalizeFixture(
      normalizer,
      loadTrivyFixture('upstream-compatible.trivy.json')
    );
    expect(result.outcome).toBe('NORMALIZED');
    if (result.outcome !== 'NORMALIZED') return;
    const modified = result.batch.findings.find(
      (finding) => finding.provenance.ruleId === 'github-pat'
    );
    expect(modified?.scannerDisposition).toEqual({
      source: 'MODIFIED',
      status: 'ignored',
      platformPolicyAuthority: false
    });
    expect(modified).not.toHaveProperty('waiver');
    expect(modified).not.toHaveProperty('suppression');
    expect(modified).not.toHaveProperty('policyDecision');
  });

  it('maps an omitted zero-value Trivy advisory status to explicit unknown provenance', async () => {
    const fixture = loadTrivyFixture(
      'upstream-compatible.trivy.json'
    );
    delete fixture.Results[0]!.Vulnerabilities![0]!.Status;
    const result = await normalizeFixture(normalizer, fixture);
    expect(result.outcome).toBe('NORMALIZED');
    if (result.outcome !== 'NORMALIZED') return;
    const dependency = result.batch.findings.find(
      (finding) =>
        finding.capability === 'DEPENDENCY_VULNERABILITY'
    );
    expect(dependency?.trivy).toMatchObject({
      advisoryStatus: 'unknown'
    });
  });

  it('retains full Trivy supply-chain provenance for an accepted zero-finding batch', async () => {
    const fixture = loadTrivyFixture(
      'upstream-compatible.trivy.json'
    );
    fixture.Results = [];
    const result = await normalizeFixture(normalizer, fixture);

    expect(result.outcome).toBe('NORMALIZED');
    if (result.outcome !== 'NORMALIZED') return;
    expect(result.batch.findings).toEqual([]);
    expect(result.batch).toMatchObject({
      scanner: 'TRIVY',
      scannerVersion: '0.66.0',
      ruleBundleDigest: digest('rule-TRIVY'),
      vulnerabilityDatabaseDigest: digest('trivy-db'),
      durablePersistenceAllowed: false
    });
  });

  it('rejects acceptance, plan, database, and supplied-attestation drift before reading artifact bytes', async () => {
    const fixture = loadTrivyFixture(
      'upstream-compatible.trivy.json'
    );
    const cases: Array<{
      mutate(input: TrivyJsonNormalizationInput): void;
      expected: string;
    }> = [
      {
        mutate(input) {
          input.disposition = {
            ...input.disposition,
            disposition: 'QUARANTINED'
          } as SastArtifactDispositionDecision;
        },
        expected: 'NORMALIZATION_ACCEPTANCE_INVALID'
      },
      {
        mutate(input) {
          input.envelope = {
            ...input.envelope,
            scanner: 'OPENGREP'
          };
        },
        expected: 'NORMALIZATION_PLAN_BINDING_MISMATCH'
      },
      {
        mutate(input) {
          input.envelope = {
            ...input.envelope,
            vulnerabilityDatabaseDigest: digest('another-db')
          };
        },
        expected: 'NORMALIZATION_PLAN_BINDING_MISMATCH'
      },
      {
        mutate(input) {
          input.plan = {
            ...input.plan,
            scannerSet: {
              ...input.plan.scannerSet,
              vulnerabilityDatabase: undefined
            }
          } as unknown as SastScanPlan;
        },
        expected: 'NORMALIZATION_PLAN_BINDING_MISMATCH'
      },
      {
        mutate(input) {
          input.coordinateAttestation = {
            ...coordinateAttestation(),
            inventoryDigest: digest('drifted-inventory')
          };
        },
        expected: 'NORMALIZATION_PLAN_BINDING_MISMATCH'
      }
    ];

    for (const testCase of cases) {
      const context = buildContext(fixture);
      testCase.mutate(context.input);
      let read = false;
      const result = await normalizeAt(
        normalizer,
        context.input,
        trackingChunks(context.artifact, () => {
          read = true;
        })
      );
      expect(read).toBe(false);
      expect(result).toMatchObject({
        outcome: 'REJECTED',
        reasonCodes: expect.arrayContaining([testCase.expected])
      });
      expect(JSON.stringify(result)).not.toContain('artifactRef');
    }
  });

  it('distinguishes an unavailable coordinate provider from malformed supplied coordinates', async () => {
    const fixture = loadTrivyFixture(
      'upstream-compatible.trivy.json'
    );
    const unavailable = buildContext(fixture);
    unavailable.input.coordinateAttestation = null;
    const normalized = await normalizeAt(
      normalizer,
      unavailable.input,
      chunks(unavailable.artifact, [17, 4079])
    );
    expect(normalized.outcome).toBe('NORMALIZED');
    if (normalized.outcome === 'NORMALIZED') {
      const locatedCapabilities = normalized.batch.findings
        .filter(
          (finding) =>
            finding.capability === 'SECRET_DETECTION' ||
            finding.capability === 'IAC_MISCONFIGURATION'
        )
        .map((finding) => finding.location);
      expect(locatedCapabilities).toEqual([
        {
          kind: 'UNKNOWN',
          reasonCode: 'LOCATION_NOT_MAPPABLE'
        },
        {
          kind: 'UNKNOWN',
          reasonCode: 'LOCATION_NOT_MAPPABLE'
        },
        {
          kind: 'UNKNOWN',
          reasonCode: 'LOCATION_NOT_MAPPABLE'
        }
      ]);
    }

    const malformed = buildContext(fixture);
    malformed.input.coordinateAttestation = {
      ...coordinateAttestation(),
      files: [
        ...coordinateAttestation().files,
        coordinateAttestation().files[0]!
      ]
    };
    const rejected = await normalizeAt(
      normalizer,
      malformed.input,
      chunks(malformed.artifact, [4096])
    );
    expect(rejected).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: ['NORMALIZATION_TRIVY_LOCATION_INVALID']
    });
  });

  it('rejects class, status, package, rule, coordinate, and duplicate identity ambiguity as whole batches', async () => {
    const mutations: Array<{
      mutate(fixture: FixtureTrivy): void;
      expected: string;
    }> = [
      {
        mutate(fixture) {
          fixture.Results[0]!.Class = 'os-pkgs';
        },
        expected: 'NORMALIZATION_TRIVY_RESULT_INVALID'
      },
      {
        mutate(fixture) {
          fixture.Results[0]!.Vulnerabilities![0]!.Status =
            'future-status';
        },
        expected: 'NORMALIZATION_TRIVY_VULNERABILITY_INVALID'
      },
      {
        mutate(fixture) {
          fixture.Results[0]!.Vulnerabilities![0]!.InstalledVersion =
            '';
        },
        expected: 'NORMALIZATION_TRIVY_PACKAGE_INVALID'
      },
      {
        mutate(fixture) {
          fixture.Results[0]!.Vulnerabilities![0]!.PkgName =
            'fixture\ninjected';
        },
        expected: 'NORMALIZATION_TRIVY_PACKAGE_INVALID'
      },
      {
        mutate(fixture) {
          fixture.Results[1]!.Misconfigurations![0]!.ID =
            'unsigned-rule';
        },
        expected: 'NORMALIZATION_TRIVY_MISCONFIGURATION_INVALID'
      },
      {
        mutate(fixture) {
          fixture.Results[2]!.Secrets![0]!.EndLine = 999;
        },
        expected: 'NORMALIZATION_TRIVY_LOCATION_INVALID'
      },
      {
        mutate(fixture) {
          delete fixture.Results[2]!.Secrets![0]!.Match;
        },
        expected: 'NORMALIZATION_TRIVY_SECRET_INVALID'
      },
      {
        mutate(fixture) {
          delete fixture.Results[2]!.Secrets![0]!.Code;
        },
        expected: 'NORMALIZATION_TRIVY_SECRET_INVALID'
      },
      {
        mutate(fixture) {
          fixture.Results[2]!.Secrets!.push(
            structuredClone(fixture.Results[2]!.Secrets![0]!)
          );
        },
        expected: 'NORMALIZATION_TRIVY_RESULT_INVALID'
      }
    ];
    for (const testCase of mutations) {
      const fixture = loadTrivyFixture(
        'upstream-compatible.trivy.json'
      );
      testCase.mutate(fixture);
      const result = await normalizeFixture(normalizer, fixture);
      expect(result).toMatchObject({
        outcome: 'REJECTED',
        reasonCodes: expect.arrayContaining([testCase.expected])
      });
    }
  });

  it('rejects unsupported modified capabilities and unknown suppression enums', async () => {
    const malicious = loadTrivyFixture(
      'malicious-modified-license.trivy.json'
    );
    const maliciousResult = await normalizeFixture(
      normalizer,
      malicious
    );
    expect(maliciousResult).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: expect.arrayContaining([
        'NORMALIZATION_TRIVY_SUPPRESSION_INVALID'
      ])
    });

    const unknownStatus = loadTrivyFixture(
      'upstream-compatible.trivy.json'
    );
    unknownStatus.Results[2]!.ExperimentalModifiedFindings![0]!
      .Status = 'waived';
    const unknownStatusResult = await normalizeFixture(
      normalizer,
      unknownStatus
    );
    expect(unknownStatusResult).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: ['NORMALIZATION_TRIVY_SUPPRESSION_INVALID']
    });
  });

  it('enforces text and identifier bounds without exposing rejected payloads', async () => {
    const oversized = loadTrivyFixture(
      'upstream-compatible.trivy.json'
    );
    oversized.Results[0]!.Vulnerabilities![0]!.PkgName =
      'x'.repeat(500);
    const oversizedResult = await normalizeFixture(
      normalizer,
      oversized
    );
    expect(oversizedResult).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: ['NORMALIZATION_FIELD_LIMIT_EXCEEDED']
    });

    const malformedIdentifier = loadTrivyFixture(
      'upstream-compatible.trivy.json'
    );
    malformedIdentifier.Results[0]!.Vulnerabilities![0]!.CweIDs =
      ['CWE-not-a-number'];
    const malformedResult = await normalizeFixture(
      normalizer,
      malformedIdentifier
    );
    expect(malformedResult).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: ['NORMALIZATION_IDENTIFIER_INVALID']
    });
    expect(JSON.stringify(malformedResult)).not.toContain(
      'Fixture dependency vulnerability'
    );
  });

  it('rehashes and recounts the stream and rejects malformed JSON, duplicate keys, and retention drift', async () => {
    const fixture = loadTrivyFixture(
      'upstream-compatible.trivy.json'
    );
    const digestMismatch = buildContext(fixture);
    digestMismatch.input = rebindEnvelope(
      digestMismatch.input,
      {
        ...digestMismatch.input.envelope,
        contentDigest: digest('different-content')
      }
    );
    const digestResult = await normalizeAt(
      normalizer,
      digestMismatch.input,
      chunks(digestMismatch.artifact, [4096])
    );
    expect(digestResult).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: ['NORMALIZATION_CONTENT_DIGEST_MISMATCH']
    });

    const context = buildContext(fixture);
    const countMismatchInput = rebindEnvelope(context.input, {
      ...context.input.envelope,
      recordCount: context.input.envelope.recordCount + 1
    });
    const countMismatchResult = await normalizeAt(
      normalizer,
      countMismatchInput,
      chunks(context.artifact, [13, 4083])
    );
    expect(countMismatchResult).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: ['NORMALIZATION_VALIDATION_BINDING_MISMATCH']
    });

    const byteMismatchInput = rebindEnvelope(context.input, {
      ...context.input.envelope,
      byteSize: context.input.envelope.byteSize + 1
    });
    const byteMismatchResult = await normalizeAt(
      normalizer,
      byteMismatchInput,
      chunks(context.artifact, [4095, 1])
    );
    expect(byteMismatchResult).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: ['NORMALIZATION_BYTE_SIZE_MISMATCH']
    });

    const malformedArtifact = Buffer.from(
      '{"SchemaVersion":2,"SchemaVersion":2,"ArtifactType":"filesystem","Results":[]}',
      'utf8'
    );
    const malformedEnvelope = buildEnvelope(
      context.input.plan,
      malformedArtifact,
      0
    );
    const malformedInput = rebindEnvelope(
      context.input,
      malformedEnvelope
    );
    const malformedResult = await normalizeAt(
      normalizer,
      malformedInput,
      chunks(malformedArtifact, [1])
    );
    expect(malformedResult).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: ['NORMALIZATION_ARTIFACT_STREAM_INVALID']
    });

    const surrogateArtifact = Buffer.from(
      '{"SchemaVersion":2,"ArtifactName":"\\uD800","ArtifactType":"filesystem","Results":[]}',
      'utf8'
    );
    const surrogateEnvelope = buildEnvelope(
      context.input.plan,
      surrogateArtifact,
      0
    );
    const surrogateInput = rebindEnvelope(
      context.input,
      surrogateEnvelope
    );
    const surrogateResult = await normalizeAt(
      normalizer,
      surrogateInput,
      chunks(surrogateArtifact, [1])
    );
    expect(surrogateResult).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: ['NORMALIZATION_ARTIFACT_STREAM_INVALID']
    });

    const expired = buildContext(fixture);
    const expiredResult = await normalizeAt(
      normalizer,
      expired.input,
      chunks(expired.artifact, [4096]),
      RETENTION_EXPIRES_AT
    );
    expect(expiredResult).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: ['NORMALIZATION_RETENTION_EXPIRED']
    });
  });
});

function normalizeAt(
  normalizer: TrivyJsonNormalizer,
  input: Readonly<TrivyJsonNormalizationInput>,
  artifact: AsyncIterable<Uint8Array>,
  referenceTime = NORMALIZED_AT
) {
  return normalizer.normalize(
    input,
    artifact,
    () => new Date(referenceTime)
  );
}

function rebindEnvelope(
  input: Readonly<TrivyJsonNormalizationInput>,
  envelope: ScannerArtifactEnvelope
): TrivyJsonNormalizationInput {
  const envelopeDigest = digest(
    canonicalizeScannerArtifactEnvelope(envelope)
  );
  const validation = buildValidation(envelope, envelopeDigest);
  return {
    ...input,
    envelope,
    envelopeDigest,
    validation,
    disposition: buildAcceptedDisposition(validation)
  };
}

async function normalizeFixture(
  normalizer: TrivyJsonNormalizer,
  fixture: FixtureTrivy
) {
  const context = buildContext(fixture);
  return normalizeAt(
    normalizer,
    context.input,
    chunks(context.artifact, [5, 4091, 13])
  );
}

function buildContext(fixture: FixtureTrivy): {
  input: TrivyJsonNormalizationInput;
  artifact: Buffer;
} {
  const artifact = Buffer.from(JSON.stringify(fixture), 'utf8');
  const plan = buildPlan();
  const envelope = buildEnvelope(
    plan,
    artifact,
    countFindings(fixture)
  );
  const envelopeDigest = digest(
    canonicalizeScannerArtifactEnvelope(envelope)
  );
  const validation = buildValidation(envelope, envelopeDigest);
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

function countFindings(fixture: Readonly<FixtureTrivy>): number {
  return fixture.Results.reduce(
    (count, result) =>
      count +
      (result.Vulnerabilities?.length ?? 0) +
      (result.Misconfigurations?.length ?? 0) +
      (result.Secrets?.length ?? 0) +
      (result.ExperimentalModifiedFindings?.length ?? 0),
    0
  );
}

function buildEnvelope(
  plan: Readonly<SastScanPlan>,
  artifact: Buffer,
  recordCount: number
): ScannerArtifactEnvelope {
  const scanner = plan.scannerSet.scanners.TRIVY;
  const ruleBundle = plan.scannerSet.ruleBundles.find(
    (bundle) => bundle.scanner === 'TRIVY'
  )!;
  return {
    tenantId: plan.tenantId,
    repositoryBindingId:
      plan.repositoryState.repositoryBindingId,
    scanRequestId: plan.scanRequestId,
    attemptId: 'attempt-1',
    scannerRunId: 'scanner-run-trivy',
    workloadIdentityRef: 'spiffe://aegis/scan/attempt-1',
    scanner: 'TRIVY',
    scannerVersion: scanner.version,
    scannerImageDigest: scanner.digest,
    wrapperDigest: scanner.wrapper.digest,
    ruleBundleDigest: ruleBundle.digest,
    vulnerabilityDatabaseDigest:
      plan.scannerSet.vulnerabilityDatabase.digest,
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
    artifactSchema: 'TRIVY_JSON',
    artifactSchemaVersion:
      SAST_ARTIFACT_SCHEMA_VERSIONS.TRIVY_JSON,
    artifactRef: 'result-ingress://tenant-1/scan-1/trivy',
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
    artifactSchema: 'TRIVY_JSON',
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
      normalizedPathCount: 3,
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
  const intentDigest = digest('accepted-trivy-intent');
  const core: SastArtifactDispositionDecisionCore = {
    version: SAST_ARTIFACT_DISPOSITION_VERSION,
    ingestionId: 'ingestion-trivy-1',
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
    storageReceiptRef: 'storage-receipt://accepted/trivy-1',
    storageReceiptDigest: digest('accepted-trivy-receipt'),
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
    manifestId: `sast-rule-bundle-manifest://${digest(`manifest-${kind}`).slice('sha256:'.length)}`,
    manifestDigest: digest(`manifest-${kind}`),
    verificationId: `sast-rule-bundle-verification://${digest(`manifest-${kind}`).slice('sha256:'.length)}`,
    verificationDigest: digest(`verification-${kind}`),
    compatibilityRef: `compatibility://${kind}`,
    rolloutPolicyRef: `rollout://${kind}`,
    killSwitchRef: `kill-switch://${kind}`,
    rollbackTargetDigest: digest(`rollback-${kind}`),
    compatibilityReceiptId: `sast-rule-bundle-compatibility://${digest(`receipt-${kind}`).slice('sha256:'.length)}`,
    compatibilityReceiptDigest: digest(`receipt-${kind}`),
    scanner: kind,
    source: 'PLATFORM_MANAGED' as const,
    immutable: true as const,
    customerExecutableConfigAllowed: false as const,
    rules:
      kind === 'OPENGREP'
        ? [
            {
              ruleId: 'rules.fixture',
              ruleRevision: '2026.07.0',
              ruleSemanticId: 'java.fixture',
              metadataDigest: digest('metadata-opengrep')
            }
          ]
        : [
            {
              ruleId: 'DS002',
              ruleRevision: '2026.07.2',
              ruleSemanticId: 'iac.dockerfile.non-root-user',
              metadataDigest: digest('metadata-ds002')
            },
            {
              ruleId: 'aws-access-key-id',
              ruleRevision: '2026.07.4',
              ruleSemanticId: 'secret.aws-access-key-id',
              metadataDigest: digest('metadata-aws')
            },
            {
              ruleId: 'github-pat',
              ruleRevision: '2026.07.3',
              ruleSemanticId: 'secret.github-personal-access-token',
              metadataDigest: digest('metadata-github')
            }
          ]
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
        normalizedPath: 'package-lock.json',
        lineCount: 100,
        maxColumnByLine: new Array<number>(100).fill(120)
      },
      {
        normalizedPath: 'Dockerfile',
        lineCount: 10,
        maxColumnByLine: new Array<number>(10).fill(120)
      },
      {
        normalizedPath: 'deploy.sh',
        lineCount: 20,
        maxColumnByLine: new Array<number>(20).fill(120)
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

async function* trackingChunks(
  artifact: Buffer,
  onRead: () => void
): AsyncGenerator<Uint8Array> {
  onRead();
  yield artifact;
}

function loadTrivyFixture(name: string): FixtureTrivy {
  return loadJsonFixture(name) as FixtureTrivy;
}

function loadJsonFixture(name: string): unknown {
  return JSON.parse(
    readFileSync(
      join(__dirname, '..', 'fixtures', 'trivy-json', name),
      'utf8'
    )
  ) as unknown;
}

function digest(value: string | Uint8Array): `sha256:${string}` {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}
