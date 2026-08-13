import { createHash } from 'node:crypto';

import {
  SAST_APPROVED_PROFILE_DIGESTS,
  SAST_ARTIFACT_SCHEMA_VERSIONS,
  SAST_ARTIFACT_VALIDATION_LIMITS,
  SAST_FORBIDDEN_CAPABILITIES,
  SAST_SCAN_PROFILES,
  canonicalizeScannerArtifactEnvelope,
  isSastArtifactValidationResultShapeValid,
  type ExpectedScannerArtifactBinding,
  type ScannerArtifactEnvelope,
  type SastArtifactSchema,
  type SastScanPlan
} from '@aegisai/shared';

import { SastArtifactStreamValidationSession } from '../../src/scan-plane/sast-artifact-stream-validator';
import type { SastFileCoordinateAttestation } from '../../src/scan-plane/sast-file-coordinate-attestation.provider';

const FIXED_COMMIT = 'a'.repeat(40);

describe('SAST bounded artifact validation', () => {
  it.each([
    {
      schema: 'OPENGREP_SARIF' as const,
      artifact: validSarif(),
      recordCount: 1,
      attestation: coordinateAttestation()
    },
    {
      schema: 'TRIVY_JSON' as const,
      artifact: validTrivy(),
      recordCount: 1,
      attestation: coordinateAttestation()
    },
    {
      schema: 'CYCLONEDX_JSON' as const,
      artifact: validCycloneDx(),
      recordCount: 1,
      attestation: null
    }
  ])(
    'accepts a pinned $schema artifact without materializing it',
    async ({ schema, artifact, recordCount, attestation }) => {
      const result = await validate({
        schema,
        artifact: jsonBytes(artifact),
        recordCount,
        attestation,
        chunkSizes: [1, 2, 3, 5, 8, 13]
      });

      expect(result.forwarded).toEqual(result.artifact);
      expect(result.validation).toMatchObject({
        outcome: 'PASSED',
        reasonCodes: [],
        artifactSchema: schema,
        statistics: {
          observedRecordCount: recordCount
        }
      });
      expect(
        isSastArtifactValidationResultShapeValid(result.validation)
      ).toBe(true);
    }
  );

  it('counts root and nested CycloneDX inventory components but excludes metadata tools', async () => {
    const artifact = validCycloneDx();
    Object.assign(artifact, {
      metadata: {
        tools: {
          components: [
            {
              type: 'application',
              name: 'syft',
              version: '1.44.0'
            }
          ]
        }
      }
    });
    (
      artifact.components[0] as Record<string, unknown>
    ).components = [
      {
        type: 'library',
        name: 'nested-example',
        version: '2.0.0'
      }
    ];

    const result = await validate({
      schema: 'CYCLONEDX_JSON',
      artifact: jsonBytes(artifact),
      recordCount: 2,
      attestation: null,
      chunkSizes: [1, 4095, 3]
    });

    expect(result.validation).toMatchObject({
      outcome: 'PASSED',
      statistics: {
        observedRecordCount: 2
      }
    });
  });

  it.each([
    {
      schema: 'OPENGREP_SARIF' as const,
      artifact: (() => {
        const artifact = validSarif();
        Object.assign(artifact.runs[0]!.results[0]!, {
          kind: 'unsupported'
        });
        return artifact;
      })(),
      attestation: coordinateAttestation()
    },
    {
      schema: 'TRIVY_JSON' as const,
      artifact: (() => {
        const artifact = validTrivy();
        artifact.Results[0]!.Vulnerabilities[0]!.Severity = 'SEVERE';
        return artifact;
      })(),
      attestation: coordinateAttestation()
    },
    {
      schema: 'CYCLONEDX_JSON' as const,
      artifact: (() => {
        const artifact = validCycloneDx();
        artifact.components[0]!.scope = 'runtime';
        return artifact;
      })(),
      attestation: null
    }
  ])('rejects an unknown $schema enum value', async (fixture) => {
    const result = await validate({
      schema: fixture.schema,
      artifact: jsonBytes(fixture.artifact),
      recordCount: 1,
      attestation: fixture.attestation
    });

    expect(result.validation.reasonCodes).toContain(
      'ARTIFACT_SCHEMA_FIELD_INVALID'
    );
  });

  it.each([
    {
      schema: 'OPENGREP_SARIF' as const,
      artifact: { ...validSarif(), version: '2.0.0' },
      attestation: coordinateAttestation()
    },
    {
      schema: 'TRIVY_JSON' as const,
      artifact: { ...validTrivy(), SchemaVersion: 3 },
      attestation: coordinateAttestation()
    },
    {
      schema: 'CYCLONEDX_JSON' as const,
      artifact: { ...validCycloneDx(), specVersion: '1.5' },
      attestation: null
    }
  ])('rejects an unpinned $schema payload version', async (fixture) => {
    const result = await validate({
      schema: fixture.schema,
      artifact: jsonBytes(fixture.artifact),
      recordCount: 1,
      attestation: fixture.attestation
    });

    expect(result.validation.reasonCodes).toContain(
      'ARTIFACT_SCHEMA_FIELD_INVALID'
    );
  });

  it.each([
    {
      name: 'duplicate keys',
      artifact: Buffer.from(
        '{"bomFormat":"CycloneDX","bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[]}'
      ),
      recordCount: 0,
      reason: 'ARTIFACT_JSON_DUPLICATE_KEY'
    },
    {
      name: 'malformed JSON',
      artifact: Buffer.from(
        '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":['
      ),
      recordCount: 0,
      reason: 'ARTIFACT_JSON_MALFORMED'
    },
    {
      name: 'excessive nesting',
      artifact: Buffer.from(
        `${'['.repeat(65)}null${']'.repeat(65)}`
      ),
      recordCount: 0,
      reason: 'ARTIFACT_JSON_DEPTH_LIMIT_EXCEEDED'
    },
    {
      name: 'excessive object keys',
      artifact: jsonBytes(
        Object.fromEntries(
          Array.from({ length: 4097 }, (_, index) => [
            `key-${index}`,
            index
          ])
        )
      ),
      recordCount: 0,
      reason: 'ARTIFACT_JSON_KEY_COUNT_LIMIT_EXCEEDED'
    },
    {
      name: 'overlong strings',
      artifact: jsonBytes({
        bomFormat: 'CycloneDX',
        specVersion: '1.6',
        version: 1,
        components: [
          { type: 'library', name: 'x'.repeat(4097) }
        ]
      }),
      recordCount: 0,
      reason: 'ARTIFACT_JSON_STRING_LIMIT_EXCEEDED'
    },
    {
      name: 'overlong numbers',
      artifact: Buffer.from(
        `{"bomFormat":"CycloneDX","specVersion":"1.6","version":${'1'.repeat(
          129
        )},"components":[]}`
      ),
      recordCount: 0,
      reason: 'ARTIFACT_JSON_NUMBER_LIMIT_EXCEEDED'
    },
    {
      name: 'unknown schema fields',
      artifact: jsonBytes({
        bomFormat: 'CycloneDX',
        specVersion: '1.6',
        version: 1,
        components: [],
        unexpected: true
      }),
      recordCount: 0,
      reason: 'ARTIFACT_SCHEMA_UNKNOWN_FIELD'
    },
    {
      name: 'unknown enum values',
      artifact: jsonBytes({
        bomFormat: 'CycloneDX',
        specVersion: '1.6',
        version: 1,
        components: [{ type: 'executable', name: 'example' }]
      }),
      recordCount: 1,
      reason: 'ARTIFACT_SCHEMA_FIELD_INVALID'
    }
  ])('fails closed for $name and still drains the stream', async (fixture) => {
    const result = await validate({
      schema: 'CYCLONEDX_JSON',
      artifact: fixture.artifact,
      recordCount: fixture.recordCount,
      attestation: null,
      chunkSizes: [7]
    });

    expect(result.forwarded).toEqual(result.artifact);
    expect(result.validation.outcome).toBe('FAILED');
    expect(result.validation.reasonCodes).toContain(fixture.reason);
  });

  it.each([
    {
      name: 'SARIF tool driver',
      mutate: (artifact: ReturnType<typeof validSarif>) => {
        Reflect.deleteProperty(artifact.runs[0]!.tool, 'driver');
      }
    },
    {
      name: 'SARIF result message content',
      mutate: (artifact: ReturnType<typeof validSarif>) => {
        Reflect.deleteProperty(
          artifact.runs[0]!.results[0]!.message,
          'text'
        );
      }
    }
  ])('rejects a missing required $name structure', async (fixture) => {
    const artifact = validSarif();
    fixture.mutate(artifact);

    const result = await validate({
      schema: 'OPENGREP_SARIF',
      artifact: jsonBytes(artifact),
      recordCount: 1,
      attestation: coordinateAttestation()
    });

    expect(result.validation.reasonCodes).toContain(
      'ARTIFACT_SCHEMA_REQUIRED_FIELD_MISSING'
    );
  });

  it('rejects invalid UTF-8 independently of JSON tokenization', async () => {
    const prefix = Buffer.from(
      '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"library","name":"'
    );
    const suffix = Buffer.from('"}]}');
    const artifact = Buffer.concat([
      prefix,
      Buffer.from([0xc3, 0x28]),
      suffix
    ]);

    const result = await validate({
      schema: 'CYCLONEDX_JSON',
      artifact,
      recordCount: 1,
      attestation: null,
      chunkSizes: [1]
    });

    expect(result.forwarded).toEqual(artifact);
    expect(result.validation.reasonCodes).toContain(
      'ARTIFACT_INVALID_UTF8'
    );
  });

  it('rejects unpaired JSON Unicode escapes across byte-sized chunks', async () => {
    const artifact = validCycloneDx();
    artifact.components[0]!.name = '\ud800';
    const result = await validate({
      schema: 'CYCLONEDX_JSON',
      artifact: jsonBytes(artifact),
      recordCount: 1,
      attestation: null,
      chunkSizes: [1]
    });

    expect(result.validation.reasonCodes).toContain(
      'ARTIFACT_INVALID_UTF8'
    );
  });

  it('accepts a paired JSON Unicode surrogate escape across byte-sized chunks', async () => {
    const source = jsonBytes(validCycloneDx()).toString('utf8');
    expect(source).toContain('"name":"example"');
    const artifact = Buffer.from(
      source.replace(
        '"name":"example"',
        '"name":"\\ud83d\\ude00"'
      ),
      'utf8'
    );
    const result = await validate({
      schema: 'CYCLONEDX_JSON',
      artifact,
      recordCount: 1,
      attestation: null,
      chunkSizes: [1]
    });

    expect(result.validation.outcome).toBe('PASSED');
  });

  it.each([
    {
      name: 'content digest',
      overrides: {
        contentDigest: digest('different')
      },
      recordCount: 1,
      reason: 'ARTIFACT_CONTENT_DIGEST_MISMATCH'
    },
    {
      name: 'byte count',
      overrides: {
        byteSize: jsonBytes(validSarif()).byteLength + 1
      },
      recordCount: 1,
      reason: 'ARTIFACT_BYTE_SIZE_MISMATCH'
    },
    {
      name: 'record count',
      overrides: {},
      recordCount: 2,
      reason: 'ARTIFACT_RECORD_COUNT_MISMATCH'
    },
    {
      name: 'schema version',
      overrides: {
        artifactSchemaVersion: '2.0.0'
      },
      recordCount: 1,
      reason: 'ARTIFACT_SCHEMA_VERSION_MISMATCH'
    }
  ])('records a deterministic $name mismatch', async (fixture) => {
    const result = await validate({
      schema: 'OPENGREP_SARIF',
      artifact: jsonBytes(validSarif()),
      recordCount: fixture.recordCount,
      attestation: coordinateAttestation(),
      envelopeOverrides: fixture.overrides
    });

    expect(result.validation.outcome).toBe('FAILED');
    expect(result.validation.reasonCodes).toContain(fixture.reason);
  });

  it('rebinds the exact durable scanner and artifact reference', async () => {
    const result = await validate({
      schema: 'OPENGREP_SARIF',
      artifact: jsonBytes(validSarif()),
      recordCount: 1,
      attestation: coordinateAttestation(),
      expectedBindingOverrides: {
        scanner: 'TRIVY',
        artifactRef: 'ingress://attempt-1/trivy'
      }
    });

    expect(result.validation.reasonCodes).toContain(
      'ARTIFACT_PLAN_BINDING_MISMATCH'
    );
  });

  it('rejects traversal paths and case-fold path collisions', async () => {
    const artifact = validSarif();
    artifact.runs[0]!.results = [
      sarifResult('../secrets.txt', 1),
      sarifResult('Src/App.java', 1),
      sarifResult('src/app.java', 1)
    ];
    const result = await validate({
      schema: 'OPENGREP_SARIF',
      artifact: jsonBytes(artifact),
      recordCount: 3,
      attestation: coordinateAttestation([
        fileCoordinate('Src/App.java'),
        fileCoordinate('src/app.java')
      ])
    });

    expect(result.validation.reasonCodes).toEqual(
      expect.arrayContaining([
        'ARTIFACT_PATH_INVALID',
        'ARTIFACT_PATH_COLLISION'
      ])
    );
    expect(
      isSastArtifactValidationResultShapeValid({
        ...result.validation,
        checks: {
          ...result.validation.checks,
          path: true
        }
      })
    ).toBe(false);
  });

  it('accepts only the OpenGrep %SRCROOT% physical URI base', async () => {
    const artifact = validSarif();
    Object.assign(
      artifact.runs[0]!.results[0]!.locations[0]!.physicalLocation
        .artifactLocation,
      { uriBaseId: 'WORKSPACE' }
    );
    const result = await validate({
      schema: 'OPENGREP_SARIF',
      artifact: jsonBytes(artifact),
      recordCount: 1,
      attestation: coordinateAttestation()
    });

    expect(result.validation.reasonCodes).toContain(
      'ARTIFACT_PATH_INVALID'
    );
  });

  it('enforces the finding limit separately from the larger artifact-record limit', async () => {
    const plan = buildPlan('JAVA_FAST_V1');
    const findingCount = plan.profile.limits.maxFindings + 1;
    const artifact = {
      version: '2.1.0',
      runs: [
        {
          tool: { driver: { name: 'OpenGrep' } },
          results: Array.from({ length: findingCount }, (_, index) => ({
            ruleId: `rule-${index}`,
            message: { text: 'bounded finding' }
          }))
        }
      ]
    };
    const result = await validate({
      plan,
      schema: 'OPENGREP_SARIF',
      artifact: jsonBytes(artifact),
      recordCount: findingCount,
      attestation: null
    });

    expect(result.validation.reasonCodes).toContain(
      'ARTIFACT_RECORD_LIMIT_EXCEEDED'
    );
  });

  it.each([
    {
      name: 'missing attestation',
      attestation: null,
      line: 2,
      reason: 'ARTIFACT_COORDINATE_ATTESTATION_MISSING'
    },
    {
      name: 'out-of-range coordinates',
      attestation: coordinateAttestation(),
      line: 4,
      reason: 'ARTIFACT_COORDINATE_INVALID'
    },
    {
      name: 'malformed coordinate attestation',
      attestation: {
        ...coordinateAttestation(),
        files: [
          {
            ...fileCoordinate('src/Café.java'),
            unboundedProviderField: true
          }
        ]
      } as unknown as SastFileCoordinateAttestation,
      line: 2,
      reason: 'ARTIFACT_COORDINATE_ATTESTATION_MISSING'
    }
  ])('fails closed for $name', async (fixture) => {
    const artifact = validSarif();
    artifact.runs[0]!.results = [
      sarifResult('src/Caf%C3%A9.java', fixture.line)
    ];
    const result = await validate({
      schema: 'OPENGREP_SARIF',
      artifact: jsonBytes(artifact),
      recordCount: 1,
      attestation: fixture.attestation
    });

    expect(result.validation.reasonCodes).toContain(fixture.reason);
  });

  it('rejects an oversized attestation before scanning its column array', async () => {
    const lineCount =
      SAST_ARTIFACT_VALIDATION_LIMITS.maximumCoordinateAttestationLines + 1;
    const maxColumnByLine = new Array<number>(lineCount);
    Object.defineProperty(maxColumnByLine, 0, {
      get: () => {
        throw new Error('oversized column array must not be scanned');
      }
    });
    const result = await validate({
      schema: 'OPENGREP_SARIF',
      artifact: jsonBytes(validSarif()),
      recordCount: 1,
      attestation: {
        attestationRef: 'preflight://attempt-1',
        inventoryDigest: digest('inventory'),
        verified: true,
        files: [
          {
            normalizedPath: 'src/Café.java',
            lineCount,
            maxColumnByLine
          }
        ]
      }
    });

    expect(result.validation.reasonCodes).toContain(
      'ARTIFACT_COORDINATE_ATTESTATION_MISSING'
    );
  });

  it('produces the same validation digest for every transport chunking', async () => {
    const artifact = jsonBytes(validSarif());
    const first = await validate({
      schema: 'OPENGREP_SARIF',
      artifact,
      recordCount: 1,
      attestation: coordinateAttestation(),
      chunkSizes: [artifact.byteLength]
    });
    const second = await validate({
      schema: 'OPENGREP_SARIF',
      artifact,
      recordCount: 1,
      attestation: coordinateAttestation(),
      chunkSizes: [1]
    });

    expect(second.validation).toEqual(first.validation);
  });

  it('keeps invalid-payload statistics deterministic across transport chunking', async () => {
    const artifact = jsonBytes({
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
      version: 1,
      components: [
        { type: 'library', name: 'x'.repeat(4097) }
      ]
    });
    const first = await validate({
      schema: 'CYCLONEDX_JSON',
      artifact,
      recordCount: 1,
      attestation: null,
      chunkSizes: [artifact.byteLength]
    });
    const second = await validate({
      schema: 'CYCLONEDX_JSON',
      artifact,
      recordCount: 1,
      attestation: null,
      chunkSizes: [1]
    });

    expect(first.validation.reasonCodes).toContain(
      'ARTIFACT_JSON_STRING_LIMIT_EXCEEDED'
    );
    expect(second.validation).toEqual(first.validation);
  });
});

interface ValidateInput {
  plan?: SastScanPlan;
  schema: SastArtifactSchema;
  artifact: Buffer;
  recordCount: number;
  attestation: Readonly<SastFileCoordinateAttestation> | null;
  chunkSizes?: readonly number[];
  envelopeOverrides?: Partial<ScannerArtifactEnvelope>;
  expectedBindingOverrides?: Partial<ExpectedScannerArtifactBinding>;
}

async function validate(input: ValidateInput) {
  const plan = input.plan ?? buildPlan();
  const envelope = {
    ...buildEnvelope(
      plan,
      input.schema,
      input.artifact,
      input.recordCount
    ),
    ...input.envelopeOverrides
  };
  const session = new SastArtifactStreamValidationSession({
    envelope,
    plan,
    expectedBinding: {
      attemptId: envelope.attemptId,
      scannerRunId: envelope.scannerRunId,
      scanner: envelope.scanner,
      artifactRef: envelope.artifactRef,
      workloadIdentityRef: envelope.workloadIdentityRef,
      preflightAttestationRef: envelope.preflightAttestationRef,
      preflightInventoryDigest: envelope.preflightInventoryDigest,
      ...input.expectedBindingOverrides
    },
    envelopeDigest: digest(
      canonicalizeScannerArtifactEnvelope(envelope)
    ),
    coordinateAttestation: input.attestation
  });
  const chunks: Buffer[] = [];
  for await (const chunk of session.observe(
    chunkArtifact(input.artifact, input.chunkSizes ?? [4096])
  )) {
    chunks.push(Buffer.from(chunk));
  }
  return {
    artifact: input.artifact,
    forwarded: Buffer.concat(chunks),
    validation: session.finish()
  };
}

async function* chunkArtifact(
  artifact: Buffer,
  chunkSizes: readonly number[]
): AsyncGenerator<Uint8Array> {
  let offset = 0;
  let index = 0;
  while (offset < artifact.byteLength) {
    const size = chunkSizes[index % chunkSizes.length] ?? 1;
    const end = Math.min(artifact.byteLength, offset + Math.max(size, 1));
    yield artifact.subarray(offset, end);
    offset = end;
    index += 1;
  }
}

function validSarif() {
  return {
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'OpenGrep'
          }
        },
        results: [sarifResult('src/Caf%C3%A9.java', 2)]
      }
    ]
  };
}

function validTrivy() {
  return {
    SchemaVersion: 2,
    ArtifactName: 'repository',
    ArtifactType: 'filesystem',
    Results: [
      {
        Class: 'lang-pkgs',
        Type: 'jar',
        Vulnerabilities: [
          {
            VulnerabilityID: 'CVE-2026-0001',
            PkgName: 'example',
            InstalledVersion: '1.0.0',
            Severity: 'HIGH',
            VendorSeverity: { nvd: 3 }
          }
        ],
        Target: 'pom.xml'
      }
    ]
  };
}

function validCycloneDx() {
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    components: [
      {
        type: 'library',
        name: 'example',
        version: '1.0.0',
        scope: 'required',
        omniborId: ['gitoid:blob:sha256:example'],
        swhid: ['swh:1:cnt:example']
      }
    ]
  };
}

function sarifResult(uri: string, line: number) {
  return {
    ruleId: 'java.sql-injection',
    message: {
      text: 'Potential SQL injection'
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri,
            uriBaseId: '%SRCROOT%'
          },
          region: {
            startLine: line,
            endLine: line,
            startColumn: 2,
            endColumn: 5
          }
        }
      }
    ]
  };
}

function coordinateAttestation(
  files = [fileCoordinate('src/Café.java'), fileCoordinate('pom.xml')]
): SastFileCoordinateAttestation {
  return {
    attestationRef: 'preflight://attempt-1',
    inventoryDigest: digest('inventory'),
    verified: true,
    files
  };
}

function fileCoordinate(normalizedPath: string) {
  return {
    normalizedPath,
    lineCount: 3,
    maxColumnByLine: [80, 80, 80]
  };
}

function buildEnvelope(
  plan: SastScanPlan,
  schema: SastArtifactSchema,
  artifact: Buffer,
  recordCount: number
): ScannerArtifactEnvelope {
  const scanner =
    schema === 'OPENGREP_SARIF'
      ? 'OPENGREP'
      : schema === 'TRIVY_JSON'
        ? 'TRIVY'
        : 'SYFT';
  const descriptor = plan.scannerSet.scanners[scanner];
  const rule = plan.scannerSet.ruleBundles.find(
    (bundle) => bundle.scanner === scanner
  );
  return {
    tenantId: plan.tenantId,
    repositoryBindingId: plan.repositoryState.repositoryBindingId,
    scanRequestId: plan.scanRequestId,
    attemptId: 'attempt-1',
    scannerRunId: `scanner-run-${scanner.toLowerCase()}`,
    workloadIdentityRef: 'spiffe://aegis/scan/attempt-1',
    scanner,
    scannerVersion: descriptor.version,
    scannerImageDigest: descriptor.digest,
    wrapperDigest: descriptor.wrapper.digest,
    ...(rule ? { ruleBundleDigest: rule.digest } : {}),
    ...(scanner === 'TRIVY'
      ? {
          vulnerabilityDatabaseDigest:
            plan.scannerSet.vulnerabilityDatabase.digest
        }
      : {}),
    scannerSetDigest: plan.scannerSet.scannerSetDigest,
    schemaBundleDigest: plan.scannerSet.schemaBundle.digest,
    normalizerBundleDigest: plan.scannerSet.normalizerBundle.digest,
    profileId: plan.profile.id,
    profileDigest: plan.profileDigest,
    preflightAttestationRef: 'preflight://attempt-1',
    preflightInventoryDigest: digest('inventory'),
    scannerWorkspaceInventoryDigest: digest('inventory'),
    inputCommitSha: plan.repositoryState.fixedCommitSha,
    artifactSchema: schema,
    artifactSchemaVersion: SAST_ARTIFACT_SCHEMA_VERSIONS[schema],
    artifactRef: `${plan.resultIngressRef}/${scanner.toLowerCase()}`,
    contentDigest: digest(artifact),
    byteSize: artifact.byteLength,
    recordCount,
    truncated: false,
    exitCode: 0,
    executionStatus: 'SUCCEEDED',
    producedAt: '2026-07-24T18:00:00.000Z'
  };
}

function buildPlan(
  profileId: 'JAVA_FAST_V1' | 'JAVA_DEEP_V1' = 'JAVA_DEEP_V1'
): SastScanPlan {
  const profile = SAST_SCAN_PROFILES[profileId];
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
    version: '1',
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
    rules: [
      {
        ruleId: `${kind.toLowerCase()}.fixture`,
        ruleRevision: '1',
        ruleSemanticId: `${kind.toLowerCase()}.fixture`,
        metadataDigest: digest(`rule-metadata-${kind}`)
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
        OPENGREP: scanner('OPENGREP', '1.1.0'),
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
    createdAt: '2026-07-24T17:00:00.000Z'
  };
}

function jsonBytes(value: unknown): Buffer {
  return Buffer.from(JSON.stringify(value), 'utf8');
}

function digest(value: string | Uint8Array): `sha256:${string}` {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}
