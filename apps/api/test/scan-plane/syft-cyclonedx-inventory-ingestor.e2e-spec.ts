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
  canonicalizeSyftCycloneDxInventoryBatch,
  isSyftCycloneDxInventoryBatchShapeValid,
  type ExpectedScannerArtifactBinding,
  type SastArtifactDispositionDecision,
  type SastArtifactDispositionDecisionCore,
  type SastArtifactValidationResult,
  type SastArtifactValidationResultCore,
  type SastScanPlan,
  type ScannerArtifactEnvelope
} from '@aegisai/shared';

import {
  SyftCycloneDxInventoryIngestor,
  type SyftCycloneDxInventoryInput
} from '../../src/scan-plane/syft-cyclonedx-inventory-ingestor';
import {
  SastArtifactStreamValidationSession
} from '../../src/scan-plane/sast-artifact-stream-validator';

const FIXED_COMMIT = 'b'.repeat(40);
const NORMALIZED_AT = '2026-07-26T12:02:00.000Z';
const DECIDED_AT = '2026-07-26T12:01:00.000Z';
const RETENTION_EXPIRES_AT = '2026-08-01T12:00:00.000Z';

interface FixtureDependency {
  ref: string;
  dependsOn: string[];
}

interface FixtureCycloneDx {
  $schema: string;
  bomFormat: string;
  specVersion: string;
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    tools: {
      components: Array<Record<string, unknown>>;
    };
    component: Record<string, unknown>;
  };
  components: Array<Record<string, unknown>>;
  dependencies?: FixtureDependency[];
  [key: string]: unknown;
}

describe('SyftCycloneDxInventoryIngestor', () => {
  const ingestor = new SyftCycloneDxInventoryIngestor();

  it('ingests the pinned Syft package/OS inventory byte-exactly across chunking', async () => {
    const fixture = loadCycloneDxFixture();
    const context = buildContext(fixture);
    const first = await ingestAt(
      ingestor,
      context.input,
      chunks(context.artifact, [1])
    );
    const second = await ingestAt(
      ingestor,
      context.input,
      chunks(context.artifact, [4093, 2, 8191, 7])
    );
    const withEmptyChunks = await ingestAt(
      ingestor,
      context.input,
      chunksWithEmptySegments(
        context.artifact,
        [3, 4093, 11]
      )
    );

    expect(first).toEqual(second);
    expect(first).toEqual(withEmptyChunks);
    expect(first.outcome).toBe('INGESTED');
    if (first.outcome !== 'INGESTED') return;

    const expected = loadExpectedFixture();
    const componentNameById = new Map(
      first.batch.components.map((component) => [
        component.componentId,
        component.name
      ])
    );
    const components = first.batch.components
      .map((component) => ({
        type: component.type,
        group: component.group,
        name: component.name,
        version: component.version,
        purl: component.purl,
        cpe: component.cpe,
        licenses: component.licenses,
        rawPropertiesStored: component.rawPropertiesStored,
        sourceLocationsStored: component.sourceLocationsStored
      }))
      .sort((left, right) =>
        left.name.localeCompare(right.name, 'en-US')
      );
    const dependencies = first.batch.dependencies.map(
      (dependency) => ({
        component: componentNameById.get(
          dependency.componentId
        ),
        dependsOn: componentNameById.get(
          dependency.dependsOnComponentId
        )
      })
    );
    expect({
      components,
      dependencies,
      statistics: first.batch.statistics
    }).toEqual(expected);

    expect(
      isSyftCycloneDxInventoryBatchShapeValid(first.batch)
    ).toBe(true);
    expect(first.batch).toMatchObject({
      scanner: 'SYFT',
      scannerVersion: '1.44.0',
      scannerRunId: context.input.envelope.scannerRunId,
      scannerImageDigest:
        context.input.envelope.scannerImageDigest,
      wrapperDigest: context.input.envelope.wrapperDigest,
      planDigest: digest(
        buildSastScanPlanDigestPreimage(context.input.plan)
      ),
      canonicalScanKey: context.input.plan.canonicalScanKey,
      retentionExpiresAt: RETENTION_EXPIRES_AT,
      authority: {
        capability: 'SBOM',
        mayCreateFindings: false,
        mayEvaluateVulnerabilities: false,
        policyAuthority: false,
        aiPayloadEligible: false
      },
      durablePersistenceAllowed: false
    });
    expect(first.batch).not.toHaveProperty('findings');
    expect(first.batch).not.toHaveProperty('severity');
    expect(first.batch).not.toHaveProperty('stableFingerprint');
    expect(first.batch).not.toHaveProperty('artifactRef');
    const serialized = JSON.stringify(first);
    for (const forbidden of [
      'PRIVATE_PATH_SENTINEL',
      'SHOULD_NOT_COPY_PROPERTY_VALUE',
      'UNTRUSTED-AUTHOR-MUST-NOT-BE-COPIED',
      'UNTRUSTED-PUBLISHER-MUST-NOT-BE-COPIED',
      'UNTRUSTED-DESCRIPTION-MUST-NOT-BE-COPIED',
      'UNTRUSTED-EXTERNAL-COMMENT-MUST-NOT-BE-COPIED',
      'UNTRUSTED-OS-DESCRIPTION-MUST-NOT-BE-COPIED',
      'https://example.invalid/package-b',
      'https://example.invalid/package-c.git',
      'https://spdx.org/licenses/Apache-2.0.html'
    ]) {
      expect(serialized).not.toContain(forbidden);
    }
    const { batchDigest, ...batchCore } = first.batch;
    expect(batchDigest).toBe(
      digest(canonicalizeSyftCycloneDxInventoryBatch(batchCore))
    );
  });

  it('passes the same producer artifact through T030 with inventory-only record counting', async () => {
    const fixture = loadCycloneDxFixture();
    const context = buildContext(fixture);
    const session = new SastArtifactStreamValidationSession({
      envelope: context.input.envelope,
      plan: context.input.plan,
      expectedBinding: context.input.expectedBinding,
      envelopeDigest: context.input.envelopeDigest,
      coordinateAttestation: null
    });
    for await (const chunk of session.observe(
      chunks(context.artifact, [1, 4095, 17])
    )) {
      // T030 is a tee; draining proves the same bytes remain available.
      expect(chunk).toBeInstanceOf(Uint8Array);
    }
    const validation = session.finish();
    expect(validation.outcome).toBe('PASSED');
    expect(validation.statistics.observedRecordCount).toBe(
      fixture.components.length
    );

    const input = {
      ...context.input,
      validation,
      disposition: buildAcceptedDisposition(validation)
    };
    const result = await ingestAt(
      ingestor,
      input,
      chunks(context.artifact, [4096])
    );
    expect(result.outcome).toBe('INGESTED');
  });

  it('accepts an empty package inventory with complete Syft provenance', async () => {
    const fixture = loadCycloneDxFixture();
    fixture.components = [];
    Reflect.deleteProperty(fixture, 'dependencies');
    const result = await ingestFixture(ingestor, fixture);
    expect(result.outcome).toBe('INGESTED');
    if (result.outcome !== 'INGESTED') return;
    expect(result.batch.components).toEqual([]);
    expect(result.batch.dependencies).toEqual([]);
    expect(result.batch.statistics).toEqual({
      observedComponentCount: 0,
      observedDependencyNodeCount: 0,
      observedDependencyEdgeCount: 0,
      discardedPropertyCount: 0,
      discardedSourceLocationPropertyCount: 0,
      discardedExternalReferenceCount: 0,
      discardedLicenseUrlCount: 0,
      discardedProseFieldCount: 0
    });
    expect(result.batch.scannerVersion).toBe('1.44.0');
  });

  it.each(['application', 'machine-learning-model'] as const)(
    'accepts Syft %s package components that use the package-ID BOM reference fallback',
    async (componentType) => {
      const fixture = loadCycloneDxFixture();
      fixture.components[0]!.type = componentType;
      fixture.components[0]!['bom-ref'] =
        '4444444444444444';
      Reflect.deleteProperty(fixture.components[0]!, 'purl');
      Reflect.deleteProperty(fixture, 'dependencies');

      const result = await ingestFixture(ingestor, fixture);
      expect(result.outcome).toBe('INGESTED');
      if (result.outcome !== 'INGESTED') return;
      expect(
        result.batch.components.find(
          (component) => component.name === 'package-a'
        )
      ).toMatchObject({
        type: componentType,
        purl: ''
      });
    }
  );

  it('rejects acceptance, plan, and expected-binding drift before reading artifact bytes', async () => {
    const cases: Array<{
      mutate(input: SyftCycloneDxInventoryInput): void;
      reason: string;
    }> = [
      {
        mutate(input) {
          input.disposition = {
            ...input.disposition,
            disposition: 'QUARANTINED',
            normalizationEligible: false
          };
        },
        reason: 'NORMALIZATION_ACCEPTANCE_INVALID'
      },
      {
        mutate(input) {
          input.plan = {
            ...input.plan,
            scannerSet: {
              ...input.plan.scannerSet,
              scannerSetDigest: digest('different-scanner-set')
            }
          };
        },
        reason: 'NORMALIZATION_PLAN_BINDING_MISMATCH'
      },
      {
        mutate(input) {
          input.expectedBinding = {
            ...input.expectedBinding,
            preflightInventoryDigest: digest('different-inventory')
          };
        },
        reason: 'NORMALIZATION_PLAN_BINDING_MISMATCH'
      }
    ];

    for (const testCase of cases) {
      const context = buildContext(loadCycloneDxFixture());
      testCase.mutate(context.input);
      let reads = 0;
      const result = await ingestAt(
        ingestor,
        context.input,
        trackingChunks(context.artifact, () => {
          reads += 1;
        })
      );
      expect(result).toMatchObject({
        outcome: 'REJECTED',
        reasonCodes: expect.arrayContaining([testCase.reason])
      });
      expect(reads).toBe(0);
    }
  });

  it('rejects an unreviewed Syft producer upgrade before reading artifact bytes', async () => {
    const fixture = loadCycloneDxFixture();
    fixture.metadata.tools.components[0]!.version = '1.45.0';
    const context = buildContext(fixture, '1.45.0');
    let reads = 0;

    const result = await ingestAt(
      ingestor,
      context.input,
      trackingChunks(context.artifact, () => {
        reads += 1;
      })
    );

    expect(result).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: expect.arrayContaining([
        'NORMALIZATION_PLAN_BINDING_MISMATCH'
      ])
    });
    expect(reads).toBe(0);
  });

  it.each([
    {
      name: 'foreign schema URI',
      mutate(fixture: FixtureCycloneDx) {
        fixture.$schema =
          'https://cyclonedx.org/schema/bom-1.6.schema.json';
      },
      reason: 'NORMALIZATION_CYCLONEDX_STRUCTURE_INVALID'
    },
    {
      name: 'foreign tool version',
      mutate(fixture: FixtureCycloneDx) {
        fixture.metadata.tools.components[0]!.version =
          '1.43.0';
      },
      reason: 'NORMALIZATION_CYCLONEDX_PRODUCER_INVALID'
    },
    {
      name: 'source path drift',
      mutate(fixture: FixtureCycloneDx) {
        fixture.metadata.component.name =
          '/workspace/customer-controlled';
      },
      reason: 'NORMALIZATION_CYCLONEDX_PRODUCER_INVALID'
    },
    {
      name: 'generic CycloneDX vulnerability extension',
      mutate(fixture: FixtureCycloneDx) {
        fixture.vulnerabilities = [];
      },
      reason: 'NORMALIZATION_CYCLONEDX_STRUCTURE_INVALID'
    }
  ])('rejects $name as producer drift', async (testCase) => {
    const fixture = loadCycloneDxFixture();
    testCase.mutate(fixture);
    const result = await ingestFixture(ingestor, fixture);
    expect(result).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: expect.arrayContaining([testCase.reason])
    });
  });

  it.each([
    {
      name: 'duplicate bom-ref',
      mutate(fixture: FixtureCycloneDx) {
        fixture.components[1]!['bom-ref'] =
          fixture.components[0]!['bom-ref'];
      },
      reason:
        'NORMALIZATION_CYCLONEDX_COMPONENT_IDENTITY_INVALID'
    },
    {
      name: 'PURL and BOM-reference mismatch',
      mutate(fixture: FixtureCycloneDx) {
        fixture.components[0]!.purl =
          'pkg:maven/org.example/other-name@1.2.3';
      },
      reason:
        'NORMALIZATION_CYCLONEDX_COMPONENT_IDENTITY_INVALID'
    },
    {
      name: 'component and scoped PURL name mismatch',
      mutate(fixture: FixtureCycloneDx) {
        fixture.components[1]!.name = 'package-b';
      },
      reason:
        'NORMALIZATION_CYCLONEDX_COMPONENT_IDENTITY_INVALID'
    },
    {
      name: 'non-canonical percent-encoded PURL identity',
      mutate(fixture: FixtureCycloneDx) {
        fixture.components[0]!.purl =
          'pkg:maven/org.example/%70ackage-a@1.2.3';
        fixture.components[0]!['bom-ref'] =
          'pkg:maven/org.example/%70ackage-a@1.2.3?package-id=1111111111111111';
      },
      reason:
        'NORMALIZATION_CYCLONEDX_COMPONENT_IDENTITY_INVALID'
    },
    {
      name: 'non-percent-encoded Unicode PURL identity',
      mutate(fixture: FixtureCycloneDx) {
        fixture.components[2]!.name = 'päckage-c';
        fixture.components[2]!.purl =
          'pkg:pypi/päckage-c@7.8.9';
        fixture.components[2]!['bom-ref'] =
          'pkg:pypi/päckage-c@7.8.9?package-id=3333333333333333';
      },
      reason:
        'NORMALIZATION_CYCLONEDX_COMPONENT_IDENTITY_INVALID'
    },
    {
      name: 'unescaped scoped PURL namespace',
      mutate(fixture: FixtureCycloneDx) {
        fixture.components[1]!.purl =
          'pkg:npm/@scope/package-b@4.5.6';
        fixture.components[1]!['bom-ref'] =
          'pkg:npm/@scope/package-b@4.5.6?package-id=2222222222222222';
      },
      reason:
        'NORMALIZATION_CYCLONEDX_COMPONENT_IDENTITY_INVALID'
    },
    {
      name: 'non-Maven producer group injection',
      mutate(fixture: FixtureCycloneDx) {
        fixture.components[1]!.group = '@scope';
      },
      reason:
        'NORMALIZATION_CYCLONEDX_COMPONENT_IDENTITY_INVALID'
    },
    {
      name: 'CPE with an invalid part',
      mutate(fixture: FixtureCycloneDx) {
        fixture.components[0]!.cpe =
          'cpe:2.3:z:example:package-a:1.2.3:*:*:*:*:*:*:*';
      },
      reason:
        'NORMALIZATION_CYCLONEDX_COMPONENT_IDENTITY_INVALID'
    },
    {
      name: 'CPE with an empty attribute',
      mutate(fixture: FixtureCycloneDx) {
        fixture.components[0]!.cpe =
          'cpe:2.3:a::package-a:1.2.3:*:*:*:*:*:*:*';
      },
      reason:
        'NORMALIZATION_CYCLONEDX_COMPONENT_IDENTITY_INVALID'
    },
    {
      name: 'CPE with unquoted punctuation',
      mutate(fixture: FixtureCycloneDx) {
        fixture.components[0]!.cpe =
          'cpe:2.3:a:exam!ple:package-a:1.2.3:*:*:*:*:*:*:*';
      },
      reason:
        'NORMALIZATION_CYCLONEDX_COMPONENT_IDENTITY_INVALID'
    },
    {
      name: 'CPE with a malformed language',
      mutate(fixture: FixtureCycloneDx) {
        fixture.components[0]!.cpe =
          'cpe:2.3:a:example:package-a:1.2.3:*:*:english:*:*:*:*';
      },
      reason:
        'NORMALIZATION_CYCLONEDX_COMPONENT_IDENTITY_INVALID'
    },
    {
      name: 'CPE with a missing field',
      mutate(fixture: FixtureCycloneDx) {
        fixture.components[0]!.cpe =
          'cpe:2.3:a:example:package-a:1.2.3:*:*:*:*:*:*';
      },
      reason:
        'NORMALIZATION_CYCLONEDX_COMPONENT_IDENTITY_INVALID'
    },
    {
      name: 'CPE with an embedded wildcard',
      mutate(fixture: FixtureCycloneDx) {
        fixture.components[0]!.cpe =
          'cpe:2.3:a:example:pack*age:1.2.3:*:*:*:*:*:*:*';
      },
      reason:
        'NORMALIZATION_CYCLONEDX_COMPONENT_IDENTITY_INVALID'
    },
    {
      name: 'CPE with a quoted unreserved character',
      mutate(fixture: FixtureCycloneDx) {
        fixture.components[0]!.cpe =
          'cpe:2.3:a:example:package\\-a:1.2.3:*:*:*:*:*:*:*';
      },
      reason:
        'NORMALIZATION_CYCLONEDX_COMPONENT_IDENTITY_INVALID'
    },
    {
      name: 'CPE with a dangling quote',
      mutate(fixture: FixtureCycloneDx) {
        fixture.components[0]!.cpe =
          'cpe:2.3:a:example:package-a:1.2.3:*:*:*:*:*:*:\\';
      },
      reason:
        'NORMALIZATION_CYCLONEDX_COMPONENT_IDENTITY_INVALID'
    },
    {
      name: 'file component forbidden by wrapper profile',
      mutate(fixture: FixtureCycloneDx) {
        fixture.components[0]!.type = 'file';
      },
      reason: 'NORMALIZATION_CYCLONEDX_COMPONENT_INVALID'
    },
    {
      name: 'nested generic component extension',
      mutate(fixture: FixtureCycloneDx) {
        fixture.components[0]!.components = [];
      },
      reason: 'NORMALIZATION_CYCLONEDX_COMPONENT_INVALID'
    },
    {
      name: 'missing Syft package provenance properties',
      mutate(fixture: FixtureCycloneDx) {
        Reflect.deleteProperty(
          fixture.components[0]!,
          'properties'
        );
      },
      reason:
        'NORMALIZATION_CYCLONEDX_COMPONENT_IDENTITY_INVALID'
    },
    {
      name: 'malformed build metadata digest',
      mutate(fixture: FixtureCycloneDx) {
        const references =
          fixture.components[0]!.externalReferences as Array<{
            type?: string;
            hashes?: Array<Record<string, unknown>>;
          }>;
        const buildMetadata = references.find(
          (reference) => reference.type === 'build-meta'
        );
        buildMetadata!.hashes![0]!.content = 'not-a-sha1';
      },
      reason: 'NORMALIZATION_CYCLONEDX_COMPONENT_INVALID'
    }
  ])('rejects $name as a whole component batch', async (testCase) => {
    const fixture = loadCycloneDxFixture();
    testCase.mutate(fixture);
    const result = await ingestFixture(ingestor, fixture);
    expect(result).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: expect.arrayContaining([testCase.reason])
    });
  });

  it.each([
    {
      name: 'dangling dependency',
      mutate(fixture: FixtureCycloneDx) {
        fixture.dependencies![0]!.dependsOn = ['missing-ref'];
      }
    },
    {
      name: 'duplicate dependency edge',
      mutate(fixture: FixtureCycloneDx) {
        fixture.dependencies![0]!.dependsOn.push(
          fixture.dependencies![0]!.dependsOn[0] as string
        );
      }
    },
    {
      name: 'self dependency',
      mutate(fixture: FixtureCycloneDx) {
        fixture.dependencies![0]!.dependsOn = [
          fixture.dependencies![0]!.ref
        ];
      }
    },
    {
      name: 'non-canonical producer edge order',
      mutate(fixture: FixtureCycloneDx) {
        fixture.dependencies![0]!.dependsOn = [
          fixture.dependencies![0]!.dependsOn[0] as string,
          'os:debian@12'
        ];
      }
    },
    {
      name: 'empty producer dependency node',
      mutate(fixture: FixtureCycloneDx) {
        fixture.dependencies![0]!.dependsOn = [];
      }
    },
    {
      name: 'non-canonical producer node order',
      mutate(fixture: FixtureCycloneDx) {
        fixture.dependencies!.unshift({
          ref: fixture.components[1]!['bom-ref'] as string,
          dependsOn: [
            fixture.components[2]!['bom-ref'] as string
          ]
        });
      }
    }
  ])('rejects $name', async (testCase) => {
    const fixture = loadCycloneDxFixture();
    testCase.mutate(fixture);
    const result = await ingestFixture(ingestor, fixture);
    expect(result).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: expect.arrayContaining([
        'NORMALIZATION_CYCLONEDX_DEPENDENCY_INVALID'
      ])
    });
  });

  it.each([
    {
      name: 'raw license text',
      mutate(fixture: FixtureCycloneDx) {
        const licenses =
          fixture.components[0]!.licenses as Array<{
            license: Record<string, unknown>;
          }>;
        licenses[0]!.license.text = {
          content: 'RAW-LICENSE-BODY-MUST-NOT-BE-ACCEPTED'
        };
      }
    },
    {
      name: 'invalid SPDX expression',
      mutate(fixture: FixtureCycloneDx) {
        const licenses =
          fixture.components[1]!.licenses as Array<
            Record<string, unknown>
          >;
        licenses[0]!.expression = 'MIT OR OR Apache-2.0';
      }
    },
    {
      name: 'invented SPDX license ID',
      mutate(fixture: FixtureCycloneDx) {
        const licenses =
          fixture.components[0]!.licenses as Array<{
            license: Record<string, unknown>;
          }>;
        licenses[0]!.license.id = 'Not-A-Real-SPDX-License';
      }
    },
    {
      name: 'LicenseRef in a CycloneDX SPDX ID field',
      mutate(fixture: FixtureCycloneDx) {
        const licenses =
          fixture.components[0]!.licenses as Array<{
            license: Record<string, unknown>;
          }>;
        licenses[0]!.license.id = 'LicenseRef-Aegis-Custom';
      }
    },
    {
      name: 'invented SPDX expression license',
      mutate(fixture: FixtureCycloneDx) {
        const licenses =
          fixture.components[1]!.licenses as Array<
            Record<string, unknown>
          >;
        licenses[0]!.expression =
          'MIT OR Not-A-Real-SPDX-License';
      }
    },
    {
      name: 'invented SPDX license exception',
      mutate(fixture: FixtureCycloneDx) {
        const licenses =
          fixture.components[1]!.licenses as Array<
            Record<string, unknown>
          >;
        licenses[0]!.expression =
          'GPL-2.0-only WITH Not-A-Real-Exception';
      }
    },
    {
      name: 'SPDX exception used as a license',
      mutate(fixture: FixtureCycloneDx) {
        const licenses =
          fixture.components[1]!.licenses as Array<
            Record<string, unknown>
          >;
        licenses[0]!.expression = 'Classpath-exception-2.0';
      }
    },
    {
      name: 'SPDX WITH applied to a parenthesized expression',
      mutate(fixture: FixtureCycloneDx) {
        const licenses =
          fixture.components[1]!.licenses as Array<
            Record<string, unknown>
          >;
        licenses[0]!.expression =
          '(GPL-2.0-only) WITH Classpath-exception-2.0';
      }
    },
    {
      name: 'malformed SPDX LicenseRef',
      mutate(fixture: FixtureCycloneDx) {
        const licenses =
          fixture.components[1]!.licenses as Array<
            Record<string, unknown>
          >;
        licenses[0]!.expression =
          'LicenseRef-Aegis_Custom OR MIT';
      }
    }
  ])('rejects $name without exposing license payloads', async (testCase) => {
    const fixture = loadCycloneDxFixture();
    testCase.mutate(fixture);
    const result = await ingestFixture(ingestor, fixture);
    expect(result).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: expect.arrayContaining([
        'NORMALIZATION_CYCLONEDX_LICENSE_INVALID'
      ])
    });
    expect(JSON.stringify(result)).not.toContain(
      'RAW-LICENSE-BODY-MUST-NOT-BE-ACCEPTED'
    );
  });

  it('deduplicates producer-valid repeated license identities after discarding URLs', async () => {
    const fixture = loadCycloneDxFixture();
    const licenses =
      fixture.components[0]!.licenses as Array<{
        license: Record<string, unknown>;
      }>;
    const repeated = structuredClone(licenses[0]!);
    repeated.license.url =
      'https://licenses.example.invalid/apache-2.0';
    licenses.push(repeated);

    const result = await ingestFixture(ingestor, fixture);
    expect(result.outcome).toBe('INGESTED');
    if (result.outcome !== 'INGESTED') return;
    const component = result.batch.components.find(
      (candidate) => candidate.name === 'package-a'
    );
    expect(component?.licenses).toEqual([
      { kind: 'SPDX_ID', value: 'Apache-2.0' }
    ]);
    expect(result.batch.statistics.discardedLicenseUrlCount).toBe(
      2
    );
  });

  it('canonicalizes producer-valid SPDX expression whitespace', async () => {
    const fixture = loadCycloneDxFixture();
    const licenses =
      fixture.components[1]!.licenses as Array<
        Record<string, unknown>
      >;
    licenses[0]!.expression = 'MIT  OR Apache-2.0';

    const result = await ingestFixture(ingestor, fixture);
    expect(result.outcome).toBe('INGESTED');
    if (result.outcome !== 'INGESTED') return;
    expect(
      result.batch.components.find(
        (component) => component.name === '@scope/package-b'
      )?.licenses
    ).toEqual([
      {
        kind: 'SPDX_EXPRESSION',
        value: 'MIT OR Apache-2.0'
      }
    ]);
  });

  it('canonicalizes case-insensitive SPDX ID fields to License List 3.28.0', async () => {
    const fixture = loadCycloneDxFixture();
    const licenses =
      fixture.components[0]!.licenses as Array<{
        license: Record<string, unknown>;
      }>;
    licenses[0]!.license.id = 'apache-2.0';

    const result = await ingestFixture(ingestor, fixture);
    expect(result.outcome).toBe('INGESTED');
    if (result.outcome !== 'INGESTED') return;
    expect(
      result.batch.components.find(
        (component) => component.name === 'package-a'
      )?.licenses
    ).toEqual([{ kind: 'SPDX_ID', value: 'Apache-2.0' }]);
  });

  it.each([
    {
      expression:
        'gpl-2.0-only  WITH classpath-exception-2.0',
      expected:
        'GPL-2.0-only WITH Classpath-exception-2.0'
    },
    {
      expression: 'LicenseRef-Aegis-Custom OR mit',
      expected: 'LicenseRef-Aegis-Custom OR MIT'
    },
    {
      expression:
        'DocumentRef-upstream.1:LicenseRef-Custom-2 AND apache-2.0',
      expected:
        'DocumentRef-upstream.1:LicenseRef-Custom-2 AND Apache-2.0'
    }
  ])(
    'validates and canonicalizes SPDX 3.28.0 expression $expression',
    async ({ expression, expected }) => {
      const fixture = loadCycloneDxFixture();
      const licenses =
        fixture.components[1]!.licenses as Array<
          Record<string, unknown>
        >;
      licenses[0]!.expression = expression;

      const result = await ingestFixture(ingestor, fixture);
      expect(result.outcome).toBe('INGESTED');
      if (result.outcome !== 'INGESTED') return;
      expect(
        result.batch.components.find(
          (component) => component.name === '@scope/package-b'
        )?.licenses
      ).toEqual([
        {
          kind: 'SPDX_EXPRESSION',
          value: expected
        }
      ]);
    }
  );

  it('accepts NIST CPE 2.3 quoted punctuation and language tags', async () => {
    const fixture = loadCycloneDxFixture();
    fixture.components[0]!.cpe =
      'cpe:2.3:a:?example?:package\\:a:1.2.3:*:*:en-US:*:*:*:*';

    const result = await ingestFixture(ingestor, fixture);
    expect(result.outcome).toBe('INGESTED');
    if (result.outcome !== 'INGESTED') return;
    expect(
      result.batch.components.find(
        (component) => component.name === 'package-a'
      )?.cpe
    ).toBe(
      'cpe:2.3:a:?example?:package\\:a:1.2.3:*:*:en-US:*:*:*:*'
    );
  });

  it('discards Syft URL-only license fallback without retaining the duplicated name', async () => {
    const fixture = loadCycloneDxFixture();
    const sentinel =
      'https://licenses.example.invalid/url-only-license';
    fixture.components[0]!.licenses = [
      {
        license: {
          name: sentinel,
          url: sentinel
        }
      }
    ];

    const result = await ingestFixture(ingestor, fixture);
    expect(result.outcome).toBe('INGESTED');
    if (result.outcome !== 'INGESTED') return;
    expect(
      result.batch.components.find(
        (component) => component.name === 'package-a'
      )?.licenses
    ).toEqual([]);
    expect(JSON.stringify(result)).not.toContain(sentinel);
    expect(result.batch.statistics.discardedLicenseUrlCount).toBe(
      1
    );
  });

  it('enforces component and discarded-property limits without truncation', async () => {
    const overlong = loadCycloneDxFixture();
    overlong.components[0]!.name = 'x'.repeat(513);
    const overlongResult = await ingestFixture(
      ingestor,
      overlong
    );
    expect(overlongResult).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: expect.arrayContaining([
        'NORMALIZATION_CYCLONEDX_COMPONENT_INVALID'
      ])
    });

    const propertyBomb = loadCycloneDxFixture();
    const properties =
      propertyBomb.components[0]!.properties as Array<
        Record<string, unknown>
      >;
    for (let index = properties.length; index < 257; index += 1) {
      properties.push({
        name: `syft:metadata:extra:${index}`,
        value: 'bounded-but-excessive'
      });
    }
    const propertyResult = await ingestFixture(
      ingestor,
      propertyBomb
    );
    expect(propertyResult).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: expect.arrayContaining([
        'NORMALIZATION_CYCLONEDX_COMPONENT_INVALID'
      ])
    });
  });

  it('rehashes, recounts, rejects malformed streams, and rechecks retention after streaming', async () => {
    const fixture = loadCycloneDxFixture();
    const digestMismatch = buildContext(fixture);
    digestMismatch.input = rebindEnvelope(
      digestMismatch.input,
      {
        ...digestMismatch.input.envelope,
        contentDigest: digest('different-content')
      }
    );
    expect(
      await ingestAt(
        ingestor,
        digestMismatch.input,
        chunks(digestMismatch.artifact, [4096])
      )
    ).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: expect.arrayContaining([
        'NORMALIZATION_CONTENT_DIGEST_MISMATCH'
      ])
    });

    const countMismatch = buildContext(fixture);
    countMismatch.input = rebindEnvelope(countMismatch.input, {
      ...countMismatch.input.envelope,
      recordCount: countMismatch.input.envelope.recordCount + 1
    });
    expect(
      await ingestAt(
        ingestor,
        countMismatch.input,
        chunks(countMismatch.artifact, [1])
      )
    ).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: expect.arrayContaining([
        'NORMALIZATION_VALIDATION_BINDING_MISMATCH'
      ])
    });

    const duplicate = Buffer.from(
      JSON.stringify(fixture).replace(
        '"bomFormat":"CycloneDX"',
        '"bomFormat":"CycloneDX","bomFormat":"CycloneDX"'
      ),
      'utf8'
    );
    const duplicateContext = buildArtifactContext(
      duplicate,
      fixture.components.length
    );
    expect(
      await ingestAt(
        ingestor,
        duplicateContext.input,
        chunks(duplicate, [1])
      )
    ).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: expect.arrayContaining([
        'NORMALIZATION_ARTIFACT_STREAM_INVALID'
      ])
    });

    const malformed = Buffer.from(
      JSON.stringify(fixture).slice(0, -2),
      'utf8'
    );
    const malformedContext = buildArtifactContext(
      malformed,
      fixture.components.length
    );
    expect(
      await ingestAt(
        ingestor,
        malformedContext.input,
        chunks(malformed, [4095, 1])
      )
    ).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: expect.arrayContaining([
        'NORMALIZATION_ARTIFACT_STREAM_INVALID'
      ])
    });

    const retention = buildContext(fixture);
    let clockReads = 0;
    const retentionResult = await ingestor.ingest(
      retention.input,
      chunks(retention.artifact, [19]),
      () =>
        new Date(
          clockReads++ === 0
            ? NORMALIZED_AT
            : RETENTION_EXPIRES_AT
        )
    );
    expect(retentionResult).toMatchObject({
      outcome: 'REJECTED',
      reasonCodes: ['NORMALIZATION_RETENTION_EXPIRED']
    });
  });
});

function ingestAt(
  ingestor: SyftCycloneDxInventoryIngestor,
  input: Readonly<SyftCycloneDxInventoryInput>,
  artifact: AsyncIterable<Uint8Array>
) {
  return ingestor.ingest(
    input,
    artifact,
    () => new Date(NORMALIZED_AT)
  );
}

async function ingestFixture(
  ingestor: SyftCycloneDxInventoryIngestor,
  fixture: FixtureCycloneDx
) {
  const context = buildContext(fixture);
  return ingestAt(
    ingestor,
    context.input,
    chunks(context.artifact, [5, 4091, 13])
  );
}

function buildContext(
  fixture: FixtureCycloneDx,
  syftVersion = '1.44.0'
): {
  input: SyftCycloneDxInventoryInput;
  artifact: Buffer;
} {
  const artifact = Buffer.from(JSON.stringify(fixture), 'utf8');
  return buildArtifactContext(
    artifact,
    fixture.components.length,
    syftVersion
  );
}

function buildArtifactContext(
  artifact: Buffer,
  recordCount: number,
  syftVersion = '1.44.0'
): {
  input: SyftCycloneDxInventoryInput;
  artifact: Buffer;
} {
  const plan = buildPlan(syftVersion);
  const envelope = buildEnvelope(plan, artifact, recordCount);
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
      disposition
    }
  };
}

function rebindEnvelope(
  input: Readonly<SyftCycloneDxInventoryInput>,
  envelope: ScannerArtifactEnvelope
): SyftCycloneDxInventoryInput {
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

function buildEnvelope(
  plan: Readonly<SastScanPlan>,
  artifact: Buffer,
  recordCount: number
): ScannerArtifactEnvelope {
  const scanner = plan.scannerSet.scanners.SYFT;
  return {
    tenantId: plan.tenantId,
    repositoryBindingId:
      plan.repositoryState.repositoryBindingId,
    scanRequestId: plan.scanRequestId,
    attemptId: 'attempt-1',
    scannerRunId: 'scanner-run-syft',
    workloadIdentityRef: 'spiffe://aegis/scan/attempt-1',
    scanner: 'SYFT',
    scannerVersion: scanner.version,
    scannerImageDigest: scanner.digest,
    wrapperDigest: scanner.wrapper.digest,
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
    artifactSchema: 'CYCLONEDX_JSON',
    artifactSchemaVersion:
      SAST_ARTIFACT_SCHEMA_VERSIONS.CYCLONEDX_JSON,
    artifactRef: 'result-ingress://tenant-1/scan-1/syft',
    contentDigest: digest(artifact),
    byteSize: artifact.byteLength,
    recordCount,
    truncated: false,
    exitCode: 0,
    executionStatus: 'SUCCEEDED',
    producedAt: '2026-07-26T12:00:01.000Z'
  };
}

function buildValidation(
  envelope: Readonly<ScannerArtifactEnvelope>,
  envelopeDigest: `sha256:${string}`
): SastArtifactValidationResult {
  const core: SastArtifactValidationResultCore = {
    version: SAST_ARTIFACT_VALIDATION_VERSION,
    outcome: 'PASSED',
    artifactSchema: 'CYCLONEDX_JSON',
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
      maximumObservedDepth: 12,
      maximumObservedStringBytes: 512,
      normalizedPathCount: 0,
      coordinateCount: 0
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
  const intentDigest = digest('accepted-syft-intent');
  const core: SastArtifactDispositionDecisionCore = {
    version: SAST_ARTIFACT_DISPOSITION_VERSION,
    ingestionId: 'ingestion-syft-1',
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
    storageReceiptRef: 'storage-receipt://accepted/syft-1',
    storageReceiptDigest: digest('accepted-syft-receipt'),
    decidedAt: DECIDED_AT
  };
  return {
    ...core,
    decisionDigest: digest(
      canonicalizeSastArtifactDispositionDecision(core)
    )
  };
}

function buildPlan(syftVersion = '1.44.0'): SastScanPlan {
  const profile = SAST_SCAN_PROFILES.JAVA_DEEP_V1;
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
    customerExecutableConfigAllowed: false as const,
    rules: [
      {
        ruleId: `${kind.toLowerCase()}.fixture`,
        ruleRevision: '2026.07.0',
        ruleSemanticId: `${kind.toLowerCase()}.fixture`,
        metadataDigest: digest(`metadata-${kind}`)
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
        SYFT: scanner('SYFT', syftVersion)
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

function loadCycloneDxFixture(): FixtureCycloneDx {
  return loadJsonFixture(
    'upstream-compatible.cdx.json'
  ) as FixtureCycloneDx;
}

function loadExpectedFixture(): unknown {
  return loadJsonFixture('upstream-compatible.expected.json');
}

function loadJsonFixture(name: string): unknown {
  return JSON.parse(
    readFileSync(
      join(__dirname, '..', 'fixtures', 'syft-cyclonedx', name),
      'utf8'
    )
  ) as unknown;
}

function digest(value: string | Uint8Array): `sha256:${string}` {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}
