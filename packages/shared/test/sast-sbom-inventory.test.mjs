import assert from 'node:assert/strict';
import test from 'node:test';

import {
  SYFT_CYCLONEDX_INVENTORY_INGESTOR_VERSION,
  SYFT_CYCLONEDX_INVENTORY_LIMITS,
  SYFT_CYCLONEDX_PRODUCER_VERSION,
  SYFT_CYCLONEDX_SCHEMA_URI,
  canonicalizeSyftCycloneDxInventoryBatch,
  canonicalizeSyftCycloneDxInventoryRejection,
  isSyftCycloneDxInventoryBatchShapeValid,
  isSyftCycloneDxInventoryRejectionShapeValid
} from '../dist/index.js';

const DIGEST_A = `sha256:${'a'.repeat(64)}`;
const DIGEST_B = `sha256:${'b'.repeat(64)}`;
const DIGEST_C = `sha256:${'c'.repeat(64)}`;
const DIGEST_D = `sha256:${'d'.repeat(64)}`;

test('pins a canonical transient Syft CycloneDX inventory contract', () => {
  assert.equal(
    SYFT_CYCLONEDX_INVENTORY_INGESTOR_VERSION,
    'syft-cyclonedx-inventory-ingestor-v1'
  );
  assert.equal(SYFT_CYCLONEDX_PRODUCER_VERSION, '1.44.0');
  assert.equal(
    SYFT_CYCLONEDX_SCHEMA_URI,
    'http://cyclonedx.org/schema/bom-1.6.schema.json'
  );
  assert.deepEqual(SYFT_CYCLONEDX_INVENTORY_LIMITS, {
    maximumComponents: 250_000,
    maximumDependencyNodes: 250_000,
    maximumDependencyEdges: 250_000,
    maximumLicensesPerComponent: 64,
    maximumPropertiesPerComponent: 256,
    maximumExternalReferencesPerComponent: 64,
    maximumHashesPerExternalReference: 16,
    maximumDiscardedProseFieldsPerComponent: 3,
    componentNameBytes: 512,
    componentGroupBytes: 512,
    componentVersionBytes: 512,
    bomReferenceBytes: 2_048,
    packageUrlBytes: 2_048,
    cpeBytes: 1_024,
    licenseValueBytes: 512
  });
  const core = batchCore();
  const canonical = canonicalizeSyftCycloneDxInventoryBatch(core);
  const reordered = {
    durablePersistenceAllowed: false,
    dataHandling: core.dataHandling,
    authority: core.authority,
    statistics: core.statistics,
    dependencies: core.dependencies,
    components: core.components,
    producer: core.producer,
    retentionExpiresAt: core.retentionExpiresAt,
    dispositionDecisionDigest: core.dispositionDecisionDigest,
    validationResultDigest: core.validationResultDigest,
    normalizerBundleDigest: core.normalizerBundleDigest,
    schemaBundleDigest: core.schemaBundleDigest,
    artifactDigest: core.artifactDigest,
    envelopeDigest: core.envelopeDigest,
    commitSha: core.commitSha,
    lane: core.lane,
    preflightInventoryDigest: core.preflightInventoryDigest,
    preflightAttestationRef: core.preflightAttestationRef,
    canonicalScanKey: core.canonicalScanKey,
    planDigest: core.planDigest,
    profileDigest: core.profileDigest,
    profileId: core.profileId,
    scannerSetDigest: core.scannerSetDigest,
    wrapperDigest: core.wrapperDigest,
    scannerImageDigest: core.scannerImageDigest,
    scannerVersion: core.scannerVersion,
    scanner: core.scanner,
    scannerRunId: core.scannerRunId,
    scope: {
      scannerRunId: core.scope.scannerRunId,
      attemptId: core.scope.attemptId,
      scanRequestId: core.scope.scanRequestId,
      repositoryBindingId: core.scope.repositoryBindingId,
      tenantId: core.scope.tenantId
    },
    ingestionId: core.ingestionId,
    artifactSchemaVersion: core.artifactSchemaVersion,
    artifactSchema: core.artifactSchema,
    adapterVersion: core.adapterVersion,
    version: core.version
  };

  assert.equal(
    canonical,
    canonicalizeSyftCycloneDxInventoryBatch(reordered)
  );
  assert.match(canonical, /"capability":"SBOM"/u);
  assert.match(canonical, /"mayCreateFindings":false/u);
  assert.match(canonical, /"sourceLocationsStored":false/u);
  const nonCanonicalAuthority = structuredClone(core);
  nonCanonicalAuthority.authority.mayCreateFindings = true;
  nonCanonicalAuthority.dataHandling.sourceLocationsStored = true;
  nonCanonicalAuthority.durablePersistenceAllowed = true;
  const nonCanonicalPreimage =
    canonicalizeSyftCycloneDxInventoryBatch(nonCanonicalAuthority);
  assert.match(nonCanonicalPreimage, /"mayCreateFindings":true/u);
  assert.match(nonCanonicalPreimage, /"sourceLocationsStored":true/u);
  assert.match(
    nonCanonicalPreimage,
    /"durablePersistenceAllowed":true/u
  );
  assert.doesNotMatch(
    canonical,
    /stableFingerprint|severity|evidencePackIds|artifactRef/u
  );
});

test('validates exact component, dependency, authority, and retention shape', () => {
  const core = batchCore();
  const batch = { ...core, batchDigest: DIGEST_A };
  assert.equal(isSyftCycloneDxInventoryBatchShapeValid(batch), true);

  assert.equal(
    isSyftCycloneDxInventoryBatchShapeValid({
      ...batch,
      authority: {
        ...batch.authority,
        mayCreateFindings: true
      }
    }),
    false
  );
  assert.equal(
    isSyftCycloneDxInventoryBatchShapeValid({
      ...batch,
      dataHandling: {
        ...batch.dataHandling,
        sourceLocationsStored: true
      }
    }),
    false
  );
  assert.equal(
    isSyftCycloneDxInventoryBatchShapeValid({
      ...batch,
      dependencies: [
        {
          componentId: DIGEST_A,
          dependsOnComponentId: DIGEST_D
        }
      ]
    }),
    false
  );
  assert.equal(
    isSyftCycloneDxInventoryBatchShapeValid({
      ...batch,
      components: [...batch.components].reverse()
    }),
    false
  );
  assert.equal(
    isSyftCycloneDxInventoryBatchShapeValid({
      ...batch,
      retentionExpiresAt: batch.producer.generatedAt
    }),
    false
  );
  assert.equal(
    isSyftCycloneDxInventoryBatchShapeValid({
      ...batch,
      statistics: {
        ...batch.statistics,
        observedDependencyNodeCount: 0
      }
    }),
    false
  );
  assert.equal(
    isSyftCycloneDxInventoryBatchShapeValid({
      ...batch,
      statistics: {
        ...batch.statistics,
        observedDependencyNodeCount:
          batch.components.length + 1
      }
    }),
    false
  );
  assert.equal(
    isSyftCycloneDxInventoryBatchShapeValid({
      ...batch,
      statistics: {
        ...batch.statistics,
        discardedPropertyCount:
          batch.components.length *
            SYFT_CYCLONEDX_INVENTORY_LIMITS
              .maximumPropertiesPerComponent +
          1
      }
    }),
    false
  );
});

test('canonicalizes bounded ordered CycloneDX rejection metadata only', () => {
  const core = {
    version: SYFT_CYCLONEDX_INVENTORY_INGESTOR_VERSION,
    adapterVersion:
      SYFT_CYCLONEDX_INVENTORY_INGESTOR_VERSION,
    outcome: 'REJECTED',
    ingestionId: 'ingestion-syft-1',
    reasonCodes: [
      'NORMALIZATION_CYCLONEDX_COMPONENT_INVALID',
      'NORMALIZATION_CYCLONEDX_DEPENDENCY_INVALID'
    ]
  };
  const canonical =
    canonicalizeSyftCycloneDxInventoryRejection(core);
  assert.equal(
    canonical,
    '{"version":"syft-cyclonedx-inventory-ingestor-v1","adapterVersion":"syft-cyclonedx-inventory-ingestor-v1","outcome":"REJECTED","ingestionId":"ingestion-syft-1","reasonCodes":["NORMALIZATION_CYCLONEDX_COMPONENT_INVALID","NORMALIZATION_CYCLONEDX_DEPENDENCY_INVALID"]}'
  );
  assert.equal(
    isSyftCycloneDxInventoryRejectionShapeValid({
      ...core,
      rejectionDigest: DIGEST_A
    }),
    true
  );
  assert.equal(
    isSyftCycloneDxInventoryRejectionShapeValid({
      ...core,
      reasonCodes: [...core.reasonCodes].reverse(),
      rejectionDigest: DIGEST_A
    }),
    false
  );
});

function batchCore() {
  return {
    version: SYFT_CYCLONEDX_INVENTORY_INGESTOR_VERSION,
    adapterVersion:
      SYFT_CYCLONEDX_INVENTORY_INGESTOR_VERSION,
    artifactSchema: 'CYCLONEDX_JSON',
    artifactSchemaVersion: '1.6',
    ingestionId: 'ingestion-syft-1',
    scope: {
      tenantId: 'tenant-1',
      repositoryBindingId: 'repository-1',
      scanRequestId: 'scan-1',
      attemptId: 'attempt-1',
      scannerRunId: 'scanner-run-syft'
    },
    scannerRunId: 'scanner-run-syft',
    scanner: 'SYFT',
    scannerVersion: '1.44.0',
    scannerImageDigest: DIGEST_A,
    wrapperDigest: DIGEST_A,
    scannerSetDigest: DIGEST_A,
    profileId: 'JAVA_DEEP_V1',
    profileDigest: DIGEST_A,
    planDigest: DIGEST_A,
    canonicalScanKey: DIGEST_A,
    preflightAttestationRef: 'preflight://attempt-1',
    preflightInventoryDigest: DIGEST_A,
    lane: 'DEEP',
    commitSha: 'a'.repeat(40),
    envelopeDigest: DIGEST_A,
    artifactDigest: DIGEST_A,
    schemaBundleDigest: DIGEST_A,
    normalizerBundleDigest: DIGEST_A,
    validationResultDigest: DIGEST_A,
    dispositionDecisionDigest: DIGEST_A,
    retentionExpiresAt: '2026-08-01T12:00:00.000Z',
    producer: {
      schemaUri: SYFT_CYCLONEDX_SCHEMA_URI,
      specVersion: '1.6',
      bomVersion: 1,
      toolVendor: 'anchore',
      toolName: 'syft',
      toolVersion: '1.44.0',
      generatedAt: '2026-07-26T12:00:00Z',
      serialNumberDigest: DIGEST_A
    },
    components: [
      component(DIGEST_A, DIGEST_C, 'alpha'),
      component(DIGEST_B, DIGEST_D, 'beta')
    ],
    dependencies: [
      {
        componentId: DIGEST_A,
        dependsOnComponentId: DIGEST_B
      }
    ],
    statistics: {
      observedComponentCount: 2,
      observedDependencyNodeCount: 1,
      observedDependencyEdgeCount: 1,
      discardedPropertyCount: 4,
      discardedSourceLocationPropertyCount: 2,
      discardedExternalReferenceCount: 1,
      discardedLicenseUrlCount: 1,
      discardedProseFieldCount: 1
    },
    authority: {
      capability: 'SBOM',
      mayCreateFindings: false,
      mayEvaluateVulnerabilities: false,
      policyAuthority: false,
      aiPayloadEligible: false
    },
    dataHandling: {
      rawArtifactEmbedded: false,
      rawPropertiesStored: false,
      sourceLocationsStored: false,
      rawLicenseTextStored: false
    },
    durablePersistenceAllowed: false
  };
}

function component(componentId, producerBomRefDigest, name) {
  return {
    componentId,
    producerBomRefDigest,
    type: 'library',
    group: '',
    name,
    version: '1.0.0',
    purl: `pkg:npm/${name}@1.0.0`,
    cpe: '',
    licenses: [{ kind: 'SPDX_ID', value: 'MIT' }],
    rawPropertiesStored: false,
    sourceLocationsStored: false
  };
}
