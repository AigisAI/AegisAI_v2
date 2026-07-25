import type {
  SastArtifactDispositionScope
} from './sast-artifact-disposition';
import {
  orderSastNormalizationRejectionReasons,
  type SastNormalizationRejectionReasonCode
} from './sast-normalization';
import {
  hasExactKeys,
  isAllowedString,
  isBoundedIdentifier,
  isBoundedReference,
  isCommitSha,
  isNormalizationScopeValid,
  isRecord,
  isSha256Digest
} from './sast-normalization-validation';
import {
  SAST_PROFILE_IDS,
  type SastProfileId,
  type SastScanLane
} from './sast-runtime';

export const SYFT_CYCLONEDX_INVENTORY_INGESTOR_VERSION =
  'syft-cyclonedx-inventory-ingestor-v1' as const;

export const SYFT_CYCLONEDX_PRODUCER_VERSION = '1.44.0' as const;

export const SYFT_CYCLONEDX_SCHEMA_URI =
  'http://cyclonedx.org/schema/bom-1.6.schema.json' as const;

export const SYFT_CYCLONEDX_COMPONENT_TYPES = [
  'application',
  'library',
  'machine-learning-model',
  'operating-system'
] as const;
export type SyftCycloneDxComponentType =
  (typeof SYFT_CYCLONEDX_COMPONENT_TYPES)[number];

export const SYFT_CYCLONEDX_LICENSE_KINDS = [
  'SPDX_ID',
  'SPDX_EXPRESSION',
  'DECLARED_NAME'
] as const;
export type SyftCycloneDxLicenseKind =
  (typeof SYFT_CYCLONEDX_LICENSE_KINDS)[number];

export const SYFT_CYCLONEDX_INVENTORY_LIMITS = Object.freeze({
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

export interface SyftCycloneDxInventoryLicense {
  kind: SyftCycloneDxLicenseKind;
  value: string;
}

/**
 * The producer BOM reference is retained only as a digest. Syft may derive it
 * from package-local identity and locations; callers do not receive the raw
 * value or any `syft:location:*` property.
 */
export interface SyftCycloneDxInventoryComponent {
  componentId: `sha256:${string}`;
  producerBomRefDigest: `sha256:${string}`;
  type: SyftCycloneDxComponentType;
  group: string;
  name: string;
  version: string;
  purl: string;
  cpe: string;
  licenses: SyftCycloneDxInventoryLicense[];
  rawPropertiesStored: false;
  sourceLocationsStored: false;
}

export interface SyftCycloneDxDependencyEdge {
  componentId: `sha256:${string}`;
  dependsOnComponentId: `sha256:${string}`;
}

export interface SyftCycloneDxProducerMetadata {
  schemaUri: typeof SYFT_CYCLONEDX_SCHEMA_URI;
  specVersion: '1.6';
  bomVersion: 1;
  toolVendor: 'anchore';
  toolName: 'syft';
  toolVersion: typeof SYFT_CYCLONEDX_PRODUCER_VERSION;
  generatedAt: string;
  serialNumberDigest: `sha256:${string}`;
}

export interface SyftCycloneDxInventoryStatistics {
  observedComponentCount: number;
  observedDependencyNodeCount: number;
  observedDependencyEdgeCount: number;
  discardedPropertyCount: number;
  discardedSourceLocationPropertyCount: number;
  discardedExternalReferenceCount: number;
  discardedLicenseUrlCount: number;
  discardedProseFieldCount: number;
}

export interface SyftCycloneDxInventoryAuthority {
  capability: 'SBOM';
  mayCreateFindings: false;
  mayEvaluateVulnerabilities: false;
  policyAuthority: false;
  aiPayloadEligible: false;
}

export interface SyftCycloneDxInventoryDataHandling {
  rawArtifactEmbedded: false;
  rawPropertiesStored: false;
  sourceLocationsStored: false;
  rawLicenseTextStored: false;
}

export interface SyftCycloneDxInventoryBatch {
  version: typeof SYFT_CYCLONEDX_INVENTORY_INGESTOR_VERSION;
  adapterVersion: typeof SYFT_CYCLONEDX_INVENTORY_INGESTOR_VERSION;
  artifactSchema: 'CYCLONEDX_JSON';
  artifactSchemaVersion: '1.6';
  ingestionId: string;
  scope: Readonly<SastArtifactDispositionScope>;
  scannerRunId: string;
  scanner: 'SYFT';
  scannerVersion: typeof SYFT_CYCLONEDX_PRODUCER_VERSION;
  scannerImageDigest: `sha256:${string}`;
  wrapperDigest: `sha256:${string}`;
  scannerSetDigest: `sha256:${string}`;
  profileId: SastProfileId;
  profileDigest: `sha256:${string}`;
  planDigest: `sha256:${string}`;
  canonicalScanKey: `sha256:${string}`;
  preflightAttestationRef: string;
  preflightInventoryDigest: `sha256:${string}`;
  lane: SastScanLane;
  commitSha: string;
  envelopeDigest: `sha256:${string}`;
  artifactDigest: `sha256:${string}`;
  schemaBundleDigest: `sha256:${string}`;
  normalizerBundleDigest: `sha256:${string}`;
  validationResultDigest: `sha256:${string}`;
  dispositionDecisionDigest: `sha256:${string}`;
  retentionExpiresAt: string;
  producer: SyftCycloneDxProducerMetadata;
  components: SyftCycloneDxInventoryComponent[];
  dependencies: SyftCycloneDxDependencyEdge[];
  statistics: SyftCycloneDxInventoryStatistics;
  authority: SyftCycloneDxInventoryAuthority;
  dataHandling: SyftCycloneDxInventoryDataHandling;
  durablePersistenceAllowed: false;
  batchDigest: `sha256:${string}`;
}

export type SyftCycloneDxInventoryBatchCore = Omit<
  SyftCycloneDxInventoryBatch,
  'batchDigest'
>;

export interface SyftCycloneDxInventorySuccess {
  outcome: 'INGESTED';
  batch: SyftCycloneDxInventoryBatch;
}

export interface SyftCycloneDxInventoryRejection {
  version: typeof SYFT_CYCLONEDX_INVENTORY_INGESTOR_VERSION;
  adapterVersion: typeof SYFT_CYCLONEDX_INVENTORY_INGESTOR_VERSION;
  outcome: 'REJECTED';
  ingestionId: string;
  reasonCodes: SastNormalizationRejectionReasonCode[];
  rejectionDigest: `sha256:${string}`;
}

export type SyftCycloneDxInventoryRejectionCore = Omit<
  SyftCycloneDxInventoryRejection,
  'rejectionDigest'
>;

export type SyftCycloneDxInventoryResult =
  | SyftCycloneDxInventorySuccess
  | SyftCycloneDxInventoryRejection;

export function canonicalizeSyftCycloneDxInventoryLicense(
  license: Readonly<SyftCycloneDxInventoryLicense>
) {
  return {
    kind: license.kind,
    value: license.value
  };
}

export function canonicalizeSyftCycloneDxInventoryComponent(
  component: Readonly<SyftCycloneDxInventoryComponent>
) {
  return {
    componentId: component.componentId,
    producerBomRefDigest: component.producerBomRefDigest,
    type: component.type,
    group: component.group,
    name: component.name,
    version: component.version,
    purl: component.purl,
    cpe: component.cpe,
    licenses: component.licenses.map(
      canonicalizeSyftCycloneDxInventoryLicense
    ),
    rawPropertiesStored: false,
    sourceLocationsStored: false
  };
}

export function canonicalizeSyftCycloneDxDependencyEdge(
  dependency: Readonly<SyftCycloneDxDependencyEdge>
) {
  return {
    componentId: dependency.componentId,
    dependsOnComponentId: dependency.dependsOnComponentId
  };
}

export function canonicalizeSyftCycloneDxInventoryBatch(
  batch: Readonly<SyftCycloneDxInventoryBatchCore>
): string {
  return JSON.stringify({
    version: batch.version,
    adapterVersion: batch.adapterVersion,
    artifactSchema: batch.artifactSchema,
    artifactSchemaVersion: batch.artifactSchemaVersion,
    ingestionId: batch.ingestionId,
    scope: {
      tenantId: batch.scope.tenantId,
      repositoryBindingId: batch.scope.repositoryBindingId,
      scanRequestId: batch.scope.scanRequestId,
      attemptId: batch.scope.attemptId,
      scannerRunId: batch.scope.scannerRunId
    },
    scannerRunId: batch.scannerRunId,
    scanner: batch.scanner,
    scannerVersion: batch.scannerVersion,
    scannerImageDigest: batch.scannerImageDigest,
    wrapperDigest: batch.wrapperDigest,
    scannerSetDigest: batch.scannerSetDigest,
    profileId: batch.profileId,
    profileDigest: batch.profileDigest,
    planDigest: batch.planDigest,
    canonicalScanKey: batch.canonicalScanKey,
    preflightAttestationRef: batch.preflightAttestationRef,
    preflightInventoryDigest: batch.preflightInventoryDigest,
    lane: batch.lane,
    commitSha: batch.commitSha,
    envelopeDigest: batch.envelopeDigest,
    artifactDigest: batch.artifactDigest,
    schemaBundleDigest: batch.schemaBundleDigest,
    normalizerBundleDigest: batch.normalizerBundleDigest,
    validationResultDigest: batch.validationResultDigest,
    dispositionDecisionDigest: batch.dispositionDecisionDigest,
    retentionExpiresAt: batch.retentionExpiresAt,
    producer: {
      schemaUri: batch.producer.schemaUri,
      specVersion: batch.producer.specVersion,
      bomVersion: batch.producer.bomVersion,
      toolVendor: batch.producer.toolVendor,
      toolName: batch.producer.toolName,
      toolVersion: batch.producer.toolVersion,
      generatedAt: batch.producer.generatedAt,
      serialNumberDigest: batch.producer.serialNumberDigest
    },
    components: batch.components.map(
      canonicalizeSyftCycloneDxInventoryComponent
    ),
    dependencies: batch.dependencies.map(
      canonicalizeSyftCycloneDxDependencyEdge
    ),
    statistics: {
      observedComponentCount:
        batch.statistics.observedComponentCount,
      observedDependencyNodeCount:
        batch.statistics.observedDependencyNodeCount,
      observedDependencyEdgeCount:
        batch.statistics.observedDependencyEdgeCount,
      discardedPropertyCount:
        batch.statistics.discardedPropertyCount,
      discardedSourceLocationPropertyCount:
        batch.statistics.discardedSourceLocationPropertyCount,
      discardedExternalReferenceCount:
        batch.statistics.discardedExternalReferenceCount,
      discardedLicenseUrlCount:
        batch.statistics.discardedLicenseUrlCount,
      discardedProseFieldCount:
        batch.statistics.discardedProseFieldCount
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
  });
}

export function canonicalizeSyftCycloneDxInventoryRejection(
  rejection: Readonly<SyftCycloneDxInventoryRejectionCore>
): string {
  return JSON.stringify({
    version: rejection.version,
    adapterVersion: rejection.adapterVersion,
    outcome: rejection.outcome,
    ingestionId: rejection.ingestionId,
    reasonCodes: [...rejection.reasonCodes]
  });
}

export function compareSyftCycloneDxInventoryLicenses(
  left: Readonly<SyftCycloneDxInventoryLicense>,
  right: Readonly<SyftCycloneDxInventoryLicense>
): number {
  return (
    compareCodeUnitStrings(left.kind, right.kind) ||
    compareCodeUnitStrings(left.value, right.value)
  );
}

export function compareSyftCycloneDxInventoryComponents(
  left: Readonly<SyftCycloneDxInventoryComponent>,
  right: Readonly<SyftCycloneDxInventoryComponent>
): number {
  return (
    compareCodeUnitStrings(left.componentId, right.componentId) ||
    compareCodeUnitStrings(
      left.producerBomRefDigest,
      right.producerBomRefDigest
    )
  );
}

export function compareSyftCycloneDxDependencyEdges(
  left: Readonly<SyftCycloneDxDependencyEdge>,
  right: Readonly<SyftCycloneDxDependencyEdge>
): number {
  return (
    compareCodeUnitStrings(left.componentId, right.componentId) ||
    compareCodeUnitStrings(
      left.dependsOnComponentId,
      right.dependsOnComponentId
    )
  );
}

export function isSyftCycloneDxInventoryBatchShapeValid(
  value: unknown
): value is SyftCycloneDxInventoryBatch {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'version',
      'adapterVersion',
      'artifactSchema',
      'artifactSchemaVersion',
      'ingestionId',
      'scope',
      'scannerRunId',
      'scanner',
      'scannerVersion',
      'scannerImageDigest',
      'wrapperDigest',
      'scannerSetDigest',
      'profileId',
      'profileDigest',
      'planDigest',
      'canonicalScanKey',
      'preflightAttestationRef',
      'preflightInventoryDigest',
      'lane',
      'commitSha',
      'envelopeDigest',
      'artifactDigest',
      'schemaBundleDigest',
      'normalizerBundleDigest',
      'validationResultDigest',
      'dispositionDecisionDigest',
      'retentionExpiresAt',
      'producer',
      'components',
      'dependencies',
      'statistics',
      'authority',
      'dataHandling',
      'durablePersistenceAllowed',
      'batchDigest'
    ]) ||
    value.version !==
      SYFT_CYCLONEDX_INVENTORY_INGESTOR_VERSION ||
    value.adapterVersion !==
      SYFT_CYCLONEDX_INVENTORY_INGESTOR_VERSION ||
    value.artifactSchema !== 'CYCLONEDX_JSON' ||
    value.artifactSchemaVersion !== '1.6' ||
    !isBoundedReference(value.ingestionId) ||
    !isNormalizationScopeValid(value.scope) ||
    !isBoundedReference(value.scannerRunId) ||
    value.scanner !== 'SYFT' ||
    value.scannerVersion !== SYFT_CYCLONEDX_PRODUCER_VERSION ||
    !isAllowedString(value.profileId, SAST_PROFILE_IDS) ||
    !isAllowedString(value.lane, ['FAST', 'DEEP']) ||
    !isBoundedReference(value.preflightAttestationRef) ||
    !isCommitSha(value.commitSha) ||
    !isCanonicalTimestamp(value.retentionExpiresAt) ||
    ![
      value.scannerImageDigest,
      value.wrapperDigest,
      value.scannerSetDigest,
      value.profileDigest,
      value.planDigest,
      value.canonicalScanKey,
      value.preflightInventoryDigest,
      value.envelopeDigest,
      value.artifactDigest,
      value.schemaBundleDigest,
      value.normalizerBundleDigest,
      value.validationResultDigest,
      value.dispositionDecisionDigest,
      value.batchDigest
    ].every(isSha256Digest) ||
    !isProducerMetadataValid(
      value.producer,
      value.scannerVersion
    ) ||
    !Array.isArray(value.components) ||
    value.components.length >
      SYFT_CYCLONEDX_INVENTORY_LIMITS.maximumComponents ||
    !Array.isArray(value.dependencies) ||
    value.dependencies.length >
      SYFT_CYCLONEDX_INVENTORY_LIMITS.maximumDependencyEdges ||
    !isInventoryStatisticsValid(
      value.statistics,
      value.components.length,
      value.dependencies.length
    ) ||
    !isInventoryAuthorityValid(value.authority) ||
    !isInventoryDataHandlingValid(value.dataHandling) ||
    value.durablePersistenceAllowed !== false
  ) {
    return false;
  }

  const scope = value.scope as SastArtifactDispositionScope;
  if (
    value.scannerRunId !== scope.scannerRunId ||
    Date.parse(value.retentionExpiresAt as string) <=
      Date.parse(
        (value.producer as SyftCycloneDxProducerMetadata).generatedAt
      )
  ) {
    return false;
  }

  const components =
    value.components as readonly SyftCycloneDxInventoryComponent[];
  const componentIds = new Set<string>();
  const producerBomRefs = new Set<string>();
  for (let index = 0; index < components.length; index += 1) {
    const component = components[index]!;
    if (
      !isInventoryComponentValid(component) ||
      componentIds.has(component.componentId) ||
      producerBomRefs.has(component.producerBomRefDigest) ||
      (index > 0 &&
        compareSyftCycloneDxInventoryComponents(
          components[index - 1]!,
          component
        ) >= 0)
    ) {
      return false;
    }
    componentIds.add(component.componentId);
    producerBomRefs.add(component.producerBomRefDigest);
  }

  const dependencies =
    value.dependencies as readonly SyftCycloneDxDependencyEdge[];
  if (
    !dependencies.every(
      (dependency, index) =>
        isDependencyEdgeValid(dependency) &&
        componentIds.has(dependency.componentId) &&
        componentIds.has(dependency.dependsOnComponentId) &&
        dependency.componentId !==
          dependency.dependsOnComponentId &&
        (index === 0 ||
          compareSyftCycloneDxDependencyEdges(
            dependencies[index - 1]!,
            dependency
          ) < 0)
    )
  ) {
    return false;
  }
  return (
    new Set(
      dependencies.map((dependency) => dependency.componentId)
    ).size ===
    (
      value.statistics as SyftCycloneDxInventoryStatistics
    ).observedDependencyNodeCount
  );
}

export function isSyftCycloneDxInventoryRejectionShapeValid(
  value: unknown
): value is SyftCycloneDxInventoryRejection {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'version',
      'adapterVersion',
      'outcome',
      'ingestionId',
      'reasonCodes',
      'rejectionDigest'
    ]) ||
    value.version !==
      SYFT_CYCLONEDX_INVENTORY_INGESTOR_VERSION ||
    value.adapterVersion !==
      SYFT_CYCLONEDX_INVENTORY_INGESTOR_VERSION ||
    value.outcome !== 'REJECTED' ||
    !isBoundedReference(value.ingestionId) ||
    !Array.isArray(value.reasonCodes) ||
    value.reasonCodes.length === 0 ||
    !isSha256Digest(value.rejectionDigest)
  ) {
    return false;
  }
  const ordered = orderSastNormalizationRejectionReasons(
    value.reasonCodes as SastNormalizationRejectionReasonCode[]
  );
  return arraysEqual(value.reasonCodes, ordered);
}

function isProducerMetadataValid(
  value: unknown,
  scannerVersion: unknown
): value is SyftCycloneDxProducerMetadata {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      'schemaUri',
      'specVersion',
      'bomVersion',
      'toolVendor',
      'toolName',
      'toolVersion',
      'generatedAt',
      'serialNumberDigest'
    ]) &&
    value.schemaUri === SYFT_CYCLONEDX_SCHEMA_URI &&
    value.specVersion === '1.6' &&
    value.bomVersion === 1 &&
    value.toolVendor === 'anchore' &&
    value.toolName === 'syft' &&
    value.toolVersion === SYFT_CYCLONEDX_PRODUCER_VERSION &&
    value.toolVersion === scannerVersion &&
    isBoundedIdentifier(value.toolVersion, 255, false) &&
    isCanonicalTimestamp(value.generatedAt) &&
    isSha256Digest(value.serialNumberDigest)
  );
}

function isInventoryComponentValid(
  value: unknown
): value is SyftCycloneDxInventoryComponent {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'componentId',
      'producerBomRefDigest',
      'type',
      'group',
      'name',
      'version',
      'purl',
      'cpe',
      'licenses',
      'rawPropertiesStored',
      'sourceLocationsStored'
    ]) ||
    !isSha256Digest(value.componentId) ||
    !isSha256Digest(value.producerBomRefDigest) ||
    !isAllowedString(value.type, SYFT_CYCLONEDX_COMPONENT_TYPES) ||
    !isBoundedIdentifier(
      value.group,
      SYFT_CYCLONEDX_INVENTORY_LIMITS.componentGroupBytes,
      true
    ) ||
    !isBoundedIdentifier(
      value.name,
      SYFT_CYCLONEDX_INVENTORY_LIMITS.componentNameBytes,
      false
    ) ||
    !isBoundedIdentifier(
      value.version,
      SYFT_CYCLONEDX_INVENTORY_LIMITS.componentVersionBytes,
      true
    ) ||
    !isBoundedIdentifier(
      value.purl,
      SYFT_CYCLONEDX_INVENTORY_LIMITS.packageUrlBytes,
      true
    ) ||
    !isBoundedIdentifier(
      value.cpe,
      SYFT_CYCLONEDX_INVENTORY_LIMITS.cpeBytes,
      true
    ) ||
    (value.purl !== '' &&
      !(value.purl as string).startsWith('pkg:')) ||
    (value.cpe !== '' &&
      !(value.cpe as string).startsWith('cpe:2.3:')) ||
    !Array.isArray(value.licenses) ||
    value.licenses.length >
      SYFT_CYCLONEDX_INVENTORY_LIMITS.maximumLicensesPerComponent ||
    value.rawPropertiesStored !== false ||
    value.sourceLocationsStored !== false
  ) {
    return false;
  }
  const licenses =
    value.licenses as readonly SyftCycloneDxInventoryLicense[];
  return licenses.every(
    (license, index) =>
      isInventoryLicenseValid(license) &&
      (index === 0 ||
        compareSyftCycloneDxInventoryLicenses(
          licenses[index - 1]!,
          license
        ) < 0)
  );
}

function isInventoryLicenseValid(
  value: unknown
): value is SyftCycloneDxInventoryLicense {
  return (
    isRecord(value) &&
    hasExactKeys(value, ['kind', 'value']) &&
    isAllowedString(value.kind, SYFT_CYCLONEDX_LICENSE_KINDS) &&
    isBoundedIdentifier(
      value.value,
      SYFT_CYCLONEDX_INVENTORY_LIMITS.licenseValueBytes,
      false
    )
  );
}

function isDependencyEdgeValid(
  value: unknown
): value is SyftCycloneDxDependencyEdge {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      'componentId',
      'dependsOnComponentId'
    ]) &&
    isSha256Digest(value.componentId) &&
    isSha256Digest(value.dependsOnComponentId)
  );
}

function isInventoryStatisticsValid(
  value: unknown,
  componentCount: number,
  dependencyEdgeCount: number
): value is SyftCycloneDxInventoryStatistics {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'observedComponentCount',
      'observedDependencyNodeCount',
      'observedDependencyEdgeCount',
      'discardedPropertyCount',
      'discardedSourceLocationPropertyCount',
      'discardedExternalReferenceCount',
      'discardedLicenseUrlCount',
      'discardedProseFieldCount'
    ])
  ) {
    return false;
  }
  if (!Object.values(value).every(isNonNegativeSafeInteger)) {
    return false;
  }
  const statistics =
    value as unknown as SyftCycloneDxInventoryStatistics;
  return (
    statistics.observedComponentCount === componentCount &&
    statistics.observedComponentCount <=
      SYFT_CYCLONEDX_INVENTORY_LIMITS.maximumComponents &&
    statistics.observedDependencyNodeCount <= componentCount &&
    statistics.observedDependencyNodeCount <=
      dependencyEdgeCount &&
    statistics.observedDependencyNodeCount <=
      SYFT_CYCLONEDX_INVENTORY_LIMITS.maximumDependencyNodes &&
    statistics.observedDependencyEdgeCount ===
      dependencyEdgeCount &&
    statistics.observedDependencyEdgeCount <=
      SYFT_CYCLONEDX_INVENTORY_LIMITS.maximumDependencyEdges &&
    statistics.discardedPropertyCount <=
      componentCount *
        SYFT_CYCLONEDX_INVENTORY_LIMITS
          .maximumPropertiesPerComponent &&
    statistics.discardedSourceLocationPropertyCount <=
      statistics.discardedPropertyCount &&
    statistics.discardedExternalReferenceCount <=
      componentCount *
        SYFT_CYCLONEDX_INVENTORY_LIMITS
          .maximumExternalReferencesPerComponent &&
    statistics.discardedLicenseUrlCount <=
      componentCount *
        SYFT_CYCLONEDX_INVENTORY_LIMITS
          .maximumLicensesPerComponent &&
    statistics.discardedProseFieldCount <=
      componentCount *
        SYFT_CYCLONEDX_INVENTORY_LIMITS
          .maximumDiscardedProseFieldsPerComponent
  );
}

function isInventoryAuthorityValid(
  value: unknown
): value is SyftCycloneDxInventoryAuthority {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      'capability',
      'mayCreateFindings',
      'mayEvaluateVulnerabilities',
      'policyAuthority',
      'aiPayloadEligible'
    ]) &&
    value.capability === 'SBOM' &&
    value.mayCreateFindings === false &&
    value.mayEvaluateVulnerabilities === false &&
    value.policyAuthority === false &&
    value.aiPayloadEligible === false
  );
}

function isInventoryDataHandlingValid(
  value: unknown
): value is SyftCycloneDxInventoryDataHandling {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      'rawArtifactEmbedded',
      'rawPropertiesStored',
      'sourceLocationsStored',
      'rawLicenseTextStored'
    ]) &&
    value.rawArtifactEmbedded === false &&
    value.rawPropertiesStored === false &&
    value.sourceLocationsStored === false &&
    value.rawLicenseTextStored === false
  );
}

function isCanonicalTimestamp(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u.test(
      value
    ) &&
    Number.isFinite(Date.parse(value))
  );
}

function isNonNegativeSafeInteger(value: unknown): value is number {
  return (
    typeof value === 'number' &&
    Number.isSafeInteger(value) &&
    value >= 0
  );
}

function arraysEqual(
  left: readonly unknown[],
  right: readonly unknown[]
): boolean {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

function compareCodeUnitStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
