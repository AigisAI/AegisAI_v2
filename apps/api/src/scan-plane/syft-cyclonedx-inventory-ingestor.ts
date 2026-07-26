import {
  SAST_ARTIFACT_SCHEMA_VERSIONS,
  SAST_SCANNER_SELECTED_WORKSPACE_ROOT,
  SAST_SCANNER_WORKSPACE_ROOT,
  SYFT_CYCLONEDX_COMPONENT_TYPES,
  SYFT_CYCLONEDX_INVENTORY_INGESTOR_VERSION,
  SYFT_CYCLONEDX_INVENTORY_LIMITS,
  SYFT_CYCLONEDX_PRODUCER_VERSION,
  SYFT_CYCLONEDX_SCHEMA_URI,
  buildSastScanPlanDigestPreimage,
  canonicalizeSastArtifactDispositionDecision,
  canonicalizeSastArtifactValidationResult,
  canonicalizeScannerArtifactEnvelope,
  canonicalizeSyftCycloneDxInventoryBatch,
  canonicalizeSyftCycloneDxInventoryRejection,
  compareSyftCycloneDxDependencyEdges,
  compareSyftCycloneDxInventoryComponents,
  compareSyftCycloneDxInventoryLicenses,
  isSastArtifactDispositionDecisionShapeValid,
  isSastArtifactValidationResultShapeValid,
  isScannerArtifactEnvelopeBoundToPlan,
  isSyftCycloneDxInventoryBatchShapeValid,
  orderSastNormalizationRejectionReasons,
  type ExpectedScannerArtifactBinding,
  type SastArtifactDispositionDecision,
  type SastArtifactValidationResult,
  type SastNormalizationRejectionReasonCode,
  type SastScanPlan,
  type ScannerArtifactEnvelope,
  type SyftCycloneDxComponentType,
  type SyftCycloneDxDependencyEdge,
  type SyftCycloneDxInventoryBatchCore,
  type SyftCycloneDxInventoryComponent,
  type SyftCycloneDxInventoryLicense,
  type SyftCycloneDxInventoryRejectionCore,
  type SyftCycloneDxInventoryResult,
  type SyftCycloneDxInventoryStatistics
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';

import {
  type ContainerKind,
  type JsonPath,
  type JsonPrimitive
} from './sast-artifact-stream-validator';
import {
  canonicalizeSpdxLicenseExceptionIdentifier,
  canonicalizeSpdxLicenseExpressionIdentifier,
  canonicalizeSpdxLicenseIdentifier
} from './spdx-license-list-3.28';
import {
  digest,
  hasUnsafeControls,
  omitDecisionDigest,
  omitResultDigest,
  readReferenceTime,
  SastNormalizationJsonStreamSession,
  type SastNormalizationJsonCollector,
  utf8Bytes,
  validateSastNormalizationReferenceTime
} from './sast-normalization-support';

const ROOT_KEYS = new Set([
  '$schema',
  'bomFormat',
  'specVersion',
  'serialNumber',
  'version',
  'metadata',
  'components',
  'dependencies'
]);
const METADATA_KEYS = new Set([
  'timestamp',
  'tools',
  'component'
]);
const TOOLS_KEYS = new Set(['components']);
const TOOL_COMPONENT_KEYS = new Set([
  'type',
  'author',
  'name',
  'version'
]);
const SOURCE_COMPONENT_KEYS = new Set([
  'bom-ref',
  'type',
  'name'
]);
const COMPONENT_KEYS = new Set([
  'bom-ref',
  'type',
  'group',
  'name',
  'version',
  'licenses',
  'cpe',
  'purl',
  'author',
  'publisher',
  'description',
  'externalReferences',
  'properties',
  'swid'
]);
const LICENSE_CHOICE_KEYS = new Set(['license', 'expression']);
const LICENSE_KEYS = new Set(['id', 'name', 'url']);
const PROPERTY_KEYS = new Set(['name', 'value']);
const EXTERNAL_REFERENCE_KEYS = new Set([
  'type',
  'url',
  'comment',
  'hashes'
]);
const HASH_KEYS = new Set(['alg', 'content']);
const SWID_KEYS = new Set(['tagId', 'name', 'version']);
const DEPENDENCY_KEYS = new Set(['ref', 'dependsOn']);
const SYFT_EXTERNAL_REFERENCE_TYPES = new Set([
  'build-meta',
  'distribution',
  'issue-tracker',
  'other',
  'vcs',
  'website'
]);
const SYFT_EXTERNAL_REFERENCE_HASH_PATTERNS = new Map([
  ['MD5', /^[a-f0-9]{32}$/u],
  ['SHA-1', /^[a-f0-9]{40}$/u],
  ['SHA-256', /^[a-f0-9]{64}$/u]
]);

const COMPONENT_IDENTITY_VERSION =
  'syft-cyclonedx-component-identity-v1';
const UUID_URN_PATTERN =
  /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SYFT_ARTIFACT_ID_PATTERN = /^[a-f0-9]{16}$/u;
const SYFT_PURL_TYPES_WITH_LEAF_COMPONENT_NAME = new Set([
  'apk',
  'alpm',
  'conan',
  'cpan',
  'deb',
  'maven',
  'qpkg',
  'rpm',
  'swid'
]);

interface SyftComponentState {
  key: string;
  index: number;
  keys: Set<string>;
  type?: string;
  bomRef?: string;
  group?: string;
  name?: string;
  version?: string;
  purl?: string;
  cpe?: string;
  licenses: SyftCycloneDxInventoryLicense[];
  propertyNames: Set<string>;
  propertyCount: number;
  externalReferenceCount: number;
  swidKeys: Set<string>;
  swidTagId?: string;
  swidName?: string;
  swidVersion?: string;
}

interface PropertyState {
  key: string;
  componentKey: string;
  keys: Set<string>;
  name?: string;
}

interface LicenseChoiceState {
  key: string;
  componentKey: string;
  keys: Set<string>;
  licenseSeen: boolean;
  discarded: boolean;
  expression?: string;
  resolved?: SyftCycloneDxInventoryLicense;
}

interface LicenseState {
  key: string;
  choiceKey: string;
  keys: Set<string>;
  id?: string;
  name?: string;
  url?: string;
}

interface ExternalReferenceState {
  key: string;
  componentKey: string;
  keys: Set<string>;
  type?: string;
  url?: string;
  hashCount: number;
}

interface HashState {
  key: string;
  externalReferenceKey: string;
  keys: Set<string>;
  algorithm?: string;
  content?: string;
}

interface DependencyState {
  key: string;
  index: number;
  keys: Set<string>;
  ref?: string;
  dependsOn: string[];
  dependsOnSet: Set<string>;
}

interface ParsedSyftComponent {
  bomRef: string;
  type: SyftCycloneDxComponentType;
  group: string;
  name: string;
  version: string;
  purl: string;
  cpe: string;
  licenses: SyftCycloneDxInventoryLicense[];
}

interface ParsedSyftCycloneDx {
  serialNumber: string;
  generatedAt: string;
  components: ParsedSyftComponent[];
  dependencies: Array<{
    ref: string;
    dependsOn: string[];
  }>;
  statistics: SyftCycloneDxInventoryStatistics;
}

interface ParsedPurlQualifier {
  key: string;
  rawValue: string;
  decodedValue: string;
}

interface ParsedPurl {
  type: string;
  namespace: string;
  name: string;
  version: string;
  qualifiers: ParsedPurlQualifier[];
  withoutPackageId: string;
}

export interface SyftCycloneDxInventoryInput {
  ingestionId: string;
  envelope: Readonly<ScannerArtifactEnvelope>;
  envelopeDigest: `sha256:${string}`;
  plan: Readonly<SastScanPlan>;
  expectedBinding: Readonly<ExpectedScannerArtifactBinding>;
  validation: Readonly<SastArtifactValidationResult>;
  disposition: Readonly<SastArtifactDispositionDecision>;
}

@Injectable()
export class SyftCycloneDxInventoryIngestor {
  async ingest(
    input: Readonly<SyftCycloneDxInventoryInput>,
    artifact: AsyncIterable<Uint8Array>,
    referenceClock: () => Date = () => new Date()
  ): Promise<SyftCycloneDxInventoryResult> {
    const binding = this.validateBinding(
      input,
      readReferenceTime(referenceClock)
    );
    if (binding.reasons.size > 0 || !binding.planDigest) {
      return this.reject(input.ingestionId, binding.reasons);
    }

    const stream =
      new SastNormalizationJsonStreamSession<ParsedSyftCycloneDx>(
        input.envelope,
        input.plan.profile.limits.maxArtifactBytes,
        (reasons) =>
          new SyftCycloneDxCollector(
            input.plan.profile.limits.maxArtifactRecords,
            SYFT_CYCLONEDX_PRODUCER_VERSION,
            expectedScannerInputPath(input),
            input.plan.createdAt,
            input.envelope.producedAt,
            reasons
          )
      );
    const parsed = await stream.parse(artifact);
    for (const reason of stream.reasons) {
      binding.reasons.add(reason);
    }

    const completedAtMilliseconds =
      validateSastNormalizationReferenceTime(
        input.disposition,
        readReferenceTime(referenceClock),
        binding.reasons
      );
    if (
      Number.isFinite(binding.startedAtMilliseconds) &&
      Number.isFinite(completedAtMilliseconds) &&
      completedAtMilliseconds < binding.startedAtMilliseconds
    ) {
      binding.reasons.add('NORMALIZATION_ACCEPTANCE_INVALID');
    }
    if (!parsed || binding.reasons.size > 0) {
      return this.reject(input.ingestionId, binding.reasons);
    }

    const inventory = buildInventory(parsed, binding.reasons);
    if (!inventory || binding.reasons.size > 0) {
      return this.reject(input.ingestionId, binding.reasons);
    }

    const core: SyftCycloneDxInventoryBatchCore = {
      version: SYFT_CYCLONEDX_INVENTORY_INGESTOR_VERSION,
      adapterVersion:
        SYFT_CYCLONEDX_INVENTORY_INGESTOR_VERSION,
      artifactSchema: 'CYCLONEDX_JSON',
      artifactSchemaVersion:
        SAST_ARTIFACT_SCHEMA_VERSIONS.CYCLONEDX_JSON,
      ingestionId: input.ingestionId,
      scope: {
        tenantId: input.envelope.tenantId,
        repositoryBindingId:
          input.envelope.repositoryBindingId,
        scanRequestId: input.envelope.scanRequestId,
        attemptId: input.envelope.attemptId,
        scannerRunId: input.envelope.scannerRunId
      },
      scannerRunId: input.envelope.scannerRunId,
      scanner: 'SYFT',
      scannerVersion: SYFT_CYCLONEDX_PRODUCER_VERSION,
      scannerImageDigest: input.envelope.scannerImageDigest,
      wrapperDigest: input.envelope.wrapperDigest,
      scannerSetDigest: input.envelope.scannerSetDigest,
      profileId: input.envelope.profileId,
      profileDigest: input.envelope.profileDigest,
      planDigest: binding.planDigest,
      canonicalScanKey: input.plan.canonicalScanKey,
      preflightAttestationRef:
        input.expectedBinding.preflightAttestationRef,
      preflightInventoryDigest:
        input.expectedBinding.preflightInventoryDigest,
      lane: input.plan.profile.lane,
      commitSha: input.plan.repositoryState.fixedCommitSha,
      envelopeDigest: input.envelopeDigest,
      artifactDigest: input.envelope.contentDigest,
      schemaBundleDigest: input.envelope.schemaBundleDigest,
      normalizerBundleDigest:
        input.envelope.normalizerBundleDigest,
      validationResultDigest: input.validation.resultDigest,
      dispositionDecisionDigest:
        input.disposition.decisionDigest,
      retentionExpiresAt:
        input.disposition.retentionExpiresAt as string,
      producer: {
        schemaUri: SYFT_CYCLONEDX_SCHEMA_URI,
        specVersion: '1.6',
        bomVersion: 1,
        toolVendor: 'anchore',
        toolName: 'syft',
        toolVersion: SYFT_CYCLONEDX_PRODUCER_VERSION,
        generatedAt: parsed.generatedAt,
        serialNumberDigest: digest(parsed.serialNumber)
      },
      components: inventory.components,
      dependencies: inventory.dependencies,
      statistics: parsed.statistics,
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
    const batch = {
      ...core,
      batchDigest: digest(
        canonicalizeSyftCycloneDxInventoryBatch(core)
      )
    };
    if (!isSyftCycloneDxInventoryBatchShapeValid(batch)) {
      binding.reasons.add(
        'NORMALIZATION_CYCLONEDX_STRUCTURE_INVALID'
      );
      return this.reject(input.ingestionId, binding.reasons);
    }
    return { outcome: 'INGESTED', batch };
  }

  private validateBinding(
    input: Readonly<SyftCycloneDxInventoryInput>,
    referenceTime: Readonly<Date>
  ): {
    reasons: Set<SastNormalizationRejectionReasonCode>;
    planDigest: `sha256:${string}` | null;
    startedAtMilliseconds: number;
  } {
    const reasons = new Set<SastNormalizationRejectionReasonCode>();
    const validationShapeValid =
      isSastArtifactValidationResultShapeValid(input.validation);
    const decisionShapeValid =
      isSastArtifactDispositionDecisionShapeValid(input.disposition);
    let envelopeDigest: `sha256:${string}` | null = null;
    let validationDigest: `sha256:${string}` | null = null;
    let decisionDigest: `sha256:${string}` | null = null;
    let planDigest: `sha256:${string}` | null = null;
    try {
      envelopeDigest = digest(
        canonicalizeScannerArtifactEnvelope(input.envelope)
      );
      if (validationShapeValid) {
        validationDigest = digest(
          canonicalizeSastArtifactValidationResult(
            omitResultDigest(input.validation)
          )
        );
      }
      if (decisionShapeValid) {
        decisionDigest = digest(
          canonicalizeSastArtifactDispositionDecision(
            omitDecisionDigest(input.disposition)
          )
        );
      }
      planDigest = digest(
        buildSastScanPlanDigestPreimage(input.plan)
      );
    } catch {
      // Malformed inputs expose only bounded reason codes.
    }

    if (
      !decisionShapeValid ||
      decisionDigest !== input.disposition.decisionDigest ||
      input.disposition.ingestionId !== input.ingestionId ||
      input.disposition.disposition !== 'ACCEPTED' ||
      input.disposition.storageAction !== 'RETAIN_ACCEPTED' ||
      input.disposition.normalizationEligible !== true
    ) {
      reasons.add('NORMALIZATION_ACCEPTANCE_INVALID');
    }

    const startedAtMilliseconds =
      validateSastNormalizationReferenceTime(
        input.disposition,
        referenceTime,
        reasons
      );
    if (
      envelopeDigest !== input.envelopeDigest ||
      planDigest === null ||
      !isScannerArtifactEnvelopeBoundToPlan(
        input.envelope,
        input.plan,
        input.expectedBinding
      ) ||
      input.envelope.scanner !== 'SYFT' ||
      input.envelope.scannerVersion !==
        SYFT_CYCLONEDX_PRODUCER_VERSION ||
      input.envelope.artifactSchema !== 'CYCLONEDX_JSON' ||
      input.envelope.artifactSchemaVersion !==
        SAST_ARTIFACT_SCHEMA_VERSIONS.CYCLONEDX_JSON ||
      input.envelope.ruleBundleDigest !== undefined ||
      input.envelope.vulnerabilityDatabaseDigest !== undefined
    ) {
      reasons.add('NORMALIZATION_PLAN_BINDING_MISMATCH');
    }

    if (
      !validationShapeValid ||
      validationDigest !== input.validation.resultDigest ||
      input.validation.outcome !== 'PASSED' ||
      input.validation.artifactSchema !== 'CYCLONEDX_JSON' ||
      input.validation.envelopeDigest !== input.envelopeDigest ||
      input.validation.observedContentDigest !==
        input.envelope.contentDigest ||
      input.validation.statistics.observedByteSize !==
        input.envelope.byteSize ||
      input.validation.statistics.observedRecordCount !==
        input.envelope.recordCount ||
      input.disposition.validationResultDigest !==
        input.validation.resultDigest
    ) {
      reasons.add('NORMALIZATION_VALIDATION_BINDING_MISMATCH');
    }

    return {
      reasons,
      planDigest,
      startedAtMilliseconds
    };
  }

  private reject(
    ingestionId: string,
    reasons: Iterable<SastNormalizationRejectionReasonCode>
  ): SyftCycloneDxInventoryResult {
    const core: SyftCycloneDxInventoryRejectionCore = {
      version: SYFT_CYCLONEDX_INVENTORY_INGESTOR_VERSION,
      adapterVersion:
        SYFT_CYCLONEDX_INVENTORY_INGESTOR_VERSION,
      outcome: 'REJECTED',
      ingestionId,
      reasonCodes: orderSastNormalizationRejectionReasons(reasons)
    };
    return {
      ...core,
      rejectionDigest: digest(
        canonicalizeSyftCycloneDxInventoryRejection(core)
      )
    };
  }
}

class SyftCycloneDxCollector implements
  SastNormalizationJsonCollector<ParsedSyftCycloneDx> {
  private rootKind?: ContainerKind;
  private readonly rootKeys = new Set<string>();
  private readonly metadataKeys = new Set<string>();
  private readonly toolsKeys = new Set<string>();
  private readonly toolKeys = new Set<string>();
  private readonly sourceComponentKeys = new Set<string>();
  private schemaUri?: string;
  private bomFormat?: string;
  private specVersion?: string;
  private serialNumber?: string;
  private bomVersion?: number;
  private generatedAt?: string;
  private toolType?: string;
  private toolAuthor?: string;
  private toolName?: string;
  private toolVersion?: string;
  private sourceBomRef?: string;
  private sourceType?: string;
  private sourceName?: string;
  private componentsSeen = false;
  private toolComponentsSeen = false;
  private toolComponentCount = 0;
  private componentCount = 0;
  private dependencyEdgeCount = 0;
  private discardedPropertyCount = 0;
  private discardedSourceLocationPropertyCount = 0;
  private discardedExternalReferenceCount = 0;
  private discardedLicenseUrlCount = 0;
  private discardedProseFieldCount = 0;
  private readonly components = new Map<
    string,
    SyftComponentState
  >();
  private readonly properties = new Map<string, PropertyState>();
  private readonly licenseChoices = new Map<
    string,
    LicenseChoiceState
  >();
  private readonly licenses = new Map<string, LicenseState>();
  private readonly externalReferences = new Map<
    string,
    ExternalReferenceState
  >();
  private readonly hashes = new Map<string, HashState>();
  private readonly dependencies = new Map<
    string,
    DependencyState
  >();

  constructor(
    private readonly maximumRecords: number,
    private readonly scannerVersion: string,
    private readonly sourceInputPath: string,
    private readonly planCreatedAt: string,
    private readonly envelopeProducedAt: string,
    private readonly reasons:
      Set<SastNormalizationRejectionReasonCode>
  ) {}

  get recordCount(): number {
    return this.componentCount;
  }

  onContainer(path: JsonPath, kind: ContainerKind): void {
    if (path.length === 0) {
      this.rootKind = kind;
      if (kind !== 'OBJECT') this.structureInvalid();
      return;
    }
    const expectedKind = expectedContainerKind(path);
    if (!expectedKind || expectedKind !== kind) {
      this.reasonForPath(path);
      return;
    }

    if (matches(path, ['metadata', 'tools', 'components'])) {
      this.toolComponentsSeen = true;
      return;
    }
    if (isToolComponentPath(path)) {
      this.toolComponentCount += 1;
      if (path[3] !== 0 || this.toolComponentCount > 1) {
        this.producerInvalid();
      }
      return;
    }
    if (matches(path, ['components'])) {
      this.componentsSeen = true;
      return;
    }
    if (isComponentPath(path)) {
      this.componentCount += 1;
      if (
        this.componentCount >
          Math.min(
            this.maximumRecords,
            SYFT_CYCLONEDX_INVENTORY_LIMITS
              .maximumComponents
          ) ||
        this.components.has(keyForPath(path))
      ) {
        this.componentInvalid();
        return;
      }
      this.components.set(keyForPath(path), {
        key: keyForPath(path),
        index: path[1] as number,
        keys: new Set(),
        licenses: [],
        propertyNames: new Set(),
        propertyCount: 0,
        externalReferenceCount: 0,
        swidKeys: new Set()
      });
      return;
    }
    if (isLicenseChoicePath(path)) {
      const component = this.componentFor(path);
      if (!component) {
        this.licenseInvalid();
        return;
      }
      const key = keyForPath(path);
      if (
        component.licenses.length +
          countOpenLicenses(this.licenseChoices, component.key) >=
          SYFT_CYCLONEDX_INVENTORY_LIMITS
            .maximumLicensesPerComponent ||
        this.licenseChoices.has(key)
      ) {
        this.licenseInvalid();
        return;
      }
      this.licenseChoices.set(key, {
        key,
        componentKey: component.key,
        keys: new Set(),
        licenseSeen: false,
        discarded: false
      });
      return;
    }
    if (isLicensePath(path)) {
      const choice = this.licenseChoiceFor(path);
      if (!choice || choice.licenseSeen) {
        this.licenseInvalid();
        return;
      }
      choice.licenseSeen = true;
      this.licenses.set(keyForPath(path), {
        key: keyForPath(path),
        choiceKey: choice.key,
        keys: new Set()
      });
      return;
    }
    if (isPropertyPath(path)) {
      const component = this.componentFor(path);
      if (
        !component ||
        component.propertyCount >=
          SYFT_CYCLONEDX_INVENTORY_LIMITS
            .maximumPropertiesPerComponent
      ) {
        this.componentInvalid();
        return;
      }
      component.propertyCount += 1;
      this.discardedPropertyCount += 1;
      this.properties.set(keyForPath(path), {
        key: keyForPath(path),
        componentKey: component.key,
        keys: new Set()
      });
      return;
    }
    if (isExternalReferencePath(path)) {
      const component = this.componentFor(path);
      if (
        !component ||
        component.externalReferenceCount >=
          SYFT_CYCLONEDX_INVENTORY_LIMITS
            .maximumExternalReferencesPerComponent
      ) {
        this.componentInvalid();
        return;
      }
      component.externalReferenceCount += 1;
      this.discardedExternalReferenceCount += 1;
      this.externalReferences.set(keyForPath(path), {
        key: keyForPath(path),
        componentKey: component.key,
        keys: new Set(),
        hashCount: 0
      });
      return;
    }
    if (isExternalReferenceHashPath(path)) {
      const externalReference =
        this.externalReferenceFor(path);
      if (
        !externalReference ||
        externalReference.hashCount >=
          SYFT_CYCLONEDX_INVENTORY_LIMITS
            .maximumHashesPerExternalReference
      ) {
        this.componentInvalid();
        return;
      }
      externalReference.hashCount += 1;
      this.hashes.set(keyForPath(path), {
        key: keyForPath(path),
        externalReferenceKey: externalReference.key,
        keys: new Set()
      });
      return;
    }
    if (matches(path, ['dependencies'])) {
      return;
    }
    if (isDependencyPath(path)) {
      const key = keyForPath(path);
      if (
        this.dependencies.size >=
          Math.min(
            this.maximumRecords,
            SYFT_CYCLONEDX_INVENTORY_LIMITS
              .maximumDependencyNodes
          ) ||
        this.dependencies.has(key)
      ) {
        this.dependencyInvalid();
        return;
      }
      this.dependencies.set(key, {
        key,
        index: path[1] as number,
        keys: new Set(),
        dependsOn: [],
        dependsOnSet: new Set()
      });
    }
  }

  onContainerEnd(path: JsonPath, kind: ContainerKind): void {
    if (kind !== 'OBJECT') return;
    const key = keyForPath(path);

    const property = this.properties.get(key);
    if (property) {
      const component = this.components.get(property.componentKey);
      if (
        !component ||
        !setEquals(property.keys, PROPERTY_KEYS) ||
        !property.name ||
        !property.name.startsWith('syft:') ||
        component.propertyNames.has(property.name)
      ) {
        this.componentInvalid();
      } else {
        component.propertyNames.add(property.name);
        if (/^syft:location:\d+:path$/u.test(property.name)) {
          this.discardedSourceLocationPropertyCount += 1;
        }
      }
      this.properties.delete(key);
      return;
    }

    const license = this.licenses.get(key);
    if (license) {
      const choice = this.licenseChoices.get(license.choiceKey);
      const hasId = license.id !== undefined;
      const hasName = license.name !== undefined;
      if (
        !choice ||
        (!license.keys.has('id') &&
          !license.keys.has('name')) ||
        hasId === hasName ||
        [...license.keys].some((field) => !LICENSE_KEYS.has(field))
      ) {
        this.licenseInvalid();
      } else if (
        hasName &&
        license.url !== undefined &&
        license.name === license.url
      ) {
        choice.discarded = true;
      } else {
        choice.resolved = {
          kind: hasId ? 'SPDX_ID' : 'DECLARED_NAME',
          value: (license.id ?? license.name) as string
        };
      }
      this.licenses.delete(key);
      return;
    }

    const choice = this.licenseChoices.get(key);
    if (choice) {
      const component = this.components.get(choice.componentKey);
      const expressionChoice =
        choice.expression !== undefined &&
        !choice.licenseSeen &&
        choice.keys.size === 1 &&
        choice.keys.has('expression');
      const licenseChoice =
        choice.expression === undefined &&
        choice.licenseSeen &&
        choice.keys.size === 1 &&
        choice.keys.has('license') &&
        (choice.resolved !== undefined || choice.discarded);
      if (!component || (!expressionChoice && !licenseChoice)) {
        this.licenseInvalid();
      } else if (!choice.discarded) {
        component.licenses.push(
          expressionChoice
            ? {
                kind: 'SPDX_EXPRESSION',
                value: choice.expression as string
              }
            : (choice.resolved as SyftCycloneDxInventoryLicense)
        );
      }
      this.licenseChoices.delete(key);
      return;
    }

    const externalReference = this.externalReferences.get(key);
    if (externalReference) {
      if (
        !externalReference.type ||
        !SYFT_EXTERNAL_REFERENCE_TYPES.has(
          externalReference.type
        ) ||
        externalReference.url === undefined ||
        (externalReference.type === 'build-meta'
          ? externalReference.url.length !== 0 ||
            externalReference.hashCount !== 1 ||
            !externalReference.keys.has('hashes')
          : externalReference.url.length === 0 ||
            externalReference.hashCount !== 0 ||
            externalReference.keys.has('hashes') ||
            !isSafeDiscardedUri(externalReference.url)) ||
        [...externalReference.keys].some(
          (field) => !EXTERNAL_REFERENCE_KEYS.has(field)
        )
      ) {
        this.componentInvalid();
      }
      this.externalReferences.delete(key);
      return;
    }

    const hash = this.hashes.get(key);
    if (hash) {
      const contentPattern = hash.algorithm
        ? SYFT_EXTERNAL_REFERENCE_HASH_PATTERNS.get(
            hash.algorithm
          )
        : undefined;
      if (
        !setEquals(hash.keys, HASH_KEYS) ||
        !contentPattern ||
        !hash.content ||
        !contentPattern.test(hash.content)
      ) {
        this.componentInvalid();
      }
      this.hashes.delete(key);
    }
  }

  onKey(objectPath: JsonPath, key: string): void {
    const allowed = allowedKeys(objectPath);
    if (!allowed || !allowed.has(key)) {
      this.reasonForPath(objectPath);
    }
    const objectPathKey = keyForPath(objectPath);

    if (objectPath.length === 0) this.rootKeys.add(key);
    else if (matches(objectPath, ['metadata'])) {
      this.metadataKeys.add(key);
    } else if (matches(objectPath, ['metadata', 'tools'])) {
      this.toolsKeys.add(key);
    } else if (isToolComponentPath(objectPath)) {
      this.toolKeys.add(key);
    } else if (matches(objectPath, ['metadata', 'component'])) {
      this.sourceComponentKeys.add(key);
    }

    this.components.get(objectPathKey)?.keys.add(key);
    this.properties.get(objectPathKey)?.keys.add(key);
    this.licenseChoices.get(objectPathKey)?.keys.add(key);
    this.licenses.get(objectPathKey)?.keys.add(key);
    this.externalReferences.get(objectPathKey)?.keys.add(key);
    this.hashes.get(objectPathKey)?.keys.add(key);
    this.dependencies.get(objectPathKey)?.keys.add(key);

    if (matches(objectPath.slice(-1), ['swid'])) {
      this.componentFor(objectPath)?.swidKeys.add(key);
    }
  }

  onPrimitive(path: JsonPath, value: JsonPrimitive): void {
    if (expectedContainerKind(path)) {
      this.reasonForPath(path);
      return;
    }
    if (!isExpectedScalarPath(path)) {
      this.reasonForPath(path);
      return;
    }

    if (path.length === 1) {
      this.captureRootScalar(path[0] as string, value);
      return;
    }
    if (matches(path, ['metadata', 'timestamp'])) {
      if (typeof value !== 'string') this.producerInvalid();
      else this.generatedAt = value;
      return;
    }
    if (isToolScalarPath(path)) {
      this.captureToolScalar(path[4] as string, value);
      return;
    }
    if (isSourceComponentScalarPath(path)) {
      this.captureSourceScalar(path[2] as string, value);
      return;
    }

    const component = this.componentFor(path);
    if (component && path.length === 3) {
      this.captureComponentScalar(
        component,
        path[2] as string,
        value
      );
      return;
    }

    const property = this.propertyFor(path);
    if (property) {
      this.capturePropertyScalar(
        property,
        path.at(-1) as string,
        value
      );
      return;
    }
    const choice = this.licenseChoiceFor(path);
    if (
      choice &&
      path.at(-1) === 'expression' &&
      path.length === 5
    ) {
      const expression =
        typeof value === 'string'
          ? canonicalizeSpdxExpression(value)
          : null;
      if (!expression) {
        this.licenseInvalid();
      } else {
        choice.expression = expression;
      }
      return;
    }
    const license = this.licenseFor(path);
    if (license) {
      this.captureLicenseScalar(
        license,
        path.at(-1) as string,
        value
      );
      return;
    }
    const externalReference = this.externalReferenceFor(path);
    if (
      externalReference &&
      path.length === 5 &&
      typeof path.at(-1) === 'string'
    ) {
      this.captureExternalReferenceScalar(
        externalReference,
        path.at(-1) as string,
        value
      );
      return;
    }
    const hash = this.hashFor(path);
    if (hash) {
      this.captureHashScalar(
        hash,
        path.at(-1) as string,
        value
      );
      return;
    }
    if (component && isSwidScalarPath(path)) {
      this.captureSwidScalar(
        component,
        path.at(-1) as string,
        value
      );
      return;
    }
    const dependency = this.dependencyFor(path);
    if (dependency) {
      this.captureDependencyScalar(dependency, path, value);
    }
  }

  finish(): ParsedSyftCycloneDx | null {
    if (
      this.rootKind !== 'OBJECT' ||
      !setEquals(this.rootKeys, ROOT_KEYS, ['dependencies']) ||
      this.schemaUri !== SYFT_CYCLONEDX_SCHEMA_URI ||
      this.bomFormat !== 'CycloneDX' ||
      this.specVersion !==
        SAST_ARTIFACT_SCHEMA_VERSIONS.CYCLONEDX_JSON ||
      this.bomVersion !== 1 ||
      !this.serialNumber ||
      !UUID_URN_PATTERN.test(this.serialNumber) ||
      !setEquals(this.metadataKeys, METADATA_KEYS) ||
      !setEquals(this.toolsKeys, TOOLS_KEYS) ||
      !setEquals(this.toolKeys, TOOL_COMPONENT_KEYS) ||
      !setEquals(
        this.sourceComponentKeys,
        SOURCE_COMPONENT_KEYS
      ) ||
      !this.toolComponentsSeen ||
      this.toolComponentCount !== 1 ||
      !this.componentsSeen
    ) {
      this.structureInvalid();
    }
    if (
      this.toolType !== 'application' ||
      this.toolAuthor !== 'anchore' ||
      this.toolName !== 'syft' ||
      this.toolVersion !== this.scannerVersion ||
      !this.generatedAt ||
      !isCanonicalTimestamp(this.generatedAt) ||
      Date.parse(this.generatedAt) <
        Date.parse(this.planCreatedAt) ||
      Date.parse(this.generatedAt) >
        Date.parse(this.envelopeProducedAt) ||
      this.sourceType !== 'file' ||
      this.sourceName !== this.sourceInputPath ||
      !this.sourceBomRef ||
      !SYFT_ARTIFACT_ID_PATTERN.test(this.sourceBomRef)
    ) {
      this.producerInvalid();
    }
    if (
      this.properties.size > 0 ||
      this.licenseChoices.size > 0 ||
      this.licenses.size > 0 ||
      this.externalReferences.size > 0 ||
      this.hashes.size > 0
    ) {
      this.structureInvalid();
    }

    const parsedComponents: ParsedSyftComponent[] = [];
    const bomRefs = new Set<string>();
    for (const component of [...this.components.values()].sort(
      (left, right) => left.index - right.index
    )) {
      const parsed = this.finishComponent(component);
      if (!parsed) continue;
      if (bomRefs.has(parsed.bomRef)) {
        this.componentIdentityInvalid();
        continue;
      }
      bomRefs.add(parsed.bomRef);
      parsedComponents.push(parsed);
    }

    const parsedDependencies: ParsedSyftCycloneDx['dependencies'] = [];
    const dependencyRefs = new Set<string>();
    let previousDependencyRef: string | undefined;
    for (const dependency of [...this.dependencies.values()].sort(
      (left, right) => left.index - right.index
    )) {
      if (
        !setEquals(dependency.keys, DEPENDENCY_KEYS) ||
        !dependency.ref ||
        !isSafeBomReference(dependency.ref) ||
        dependencyRefs.has(dependency.ref) ||
        (previousDependencyRef !== undefined &&
          previousDependencyRef >= dependency.ref) ||
        !bomRefs.has(dependency.ref) ||
        dependency.dependsOn.length === 0 ||
        dependency.dependsOn.some(
          (ref, index) =>
            index > 0 &&
            dependency.dependsOn[index - 1]! >= ref
        ) ||
        dependency.dependsOn.some(
          (ref) =>
            ref === dependency.ref ||
            !bomRefs.has(ref)
        )
      ) {
        this.dependencyInvalid();
        continue;
      }
      dependencyRefs.add(dependency.ref);
      previousDependencyRef = dependency.ref;
      parsedDependencies.push({
        ref: dependency.ref,
        dependsOn: [...dependency.dependsOn]
      });
    }

    if (this.reasons.size > 0) return null;
    return {
      serialNumber: this.serialNumber as string,
      generatedAt: this.generatedAt as string,
      components: parsedComponents,
      dependencies: parsedDependencies,
      statistics: {
        observedComponentCount: this.componentCount,
        observedDependencyNodeCount: this.dependencies.size,
        observedDependencyEdgeCount: this.dependencyEdgeCount,
        discardedPropertyCount: this.discardedPropertyCount,
        discardedSourceLocationPropertyCount:
          this.discardedSourceLocationPropertyCount,
        discardedExternalReferenceCount:
          this.discardedExternalReferenceCount,
        discardedLicenseUrlCount:
          this.discardedLicenseUrlCount,
        discardedProseFieldCount:
          this.discardedProseFieldCount
      }
    };
  }

  private finishComponent(
    component: SyftComponentState
  ): ParsedSyftComponent | null {
    const type = component.type as
      | SyftCycloneDxComponentType
      | undefined;
    const orderedLicenses = [...component.licenses].sort(
      compareSyftCycloneDxInventoryLicenses
    );
    const licenses = orderedLicenses.filter(
      (license, index) =>
        index === 0 ||
        compareSyftCycloneDxInventoryLicenses(
          orderedLicenses[index - 1]!,
          license
        ) !== 0
    );
    if (
      !type ||
      !SYFT_CYCLONEDX_COMPONENT_TYPES.includes(type) ||
      !component.bomRef ||
      !component.name ||
      !component.keys.has('bom-ref') ||
      !component.keys.has('type') ||
      !component.keys.has('name')
    ) {
      this.componentInvalid();
      return null;
    }
    if (
      type === 'operating-system'
        ? !component.keys.has('properties') ||
          !component.keys.has('swid') ||
          component.keys.has('group') ||
          component.keys.has('purl') ||
          component.keys.has('licenses') ||
          !component.propertyNames.has('syft:distro:id') ||
          !setEquals(component.swidKeys, SWID_KEYS, ['version']) ||
          component.swidTagId !== component.name ||
          component.swidName !== component.name ||
          (component.swidVersion ?? '') !==
            (component.version ?? '') ||
          component.bomRef !==
            `os:${component.name}${
              component.version ? `@${component.version}` : ''
            }`
        : !component.keys.has('properties') ||
          component.keys.has('swid') ||
          !component.propertyNames.has(
            'syft:package:foundBy'
          ) ||
          !component.propertyNames.has('syft:package:type') ||
          !isPackageBomReferenceValid(component)
    ) {
      this.componentIdentityInvalid();
      return null;
    }
    return {
      bomRef: component.bomRef,
      type,
      group: component.group ?? '',
      name: component.name,
      version: component.version ?? '',
      purl: component.purl ?? '',
      cpe: component.cpe ?? '',
      licenses
    };
  }

  private captureRootScalar(
    field: string,
    value: JsonPrimitive
  ): void {
    if (field === 'version') {
      if (
        typeof value !== 'number' ||
        !Number.isSafeInteger(value)
      ) {
        this.structureInvalid();
      } else {
        this.bomVersion = value;
      }
      return;
    }
    if (typeof value !== 'string') {
      this.structureInvalid();
      return;
    }
    if (field === '$schema') this.schemaUri = value;
    else if (field === 'bomFormat') this.bomFormat = value;
    else if (field === 'specVersion') this.specVersion = value;
    else if (field === 'serialNumber') this.serialNumber = value;
  }

  private captureToolScalar(
    field: string,
    value: JsonPrimitive
  ): void {
    if (
      typeof value !== 'string' ||
      !isSafeField(value, 255, false, false)
    ) {
      this.producerInvalid();
      return;
    }
    if (field === 'type') this.toolType = value;
    else if (field === 'author') this.toolAuthor = value;
    else if (field === 'name') this.toolName = value;
    else if (field === 'version') this.toolVersion = value;
  }

  private captureSourceScalar(
    field: string,
    value: JsonPrimitive
  ): void {
    if (typeof value !== 'string') {
      this.producerInvalid();
      return;
    }
    if (field === 'bom-ref') this.sourceBomRef = value;
    else if (field === 'type') this.sourceType = value;
    else if (field === 'name') this.sourceName = value;
  }

  private captureComponentScalar(
    component: SyftComponentState,
    field: string,
    value: JsonPrimitive
  ): void {
    if (typeof value !== 'string') {
      this.componentInvalid();
      return;
    }
    if (field === 'bom-ref') {
      if (!isSafeBomReference(value)) {
        this.componentIdentityInvalid();
      } else {
        component.bomRef = value;
      }
      return;
    }
    if (field === 'type') {
      if (
        !SYFT_CYCLONEDX_COMPONENT_TYPES.includes(
          value as SyftCycloneDxComponentType
        )
      ) {
        this.componentInvalid();
      } else {
        component.type = value;
      }
      return;
    }
    if (field === 'group') {
      if (
        !isSafeField(
          value,
          SYFT_CYCLONEDX_INVENTORY_LIMITS.componentGroupBytes,
          false,
          false
        )
      ) {
        this.componentInvalid();
      } else {
        component.group = value;
      }
      return;
    }
    if (field === 'name') {
      if (
        !isSafeField(
          value,
          SYFT_CYCLONEDX_INVENTORY_LIMITS.componentNameBytes,
          false,
          false
        )
      ) {
        this.componentInvalid();
      } else {
        component.name = value;
      }
      return;
    }
    if (field === 'version') {
      if (
        !isSafeField(
          value,
          SYFT_CYCLONEDX_INVENTORY_LIMITS
            .componentVersionBytes,
          false,
          false
        )
      ) {
        this.componentInvalid();
      } else {
        component.version = value;
      }
      return;
    }
    if (field === 'purl') {
      if (!parseCanonicalPurl(value)) {
        this.componentIdentityInvalid();
      } else {
        component.purl = value;
      }
      return;
    }
    if (field === 'cpe') {
      if (!isValidCpe(value)) {
        this.componentIdentityInvalid();
      } else {
        component.cpe = value;
      }
      return;
    }
    if (
      field === 'author' ||
      field === 'publisher' ||
      field === 'description'
    ) {
      if (
        !isSafeField(
          value,
          field === 'description' ? 4_096 : 512,
          false,
          field === 'description'
        )
      ) {
        this.componentInvalid();
      } else {
        this.discardedProseFieldCount += 1;
      }
    }
  }

  private capturePropertyScalar(
    property: PropertyState,
    field: string,
    value: JsonPrimitive
  ): void {
    if (
      typeof value !== 'string' ||
      !isSafeField(
        value,
        field === 'name' ? 512 : 4_096,
        false,
        field === 'value'
      )
    ) {
      this.componentInvalid();
      return;
    }
    if (field === 'name') property.name = value;
  }

  private captureLicenseScalar(
    license: LicenseState,
    field: string,
    value: JsonPrimitive
  ): void {
    if (
      typeof value !== 'string' ||
      !isSafeField(
        value,
        field === 'url'
          ? 2_048
          : SYFT_CYCLONEDX_INVENTORY_LIMITS.licenseValueBytes,
        false,
        false
      )
    ) {
      this.licenseInvalid();
      return;
    }
    if (field === 'id') {
      const identifier = canonicalizeSpdxLicenseIdentifier(value);
      if (!identifier) this.licenseInvalid();
      else license.id = identifier;
    } else if (field === 'name') {
      license.name = value;
    } else if (field === 'url') {
      if (!isSafeDiscardedUri(value)) this.licenseInvalid();
      license.url = value;
      this.discardedLicenseUrlCount += 1;
    }
  }

  private captureExternalReferenceScalar(
    externalReference: ExternalReferenceState,
    field: string,
    value: JsonPrimitive
  ): void {
    if (
      typeof value !== 'string' ||
      !isSafeField(
        value,
        field === 'comment' ? 4_096 : 2_048,
        field === 'url',
        field === 'comment'
      )
    ) {
      this.componentInvalid();
      return;
    }
    if (field === 'type') externalReference.type = value;
    else if (field === 'url') {
      externalReference.url = value;
    }
  }

  private captureHashScalar(
    hash: HashState,
    field: string,
    value: JsonPrimitive
  ): void {
    if (
      typeof value !== 'string' ||
      !isSafeField(value, 512, false, false)
    ) {
      this.componentInvalid();
      return;
    }
    if (field === 'alg') hash.algorithm = value;
    else if (field === 'content') hash.content = value;
  }

  private captureSwidScalar(
    component: SyftComponentState,
    field: string,
    value: JsonPrimitive
  ): void {
    if (
      typeof value !== 'string' ||
      !isSafeField(value, 512, false, false)
    ) {
      this.componentInvalid();
      return;
    }
    if (field === 'tagId') component.swidTagId = value;
    else if (field === 'name') component.swidName = value;
    else if (field === 'version') component.swidVersion = value;
  }

  private captureDependencyScalar(
    dependency: DependencyState,
    path: JsonPath,
    value: JsonPrimitive
  ): void {
    if (
      typeof value !== 'string' ||
      !isSafeBomReference(value)
    ) {
      this.dependencyInvalid();
      return;
    }
    if (path.at(-1) === 'ref') {
      dependency.ref = value;
      return;
    }
    if (
      dependency.dependsOnSet.has(value) ||
      this.dependencyEdgeCount >=
        Math.min(
          this.maximumRecords,
          SYFT_CYCLONEDX_INVENTORY_LIMITS
            .maximumDependencyEdges
        )
    ) {
      this.dependencyInvalid();
      return;
    }
    dependency.dependsOnSet.add(value);
    dependency.dependsOn.push(value);
    this.dependencyEdgeCount += 1;
  }

  private componentFor(
    path: JsonPath
  ): SyftComponentState | undefined {
    return this.components.get(
      keyForPath(path.slice(0, 2))
    );
  }

  private propertyFor(
    path: JsonPath
  ): PropertyState | undefined {
    const root = path.slice(0, 4);
    return this.properties.get(keyForPath(root));
  }

  private licenseChoiceFor(
    path: JsonPath
  ): LicenseChoiceState | undefined {
    return this.licenseChoices.get(
      keyForPath(path.slice(0, 4))
    );
  }

  private licenseFor(path: JsonPath): LicenseState | undefined {
    return this.licenses.get(
      keyForPath(path.slice(0, 5))
    );
  }

  private externalReferenceFor(
    path: JsonPath
  ): ExternalReferenceState | undefined {
    return this.externalReferences.get(
      keyForPath(path.slice(0, 4))
    );
  }

  private hashFor(path: JsonPath): HashState | undefined {
    return this.hashes.get(
      keyForPath(path.slice(0, 6))
    );
  }

  private dependencyFor(
    path: JsonPath
  ): DependencyState | undefined {
    return this.dependencies.get(
      keyForPath(path.slice(0, 2))
    );
  }

  private reasonForPath(path: JsonPath): void {
    if (path[0] === 'metadata') this.producerInvalid();
    else if (path[0] === 'components') {
      if (path.includes('licenses')) this.licenseInvalid();
      else this.componentInvalid();
    } else if (path[0] === 'dependencies') {
      this.dependencyInvalid();
    } else {
      this.structureInvalid();
    }
  }

  private structureInvalid(): void {
    this.reasons.add(
      'NORMALIZATION_CYCLONEDX_STRUCTURE_INVALID'
    );
  }

  private producerInvalid(): void {
    this.reasons.add(
      'NORMALIZATION_CYCLONEDX_PRODUCER_INVALID'
    );
  }

  private componentInvalid(): void {
    this.reasons.add(
      'NORMALIZATION_CYCLONEDX_COMPONENT_INVALID'
    );
  }

  private componentIdentityInvalid(): void {
    this.reasons.add(
      'NORMALIZATION_CYCLONEDX_COMPONENT_IDENTITY_INVALID'
    );
  }

  private licenseInvalid(): void {
    this.reasons.add(
      'NORMALIZATION_CYCLONEDX_LICENSE_INVALID'
    );
  }

  private dependencyInvalid(): void {
    this.reasons.add(
      'NORMALIZATION_CYCLONEDX_DEPENDENCY_INVALID'
    );
  }
}

function buildInventory(
  parsed: Readonly<ParsedSyftCycloneDx>,
  reasons: Set<SastNormalizationRejectionReasonCode>
): {
  components: SyftCycloneDxInventoryComponent[];
  dependencies: SyftCycloneDxDependencyEdge[];
} | null {
  const components: SyftCycloneDxInventoryComponent[] = [];
  const componentByBomRef = new Map<string, `sha256:${string}`>();
  const componentIds = new Set<string>();
  for (const component of parsed.components) {
    const producerBomRefDigest = digest(component.bomRef);
    const componentId = digest(
      canonicalLengthPrefixedIdentity(
        COMPONENT_IDENTITY_VERSION,
        [
          producerBomRefDigest,
          component.type,
          component.group,
          component.name,
          component.version,
          component.purl,
          component.cpe
        ]
      )
    );
    if (
      componentByBomRef.has(component.bomRef) ||
      componentIds.has(componentId)
    ) {
      reasons.add(
        'NORMALIZATION_CYCLONEDX_COMPONENT_IDENTITY_INVALID'
      );
      continue;
    }
    componentByBomRef.set(component.bomRef, componentId);
    componentIds.add(componentId);
    components.push({
      componentId,
      producerBomRefDigest,
      type: component.type,
      group: component.group,
      name: component.name,
      version: component.version,
      purl: component.purl,
      cpe: component.cpe,
      licenses: [...component.licenses],
      rawPropertiesStored: false,
      sourceLocationsStored: false
    });
  }

  const dependencies: SyftCycloneDxDependencyEdge[] = [];
  const dependencyKeys = new Set<string>();
  for (const dependency of parsed.dependencies) {
    const componentId = componentByBomRef.get(dependency.ref);
    if (!componentId) {
      reasons.add('NORMALIZATION_CYCLONEDX_DEPENDENCY_INVALID');
      continue;
    }
    for (const dependsOnRef of dependency.dependsOn) {
      const dependsOnComponentId =
        componentByBomRef.get(dependsOnRef);
      const key = `${componentId}:${dependsOnComponentId ?? ''}`;
      if (
        !dependsOnComponentId ||
        componentId === dependsOnComponentId ||
        dependencyKeys.has(key)
      ) {
        reasons.add(
          'NORMALIZATION_CYCLONEDX_DEPENDENCY_INVALID'
        );
        continue;
      }
      dependencyKeys.add(key);
      dependencies.push({
        componentId,
        dependsOnComponentId
      });
    }
  }
  if (reasons.size > 0) return null;
  return {
    components: components.sort(
      compareSyftCycloneDxInventoryComponents
    ),
    dependencies: dependencies.sort(
      compareSyftCycloneDxDependencyEdges
    )
  };
}

function expectedScannerInputPath(
  input: Readonly<SyftCycloneDxInventoryInput>
): string {
  return input.plan.profile.scope ===
    'CHANGED_FILES_WITH_CONTEXT'
    ? `${SAST_SCANNER_SELECTED_WORKSPACE_ROOT}/${input.expectedBinding.preflightInventoryDigest.slice(
        'sha256:'.length
      )}`
    : SAST_SCANNER_WORKSPACE_ROOT;
}

function allowedKeys(path: JsonPath): ReadonlySet<string> | null {
  if (path.length === 0) return ROOT_KEYS;
  if (matches(path, ['metadata'])) return METADATA_KEYS;
  if (matches(path, ['metadata', 'tools'])) return TOOLS_KEYS;
  if (isToolComponentPath(path)) return TOOL_COMPONENT_KEYS;
  if (matches(path, ['metadata', 'component'])) {
    return SOURCE_COMPONENT_KEYS;
  }
  if (isComponentPath(path)) return COMPONENT_KEYS;
  if (isLicenseChoicePath(path)) return LICENSE_CHOICE_KEYS;
  if (isLicensePath(path)) return LICENSE_KEYS;
  if (isPropertyPath(path)) return PROPERTY_KEYS;
  if (isExternalReferencePath(path)) {
    return EXTERNAL_REFERENCE_KEYS;
  }
  if (isExternalReferenceHashPath(path)) return HASH_KEYS;
  if (isSwidPath(path)) return SWID_KEYS;
  if (isDependencyPath(path)) return DEPENDENCY_KEYS;
  return null;
}

function expectedContainerKind(
  path: JsonPath
): ContainerKind | null {
  if (
    matches(path, ['metadata']) ||
    matches(path, ['metadata', 'tools']) ||
    matches(path, ['metadata', 'component']) ||
    isToolComponentPath(path) ||
    isComponentPath(path) ||
    isLicenseChoicePath(path) ||
    isLicensePath(path) ||
    isPropertyPath(path) ||
    isExternalReferencePath(path) ||
    isExternalReferenceHashPath(path) ||
    isSwidPath(path) ||
    isDependencyPath(path)
  ) {
    return 'OBJECT';
  }
  if (
    matches(path, ['metadata', 'tools', 'components']) ||
    matches(path, ['components']) ||
    matches(path, ['components', '*', 'licenses']) ||
    matches(path, ['components', '*', 'properties']) ||
    matches(path, [
      'components',
      '*',
      'externalReferences'
    ]) ||
    matches(path, [
      'components',
      '*',
      'externalReferences',
      '*',
      'hashes'
    ]) ||
    matches(path, ['dependencies']) ||
    matches(path, ['dependencies', '*', 'dependsOn'])
  ) {
    return 'ARRAY';
  }
  return null;
}

function isExpectedScalarPath(path: JsonPath): boolean {
  return (
    matches(path, ['$schema']) ||
    matches(path, ['bomFormat']) ||
    matches(path, ['specVersion']) ||
    matches(path, ['serialNumber']) ||
    matches(path, ['version']) ||
    matches(path, ['metadata', 'timestamp']) ||
    isToolScalarPath(path) ||
    isSourceComponentScalarPath(path) ||
    (matches(path, ['components', '*', '*']) &&
      [
        'bom-ref',
        'type',
        'group',
        'name',
        'version',
        'cpe',
        'purl',
        'author',
        'publisher',
        'description'
      ].includes(String(path[2]))) ||
    matches(path, [
      'components',
      '*',
      'licenses',
      '*',
      'expression'
    ]) ||
    matches(path, [
      'components',
      '*',
      'licenses',
      '*',
      'license',
      '*'
    ]) ||
    matches(path, [
      'components',
      '*',
      'properties',
      '*',
      '*'
    ]) ||
    matches(path, [
      'components',
      '*',
      'externalReferences',
      '*',
      '*'
    ]) ||
    matches(path, [
      'components',
      '*',
      'externalReferences',
      '*',
      'hashes',
      '*',
      '*'
    ]) ||
    isSwidScalarPath(path) ||
    matches(path, ['dependencies', '*', 'ref']) ||
    matches(path, ['dependencies', '*', 'dependsOn', '*'])
  );
}

function isToolComponentPath(path: JsonPath): boolean {
  return matches(path, [
    'metadata',
    'tools',
    'components',
    '*'
  ]);
}

function isToolScalarPath(path: JsonPath): boolean {
  return (
    matches(path, [
      'metadata',
      'tools',
      'components',
      '*',
      '*'
    ]) &&
    TOOL_COMPONENT_KEYS.has(String(path[4]))
  );
}

function isSourceComponentScalarPath(path: JsonPath): boolean {
  return (
    matches(path, ['metadata', 'component', '*']) &&
    SOURCE_COMPONENT_KEYS.has(String(path[2]))
  );
}

function isComponentPath(path: JsonPath): boolean {
  return matches(path, ['components', '*']);
}

function isLicenseChoicePath(path: JsonPath): boolean {
  return matches(path, [
    'components',
    '*',
    'licenses',
    '*'
  ]);
}

function isLicensePath(path: JsonPath): boolean {
  return matches(path, [
    'components',
    '*',
    'licenses',
    '*',
    'license'
  ]);
}

function isPropertyPath(path: JsonPath): boolean {
  return matches(path, [
    'components',
    '*',
    'properties',
    '*'
  ]);
}

function isExternalReferencePath(path: JsonPath): boolean {
  return matches(path, [
    'components',
    '*',
    'externalReferences',
    '*'
  ]);
}

function isExternalReferenceHashPath(path: JsonPath): boolean {
  return matches(path, [
    'components',
    '*',
    'externalReferences',
    '*',
    'hashes',
    '*'
  ]);
}

function isSwidPath(path: JsonPath): boolean {
  return matches(path, ['components', '*', 'swid']);
}

function isSwidScalarPath(path: JsonPath): boolean {
  return (
    matches(path, ['components', '*', 'swid', '*']) &&
    SWID_KEYS.has(String(path[3]))
  );
}

function isDependencyPath(path: JsonPath): boolean {
  return matches(path, ['dependencies', '*']);
}

function matches(
  path: JsonPath,
  pattern: readonly (string | '*')[]
): boolean {
  return (
    path.length === pattern.length &&
    pattern.every(
      (segment, index) =>
        segment === '*' || path[index] === segment
    )
  );
}

function keyForPath(path: JsonPath): string {
  return JSON.stringify(path);
}

function countOpenLicenses(
  choices: ReadonlyMap<string, LicenseChoiceState>,
  componentKey: string
): number {
  let count = 0;
  for (const choice of choices.values()) {
    if (choice.componentKey === componentKey) count += 1;
  }
  return count;
}

function setEquals(
  actual: ReadonlySet<string>,
  expected: ReadonlySet<string>,
  optional: readonly string[] = []
): boolean {
  return (
    [...actual].every((key) => expected.has(key)) &&
    [...expected].every(
      (key) => actual.has(key) || optional.includes(key)
    )
  );
}

function isSafeField(
  value: string,
  maximumBytes: number,
  allowEmpty: boolean,
  allowTextWhitespace: boolean
): boolean {
  return (
    (allowEmpty || value.length > 0) &&
    value === value.normalize('NFC') &&
    value === value.trim() &&
    utf8Bytes(value) <= maximumBytes &&
    !hasUnsafeControls(value, allowTextWhitespace)
  );
}

function isSafeBomReference(value: string): boolean {
  return isSafeField(
    value,
    SYFT_CYCLONEDX_INVENTORY_LIMITS.bomReferenceBytes,
    false,
    false
  );
}

function isPackageBomReferenceValid(
  component: Readonly<SyftComponentState>
): boolean {
  if (!component.bomRef || !component.name) return false;
  if (!component.purl) {
    return SYFT_ARTIFACT_ID_PATTERN.test(component.bomRef);
  }
  const purl = parseCanonicalPurl(component.purl);
  const bomRef = parseCanonicalPurl(component.bomRef);
  const packageId = bomRef?.qualifiers.find(
    (qualifier) => qualifier.key === 'package-id'
  );
  const expectedName =
    purl &&
    purl.namespace &&
    !SYFT_PURL_TYPES_WITH_LEAF_COMPONENT_NAME.has(purl.type)
      ? `${purl.namespace}/${purl.name}`
      : purl?.name;
  return (
    !!purl &&
    !!bomRef &&
    expectedName === component.name &&
    purl.version === (component.version ?? '') &&
    (component.group === undefined ||
      (purl.type === 'maven' &&
        component.group === purl.namespace)) &&
    !purl.qualifiers.some(
      (qualifier) => qualifier.key === 'package-id'
    ) &&
    !!packageId &&
    SYFT_ARTIFACT_ID_PATTERN.test(packageId.decodedValue) &&
    bomRef.qualifiers.filter(
      (qualifier) => qualifier.key === 'package-id'
    ).length === 1 &&
    bomRef.withoutPackageId === component.purl
  );
}

function parseCanonicalPurl(value: string): ParsedPurl | null {
  if (
    !isSafeField(
      value,
      SYFT_CYCLONEDX_INVENTORY_LIMITS.packageUrlBytes,
      false,
      false
    ) ||
    !value.startsWith('pkg:') ||
    value.includes('\\') ||
    !/^[\x21-\x7e]+$/u.test(value) ||
    !hasCanonicalPercentEncoding(value)
  ) {
    return null;
  }
  const hashParts = value.split('#');
  if (hashParts.length > 2) return null;
  const fragment = hashParts[1];
  if (
    fragment !== undefined &&
    !validatePurlPath(fragment, false)
  ) {
    return null;
  }
  const queryParts = (hashParts[0] as string).split('?');
  if (queryParts.length > 2) return null;
  const base = queryParts[0] as string;
  const query = queryParts[1];
  const typeSeparator = base.indexOf('/', 'pkg:'.length);
  if (typeSeparator < 0) return null;
  const type = base.slice('pkg:'.length, typeSeparator);
  const rawPath = base.slice(typeSeparator + 1);
  if (
    !/^[a-z][a-z0-9.+-]{0,63}$/u.test(type) ||
    !validatePurlPath(rawPath, true)
  ) {
    return null;
  }

  const rawSegments = rawPath.split('/');
  const lastSegment = rawSegments.at(-1) as string;
  const versionSeparator = lastSegment.lastIndexOf('@');
  const rawName =
    versionSeparator >= 0
      ? lastSegment.slice(0, versionSeparator)
      : lastSegment;
  const rawVersion =
    versionSeparator >= 0
      ? lastSegment.slice(versionSeparator + 1)
      : '';
  if (
    rawSegments
      .slice(0, -1)
      .some((segment) => segment.includes('@')) ||
    rawName.includes('@')
  ) {
    return null;
  }
  const name = decodePurlPart(rawName);
  const namespaceParts = rawSegments
    .slice(0, -1)
    .map(decodePurlPart);
  const version =
    rawVersion.length > 0 ? decodePurlPart(rawVersion) : '';
  if (
    !name ||
    namespaceParts.some((segment) => segment === null) ||
    version === null ||
    (versionSeparator >= 0 && !version)
  ) {
    return null;
  }

  const qualifiers: ParsedPurlQualifier[] = [];
  if (query !== undefined) {
    if (query.length === 0) return null;
    for (const entry of query.split('&')) {
      const equals = entry.indexOf('=');
      if (equals <= 0 || equals === entry.length - 1) return null;
      const key = entry.slice(0, equals);
      const rawValue = entry.slice(equals + 1);
      const decodedValue = decodePurlPart(rawValue);
      if (
        !/^[a-z][a-z0-9._-]{0,63}$/u.test(key) ||
        !decodedValue ||
        qualifiers.some((qualifier) => qualifier.key === key) ||
        (qualifiers.length > 0 &&
          qualifiers[qualifiers.length - 1]!.key >= key)
      ) {
        return null;
      }
      qualifiers.push({ key, rawValue, decodedValue });
    }
  }
  const retained = qualifiers.filter(
    (qualifier) => qualifier.key !== 'package-id'
  );
  return {
    type,
    namespace: (namespaceParts as string[]).join('/'),
    name,
    version,
    qualifiers,
    withoutPackageId: `${base}${
      retained.length > 0
        ? `?${retained
            .map(
              (qualifier) =>
                `${qualifier.key}=${qualifier.rawValue}`
            )
            .join('&')}`
        : ''
    }${fragment === undefined ? '' : `#${fragment}`}`
  };
}

function validatePurlPath(
  value: string,
  allowVersionSeparator: boolean
): boolean {
  const segments = value.split('/');
  return (
    segments.length > 0 &&
    segments.every((segment, index) => {
      if (segment.length === 0) return false;
      const candidate =
        allowVersionSeparator && index === segments.length - 1
          ? segment.replace(/@[^@]*$/u, '')
          : segment;
      const decoded = decodePurlPart(candidate);
      return (
        !!decoded &&
        decoded !== '.' &&
        decoded !== '..' &&
        !decoded.includes('/') &&
        !decoded.includes('\\')
      );
    })
  );
}

function decodePurlPart(value: string): string | null {
  try {
    const decoded = decodeURIComponent(value);
    return isSafeField(decoded, 2_048, false, false)
      ? decoded
      : null;
  } catch {
    return null;
  }
}

function hasCanonicalPercentEncoding(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    if (value[index] !== '%') continue;
    const encoded = value.slice(index + 1, index + 3);
    if (!/^[0-9A-F]{2}$/u.test(encoded)) {
      return false;
    }
    const byte = Number.parseInt(encoded, 16);
    if (
      (byte >= 0x41 && byte <= 0x5a) ||
      (byte >= 0x61 && byte <= 0x7a) ||
      (byte >= 0x30 && byte <= 0x39) ||
      byte === 0x2d ||
      byte === 0x2e ||
      byte === 0x5f ||
      byte === 0x7e
    ) {
      return false;
    }
    index += 2;
  }
  return true;
}

function isValidCpe(value: string): boolean {
  if (
    !isSafeField(
      value,
      SYFT_CYCLONEDX_INVENTORY_LIMITS.cpeBytes,
      false,
      false
    ) ||
    !value.startsWith('cpe:2.3:')
  ) {
    return false;
  }
  const fields = splitCpeFormattedString(value);
  if (
    !fields ||
    fields.length !== 13 ||
    fields[0] !== 'cpe' ||
    fields[1] !== '2.3' ||
    !/^(?:a|h|o|\*|-)$/u.test(fields[2] as string)
  ) {
    return false;
  }
  for (let index = 3; index < fields.length; index += 1) {
    const field = fields[index] as string;
    if (
      index === 8
        ? !isValidCpeLanguage(field)
        : !isValidCpeAttributeValue(field)
    ) {
      return false;
    }
  }
  return true;
}

function splitCpeFormattedString(value: string): string[] | null {
  const fields: string[] = [];
  let field = '';
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index] as string;
    if (character === '\\') {
      const quoted = value[index + 1];
      if (!quoted) return null;
      field += character + quoted;
      index += 1;
    } else if (character === ':') {
      fields.push(field);
      field = '';
    } else {
      field += character;
    }
  }
  fields.push(field);
  return fields;
}

function isValidCpeLanguage(value: string): boolean {
  return (
    value === '*' ||
    value === '-' ||
    /^[A-Za-z]{2,3}(?:-(?:[A-Za-z]{2}|[0-9]{3}))?$/u.test(value)
  );
}

function isValidCpeAttributeValue(value: string): boolean {
  if (value === '*' || value === '-') return true;
  if (value.length === 0) return false;

  let index = 0;
  if (value[index] === '*') {
    index += 1;
  } else {
    while (value[index] === '?') index += 1;
  }

  let coreCharacters = 0;
  while (index < value.length) {
    const character = value[index] as string;
    if (/^[A-Za-z0-9._-]$/u.test(character)) {
      coreCharacters += 1;
      index += 1;
      continue;
    }
    if (character === '\\') {
      const quoted = value[index + 1];
      if (!quoted || !isValidCpeQuotedCharacter(quoted)) {
        return false;
      }
      coreCharacters += 1;
      index += 2;
      continue;
    }
    break;
  }
  if (coreCharacters === 0) return false;
  if (index === value.length) return true;
  if (value[index] === '*') return index + 1 === value.length;
  if (value[index] !== '?') return false;
  while (value[index] === '?') index += 1;
  return index === value.length;
}

function isValidCpeQuotedCharacter(value: string): boolean {
  return (
    value === '\\' ||
    value === '*' ||
    value === '?' ||
    /^[!"#$%&'()+,/:;<=>@[\]^`{|}~]$/u.test(value)
  );
}

function isSpdxLicenseReference(value: string): boolean {
  return /^(?:DocumentRef-[A-Za-z0-9.-]+:)?LicenseRef-[A-Za-z0-9.-]+$/u.test(
    value
  );
}

function canonicalizeSpdxExpression(
  value: string
): string | null {
  if (
    !isSafeField(
      value,
      SYFT_CYCLONEDX_INVENTORY_LIMITS.licenseValueBytes,
      false,
      false
    )
  ) {
    return null;
  }
  const normalizedTokenSpacing = value
    .replace(/([()])/gu, ' $1 ')
    .trim()
    .replace(/\s+/gu, ' ');
  const tokens =
    normalizedTokenSpacing.length === 0
      ? []
      : normalizedTokenSpacing.split(' ');
  let index = 0;
  const parseSimple = (): boolean => {
    const token = tokens[index];
    if (
      !token ||
      token === ')' ||
      token === 'AND' ||
      token === 'OR' ||
      token === 'WITH'
    ) {
      return false;
    }
    if (!isSpdxLicenseReference(token)) {
      const identifier =
        canonicalizeSpdxLicenseExpressionIdentifier(token);
      if (!identifier) return false;
      tokens[index] = identifier;
    }
    index += 1;
    return true;
  };
  const parseWith = (): boolean => {
    if (tokens[index] === '(') {
      index += 1;
      if (!parseOr() || tokens[index] !== ')') return false;
      index += 1;
      return true;
    }
    if (!parseSimple()) return false;
    if (tokens[index] === 'WITH') {
      index += 1;
      const exception = tokens[index];
      if (!exception) return false;
      const canonicalException =
        canonicalizeSpdxLicenseExceptionIdentifier(exception);
      if (!canonicalException) return false;
      tokens[index] = canonicalException;
      index += 1;
    }
    return true;
  };
  const parseAnd = (): boolean => {
    if (!parseWith()) return false;
    while (tokens[index] === 'AND') {
      index += 1;
      if (!parseWith()) return false;
    }
    return true;
  };
  const parseOr = (): boolean => {
    if (!parseAnd()) return false;
    while (tokens[index] === 'OR') {
      index += 1;
      if (!parseAnd()) return false;
    }
    return true;
  };
  if (!parseOr() || index !== tokens.length) return null;
  return tokens
    .join(' ')
    .replace(/\( /gu, '(')
    .replace(/ \)/gu, ')');
}

function isSafeDiscardedUri(value: string): boolean {
  try {
    const url = new URL(value);
    return (
      /^[a-z][a-z0-9+.-]*:$/u.test(url.protocol) &&
      url.username === '' &&
      url.password === ''
    );
  } catch {
    return false;
  }
}

function isCanonicalTimestamp(value: string): boolean {
  return (
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u.test(
      value
    ) &&
    Number.isFinite(Date.parse(value))
  );
}

function canonicalLengthPrefixedIdentity(
  version: string,
  fields: readonly string[]
): string {
  let result = `${version}\u0000`;
  for (const field of fields) {
    result += `${utf8Bytes(field)}:${field}`;
  }
  return result;
}
