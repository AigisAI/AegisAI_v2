import { createHash } from 'node:crypto';
import { TextDecoder } from 'node:util';

import {
  SAST_ARTIFACT_SCHEMA_VERSIONS,
  SAST_ARTIFACT_VALIDATION_LIMITS,
  SAST_MAX_COORDINATE_VALUE,
  SAST_NORMALIZATION_LIMITS,
  TRIVY_JSON_NORMALIZER_VERSION,
  buildSastScanPlanDigestPreimage,
  canonicalizeSastArtifactDispositionDecision,
  canonicalizeSastArtifactValidationResult,
  canonicalizeScannerArtifactEnvelope,
  canonicalizeTrivyJsonNormalizationBatch,
  canonicalizeTrivyJsonNormalizationRejection,
  compareSastNormalizationIdentifiers,
  compareSastNormalizedFindingCandidates,
  isSastArtifactDispositionDecisionShapeValid,
  isSastArtifactValidationResultShapeValid,
  isSastFindingLocationValid,
  isScannerArtifactEnvelopeBoundToPlan,
  isTrivyJsonNormalizationBatchShapeValid,
  orderSastNormalizationNotes,
  orderSastNormalizationRejectionReasons,
  type ExpectedScannerArtifactBinding,
  type RuleBundleDescriptor,
  type SastArtifactDispositionDecision,
  type SastArtifactValidationReasonCode,
  type SastArtifactValidationResult,
  type SastFileCoordinateMetadata,
  type SastFindingLocation,
  type SastNormalizationNoteCode,
  type SastNormalizationRejectionReasonCode,
  type SastScanPlan,
  type ScannerArtifactEnvelope,
  type TrivyJsonNormalizationBatchCore,
  type TrivyJsonNormalizationRejectionCore,
  type TrivyJsonNormalizationResult,
  type TrivyNormalizedFindingCandidate,
  type TrivyScannerDispositionStatus,
  type VulnerabilityDatabaseDescriptor
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';
import { Tokenizer } from '@streamparser/json';

import {
  BoundedJsonStructureTracker,
  RawJsonTokenLimiter,
  normalizeArtifactPath,
  type ArtifactValidationCallbacks,
  type ContainerKind,
  type JsonPath,
  type JsonPrimitive
} from './sast-artifact-stream-validator';
import type {
  SastFileCoordinateAttestation
} from './sast-file-coordinate-attestation.provider';
import {
  digest,
  hasUnsafeControls,
  loadSastNormalizationCoordinates,
  normalizeSastDescription as normalizeDescription,
  normalizeSastTitle as normalizeTitle,
  omitDecisionDigest,
  omitResultDigest,
  readReferenceTime,
  utf8Bytes,
  validateSastNormalizationReferenceTime
} from './sast-normalization-support';

const TRIVY_FILESYSTEM_ARTIFACT_TYPE = 'filesystem';
const DEPENDENCY_SEMANTIC_PREFIX = 'trivy-advisory:';
const DEPENDENCY_IDENTITY_PREFIX = 'trivy:dependency:v1';
const SECRET_IDENTITY_PREFIX = 'trivy:secret:v1';
const IAC_IDENTITY_PREFIX = 'trivy:iac:v1';

const ROOT_KEYS = new Set([
  'SchemaVersion',
  'CreatedAt',
  'ArtifactName',
  'ArtifactType',
  'Metadata',
  'Results'
]);
const RESULT_KEYS = new Set([
  'Target',
  'Class',
  'Type',
  'Vulnerabilities',
  'MisconfSummary',
  'Misconfigurations',
  'Secrets',
  'ExperimentalModifiedFindings'
]);
const VULNERABILITY_KEYS = new Set([
  'VulnerabilityID',
  'VendorIDs',
  'PkgID',
  'PkgName',
  'PkgPath',
  'PkgIdentifier',
  'InstalledVersion',
  'FixedVersion',
  'Status',
  'Layer',
  'SeveritySource',
  'PrimaryURL',
  'DataSource',
  'Custom',
  'Title',
  'Description',
  'Severity',
  'CweIDs',
  'VendorSeverity',
  'CVSS',
  'References',
  'PublishedDate',
  'LastModifiedDate'
]);
const MISCONFIGURATION_KEYS = new Set([
  'Type',
  'ID',
  'AVDID',
  'Title',
  'Description',
  'Message',
  'Namespace',
  'Query',
  'Resolution',
  'Severity',
  'PrimaryURL',
  'References',
  'Status',
  'Layer',
  'CauseMetadata',
  'Traces'
]);
const SECRET_KEYS = new Set([
  'RuleID',
  'Category',
  'Severity',
  'Title',
  'StartLine',
  'EndLine',
  'Code',
  'Match',
  'Layer',
  'Offset'
]);
const MODIFIED_FINDING_KEYS = new Set([
  'Type',
  'Status',
  'Statement',
  'Source',
  'Finding'
]);
const MISCONF_SUMMARY_KEYS = new Set(['Successes', 'Failures']);
const PACKAGE_IDENTIFIER_KEYS = new Set(['UID', 'PURL', 'BOMRef']);
const CAUSE_METADATA_KEYS = new Set([
  'Resource',
  'Provider',
  'Service',
  'StartLine',
  'EndLine',
  'Code',
  'Occurrences',
  'RenderedCause'
]);

const TRIVY_SEVERITIES = new Set([
  'UNKNOWN',
  'LOW',
  'MEDIUM',
  'HIGH',
  'CRITICAL'
]);
const TRIVY_VULNERABILITY_STATUSES = new Set([
  'unknown',
  'not_affected',
  'affected',
  'fixed',
  'under_investigation',
  'will_not_fix',
  'fix_deferred',
  'end_of_life'
]);
const TRIVY_MODIFIED_STATUSES = new Set<
  TrivyScannerDispositionStatus
>([
  'ignored',
  'unknown',
  'not_affected',
  'affected',
  'fixed',
  'under_investigation'
]);
const TRIVY_RESULT_CLASSES = new Set([
  'lang-pkgs',
  'config',
  'secret'
]);
const TRIVY_LANGUAGE_TYPES = new Set([
  'bundler',
  'gemspec',
  'cargo',
  'composer',
  'composer-vendor',
  'npm',
  'bun',
  'nuget',
  'dotnet-core',
  'packages-props',
  'pip',
  'pipenv',
  'poetry',
  'uv',
  'conda-pkg',
  'conda-environment',
  'python-pkg',
  'node-pkg',
  'yarn',
  'pnpm',
  'jar',
  'pom',
  'gradle',
  'sbt',
  'gobinary',
  'gomod',
  'javascript',
  'rustbinary',
  'conan',
  'cocoapods',
  'swift',
  'pub',
  'hex',
  'bitnami',
  'julia'
]);
const TRIVY_CONFIG_TYPES = new Set([
  'json',
  'yaml',
  'dockerfile',
  'terraform',
  'terraformplan',
  'terraformplan-snapshot',
  'cloudformation',
  'kubernetes',
  'helm',
  'cloud',
  'azure-arm'
]);

type TrivyRecordKind =
  | 'VULNERABILITY'
  | 'MISCONFIGURATION'
  | 'SECRET';
type TrivyAdvisoryStatus =
  | 'unknown'
  | 'not_affected'
  | 'affected'
  | 'fixed'
  | 'under_investigation'
  | 'will_not_fix'
  | 'fix_deferred'
  | 'end_of_life';

interface TrivyResultState {
  index: number;
  target?: string;
  resultClass?: string;
  targetType?: string;
  vulnerabilitiesSeen: boolean;
  misconfigurationsSeen: boolean;
  secretsSeen: boolean;
  modifiedFindingsSeen: boolean;
}

interface TrivyRecordState {
  key: string;
  index: number;
  resultIndex: number;
  keys: Set<string>;
  kind?: TrivyRecordKind;
  source: 'DIRECT' | 'MODIFIED';
  modifiedStatus?: TrivyScannerDispositionStatus;
  vulnerabilityId?: string;
  vendorIds: string[];
  packageName?: string;
  packagePath?: string;
  packagePurl?: string;
  installedVersion?: string;
  fixedVersion?: string;
  advisoryStatus?: string;
  ruleId?: string;
  avdId?: string;
  checkType?: string;
  category?: string;
  titlePresent?: true;
  severity?: string;
  resultStatus?: string;
  cweIds: string[];
  startLine?: number;
  endLine?: number;
}

type CompletedTrivyRecordState = TrivyRecordState & {
  kind: TrivyRecordKind;
};

interface ModifiedFindingState {
  key: string;
  index: number;
  resultIndex: number;
  findingType?: string;
  status?: TrivyScannerDispositionStatus;
  findingSeen: boolean;
  record?: TrivyRecordState;
}

interface ParsedTrivyJson {
  results: TrivyResultState[];
  records: CompletedTrivyRecordState[];
}

export interface TrivyJsonNormalizationInput {
  ingestionId: string;
  envelope: Readonly<ScannerArtifactEnvelope>;
  envelopeDigest: `sha256:${string}`;
  plan: Readonly<SastScanPlan>;
  expectedBinding: Readonly<ExpectedScannerArtifactBinding>;
  validation: Readonly<SastArtifactValidationResult>;
  disposition: Readonly<SastArtifactDispositionDecision>;
  coordinateAttestation:
    | Readonly<SastFileCoordinateAttestation>
    | null;
}

@Injectable()
export class TrivyJsonNormalizer {
  async normalize(
    input: Readonly<TrivyJsonNormalizationInput>,
    artifact: AsyncIterable<Uint8Array>,
    referenceClock: () => Date = () => new Date()
  ): Promise<TrivyJsonNormalizationResult> {
    const binding = this.validateBinding(
      input,
      readReferenceTime(referenceClock)
    );
    if (
      binding.reasons.size > 0 ||
      !binding.ruleBundle ||
      !binding.vulnerabilityDatabase ||
      !binding.planDigest
    ) {
      return this.reject(input.ingestionId, binding.reasons);
    }

    const coordinates = this.loadCoordinates(
      input.coordinateAttestation,
      input,
      binding.reasons
    );
    if (binding.reasons.size > 0) {
      return this.reject(input.ingestionId, binding.reasons);
    }

    const stream = new TrivyJsonStreamSession(
      input.envelope,
      input.plan
    );
    const parsed = await stream.parse(artifact);
    for (const reason of stream.reasons) binding.reasons.add(reason);
    const completedAtMilliseconds = this.validateReferenceTime(
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

    const findings = this.buildCandidates(
      parsed,
      input,
      binding.ruleBundle,
      binding.vulnerabilityDatabase,
      binding.planDigest,
      coordinates,
      binding.reasons
    );
    if (!findings || binding.reasons.size > 0) {
      return this.reject(input.ingestionId, binding.reasons);
    }

    const scope = {
      tenantId: input.envelope.tenantId,
      repositoryBindingId: input.envelope.repositoryBindingId,
      scanRequestId: input.envelope.scanRequestId,
      attemptId: input.envelope.attemptId,
      scannerRunId: input.envelope.scannerRunId
    };
    const core: TrivyJsonNormalizationBatchCore = {
      version: TRIVY_JSON_NORMALIZER_VERSION,
      adapterVersion: TRIVY_JSON_NORMALIZER_VERSION,
      artifactSchema: 'TRIVY_JSON',
      artifactSchemaVersion:
        SAST_ARTIFACT_SCHEMA_VERSIONS.TRIVY_JSON,
      ingestionId: input.ingestionId,
      scope,
      scannerRunId: input.envelope.scannerRunId,
      scanner: 'TRIVY',
      scannerVersion: input.envelope.scannerVersion,
      scannerImageDigest: input.envelope.scannerImageDigest,
      ruleBundleDigest: binding.ruleBundle.digest,
      vulnerabilityDatabaseDigest:
        binding.vulnerabilityDatabase.digest,
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
      normalizerBundleDigest: input.envelope.normalizerBundleDigest,
      validationResultDigest: input.validation.resultDigest,
      dispositionDecisionDigest: input.disposition.decisionDigest,
      findings,
      durablePersistenceAllowed: false
    };
    const batch = {
      ...core,
      batchDigest: digest(
        canonicalizeTrivyJsonNormalizationBatch(core)
      )
    };
    if (!isTrivyJsonNormalizationBatchShapeValid(batch)) {
      binding.reasons.add('NORMALIZATION_TRIVY_RESULT_INVALID');
      return this.reject(input.ingestionId, binding.reasons);
    }
    return { outcome: 'NORMALIZED', batch };
  }

  private validateBinding(
    input: Readonly<TrivyJsonNormalizationInput>,
    referenceTime: Readonly<Date>
  ): {
    reasons: Set<SastNormalizationRejectionReasonCode>;
    ruleBundle: RuleBundleDescriptor | null;
    vulnerabilityDatabase: VulnerabilityDatabaseDescriptor | null;
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
      planDigest = digest(buildSastScanPlanDigestPreimage(input.plan));
    } catch {
      // Only bounded reason codes are observable on malformed input.
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

    const startedAtMilliseconds = this.validateReferenceTime(
      input.disposition,
      referenceTime,
      reasons
    );
    let vulnerabilityDatabase: VulnerabilityDatabaseDescriptor | null =
      null;
    let matchingBundles: RuleBundleDescriptor[] = [];
    try {
      vulnerabilityDatabase =
        input.plan.scannerSet.vulnerabilityDatabase;
      matchingBundles = Array.isArray(
        input.plan.scannerSet.ruleBundles
      )
        ? input.plan.scannerSet.ruleBundles.filter(
            (bundle) =>
              bundle.scanner === 'TRIVY' &&
              bundle.digest === input.envelope.ruleBundleDigest
          )
        : [];
    } catch {
      // The canonical plan validator below supplies the bounded reason.
    }
    if (
      envelopeDigest !== input.envelopeDigest ||
      planDigest === null ||
      !isScannerArtifactEnvelopeBoundToPlan(
        input.envelope,
        input.plan,
        input.expectedBinding
      ) ||
      input.envelope.scanner !== 'TRIVY' ||
      input.envelope.artifactSchema !== 'TRIVY_JSON' ||
      input.envelope.artifactSchemaVersion !==
        SAST_ARTIFACT_SCHEMA_VERSIONS.TRIVY_JSON ||
      !vulnerabilityDatabase ||
      input.envelope.vulnerabilityDatabaseDigest !==
        vulnerabilityDatabase.digest
    ) {
      reasons.add('NORMALIZATION_PLAN_BINDING_MISMATCH');
    }

    if (
      !validationShapeValid ||
      validationDigest !== input.validation.resultDigest ||
      input.validation.outcome !== 'PASSED' ||
      input.validation.artifactSchema !== 'TRIVY_JSON' ||
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

    if (matchingBundles.length !== 1) {
      reasons.add('NORMALIZATION_PLAN_BINDING_MISMATCH');
    }

    return {
      reasons,
      ruleBundle: matchingBundles[0] ?? null,
      vulnerabilityDatabase,
      planDigest,
      startedAtMilliseconds
    };
  }

  private validateReferenceTime(
    disposition: Readonly<SastArtifactDispositionDecision>,
    referenceTime: Readonly<Date>,
    reasons: Set<SastNormalizationRejectionReasonCode>
  ): number {
    return validateSastNormalizationReferenceTime(
      disposition,
      referenceTime,
      reasons
    );
  }

  private loadCoordinates(
    attestation: Readonly<SastFileCoordinateAttestation> | null,
    input: Readonly<TrivyJsonNormalizationInput>,
    reasons: Set<SastNormalizationRejectionReasonCode>
  ): ReadonlyMap<string, Readonly<SastFileCoordinateMetadata>> | null {
    return loadSastNormalizationCoordinates({
      attestation,
      expectedBinding: input.expectedBinding,
      maximumFileCount: input.plan.profile.limits.maxFileCount,
      maximumPathDepth: input.plan.profile.limits.maxPathDepth,
      invalidLocationReason: 'NORMALIZATION_TRIVY_LOCATION_INVALID',
      reasons
    });
  }

  private buildCandidates(
    parsed: Readonly<ParsedTrivyJson>,
    input: Readonly<TrivyJsonNormalizationInput>,
    ruleBundle: Readonly<RuleBundleDescriptor>,
    vulnerabilityDatabase: Readonly<VulnerabilityDatabaseDescriptor>,
    planDigest: `sha256:${string}`,
    coordinates:
      | ReadonlyMap<string, Readonly<SastFileCoordinateMetadata>>
      | null,
    reasons: Set<SastNormalizationRejectionReasonCode>
  ): TrivyNormalizedFindingCandidate[] | null {
    const bundleRulesById = new Map<
      string,
      RuleBundleDescriptor['rules'][number]
    >();
    for (const rule of ruleBundle.rules) {
      const ruleId = normalizeIdentifier(
        rule.ruleId,
        SAST_NORMALIZATION_LIMITS.ruleIdBytes,
        false
      );
      const ruleRevision = normalizeIdentifier(
        rule.ruleRevision,
        SAST_NORMALIZATION_LIMITS.ruleRevisionBytes,
        false
      );
      const ruleSemanticId = normalizeIdentifier(
        rule.ruleSemanticId,
        SAST_NORMALIZATION_LIMITS.ruleIdBytes,
        false
      );
      if (
        !ruleId ||
        !ruleRevision ||
        !ruleSemanticId ||
        bundleRulesById.has(ruleId)
      ) {
        reasons.add('NORMALIZATION_TRIVY_RULE_INVALID');
        continue;
      }
      bundleRulesById.set(ruleId, {
        ...rule,
        ruleId,
        ruleRevision,
        ruleSemanticId
      });
    }

    const databaseVersion = normalizeIdentifier(
      vulnerabilityDatabase.databaseVersion,
      SAST_NORMALIZATION_LIMITS.ruleRevisionBytes,
      false
    );
    if (!databaseVersion) {
      reasons.add('NORMALIZATION_TRIVY_VULNERABILITY_INVALID');
    }

    const resultsByIndex = new Map(
      parsed.results.map((result) => [result.index, result] as const)
    );
    const candidates: TrivyNormalizedFindingCandidate[] = [];
    const identityKeys = new Set<string>();
    const coordinateKeys = new Set<string>();
    const occurrenceOrdinals = new Map<string, number>();
    for (const record of parsed.records) {
      const result = resultsByIndex.get(record.resultIndex);
      if (!result) {
        reasons.add('NORMALIZATION_TRIVY_RESULT_INVALID');
        continue;
      }
      const location = normalizeTrivyLocation(
        record,
        result,
        input.plan.profile.limits.maxPathDepth,
        coordinates,
        reasons
      );
      if (!location) continue;

      const dispositionStatus =
        record.source === 'DIRECT'
          ? ('active' as const)
          : record.modifiedStatus;
      if (!dispositionStatus) {
        reasons.add('NORMALIZATION_TRIVY_SUPPRESSION_INVALID');
        continue;
      }
      const disposition = {
        source: record.source,
        status: dispositionStatus,
        platformPolicyAuthority: false as const
      };

      const common = {
        tenantId: input.envelope.tenantId,
        repositoryBindingId: input.envelope.repositoryBindingId,
        scanRequestId: input.envelope.scanRequestId,
        attemptId: input.envelope.attemptId,
        scannerRunId: input.envelope.scannerRunId,
        planDigest,
        canonicalScanKey: input.plan.canonicalScanKey,
        preflightAttestationRef:
          input.expectedBinding.preflightAttestationRef,
        preflightInventoryDigest:
          input.expectedBinding.preflightInventoryDigest,
        commitSha: input.plan.repositoryState.fixedCommitSha,
        lane: input.plan.profile.lane,
        confidence: 'UNKNOWN' as const,
        location,
        scannerDisposition: disposition,
        durablePersistenceAllowed: false as const
      };
      const notes = new Set<SastNormalizationNoteCode>([
        'UNKNOWN_CONFIDENCE'
      ]);
      const severity = normalizeSeverity(record.severity, notes);
      if (!severity) {
        reasons.add(reasonForRecord(record.kind));
        continue;
      }

      let candidate: TrivyNormalizedFindingCandidate | null = null;
      if (record.kind === 'VULNERABILITY') {
        const vulnerabilityId = normalizeVulnerabilityId(
          record.vulnerabilityId
        );
        const packageName = normalizeIdentifier(
          record.packageName,
          SAST_NORMALIZATION_LIMITS.packageNameBytes,
          false
        );
        const packageType = normalizeIdentifier(
          result.targetType,
          SAST_NORMALIZATION_LIMITS.packageTypeBytes,
          false
        );
        const installedVersion = normalizeIdentifier(
          record.installedVersion,
          SAST_NORMALIZATION_LIMITS.packageVersionBytes,
          false
        );
        const fixedVersion = normalizeIdentifier(
          record.fixedVersion ?? '',
          SAST_NORMALIZATION_LIMITS.packageVersionBytes,
          true
        );
        const advisoryStatus = record.advisoryStatus ?? 'unknown';
        const packagePurl =
          record.packagePurl === undefined
            ? ''
            : normalizeIdentifier(
                record.packagePurl,
                SAST_NORMALIZATION_LIMITS.scannerIdentityHintBytes,
                false
              );
        if (
          !databaseVersion ||
          !vulnerabilityId ||
          !packageName ||
          !packageType ||
          !TRIVY_LANGUAGE_TYPES.has(packageType) ||
          !installedVersion ||
          fixedVersion === null ||
          !advisoryStatus ||
          !TRIVY_VULNERABILITY_STATUSES.has(advisoryStatus) ||
          packagePurl === null
        ) {
          reasons.add('NORMALIZATION_TRIVY_PACKAGE_INVALID');
          continue;
        }
        const title = normalizeTitle(
          `${vulnerabilityId} in ${packageName}`
        );
        const description = normalizeDescription(
          fixedVersion
            ? `Detected ${vulnerabilityId} in ${packageName} ${installedVersion}; fixed version: ${fixedVersion}.`
            : `Detected ${vulnerabilityId} in ${packageName} ${installedVersion}; no fixed version was reported.`
        );
        if (!title.value || !description.value) {
          if (title.reason) reasons.add(title.reason);
          if (description.reason) reasons.add(description.reason);
          continue;
        }
        const identifiers = normalizeVulnerabilityIdentifiers(
          record,
          vulnerabilityId,
          reasons
        );
        if (!identifiers) continue;
        const ruleSemanticId = normalizeIdentifier(
          `${DEPENDENCY_SEMANTIC_PREFIX}${vulnerabilityId}`,
          SAST_NORMALIZATION_LIMITS.ruleIdBytes,
          false
        );
        if (!ruleSemanticId) {
          reasons.add('NORMALIZATION_TRIVY_VULNERABILITY_INVALID');
          continue;
        }
        const canonicalTarget = canonicalTargetForIdentity(
          record,
          result,
          input.plan.profile.limits.maxPathDepth
        );
        const scannerMatchBasedId = canonicalIdentityDigest(
          DEPENDENCY_IDENTITY_PREFIX,
          [
            vulnerabilityId,
            packageType,
            packageName,
            installedVersion,
            packagePurl ?? '',
            canonicalTarget
          ]
        );
        candidate = {
          ...common,
          capability: 'DEPENDENCY_VULNERABILITY',
          title: title.value,
          description: description.value,
          severity,
          cweIds: identifiers.cweIds,
          cveIds: identifiers.cveIds,
          identityMaterial: {
            ruleSemanticId,
            symbolAnchor: packageName,
            sinkKind: packageType,
            structuralHash: digest(
              `${DEPENDENCY_IDENTITY_PREFIX}:${scannerMatchBasedId}`
            ),
            scannerMatchBasedId
          },
          provenance: {
            scanner: 'TRIVY',
            scannerVersion: input.envelope.scannerVersion,
            scannerImageDigest: input.envelope.scannerImageDigest,
            ruleId: vulnerabilityId,
            ruleRevision: databaseVersion,
            ruleBundleDigest: ruleBundle.digest,
            artifactDigest: input.envelope.contentDigest,
            ruleSource: 'VULNERABILITY_DATABASE',
            vulnerabilityDatabaseDigest:
              vulnerabilityDatabase.digest
          },
          notes: orderSastNormalizationNotes(notes),
          trivy: {
            kind: 'DEPENDENCY_VULNERABILITY',
            vulnerabilityId,
            packageName,
            packageType,
            installedVersion,
            fixedVersion,
            advisoryStatus:
              advisoryStatus as TrivyAdvisoryStatus
          }
        };
      } else if (record.kind === 'SECRET') {
        const ruleId = normalizeIdentifier(
          record.ruleId,
          SAST_NORMALIZATION_LIMITS.ruleIdBytes,
          false
        );
        const bundleRule = ruleId
          ? bundleRulesById.get(ruleId)
          : undefined;
        const category = normalizeIdentifier(
          record.category,
          SAST_NORMALIZATION_LIMITS.trivyCategoryBytes,
          false
        );
        const title = normalizeTitle(`Secret detected: ${ruleId ?? ''}`);
        if (!ruleId || !bundleRule || !category || !title.value) {
          if (title.reason) reasons.add(title.reason);
          reasons.add('NORMALIZATION_TRIVY_SECRET_INVALID');
          continue;
        }
        const description = normalizeDescription(
          `Potential ${category} secret detected. The secret value and scanner context were discarded.`
        );
        if (!description.value) {
          if (description.reason) reasons.add(description.reason);
          continue;
        }
        const canonicalTarget = canonicalTargetForIdentity(
          record,
          result,
          input.plan.profile.limits.maxPathDepth
        );
        const coordinateKey = JSON.stringify([
          'SECRET_DETECTION',
          bundleRule.ruleSemanticId,
          canonicalTarget,
          record.startLine,
          record.endLine
        ]);
        if (coordinateKeys.has(coordinateKey)) {
          reasons.add('NORMALIZATION_TRIVY_RESULT_INVALID');
          continue;
        }
        coordinateKeys.add(coordinateKey);
        const occurrenceKey = JSON.stringify([
          'SECRET_DETECTION',
          bundleRule.ruleSemanticId,
          canonicalTarget
        ]);
        const occurrenceOrdinal =
          (occurrenceOrdinals.get(occurrenceKey) ?? 0) + 1;
        occurrenceOrdinals.set(
          occurrenceKey,
          occurrenceOrdinal
        );
        const scannerMatchBasedId = canonicalIdentityDigest(
          SECRET_IDENTITY_PREFIX,
          [
            bundleRule.ruleSemanticId,
            canonicalTarget,
            String(occurrenceOrdinal)
          ]
        );
        candidate = {
          ...common,
          capability: 'SECRET_DETECTION',
          title: title.value,
          description: description.value,
          severity,
          cweIds: [],
          cveIds: [],
          identityMaterial: {
            ruleSemanticId: bundleRule.ruleSemanticId,
            symbolAnchor: '',
            sinkKind: category,
            structuralHash: digest(
              `${SECRET_IDENTITY_PREFIX}:${scannerMatchBasedId}`
            ),
            scannerMatchBasedId
          },
          provenance: {
            scanner: 'TRIVY',
            scannerVersion: input.envelope.scannerVersion,
            scannerImageDigest: input.envelope.scannerImageDigest,
            ruleId,
            ruleRevision: bundleRule.ruleRevision,
            ruleBundleDigest: ruleBundle.digest,
            artifactDigest: input.envelope.contentDigest,
            ruleSource: 'CHECK_BUNDLE',
            vulnerabilityDatabaseDigest:
              vulnerabilityDatabase.digest
          },
          notes: orderSastNormalizationNotes(notes),
          trivy: {
            kind: 'SECRET_DETECTION',
            category,
            secretValueStored: false,
            secretPayloadDiscarded: true
          }
        };
      } else {
        const ruleId = normalizeIdentifier(
          record.ruleId,
          SAST_NORMALIZATION_LIMITS.ruleIdBytes,
          false
        );
        const bundleRule = ruleId
          ? bundleRulesById.get(ruleId)
          : undefined;
        const checkType = normalizeIdentifier(
          record.checkType,
          SAST_NORMALIZATION_LIMITS.ruleIdBytes,
          false
        );
        const avdId = normalizeIdentifier(
          record.avdId ?? '',
          SAST_NORMALIZATION_LIMITS.ruleIdBytes,
          true
        );
        const title = normalizeTitle(
          `IaC misconfiguration: ${ruleId ?? ''}`
        );
        const description = normalizeDescription(
          checkType
            ? `Trivy reported a failing ${checkType} check.`
            : undefined
        );
        if (
          !ruleId ||
          !bundleRule ||
          !checkType ||
          avdId === null ||
          record.resultStatus !== 'FAIL' ||
          !title.value ||
          !description.value
        ) {
          if (title.reason) reasons.add(title.reason);
          if (description.reason) reasons.add(description.reason);
          reasons.add('NORMALIZATION_TRIVY_MISCONFIGURATION_INVALID');
          continue;
        }
        const canonicalTarget = canonicalTargetForIdentity(
          record,
          result,
          input.plan.profile.limits.maxPathDepth
        );
        const coordinateKey = JSON.stringify([
          'IAC_MISCONFIGURATION',
          bundleRule.ruleSemanticId,
          canonicalTarget,
          record.startLine ?? 0,
          record.endLine ?? 0
        ]);
        if (coordinateKeys.has(coordinateKey)) {
          reasons.add('NORMALIZATION_TRIVY_RESULT_INVALID');
          continue;
        }
        coordinateKeys.add(coordinateKey);
        const occurrenceKey = JSON.stringify([
          'IAC_MISCONFIGURATION',
          bundleRule.ruleSemanticId,
          canonicalTarget
        ]);
        const occurrenceOrdinal =
          (occurrenceOrdinals.get(occurrenceKey) ?? 0) + 1;
        occurrenceOrdinals.set(
          occurrenceKey,
          occurrenceOrdinal
        );
        const scannerMatchBasedId = canonicalIdentityDigest(
          IAC_IDENTITY_PREFIX,
          [
            bundleRule.ruleSemanticId,
            canonicalTarget,
            String(occurrenceOrdinal)
          ]
        );
        candidate = {
          ...common,
          capability: 'IAC_MISCONFIGURATION',
          title: title.value,
          description: description.value,
          severity,
          cweIds: [],
          cveIds: [],
          identityMaterial: {
            ruleSemanticId: bundleRule.ruleSemanticId,
            symbolAnchor: '',
            sinkKind: checkType,
            structuralHash: digest(
              `${IAC_IDENTITY_PREFIX}:${scannerMatchBasedId}`
            ),
            scannerMatchBasedId
          },
          provenance: {
            scanner: 'TRIVY',
            scannerVersion: input.envelope.scannerVersion,
            scannerImageDigest: input.envelope.scannerImageDigest,
            ruleId,
            ruleRevision: bundleRule.ruleRevision,
            ruleBundleDigest: ruleBundle.digest,
            artifactDigest: input.envelope.contentDigest,
            ruleSource: 'CHECK_BUNDLE',
            vulnerabilityDatabaseDigest:
              vulnerabilityDatabase.digest
          },
          notes: orderSastNormalizationNotes(notes),
          trivy: {
            kind: 'IAC_MISCONFIGURATION',
            checkType,
            avdId,
            resultStatus: 'FAIL'
          }
        };
      }

      if (!candidate) continue;
      const identityKey = JSON.stringify([
        candidate.capability,
        candidate.identityMaterial.ruleSemanticId,
        candidate.identityMaterial.scannerMatchBasedId
      ]);
      if (identityKeys.has(identityKey)) {
        reasons.add('NORMALIZATION_TRIVY_RESULT_INVALID');
        continue;
      }
      identityKeys.add(identityKey);
      candidates.push(candidate);
    }

    if (reasons.size > 0) return null;
    return candidates.sort(compareSastNormalizedFindingCandidates);
  }

  private reject(
    ingestionId: string,
    reasons: Iterable<SastNormalizationRejectionReasonCode>
  ): TrivyJsonNormalizationResult {
    const core: TrivyJsonNormalizationRejectionCore = {
      version: TRIVY_JSON_NORMALIZER_VERSION,
      adapterVersion: TRIVY_JSON_NORMALIZER_VERSION,
      outcome: 'REJECTED',
      ingestionId,
      reasonCodes: orderSastNormalizationRejectionReasons(reasons)
    };
    return {
      ...core,
      rejectionDigest: digest(
        canonicalizeTrivyJsonNormalizationRejection(core)
      )
    };
  }
}

class TrivyJsonStreamSession {
  readonly reasons =
    new Set<SastNormalizationRejectionReasonCode>();
  private readonly contentHash = createHash('sha256');
  private readonly decoder = new TextDecoder('utf-8', { fatal: true });
  private readonly tokenizer = new Tokenizer({
    emitPartialTokens: false
  });
  private readonly parserReasons =
    new Set<SastArtifactValidationReasonCode>();
  private readonly rawLimiter = new RawJsonTokenLimiter();
  private readonly collector: TrivyJsonCollector;
  private readonly structure: BoundedJsonStructureTracker;
  private readonly pending = Buffer.alloc(
    SAST_ARTIFACT_VALIDATION_LIMITS.parserSliceBytes
  );
  private pendingLength = 0;
  private observedByteSize = 0;
  private parsingActive = true;
  private decoderActive = true;
  private readonly maximumArtifactBytes: number;

  constructor(
    private readonly envelope: Readonly<ScannerArtifactEnvelope>,
    plan: Readonly<SastScanPlan>
  ) {
    this.maximumArtifactBytes =
      plan.profile.limits.maxArtifactBytes;
    this.collector = new TrivyJsonCollector(
      plan.profile.limits.maxArtifactRecords,
      Math.min(
        plan.profile.limits.maxArtifactRecords,
        plan.profile.limits.maxFindings
      ),
      plan.profile.limits.maxPathDepth,
      this.reasons
    );
    this.structure = new BoundedJsonStructureTracker(
      this.collector,
      this.parserReasons
    );
    this.tokenizer.onToken = (token) => this.structure.accept(token);
    this.tokenizer.onError = () => {
      this.failParsing();
    };
  }

  async parse(
    artifact: AsyncIterable<Uint8Array>
  ): Promise<ParsedTrivyJson | null> {
    const hardByteLimit = Math.min(
      this.envelope.byteSize,
      this.maximumArtifactBytes
    );
    try {
      for await (const chunk of artifact) {
        const bytes = Buffer.from(chunk);
        if (bytes.byteLength === 0) continue;
        const remaining =
          hardByteLimit + 1 - this.observedByteSize;
        const observed = bytes.subarray(
          0,
          Math.max(0, Math.min(bytes.byteLength, remaining))
        );
        this.contentHash.update(observed);
        this.observedByteSize += observed.byteLength;
        if (this.observedByteSize > hardByteLimit) {
          this.reasons.add('NORMALIZATION_BYTE_SIZE_MISMATCH');
          this.parsingActive = false;
          this.pendingLength = 0;
          this.decoderActive = false;
          break;
        }
        this.validateEncoding(observed);
        this.acceptBytes(observed);
      }
    } catch {
      this.failParsing();
      this.decoderActive = false;
    }

    this.finishParser();
    const contentDigest =
      `sha256:${this.contentHash.digest('hex')}` as const;
    if (contentDigest !== this.envelope.contentDigest) {
      this.reasons.add('NORMALIZATION_CONTENT_DIGEST_MISMATCH');
    }
    if (this.observedByteSize !== this.envelope.byteSize) {
      this.reasons.add('NORMALIZATION_BYTE_SIZE_MISMATCH');
    }
    if (
      !this.reasons.has('NORMALIZATION_BYTE_SIZE_MISMATCH') &&
      !this.reasons.has('NORMALIZATION_ARTIFACT_STREAM_INVALID') &&
      this.collector.findingCount !== this.envelope.recordCount
    ) {
      this.reasons.add('NORMALIZATION_VALIDATION_BINDING_MISMATCH');
    }
    if (this.reasons.size > 0) return null;
    return this.collector.finish();
  }

  private validateEncoding(bytes: Buffer): void {
    if (!this.decoderActive) return;
    try {
      this.decoder.decode(bytes, { stream: true });
    } catch {
      this.decoderActive = false;
      this.reasons.add('NORMALIZATION_ARTIFACT_STREAM_INVALID');
    }
  }

  private acceptBytes(bytes: Buffer): void {
    if (!this.parsingActive) return;
    const sliceBytes =
      SAST_ARTIFACT_VALIDATION_LIMITS.parserSliceBytes;
    let offset = 0;
    if (this.pendingLength > 0) {
      const take = Math.min(
        sliceBytes - this.pendingLength,
        bytes.byteLength
      );
      bytes.copy(this.pending, this.pendingLength, 0, take);
      this.pendingLength += take;
      offset = take;
      if (this.pendingLength === sliceBytes) {
        this.pendingLength = 0;
        this.processSlice(this.pending);
      }
    }
    while (
      this.parsingActive &&
      offset + sliceBytes <= bytes.byteLength
    ) {
      this.processSlice(
        bytes.subarray(offset, offset + sliceBytes)
      );
      offset += sliceBytes;
    }
    if (this.parsingActive && offset < bytes.byteLength) {
      bytes.copy(this.pending, 0, offset);
      this.pendingLength = bytes.byteLength - offset;
    }
  }

  private processSlice(bytes: Buffer): void {
    try {
      this.rawLimiter.write(bytes);
      this.tokenizer.write(bytes);
    } catch {
      this.failParsing();
    }
  }

  private finishParser(): void {
    if (this.decoderActive) {
      try {
        this.decoder.decode();
      } catch {
        this.reasons.add('NORMALIZATION_ARTIFACT_STREAM_INVALID');
      }
    }
    if (this.parsingActive && this.pendingLength > 0) {
      const length = this.pendingLength;
      this.pendingLength = 0;
      this.processSlice(this.pending.subarray(0, length));
    }
    if (!this.parsingActive) return;
    try {
      this.rawLimiter.end();
      this.tokenizer.end();
      this.structure.finish();
      if (this.parserReasons.size > 0) {
        this.reasons.add('NORMALIZATION_ARTIFACT_STREAM_INVALID');
      }
    } catch {
      this.failParsing();
    }
  }

  private failParsing(): void {
    this.parsingActive = false;
    this.pendingLength = 0;
    this.reasons.add('NORMALIZATION_ARTIFACT_STREAM_INVALID');
  }
}

class TrivyJsonCollector implements ArtifactValidationCallbacks {
  private rootKind?: ContainerKind;
  private schemaVersion?: number;
  private artifactType?: string;
  private resultsSeen = false;
  private readonly results = new Map<number, TrivyResultState>();
  private readonly records = new Map<string, TrivyRecordState>();
  private readonly modifiedFindings = new Map<
    string,
    ModifiedFindingState
  >();
  findingCount = 0;

  constructor(
    private readonly maximumResults: number,
    private readonly maximumFindings: number,
    private readonly maximumPathDepth: number,
    private readonly reasons:
      Set<SastNormalizationRejectionReasonCode>
  ) {}

  onContainer(path: JsonPath, kind: ContainerKind): void {
    if (path.length === 0) {
      this.rootKind = kind;
      if (kind !== 'OBJECT') this.structureInvalid();
      return;
    }
    if (isExpectedTrivyScalarPath(path)) {
      this.reasonForPath(path);
    }
    const expectedKind = expectedTrivyContainerKind(path);
    if (expectedKind && kind !== expectedKind) {
      this.reasonForPath(path);
    }

    if (matches(path, ['Results'])) {
      this.resultsSeen = true;
      if (kind !== 'ARRAY') this.structureInvalid();
      return;
    }
    if (isTrivyResultPath(path)) {
      if (kind !== 'OBJECT') {
        this.resultInvalid();
        return;
      }
      const index = path[1] as number;
      if (
        this.results.size >= this.maximumResults ||
        this.results.has(index)
      ) {
        this.resultInvalid();
        return;
      }
      this.results.set(index, {
        index,
        vulnerabilitiesSeen: false,
        misconfigurationsSeen: false,
        secretsSeen: false,
        modifiedFindingsSeen: false
      });
      return;
    }
    const directArray = directRecordArrayKind(path);
    if (directArray) {
      const result = this.resultFor(path);
      if (!result || kind !== 'ARRAY') {
        this.resultInvalid();
        return;
      }
      if (directArray === 'VULNERABILITY') {
        result.vulnerabilitiesSeen = true;
      } else if (directArray === 'MISCONFIGURATION') {
        result.misconfigurationsSeen = true;
      } else {
        result.secretsSeen = true;
      }
      return;
    }
    const directRecord = directRecordKind(path);
    if (directRecord) {
      this.startRecord(path, kind, directRecord, 'DIRECT');
      return;
    }
    if (isModifiedFindingArrayPath(path)) {
      const result = this.resultFor(path);
      if (result) result.modifiedFindingsSeen = true;
      if (!result || kind !== 'ARRAY') this.resultInvalid();
      return;
    }
    if (isModifiedFindingPath(path)) {
      if (kind !== 'OBJECT') {
        this.suppressionInvalid();
        return;
      }
      const key = keyForPath(path);
      const resultIndex = path[1] as number;
      const index = path[3] as number;
      if (
        !this.results.has(resultIndex) ||
        this.modifiedFindings.has(key)
      ) {
        this.suppressionInvalid();
        return;
      }
      this.modifiedFindings.set(key, {
        key,
        index,
        resultIndex,
        findingSeen: false
      });
      return;
    }
    if (isModifiedFindingRecordPath(path)) {
      const modified = this.modifiedFor(path);
      if (!modified || modified.findingSeen) {
        this.suppressionInvalid();
        return;
      }
      modified.findingSeen = true;
      const record = this.startRecord(
        path,
        kind,
        undefined,
        'MODIFIED'
      );
      if (record) {
        modified.record = record;
      }
    }
  }

  onContainerEnd(): void {}

  onKey(objectPath: JsonPath, key: string): void {
    const allowed = allowedTrivyKeys(objectPath);
    if (allowed && !allowed.has(key)) {
      this.reasonForPath(objectPath);
    }
    const recordRoot = trivyRecordRoot(objectPath);
    if (
      recordRoot &&
      recordRoot.length === objectPath.length
    ) {
      this.records.get(keyForPath(recordRoot))?.keys.add(key);
    }
  }

  onPrimitive(path: JsonPath, value: JsonPrimitive): void {
    if (expectedTrivyContainerKind(path)) {
      this.reasonForPath(path);
      return;
    }
    if (matches(path, ['SchemaVersion'])) {
      if (
        typeof value !== 'number' ||
        !Number.isSafeInteger(value)
      ) {
        this.structureInvalid();
      } else {
        this.schemaVersion = value;
      }
      return;
    }
    if (matches(path, ['ArtifactType'])) {
      if (typeof value !== 'string') this.structureInvalid();
      else this.artifactType = value;
      return;
    }
    if (
      matches(path, ['CreatedAt']) ||
      matches(path, ['ArtifactName'])
    ) {
      if (typeof value !== 'string') this.structureInvalid();
      return;
    }

    const result = this.resultFor(path);
    if (result && path.length === 3) {
      const field = path[2];
      if (
        ['Target', 'Class', 'Type'].includes(String(field)) &&
        typeof value !== 'string'
      ) {
        this.resultInvalid();
      } else if (field === 'Target') {
        result.target = value as string;
      } else if (field === 'Class') {
        result.resultClass = value as string;
      } else if (field === 'Type') {
        result.targetType = value as string;
      }
      return;
    }

    const modified = this.modifiedFor(path);
    if (modified && path.length === 5) {
      const field = path[4];
      if (field === 'Type') {
        if (typeof value !== 'string') this.suppressionInvalid();
        else modified.findingType = value;
      } else if (field === 'Status') {
        if (
          typeof value !== 'string' ||
          !TRIVY_MODIFIED_STATUSES.has(
            value as TrivyScannerDispositionStatus
          )
        ) {
          this.suppressionInvalid();
        } else {
          modified.status =
            value as TrivyScannerDispositionStatus;
        }
      } else if (
        (field === 'Statement' || field === 'Source') &&
        typeof value !== 'string'
      ) {
        this.suppressionInvalid();
      }
      return;
    }

    const record = this.recordFor(path);
    if (record) this.captureRecordValue(record, path, value);
  }

  finish(): ParsedTrivyJson | null {
    if (
      this.rootKind !== 'OBJECT' ||
      this.schemaVersion !==
        Number(SAST_ARTIFACT_SCHEMA_VERSIONS.TRIVY_JSON) ||
      this.artifactType !== TRIVY_FILESYSTEM_ARTIFACT_TYPE ||
      !this.resultsSeen
    ) {
      this.structureInvalid();
    }

    for (const modified of this.modifiedFindings.values()) {
      const kind = modifiedKind(modified.findingType);
      if (
        !kind ||
        !modified.status ||
        !modified.findingSeen ||
        !modified.record
      ) {
        this.suppressionInvalid();
        continue;
      }
      modified.record.kind = kind;
      modified.record.modifiedStatus = modified.status;
      if (
        [...modified.record.keys].some(
          (key) => !keysForRecordKind(kind).has(key)
        )
      ) {
        this.suppressionInvalid();
      }
    }

    for (const result of this.results.values()) {
      const normalizedTarget =
        result.target === '.'
          ? '.'
          : normalizeArtifactPath(
              result.target,
              this.maximumPathDepth
            );
      if (
        !result.target ||
        !normalizedTarget ||
        normalizedTarget !== result.target ||
        !result.resultClass ||
        !TRIVY_RESULT_CLASSES.has(result.resultClass)
      ) {
        this.resultInvalid();
        continue;
      }
      if (
        result.resultClass === 'lang-pkgs' &&
        (!result.targetType ||
          !TRIVY_LANGUAGE_TYPES.has(result.targetType) ||
          result.misconfigurationsSeen ||
          result.secretsSeen)
      ) {
        this.resultInvalid();
      } else if (
        result.resultClass === 'config' &&
        (!result.targetType ||
          !TRIVY_CONFIG_TYPES.has(result.targetType) ||
          result.vulnerabilitiesSeen ||
          result.secretsSeen)
      ) {
        this.resultInvalid();
      } else if (
        result.resultClass === 'secret' &&
        (result.targetType !== undefined ||
          result.vulnerabilitiesSeen ||
          result.misconfigurationsSeen)
      ) {
        this.resultInvalid();
      }
    }

    const completedRecords: CompletedTrivyRecordState[] = [];
    for (const record of this.records.values()) {
      if (!record.kind) {
        this.suppressionInvalid();
        continue;
      }
      const result = this.results.get(record.resultIndex);
      if (!result || !recordMatchesResult(record.kind, result)) {
        this.resultInvalid();
      }
      if (
        !this.isRecordComplete(
          record as CompletedTrivyRecordState
        )
      ) {
        continue;
      }
      completedRecords.push(
        record as CompletedTrivyRecordState
      );
    }

    if (this.reasons.size > 0) return null;
    return {
      results: [...this.results.values()].sort(
        (left, right) => left.index - right.index
      ),
      records: completedRecords.sort((left, right) =>
        compareCodeUnitStrings(left.key, right.key)
      )
    };
  }

  private startRecord(
    path: JsonPath,
    kind: ContainerKind,
    recordKind: TrivyRecordKind | undefined,
    source: 'DIRECT' | 'MODIFIED'
  ): TrivyRecordState | null {
    this.findingCount += 1;
    if (
      this.findingCount > this.maximumFindings ||
      kind !== 'OBJECT'
    ) {
      this.reasonForKind(recordKind);
      return null;
    }
    const key = keyForPath(path);
    if (this.records.has(key)) {
      this.reasonForKind(recordKind);
      return null;
    }
    const record: TrivyRecordState = {
      key,
      index: Number(path.at(-1) ?? 0),
      resultIndex: path[1] as number,
      kind: recordKind,
      source,
      vendorIds: [],
      cweIds: [],
      keys: new Set<string>()
    };
    this.records.set(key, record);
    return record;
  }

  private captureRecordValue(
    record: TrivyRecordState,
    path: JsonPath,
    value: JsonPrimitive
  ): void {
    const root = trivyRecordRoot(path);
    if (!root) return;
    const suffix = path.slice(root.length);
    if (
      suffix.length === 2 &&
      suffix[0] === 'CweIDs' &&
      typeof suffix[1] === 'number'
    ) {
      if (typeof value !== 'string') this.reasonForKind(record.kind);
      else record.cweIds.push(value);
      return;
    }
    if (
      suffix.length === 2 &&
      suffix[0] === 'VendorIDs' &&
      typeof suffix[1] === 'number'
    ) {
      if (typeof value !== 'string') this.reasonForKind(record.kind);
      else record.vendorIds.push(value);
      return;
    }
    if (
      matches(suffix, ['PkgIdentifier', 'PURL'])
    ) {
      if (typeof value !== 'string') this.vulnerabilityInvalid();
      else record.packagePurl = value;
      return;
    }
    if (
      matches(suffix, ['CauseMetadata', 'StartLine']) ||
      matches(suffix, ['CauseMetadata', 'EndLine'])
    ) {
      const coordinate = normalizeCoordinate(value);
      if (!coordinate) {
        this.locationInvalid();
      } else if (suffix[1] === 'StartLine') {
        record.startLine = coordinate;
      } else {
        record.endLine = coordinate;
      }
      return;
    }
    if (suffix.length !== 1) return;
    const field = suffix[0];
    if (typeof field !== 'string') return;

    if (field === 'Match') {
      if (typeof value !== 'string') this.secretInvalid();
      return;
    }
    if (
      [
        'VulnerabilityID',
        'PkgID',
        'PkgName',
        'PkgPath',
        'InstalledVersion',
        'FixedVersion',
        'Status',
        'RuleID',
        'Category',
        'Type',
        'ID',
        'AVDID',
        'Title',
        'Description',
        'Severity'
      ].includes(field)
    ) {
      if (typeof value !== 'string') {
        this.reasonForKind(record.kind);
        return;
      }
      if (field === 'VulnerabilityID') {
        record.vulnerabilityId = value;
      } else if (field === 'PkgName') {
        record.packageName = value;
      } else if (field === 'PkgPath') {
        record.packagePath = value;
      } else if (field === 'InstalledVersion') {
        record.installedVersion = value;
      } else if (field === 'FixedVersion') {
        record.fixedVersion = value;
      } else if (field === 'Status') {
        // Modified record kind is finalized after parsing, and Status may
        // precede ID. Keep resultStatus populated in both branches.
        if (
          record.kind === 'MISCONFIGURATION' ||
          (record.source === 'MODIFIED' &&
            record.vulnerabilityId === undefined &&
            record.ruleId !== undefined)
        ) {
          record.resultStatus = value;
        } else {
          record.advisoryStatus = value;
          record.resultStatus = value;
        }
      } else if (field === 'RuleID') {
        record.ruleId = value;
      } else if (field === 'Category') {
        record.category = value;
      } else if (field === 'Type') {
        record.checkType = value;
      } else if (field === 'ID') {
        record.ruleId = value;
      } else if (field === 'AVDID') {
        record.avdId = value;
      } else if (field === 'Title') {
        if (value.length > 0) record.titlePresent = true;
      } else if (field === 'Severity') {
        record.severity = value;
      }
      return;
    }
    if (
      (field === 'StartLine' || field === 'EndLine') &&
      (record.kind === 'SECRET' || record.source === 'MODIFIED')
    ) {
      const coordinate = normalizeCoordinate(value);
      if (!coordinate) {
        this.locationInvalid();
      } else if (field === 'StartLine') {
        record.startLine = coordinate;
      } else {
        record.endLine = coordinate;
      }
      return;
    }
    if (
      field === 'Offset' &&
      (typeof value !== 'number' ||
        !Number.isSafeInteger(value) ||
        value < 0)
    ) {
      this.secretInvalid();
    }
  }

  private isRecordComplete(
    record: CompletedTrivyRecordState
  ): boolean {
    if (record.kind === 'VULNERABILITY') {
      if (
        !record.vulnerabilityId ||
        (record.advisoryStatus !== undefined &&
          !TRIVY_VULNERABILITY_STATUSES.has(
            record.advisoryStatus
          )) ||
        (record.severity !== undefined &&
          !TRIVY_SEVERITIES.has(record.severity))
      ) {
        this.vulnerabilityInvalid();
        return false;
      }
      if (!record.packageName || !record.installedVersion) {
        this.packageInvalid();
        return false;
      }
      return true;
    }
    if (record.kind === 'SECRET') {
      if (
        !record.ruleId ||
        !record.category ||
        !record.titlePresent ||
        !record.keys.has('Code') ||
        !record.keys.has('Match') ||
        !record.startLine ||
        !record.endLine ||
        record.endLine < record.startLine ||
        !record.severity ||
        !TRIVY_SEVERITIES.has(record.severity)
      ) {
        this.secretInvalid();
        return false;
      }
      return true;
    }
    if (
      !record.ruleId ||
      !record.checkType ||
      !record.titlePresent ||
      record.resultStatus !== 'FAIL' ||
      !record.severity ||
      !TRIVY_SEVERITIES.has(record.severity) ||
      (record.startLine === undefined) !==
        (record.endLine === undefined) ||
      (record.startLine !== undefined &&
        record.endLine !== undefined &&
        record.endLine < record.startLine)
    ) {
      this.misconfigurationInvalid();
      return false;
    }
    return true;
  }

  private recordFor(path: JsonPath): TrivyRecordState | undefined {
    const root = trivyRecordRoot(path);
    return root
      ? this.records.get(keyForPath(root))
      : undefined;
  }

  private resultFor(path: JsonPath): TrivyResultState | undefined {
    return typeof path[1] === 'number'
      ? this.results.get(path[1])
      : undefined;
  }

  private modifiedFor(
    path: JsonPath
  ): ModifiedFindingState | undefined {
    return isWithinModifiedFinding(path)
      ? this.modifiedFindings.get(
          keyForPath(path.slice(0, 4))
        )
      : undefined;
  }

  private reasonForPath(path: JsonPath): void {
    const record = this.recordFor(path);
    if (record) {
      this.reasonForKind(record.kind);
    } else if (isWithinModifiedFinding(path)) {
      this.suppressionInvalid();
    } else if (
      path.length >= 2 &&
      path[0] === 'Results'
    ) {
      this.resultInvalid();
    } else {
      this.structureInvalid();
    }
  }

  private reasonForKind(kind: TrivyRecordKind | undefined): void {
    if (kind === 'VULNERABILITY') this.vulnerabilityInvalid();
    else if (kind === 'SECRET') this.secretInvalid();
    else if (kind === 'MISCONFIGURATION') {
      this.misconfigurationInvalid();
    } else this.suppressionInvalid();
  }

  private structureInvalid(): void {
    this.reasons.add('NORMALIZATION_TRIVY_STRUCTURE_INVALID');
  }

  private resultInvalid(): void {
    this.reasons.add('NORMALIZATION_TRIVY_RESULT_INVALID');
  }

  private vulnerabilityInvalid(): void {
    this.reasons.add(
      'NORMALIZATION_TRIVY_VULNERABILITY_INVALID'
    );
  }

  private secretInvalid(): void {
    this.reasons.add('NORMALIZATION_TRIVY_SECRET_INVALID');
  }

  private misconfigurationInvalid(): void {
    this.reasons.add(
      'NORMALIZATION_TRIVY_MISCONFIGURATION_INVALID'
    );
  }

  private locationInvalid(): void {
    this.reasons.add('NORMALIZATION_TRIVY_LOCATION_INVALID');
  }

  private packageInvalid(): void {
    this.reasons.add('NORMALIZATION_TRIVY_PACKAGE_INVALID');
  }

  private suppressionInvalid(): void {
    this.reasons.add('NORMALIZATION_TRIVY_SUPPRESSION_INVALID');
  }
}

function normalizeTrivyLocation(
  record: Readonly<CompletedTrivyRecordState>,
  result: Readonly<TrivyResultState>,
  maximumDepth: number,
  coordinates:
    | ReadonlyMap<string, Readonly<SastFileCoordinateMetadata>>
    | null,
  reasons: Set<SastNormalizationRejectionReasonCode>
): SastFindingLocation | null {
  const rawPath =
    record.kind === 'VULNERABILITY' && record.packagePath
      ? record.packagePath
      : result.target;
  const normalizedPath =
    rawPath === '.'
      ? null
      : normalizeArtifactPath(rawPath, maximumDepth);
  if (
    rawPath !== '.' &&
    (!normalizedPath || normalizedPath !== rawPath)
  ) {
    reasons.add('NORMALIZATION_TRIVY_LOCATION_INVALID');
    return null;
  }
  if (record.kind === 'VULNERABILITY') {
    return {
      kind: 'UNKNOWN',
      reasonCode: 'SCANNER_LOCATION_OMITTED'
    };
  }
  if (
    record.startLine === undefined &&
    record.endLine === undefined
  ) {
    return {
      kind: 'UNKNOWN',
      reasonCode: 'SCANNER_LOCATION_OMITTED'
    };
  }
  if (
    !normalizedPath ||
    !record.startLine ||
    !record.endLine
  ) {
    reasons.add('NORMALIZATION_TRIVY_LOCATION_INVALID');
    return null;
  }
  const metadata = coordinates?.get(normalizedPath);
  if (!metadata) {
    return {
      kind: 'UNKNOWN',
      reasonCode: 'LOCATION_NOT_MAPPABLE'
    };
  }
  const location: SastFindingLocation = {
    kind: 'FILE',
    normalizedPath,
    lineStart: record.startLine,
    lineEnd: record.endLine
  };
  if (!isSastFindingLocationValid(location, metadata)) {
    reasons.add('NORMALIZATION_TRIVY_LOCATION_INVALID');
    return null;
  }
  return location;
}

function canonicalTargetForIdentity(
  record: Readonly<CompletedTrivyRecordState>,
  result: Readonly<TrivyResultState>,
  maximumDepth: number
): string {
  const rawPath =
    record.kind === 'VULNERABILITY' && record.packagePath
      ? record.packagePath
      : result.target;
  if (rawPath === '.') return '';
  return normalizeArtifactPath(rawPath, maximumDepth) ?? '';
}

function normalizeSeverity(
  value: string | undefined,
  notes: Set<SastNormalizationNoteCode>
): TrivyNormalizedFindingCandidate['severity'] | null {
  if (value === undefined || value === 'UNKNOWN') {
    notes.add('UNKNOWN_SEVERITY');
    return 'INFO';
  }
  return TRIVY_SEVERITIES.has(value)
    ? (value as TrivyNormalizedFindingCandidate['severity'])
    : null;
}

function normalizeVulnerabilityIdentifiers(
  record: Readonly<CompletedTrivyRecordState>,
  vulnerabilityId: string,
  reasons: Set<SastNormalizationRejectionReasonCode>
): { cweIds: string[]; cveIds: string[] } | null {
  if (
    record.cweIds.length >
      SAST_NORMALIZATION_LIMITS.maximumCweIds ||
    record.vendorIds.length >
      SAST_NORMALIZATION_LIMITS.maximumCveIds
  ) {
    reasons.add('NORMALIZATION_IDENTIFIER_LIMIT_EXCEEDED');
    return null;
  }
  const cweIds = new Set<string>();
  for (const raw of record.cweIds) {
    const normalized = raw.toUpperCase();
    if (
      !/^CWE-[1-9][0-9]{0,9}$/u.test(normalized) ||
      utf8Bytes(normalized) >
        SAST_NORMALIZATION_LIMITS.vulnerabilityIdentifierBytes
    ) {
      reasons.add('NORMALIZATION_IDENTIFIER_INVALID');
      return null;
    }
    cweIds.add(normalized);
  }
  const cveIds = new Set<string>();
  for (const raw of [vulnerabilityId, ...record.vendorIds]) {
    if (!/^CVE-/iu.test(raw)) continue;
    const normalized = raw.toUpperCase();
    if (
      !/^CVE-[0-9]{4}-[0-9]{4,}$/u.test(normalized) ||
      utf8Bytes(normalized) >
        SAST_NORMALIZATION_LIMITS.vulnerabilityIdentifierBytes
    ) {
      reasons.add('NORMALIZATION_IDENTIFIER_INVALID');
      return null;
    }
    cveIds.add(normalized);
  }
  if (
    cweIds.size > SAST_NORMALIZATION_LIMITS.maximumCweIds ||
    cveIds.size > SAST_NORMALIZATION_LIMITS.maximumCveIds
  ) {
    reasons.add('NORMALIZATION_IDENTIFIER_LIMIT_EXCEEDED');
    return null;
  }
  return {
    cweIds: [...cweIds].sort(compareSastNormalizationIdentifiers),
    cveIds: [...cveIds].sort(compareSastNormalizationIdentifiers)
  };
}

function normalizeVulnerabilityId(
  value: string | undefined
): string | null {
  const normalized = normalizeIdentifier(
    value?.toUpperCase(),
    SAST_NORMALIZATION_LIMITS.vulnerabilityIdBytes,
    false
  );
  return normalized &&
    /^[A-Z0-9][A-Z0-9._:+-]*$/u.test(normalized)
    ? normalized
    : null;
}

function normalizeIdentifier(
  value: string | undefined,
  maximumBytes: number,
  allowEmpty: boolean
): string | null {
  if (value === undefined) return null;
  const normalized = value.normalize('NFC');
  return (allowEmpty || normalized.length > 0) &&
    normalized === normalized.trim() &&
    utf8Bytes(normalized) <= maximumBytes &&
    !hasUnsafeControls(normalized, false)
    ? normalized
    : null;
}

function canonicalIdentityDigest(
  namespace: string,
  fields: readonly string[]
): `sha256:${string}` {
  const preimage = [
    `${namespace}\u0000`,
    ...fields.map((field) => {
      const normalized = field.normalize('NFC');
      return `${utf8Bytes(normalized)}:${normalized}`;
    })
  ].join('');
  return digest(preimage);
}

function normalizeCoordinate(value: JsonPrimitive): number | null {
  return typeof value === 'number' &&
    Number.isSafeInteger(value) &&
    value > 0 &&
    value <= SAST_MAX_COORDINATE_VALUE
    ? value
    : null;
}

function reasonForRecord(
  kind: TrivyRecordKind
): SastNormalizationRejectionReasonCode {
  return kind === 'VULNERABILITY'
    ? 'NORMALIZATION_TRIVY_VULNERABILITY_INVALID'
    : kind === 'SECRET'
      ? 'NORMALIZATION_TRIVY_SECRET_INVALID'
      : 'NORMALIZATION_TRIVY_MISCONFIGURATION_INVALID';
}

function allowedTrivyKeys(
  path: JsonPath
): ReadonlySet<string> | null {
  if (path.length === 0) return ROOT_KEYS;
  if (isTrivyResultPath(path)) return RESULT_KEYS;
  const directKind = directRecordKind(path);
  if (directKind) return keysForRecordKind(directKind);
  if (isModifiedFindingPath(path)) return MODIFIED_FINDING_KEYS;
  if (isModifiedFindingRecordPath(path)) {
    return new Set([
      ...VULNERABILITY_KEYS,
      ...MISCONFIGURATION_KEYS,
      ...SECRET_KEYS
    ]);
  }
  if (
    path.at(-1) === 'PkgIdentifier' &&
    trivyRecordRoot(path)
  ) {
    return PACKAGE_IDENTIFIER_KEYS;
  }
  if (
    path.at(-1) === 'CauseMetadata' &&
    trivyRecordRoot(path)
  ) {
    return CAUSE_METADATA_KEYS;
  }
  if (
    path.at(-1) === 'MisconfSummary' &&
    path.length === 3
  ) {
    return MISCONF_SUMMARY_KEYS;
  }
  return null;
}

function expectedTrivyContainerKind(
  path: JsonPath
): ContainerKind | null {
  if (
    matches(path, ['Results']) ||
    directRecordArrayKind(path) !== null ||
    isModifiedFindingArrayPath(path)
  ) {
    return 'ARRAY';
  }
  if (
    isTrivyResultPath(path) ||
    directRecordKind(path) !== null ||
    isModifiedFindingPath(path) ||
    isModifiedFindingRecordPath(path) ||
    matches(path, ['Metadata']) ||
    (path.length === 3 && path[2] === 'MisconfSummary')
  ) {
    return 'OBJECT';
  }
  const root = trivyRecordRoot(path);
  if (!root) return null;
  const suffix = path.slice(root.length);
  if (
    suffix.length === 1 &&
    [
      'VendorIDs',
      'CweIDs',
      'References',
      'Traces'
    ].includes(String(suffix[0]))
  ) {
    return 'ARRAY';
  }
  if (
    suffix.length === 1 &&
    [
      'PkgIdentifier',
      'Layer',
      'DataSource',
      'VendorSeverity',
      'CVSS',
      'CauseMetadata',
      'Code'
    ].includes(String(suffix[0]))
  ) {
    return 'OBJECT';
  }
  if (
    suffix.length === 2 &&
    suffix[0] === 'CauseMetadata' &&
    suffix[1] === 'Occurrences'
  ) {
    return 'ARRAY';
  }
  if (
    suffix.length === 2 &&
    suffix[0] === 'CauseMetadata' &&
    suffix[1] === 'RenderedCause'
  ) {
    return 'OBJECT';
  }
  return null;
}

function isExpectedTrivyScalarPath(path: JsonPath): boolean {
  if (
    matches(path, ['SchemaVersion']) ||
    matches(path, ['CreatedAt']) ||
    matches(path, ['ArtifactName']) ||
    matches(path, ['ArtifactType']) ||
    matches(path, ['Results', '*', 'Target']) ||
    matches(path, ['Results', '*', 'Class']) ||
    matches(path, ['Results', '*', 'Type']) ||
    matches(path, [
      'Results',
      '*',
      'ExperimentalModifiedFindings',
      '*',
      'Type'
    ]) ||
    matches(path, [
      'Results',
      '*',
      'ExperimentalModifiedFindings',
      '*',
      'Status'
    ]) ||
    matches(path, [
      'Results',
      '*',
      'ExperimentalModifiedFindings',
      '*',
      'Statement'
    ]) ||
    matches(path, [
      'Results',
      '*',
      'ExperimentalModifiedFindings',
      '*',
      'Source'
    ])
  ) {
    return true;
  }
  const root = trivyRecordRoot(path);
  if (!root) return false;
  const suffix = path.slice(root.length);
  if (
    suffix.length === 2 &&
    ['VendorIDs', 'CweIDs', 'References', 'Traces'].includes(
      String(suffix[0])
    ) &&
    typeof suffix[1] === 'number'
  ) {
    return true;
  }
  if (
    suffix.length === 2 &&
    ((suffix[0] === 'PkgIdentifier' &&
      ['UID', 'PURL', 'BOMRef'].includes(String(suffix[1]))) ||
      (suffix[0] === 'CauseMetadata' &&
        [
          'Resource',
          'Provider',
          'Service',
          'StartLine',
          'EndLine'
        ].includes(String(suffix[1]))))
  ) {
    return true;
  }
  return (
    suffix.length === 1 &&
    [
      'VulnerabilityID',
      'PkgID',
      'PkgName',
      'PkgPath',
      'InstalledVersion',
      'FixedVersion',
      'Status',
      'SeveritySource',
      'PrimaryURL',
      'Title',
      'Description',
      'Severity',
      'PublishedDate',
      'LastModifiedDate',
      'Type',
      'ID',
      'AVDID',
      'Message',
      'Namespace',
      'Query',
      'Resolution',
      'RuleID',
      'Category',
      'StartLine',
      'EndLine',
      'Match',
      'Offset'
    ].includes(String(suffix[0]))
  );
}

function keysForRecordKind(
  kind: TrivyRecordKind
): ReadonlySet<string> {
  return kind === 'VULNERABILITY'
    ? VULNERABILITY_KEYS
    : kind === 'MISCONFIGURATION'
      ? MISCONFIGURATION_KEYS
      : SECRET_KEYS;
}

function recordMatchesResult(
  kind: TrivyRecordKind,
  result: Readonly<TrivyResultState>
): boolean {
  return (
    (kind === 'VULNERABILITY' &&
      result.resultClass === 'lang-pkgs') ||
    (kind === 'MISCONFIGURATION' &&
      result.resultClass === 'config') ||
    (kind === 'SECRET' && result.resultClass === 'secret')
  );
}

function modifiedKind(
  value: string | undefined
): TrivyRecordKind | null {
  return value === 'vulnerability'
    ? 'VULNERABILITY'
    : value === 'misconfiguration'
      ? 'MISCONFIGURATION'
      : value === 'secret'
        ? 'SECRET'
        : null;
}

function directRecordArrayKind(
  path: JsonPath
): TrivyRecordKind | null {
  if (path.length !== 3 || path[0] !== 'Results') return null;
  return path[2] === 'Vulnerabilities'
    ? 'VULNERABILITY'
    : path[2] === 'Misconfigurations'
      ? 'MISCONFIGURATION'
      : path[2] === 'Secrets'
        ? 'SECRET'
        : null;
}

function directRecordKind(path: JsonPath): TrivyRecordKind | null {
  return path.length === 4 && typeof path[3] === 'number'
    ? directRecordArrayKind(path.slice(0, 3))
    : null;
}

function isTrivyResultPath(path: JsonPath): boolean {
  return (
    path.length === 2 &&
    path[0] === 'Results' &&
    typeof path[1] === 'number'
  );
}

function isModifiedFindingArrayPath(path: JsonPath): boolean {
  return matches(path, [
    'Results',
    '*',
    'ExperimentalModifiedFindings'
  ]);
}

function isModifiedFindingPath(path: JsonPath): boolean {
  return (
    path.length === 4 &&
    path[0] === 'Results' &&
    typeof path[1] === 'number' &&
    path[2] === 'ExperimentalModifiedFindings' &&
    typeof path[3] === 'number'
  );
}

function isModifiedFindingRecordPath(path: JsonPath): boolean {
  return (
    path.length === 5 &&
    isModifiedFindingPath(path.slice(0, 4)) &&
    path[4] === 'Finding'
  );
}

function isWithinModifiedFinding(path: JsonPath): boolean {
  return (
    path.length >= 4 &&
    isModifiedFindingPath(path.slice(0, 4))
  );
}

function trivyRecordRoot(path: JsonPath): JsonPath | null {
  if (
    path.length >= 4 &&
    directRecordKind(path.slice(0, 4))
  ) {
    return path.slice(0, 4);
  }
  if (
    path.length >= 5 &&
    isModifiedFindingRecordPath(path.slice(0, 5))
  ) {
    return path.slice(0, 5);
  }
  return null;
}

function matches(
  path: JsonPath,
  pattern: readonly (string | '*')[]
): boolean {
  return (
    path.length === pattern.length &&
    pattern.every(
      (segment, index) =>
        segment === '*' && typeof path[index] === 'number'
          ? true
          : path[index] === segment
    )
  );
}

function keyForPath(path: JsonPath): string {
  return JSON.stringify(path);
}

function compareCodeUnitStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
