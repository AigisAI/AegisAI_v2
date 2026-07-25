import { createHash } from 'node:crypto';
import { TextDecoder } from 'node:util';

import {
  OPENGREP_SARIF_NORMALIZER_VERSION,
  SAST_ARTIFACT_SCHEMA_VERSIONS,
  SAST_ARTIFACT_VALIDATION_LIMITS,
  SAST_MAX_COORDINATE_VALUE,
  SAST_NORMALIZATION_LIMITS,
  canonicalizeOpenGrepSarifNormalizationBatch,
  canonicalizeOpenGrepSarifNormalizationRejection,
  canonicalizeSastArtifactDispositionDecision,
  canonicalizeSastArtifactValidationResult,
  canonicalizeScannerArtifactEnvelope,
  compareSastNormalizationIdentifiers,
  compareSastNormalizedFindingCandidates,
  isOpenGrepSarifNormalizationBatchShapeValid,
  isSastArtifactDispositionDecisionShapeValid,
  isSastArtifactValidationResultShapeValid,
  isSastFindingLocationValid,
  isScannerArtifactEnvelopeBoundToPlan,
  orderSastNormalizationNotes,
  orderSastNormalizationRejectionReasons,
  type ExpectedScannerArtifactBinding,
  type OpenGrepSarifNormalizationBatchCore,
  type OpenGrepSarifNormalizationRejectionCore,
  type OpenGrepSarifNormalizationResult,
  type RuleBundleDescriptor,
  type SastArtifactDispositionDecision,
  type SastArtifactValidationReasonCode,
  type SastArtifactValidationResult,
  type SastFileCoordinateMetadata,
  type SastFindingLocation,
  type SastNormalizationNoteCode,
  type SastNormalizationRejectionReasonCode,
  type SastNormalizedFindingCandidate,
  type SastScanPlan,
  type ScannerArtifactEnvelope
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';
import { Tokenizer } from '@streamparser/json';

import {
  BoundedJsonStructureTracker,
  RawJsonTokenLimiter,
  decodeSarifArtifactUri,
  normalizeArtifactPath,
  type ArtifactValidationCallbacks,
  type ContainerKind,
  type JsonPath,
  type JsonPrimitive
} from './sast-artifact-stream-validator';
import type {
  SastFileCoordinateAttestation
} from './sast-file-coordinate-attestation.provider';

const OPENGREP_SARIF_SCHEMA =
  'https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json';
const OPENGREP_DRIVER_NAME = 'Opengrep OSS';
const OPENGREP_MATCH_ID_PROPERTY = 'matchBasedId/v1';
const STRUCTURAL_HASH_PREFIX = 'opengrep:matchBasedId/v1:';

const ROOT_KEYS = new Set(['$schema', 'runs', 'version']);
const RUN_KEYS = new Set(['invocations', 'results', 'tool']);
const TOOL_KEYS = new Set(['driver']);
const DRIVER_KEYS = new Set(['name', 'rules', 'semanticVersion']);
const RULE_KEYS = new Set([
  'defaultConfiguration',
  'fullDescription',
  'help',
  'helpUri',
  'id',
  'name',
  'properties',
  'shortDescription'
]);
const MULTIFORMAT_TEXT_KEYS = new Set(['text']);
const HELP_KEYS = new Set(['markdown', 'text']);
const RULE_CONFIGURATION_KEYS = new Set(['level']);
const RULE_PROPERTY_KEYS = new Set([
  'precision',
  'security-severity',
  'tags'
]);
const RESULT_KEYS = new Set([
  'codeFlows',
  'fingerprints',
  'fixes',
  'level',
  'locations',
  'message',
  'properties',
  'ruleId',
  'ruleIndex',
  'suppressions'
]);
const RESULT_MESSAGE_KEYS = new Set(['text']);
const RESULT_FINGERPRINT_KEYS = new Set([
  OPENGREP_MATCH_ID_PROPERTY
]);
const RESULT_PROPERTY_KEYS = new Set(['exposure']);
const LOCATION_KEYS = new Set(['physicalLocation']);
const PHYSICAL_LOCATION_KEYS = new Set([
  'artifactLocation',
  'region'
]);
const ARTIFACT_LOCATION_KEYS = new Set(['uri', 'uriBaseId']);
const REGION_KEYS = new Set([
  'endColumn',
  'endLine',
  'snippet',
  'startColumn',
  'startLine'
]);
const INVOCATION_KEYS = new Set([
  'executionSuccessful',
  'toolExecutionNotifications'
]);
const SARIF_LEVELS = new Set(['none', 'note', 'warning', 'error']);

interface RuleState {
  index: number;
  id?: string;
  name?: string;
  shortDescription?: string;
  level?: string;
  securitySeverity?: string | number;
  tagsSeen: boolean;
  tags: string[];
}

interface LocationState {
  index: number;
  uri?: string;
  uriBaseId?: string;
  startLine?: number;
  endLine?: number;
  startColumn?: number;
  endColumn?: number;
}

interface ResultState {
  index: number;
  ruleId?: string;
  ruleIndex?: number;
  level?: string;
  message?: string;
  scannerMatchBasedId?: string;
  locationsSeen: boolean;
  locationCount: number;
  locations: Map<number, LocationState>;
}

interface InvocationState {
  index: number;
  executionSuccessful?: boolean;
  notificationsSeen: boolean;
  notificationCount: number;
}

interface ParsedOpenGrepSarif {
  rules: RuleState[];
  results: ResultState[];
}

interface NormalizedText {
  value?: string;
  reason?: Extract<
    SastNormalizationRejectionReasonCode,
    'NORMALIZATION_TEXT_INVALID' | 'NORMALIZATION_FIELD_LIMIT_EXCEEDED'
  >;
}

export interface OpenGrepSarifNormalizationInput {
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
export class OpenGrepSarifNormalizer {
  async normalize(
    input: Readonly<OpenGrepSarifNormalizationInput>,
    artifact: AsyncIterable<Uint8Array>,
    referenceClock: () => Date = () => new Date()
  ): Promise<OpenGrepSarifNormalizationResult> {
    const binding = this.validateBinding(
      input,
      readReferenceTime(referenceClock)
    );
    if (binding.reasons.size > 0 || !binding.ruleBundle) {
      return this.reject(input.ingestionId, binding.reasons);
    }

    const coordinates = this.loadCoordinates(
      input.coordinateAttestation,
      input
    );
    const stream = new OpenGrepSarifStreamSession(
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
    const core: OpenGrepSarifNormalizationBatchCore = {
      version: OPENGREP_SARIF_NORMALIZER_VERSION,
      adapterVersion: OPENGREP_SARIF_NORMALIZER_VERSION,
      artifactSchema: 'OPENGREP_SARIF',
      artifactSchemaVersion:
        SAST_ARTIFACT_SCHEMA_VERSIONS.OPENGREP_SARIF,
      ingestionId: input.ingestionId,
      scope,
      scannerRunId: input.envelope.scannerRunId,
      scanner: 'OPENGREP',
      scannerVersion: input.envelope.scannerVersion,
      scannerImageDigest: input.envelope.scannerImageDigest,
      ruleBundleDigest: binding.ruleBundle.digest,
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
        canonicalizeOpenGrepSarifNormalizationBatch(core)
      )
    };
    if (!isOpenGrepSarifNormalizationBatchShapeValid(batch)) {
      binding.reasons.add('NORMALIZATION_OPENGREP_RESULT_INVALID');
      return this.reject(input.ingestionId, binding.reasons);
    }
    return { outcome: 'NORMALIZED', batch };
  }

  private validateBinding(
    input: Readonly<OpenGrepSarifNormalizationInput>,
    referenceTime: Readonly<Date>
  ): {
    reasons: Set<SastNormalizationRejectionReasonCode>;
    ruleBundle: RuleBundleDescriptor | null;
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
    } catch {
      // Shape and binding reasons below remain the only observable metadata.
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

    if (
      envelopeDigest !== input.envelopeDigest ||
      !isScannerArtifactEnvelopeBoundToPlan(
        input.envelope,
        input.plan,
        input.expectedBinding
      ) ||
      input.envelope.scanner !== 'OPENGREP' ||
      input.envelope.artifactSchema !== 'OPENGREP_SARIF' ||
      input.envelope.artifactSchemaVersion !==
        SAST_ARTIFACT_SCHEMA_VERSIONS.OPENGREP_SARIF
    ) {
      reasons.add('NORMALIZATION_PLAN_BINDING_MISMATCH');
    }

    if (
      !validationShapeValid ||
      validationDigest !== input.validation.resultDigest ||
      input.validation.outcome !== 'PASSED' ||
      input.validation.artifactSchema !== 'OPENGREP_SARIF' ||
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

    const matchingBundles = input.plan.scannerSet.ruleBundles.filter(
      (bundle) =>
        bundle.scanner === 'OPENGREP' &&
        bundle.digest === input.envelope.ruleBundleDigest
    );
    if (matchingBundles.length !== 1) {
      reasons.add('NORMALIZATION_PLAN_BINDING_MISMATCH');
    }

    return {
      reasons,
      ruleBundle: matchingBundles[0] ?? null,
      startedAtMilliseconds
    };
  }

  private validateReferenceTime(
    disposition: Readonly<SastArtifactDispositionDecision>,
    referenceTime: Readonly<Date>,
    reasons: Set<SastNormalizationRejectionReasonCode>
  ): number {
    const referenceTimeMilliseconds =
      referenceTime instanceof Date
        ? referenceTime.getTime()
        : Number.NaN;
    const decidedAtMilliseconds = Date.parse(disposition.decidedAt);
    if (
      !Number.isFinite(referenceTimeMilliseconds) ||
      referenceTimeMilliseconds < decidedAtMilliseconds
    ) {
      reasons.add('NORMALIZATION_ACCEPTANCE_INVALID');
    }
    if (
      !Number.isFinite(referenceTimeMilliseconds) ||
      !disposition.retentionExpiresAt ||
      referenceTimeMilliseconds >=
        Date.parse(disposition.retentionExpiresAt)
    ) {
      reasons.add('NORMALIZATION_RETENTION_EXPIRED');
    }
    return referenceTimeMilliseconds;
  }

  private loadCoordinates(
    attestation: Readonly<SastFileCoordinateAttestation> | null,
    input: Readonly<OpenGrepSarifNormalizationInput>
  ): ReadonlyMap<string, Readonly<SastFileCoordinateMetadata>> | null {
    if (
      !attestation ||
      attestation.verified !== true ||
      attestation.attestationRef !==
        input.expectedBinding.preflightAttestationRef ||
      attestation.inventoryDigest !==
        input.expectedBinding.preflightInventoryDigest ||
      !Array.isArray(attestation.files) ||
      attestation.files.length >
        input.plan.profile.limits.maxFileCount
    ) {
      return null;
    }

    const coordinates = new Map<
      string,
      Readonly<SastFileCoordinateMetadata>
    >();
    const foldedPaths = new Set<string>();
    let totalLines = 0;
    for (const rawFile of attestation.files as readonly unknown[]) {
      if (
        !rawFile ||
        typeof rawFile !== 'object' ||
        Array.isArray(rawFile) ||
        !hasExactObjectKeys(rawFile, [
          'normalizedPath',
          'lineCount',
          'maxColumnByLine'
        ])
      ) {
        return null;
      }
      const file = rawFile as Record<string, unknown>;
      const normalizedPath = normalizeArtifactPath(
        file.normalizedPath,
        input.plan.profile.limits.maxPathDepth
      );
      const foldedPath = normalizedPath
        ?.toLocaleLowerCase('en-US')
        .normalize('NFC');
      const lineCount = file.lineCount;
      if (
        !normalizedPath ||
        normalizedPath !== file.normalizedPath ||
        !foldedPath ||
        foldedPaths.has(foldedPath) ||
        typeof lineCount !== 'number' ||
        !Number.isSafeInteger(lineCount) ||
        lineCount <= 0 ||
        lineCount > SAST_MAX_COORDINATE_VALUE ||
        lineCount >
          SAST_ARTIFACT_VALIDATION_LIMITS
            .maximumCoordinateAttestationLines -
            totalLines ||
        coordinates.has(normalizedPath) ||
        !Array.isArray(file.maxColumnByLine) ||
        file.maxColumnByLine.length !== lineCount ||
        !file.maxColumnByLine.every(
          (column: unknown) =>
            typeof column === 'number' &&
            Number.isSafeInteger(column) &&
            column > 0 &&
            column <= SAST_MAX_COORDINATE_VALUE
        )
      ) {
        return null;
      }
      totalLines += lineCount;
      foldedPaths.add(foldedPath);
      coordinates.set(normalizedPath, {
        normalizedPath,
        lineCount,
        maxColumnByLine: file.maxColumnByLine
      });
    }
    return coordinates;
  }

  private buildCandidates(
    parsed: Readonly<ParsedOpenGrepSarif>,
    input: Readonly<OpenGrepSarifNormalizationInput>,
    ruleBundle: Readonly<RuleBundleDescriptor>,
    coordinates:
      | ReadonlyMap<string, Readonly<SastFileCoordinateMetadata>>
      | null,
    reasons: Set<SastNormalizationRejectionReasonCode>
  ): SastNormalizedFindingCandidate[] | null {
    const rulesById = new Map<string, RuleState>();
    const rulesByIndex = new Map<number, RuleState>();
    for (const rule of parsed.rules) {
      const ruleId = normalizeIdentifier(
        rule.id,
        SAST_NORMALIZATION_LIMITS.ruleIdBytes
      );
      if (!ruleId || rulesById.has(ruleId)) {
        reasons.add('NORMALIZATION_OPENGREP_RULE_INVALID');
        continue;
      }
      if (rule.name !== undefined && rule.name !== ruleId) {
        reasons.add('NORMALIZATION_OPENGREP_RULE_INVALID');
      }
      if (
        rule.level !== undefined &&
        !SARIF_LEVELS.has(rule.level)
      ) {
        reasons.add('NORMALIZATION_OPENGREP_RULE_INVALID');
      }
      if (!isSecuritySeverityValid(rule.securitySeverity)) {
        reasons.add('NORMALIZATION_OPENGREP_RULE_INVALID');
      }
      rulesById.set(ruleId, { ...rule, id: ruleId });
      rulesByIndex.set(rule.index, { ...rule, id: ruleId });
    }

    const ruleRevision = normalizeIdentifier(
      ruleBundle.version,
      SAST_NORMALIZATION_LIMITS.ruleRevisionBytes
    );
    if (!ruleRevision) {
      reasons.add('NORMALIZATION_IDENTIFIER_LIMIT_EXCEEDED');
    }

    const candidates: SastNormalizedFindingCandidate[] = [];
    const identityKeys = new Set<string>();
    for (const result of parsed.results) {
      const ruleId = normalizeIdentifier(
        result.ruleId,
        SAST_NORMALIZATION_LIMITS.ruleIdBytes
      );
      const rule = ruleId ? rulesById.get(ruleId) : undefined;
      const indexedRule =
        result.ruleIndex === undefined
          ? undefined
          : rulesByIndex.get(result.ruleIndex);
      if (
        !ruleId ||
        !rule ||
        (result.ruleIndex !== undefined &&
          (!indexedRule || indexedRule.id !== ruleId)) ||
        !ruleRevision
      ) {
        reasons.add('NORMALIZATION_OPENGREP_RESULT_INVALID');
        continue;
      }
      if (
        result.level !== undefined &&
        !SARIF_LEVELS.has(result.level)
      ) {
        reasons.add('NORMALIZATION_OPENGREP_RESULT_INVALID');
        continue;
      }

      const title = normalizeTitle(
        rule.shortDescription ??
          `Opengrep Finding: ${ruleId}`
      );
      const description = normalizeDescription(result.message);
      if (!title.value || !description.value) {
        if (title.reason) reasons.add(title.reason);
        if (description.reason) reasons.add(description.reason);
        continue;
      }

      const scannerMatchBasedId = normalizeIdentityHint(
        result.scannerMatchBasedId
      );
      const structuralHash = scannerMatchBasedId
        ? digest(`${STRUCTURAL_HASH_PREFIX}${scannerMatchBasedId}`)
        : null;
      if (
        !scannerMatchBasedId ||
        !structuralHash ||
        utf8Bytes(structuralHash) >
          SAST_NORMALIZATION_LIMITS.scannerIdentityHintBytes
      ) {
        reasons.add('NORMALIZATION_OPENGREP_RESULT_INVALID');
        continue;
      }

      const identifiers = extractIdentifiers(rule.tags, reasons);
      const confidence = mapConfidence(rule.tags, reasons);
      const severity = mapSeverity(
        result.level ?? rule.level,
        rule.securitySeverity
      );
      if (!identifiers || !confidence || !severity) continue;

      const notes = new Set<SastNormalizationNoteCode>();
      if (severity.unknown) notes.add('UNKNOWN_SEVERITY');
      if (confidence.value === 'UNKNOWN') {
        notes.add('UNKNOWN_CONFIDENCE');
      }
      const location = normalizeLocation(
        result,
        input.plan.profile.limits.maxPathDepth,
        coordinates,
        reasons
      );
      if (!location) continue;

      const identityKey = JSON.stringify([
        ruleId,
        scannerMatchBasedId,
        location
      ]);
      if (identityKeys.has(identityKey)) {
        reasons.add('NORMALIZATION_OPENGREP_RESULT_INVALID');
        continue;
      }
      identityKeys.add(identityKey);

      candidates.push({
        tenantId: input.envelope.tenantId,
        repositoryBindingId: input.envelope.repositoryBindingId,
        scanRequestId: input.envelope.scanRequestId,
        attemptId: input.envelope.attemptId,
        scannerRunId: input.envelope.scannerRunId,
        commitSha: input.plan.repositoryState.fixedCommitSha,
        lane: input.plan.profile.lane,
        capability: 'SAST',
        title: title.value,
        description: description.value,
        severity: severity.value,
        confidence: confidence.value,
        cweIds: identifiers.cweIds,
        cveIds: identifiers.cveIds,
        location,
        identityMaterial: {
          ruleSemanticId: ruleId,
          symbolAnchor: '',
          sinkKind: '',
          structuralHash,
          scannerMatchBasedId
        },
        provenance: {
          scanner: 'OPENGREP',
          scannerVersion: input.envelope.scannerVersion,
          scannerImageDigest: input.envelope.scannerImageDigest,
          ruleId,
          ruleRevision,
          ruleBundleDigest: ruleBundle.digest,
          artifactDigest: input.envelope.contentDigest
        },
        notes: orderSastNormalizationNotes(notes),
        durablePersistenceAllowed: false
      });
    }

    if (reasons.size > 0) return null;
    return candidates.sort(compareSastNormalizedFindingCandidates);
  }

  private reject(
    ingestionId: string,
    reasons: Iterable<SastNormalizationRejectionReasonCode>
  ): OpenGrepSarifNormalizationResult {
    const core: OpenGrepSarifNormalizationRejectionCore = {
      version: OPENGREP_SARIF_NORMALIZER_VERSION,
      adapterVersion: OPENGREP_SARIF_NORMALIZER_VERSION,
      outcome: 'REJECTED',
      ingestionId,
      reasonCodes: orderSastNormalizationRejectionReasons(reasons)
    };
    return {
      ...core,
      rejectionDigest: digest(
        canonicalizeOpenGrepSarifNormalizationRejection(core)
      )
    };
  }
}

class OpenGrepSarifStreamSession {
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
  private readonly collector: OpenGrepSarifCollector;
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
    this.collector = new OpenGrepSarifCollector(
      plan.profile.limits.maxArtifactRecords,
      plan.profile.limits.maxFindings,
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
  ): Promise<ParsedOpenGrepSarif | null> {
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
      this.collector.resultCount !== this.envelope.recordCount
    ) {
      this.reasons.add('NORMALIZATION_VALIDATION_BINDING_MISMATCH');
    }
    if (this.reasons.size > 0) return null;
    return this.collector.finish(this.envelope);
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

class OpenGrepSarifCollector
  implements ArtifactValidationCallbacks
{
  private rootKind?: ContainerKind;
  private schema?: string;
  private version?: string;
  private runsSeen = false;
  private readonly runIndexes = new Set<number>();
  private driverName?: string;
  private driverVersion?: string;
  private rulesSeen = false;
  private resultsSeen = false;
  private invocationsSeen = false;
  private readonly rules = new Map<number, RuleState>();
  private readonly results = new Map<number, ResultState>();
  private readonly invocations = new Map<number, InvocationState>();
  resultCount = 0;

  constructor(
    private readonly maximumRules: number,
    private readonly maximumResults: number,
    private readonly reasons:
      Set<SastNormalizationRejectionReasonCode>
  ) {}

  onContainer(path: JsonPath, kind: ContainerKind): void {
    if (path.length === 0) {
      this.rootKind = kind;
      if (kind !== 'OBJECT') this.structureInvalid();
      return;
    }
    if (isExpectedScalarPath(path)) {
      this.reasonForObject(path);
    }
    if (isRuleTagItemPath(path)) {
      this.ruleInvalid();
    }
    const expectedKind = expectedContainerKind(path);
    if (expectedKind && kind !== expectedKind) {
      this.reasonForObject(path);
    }
    if (matches(path, ['runs'])) {
      this.runsSeen = true;
      if (kind !== 'ARRAY') this.structureInvalid();
    } else if (isRunPath(path)) {
      if (kind !== 'OBJECT') this.structureInvalid();
      if (this.runIndexes.size >= 2) {
        this.structureInvalid();
      } else {
        this.runIndexes.add(path[1] as number);
      }
    } else if (matches(path, ['runs', '*', 'tool'])) {
      if (kind !== 'OBJECT') this.structureInvalid();
    } else if (
      matches(path, ['runs', '*', 'tool', 'driver'])
    ) {
      if (kind !== 'OBJECT') this.driverInvalid();
    } else if (
      matches(path, ['runs', '*', 'tool', 'driver', 'rules'])
    ) {
      this.rulesSeen = true;
      if (kind !== 'ARRAY') this.driverInvalid();
    } else if (isRulePath(path)) {
      if (kind !== 'OBJECT') {
        this.ruleInvalid();
      } else {
        const index = path[5] as number;
        if (
          this.rules.size >= this.maximumRules ||
          this.rules.has(index)
        ) {
          this.ruleInvalid();
        } else {
          this.rules.set(index, {
            index,
            tagsSeen: false,
            tags: []
          });
        }
      }
    } else if (
      matches(path, [
        'runs',
        '*',
        'tool',
        'driver',
        'rules',
        '*',
        'properties',
        'tags'
      ])
    ) {
      const rule = this.ruleFor(path);
      if (rule) rule.tagsSeen = true;
      if (kind !== 'ARRAY') this.ruleInvalid();
    } else if (
      matches(path, ['runs', '*', 'results'])
    ) {
      this.resultsSeen = true;
      if (kind !== 'ARRAY') this.structureInvalid();
    } else if (isResultPath(path)) {
      if (kind !== 'OBJECT') {
        this.resultInvalid();
      } else {
        const index = path[3] as number;
        this.resultCount += 1;
        if (
          this.results.size >= this.maximumResults ||
          this.results.has(index)
        ) {
          this.resultInvalid();
        } else {
          this.results.set(index, {
            index,
            locationsSeen: false,
            locationCount: 0,
            locations: new Map()
          });
        }
      }
    } else if (
      matches(path, ['runs', '*', 'results', '*', 'locations'])
    ) {
      const result = this.resultFor(path);
      if (result) result.locationsSeen = true;
      if (kind !== 'ARRAY') this.locationInvalid();
    } else if (isPrimaryLocationPath(path)) {
      if (kind !== 'OBJECT') {
        this.locationInvalid();
      } else {
        const result = this.resultFor(path);
        const index = path[5] as number;
        if (!result || result.locations.has(index)) {
          this.locationInvalid();
        } else if (result.locationCount >= 1) {
          result.locationCount = 2;
          this.resultInvalid();
          this.locationInvalid();
        } else {
          result.locationCount += 1;
          result.locations.set(index, { index });
        }
      }
    } else if (
      matches(path, ['runs', '*', 'invocations'])
    ) {
      this.invocationsSeen = true;
      if (kind !== 'ARRAY') this.invocationInvalid();
    } else if (isInvocationPath(path)) {
      if (kind !== 'OBJECT') {
        this.invocationInvalid();
      } else {
        const index = path[3] as number;
        if (
          this.invocations.has(index) ||
          this.invocations.size >= 2
        ) {
          this.invocationInvalid();
        } else {
          this.invocations.set(index, {
            index,
            notificationsSeen: false,
            notificationCount: 0
          });
        }
      }
    } else if (
      matches(path, [
        'runs',
        '*',
        'invocations',
        '*',
        'toolExecutionNotifications'
      ])
    ) {
      const invocation = this.invocationFor(path);
      if (invocation) invocation.notificationsSeen = true;
      if (kind !== 'ARRAY') this.invocationInvalid();
    } else if (isNotificationPath(path)) {
      const invocation = this.invocationFor(path);
      if (invocation) invocation.notificationCount += 1;
      this.invocationInvalid();
    }
  }

  onContainerEnd(): void {}

  onKey(objectPath: JsonPath, key: string): void {
    const allowed = allowedKeys(objectPath);
    if (allowed && !allowed.has(key)) {
      this.reasonForObject(objectPath);
    }
  }

  onPrimitive(path: JsonPath, value: JsonPrimitive): void {
    if (isExpectedContainerPath(path)) {
      this.reasonForObject(path);
      return;
    }
    if (
      matches(path, ['$schema']) ||
      matches(path, ['version'])
    ) {
      if (typeof value !== 'string') {
        this.structureInvalid();
      } else if (path[0] === '$schema') {
        this.schema = value;
      } else {
        this.version = value;
      }
      return;
    }
    if (
      matches(path, ['runs', '*', 'tool', 'driver', 'name'])
    ) {
      if (typeof value !== 'string') this.driverInvalid();
      else this.driverName = value;
      return;
    }
    if (
      matches(path, [
        'runs',
        '*',
        'tool',
        'driver',
        'semanticVersion'
      ])
    ) {
      if (typeof value !== 'string') this.driverInvalid();
      else this.driverVersion = value;
      return;
    }

    const rule = this.ruleFor(path);
    if (rule) {
      this.captureRuleValue(rule, path, value);
      return;
    }
    const result = this.resultFor(path);
    if (result) {
      this.captureResultValue(result, path, value);
      return;
    }
    const invocation = this.invocationFor(path);
    if (invocation) {
      if (
        path.at(-1) === 'executionSuccessful' &&
        typeof value === 'boolean'
      ) {
        invocation.executionSuccessful = value;
      } else if (path.at(-1) === 'executionSuccessful') {
        this.invocationInvalid();
      }
    }
  }

  finish(
    envelope: Readonly<ScannerArtifactEnvelope>
  ): ParsedOpenGrepSarif | null {
    if (
      this.rootKind !== 'OBJECT' ||
      !this.runsSeen ||
      this.runIndexes.size !== 1 ||
      !this.runIndexes.has(0) ||
      this.schema !== OPENGREP_SARIF_SCHEMA ||
      this.version !==
        SAST_ARTIFACT_SCHEMA_VERSIONS.OPENGREP_SARIF ||
      !this.rulesSeen ||
      !this.resultsSeen
    ) {
      this.structureInvalid();
    }
    if (
      this.driverName !== OPENGREP_DRIVER_NAME ||
      this.driverVersion !== envelope.scannerVersion
    ) {
      this.driverInvalid();
    }
    if (
      !this.invocationsSeen ||
      this.invocations.size !== 1 ||
      !this.invocations.has(0)
    ) {
      this.invocationInvalid();
    }
    for (const invocation of this.invocations.values()) {
      if (
        invocation.executionSuccessful !== true ||
        !invocation.notificationsSeen ||
        invocation.notificationCount !== 0
      ) {
        this.invocationInvalid();
      }
    }
    for (const rule of this.rules.values()) {
      if (!rule.id || !rule.tagsSeen) this.ruleInvalid();
    }
    for (const result of this.results.values()) {
      if (
        !result.ruleId ||
        !result.message ||
        !result.scannerMatchBasedId ||
        result.locationCount > 1
      ) {
        this.resultInvalid();
      }
      if (result.locationCount > 1) this.locationInvalid();
    }
    if (this.reasons.size > 0) return null;
    return {
      rules: [...this.rules.values()].sort(
        (left, right) => left.index - right.index
      ),
      results: [...this.results.values()].sort(
        (left, right) => left.index - right.index
      )
    };
  }

  private captureRuleValue(
    rule: RuleState,
    path: JsonPath,
    value: JsonPrimitive
  ): void {
    const suffix = path.slice(6);
    if (matches(suffix, ['id'])) {
      if (typeof value === 'string') rule.id = value;
      else this.ruleInvalid();
    } else if (matches(suffix, ['name'])) {
      if (typeof value === 'string') rule.name = value;
      else this.ruleInvalid();
    } else if (
      matches(suffix, ['shortDescription', 'text'])
    ) {
      if (typeof value === 'string') {
        rule.shortDescription = value;
      } else {
        this.ruleInvalid();
      }
    } else if (
      matches(suffix, ['defaultConfiguration', 'level'])
    ) {
      if (typeof value === 'string') rule.level = value;
      else this.ruleInvalid();
    } else if (
      matches(suffix, ['properties', 'security-severity'])
    ) {
      if (
        typeof value === 'string' ||
        typeof value === 'number'
      ) {
        rule.securitySeverity = value;
      } else {
        this.ruleInvalid();
      }
    } else if (
      suffix.length === 3 &&
      suffix[0] === 'properties' &&
      suffix[1] === 'tags' &&
      typeof suffix[2] === 'number'
    ) {
      if (
        typeof value !== 'string' ||
        rule.tags.length >=
          SAST_NORMALIZATION_LIMITS.maximumRuleTags
      ) {
        this.ruleInvalid();
      } else {
        rule.tags.push(value);
      }
    }
  }

  private captureResultValue(
    result: ResultState,
    path: JsonPath,
    value: JsonPrimitive
  ): void {
    const suffix = path.slice(4);
    if (matches(suffix, ['ruleId'])) {
      if (typeof value === 'string') result.ruleId = value;
      else this.resultInvalid();
    } else if (matches(suffix, ['ruleIndex'])) {
      if (
        typeof value === 'number' &&
        Number.isSafeInteger(value) &&
        value >= 0
      ) {
        result.ruleIndex = value;
      } else {
        this.resultInvalid();
      }
    } else if (matches(suffix, ['level'])) {
      if (typeof value === 'string') result.level = value;
      else this.resultInvalid();
    } else if (matches(suffix, ['message', 'text'])) {
      if (typeof value === 'string') result.message = value;
      else this.resultInvalid();
    } else if (
      matches(suffix, [
        'fingerprints',
        OPENGREP_MATCH_ID_PROPERTY
      ])
    ) {
      if (typeof value === 'string') {
        result.scannerMatchBasedId = value;
      } else {
        this.resultInvalid();
      }
    }

    const location = this.locationFor(path);
    if (!location) return;
    const key = path.at(-1);
    if (key === 'uri') {
      if (typeof value === 'string') location.uri = value;
      else this.locationInvalid();
    } else if (key === 'uriBaseId') {
      if (typeof value === 'string') location.uriBaseId = value;
      else this.locationInvalid();
    } else if (
      ['startLine', 'endLine', 'startColumn', 'endColumn'].includes(
        String(key)
      )
    ) {
      if (
        typeof value !== 'number' ||
        !Number.isSafeInteger(value) ||
        value <= 0
      ) {
        this.locationInvalid();
      } else if (key === 'startLine') {
        location.startLine = value;
      } else if (key === 'endLine') {
        location.endLine = value;
      } else if (key === 'startColumn') {
        location.startColumn = value;
      } else {
        location.endColumn = value;
      }
    }
  }

  private ruleFor(path: JsonPath): RuleState | undefined {
    return isWithinRule(path)
      ? this.rules.get(path[5] as number)
      : undefined;
  }

  private resultFor(path: JsonPath): ResultState | undefined {
    return isWithinResult(path)
      ? this.results.get(path[3] as number)
      : undefined;
  }

  private invocationFor(
    path: JsonPath
  ): InvocationState | undefined {
    return isWithinInvocation(path)
      ? this.invocations.get(path[3] as number)
      : undefined;
  }

  private locationFor(path: JsonPath): LocationState | undefined {
    if (
      path.length < 6 ||
      !isWithinResult(path) ||
      path[4] !== 'locations' ||
      typeof path[5] !== 'number'
    ) {
      return undefined;
    }
    return this.results
      .get(path[3] as number)
      ?.locations.get(path[5]);
  }

  private reasonForObject(path: JsonPath): void {
    if (isWithinPrimaryLocation(path)) this.locationInvalid();
    else if (isWithinRule(path)) this.ruleInvalid();
    else if (isWithinResult(path)) this.resultInvalid();
    else if (isWithinInvocation(path)) this.invocationInvalid();
    else if (path.includes('driver')) this.driverInvalid();
    else this.structureInvalid();
  }

  private structureInvalid(): void {
    this.reasons.add('NORMALIZATION_OPENGREP_STRUCTURE_INVALID');
  }

  private driverInvalid(): void {
    this.reasons.add('NORMALIZATION_OPENGREP_DRIVER_INVALID');
  }

  private invocationInvalid(): void {
    this.reasons.add('NORMALIZATION_OPENGREP_INVOCATION_INVALID');
  }

  private ruleInvalid(): void {
    this.reasons.add('NORMALIZATION_OPENGREP_RULE_INVALID');
  }

  private resultInvalid(): void {
    this.reasons.add('NORMALIZATION_OPENGREP_RESULT_INVALID');
  }

  private locationInvalid(): void {
    this.reasons.add('NORMALIZATION_OPENGREP_LOCATION_INVALID');
  }
}

function normalizeLocation(
  result: Readonly<ResultState>,
  maximumDepth: number,
  coordinates:
    | ReadonlyMap<string, Readonly<SastFileCoordinateMetadata>>
    | null,
  reasons: Set<SastNormalizationRejectionReasonCode>
): SastFindingLocation | null {
  if (!result.locationsSeen || result.locations.size === 0) {
    return {
      kind: 'UNKNOWN',
      reasonCode: 'SCANNER_LOCATION_OMITTED'
    };
  }
  if (result.locations.size !== 1) {
    reasons.add('NORMALIZATION_OPENGREP_LOCATION_INVALID');
    return null;
  }
  const raw = result.locations.get(0);
  if (
    !raw
  ) {
    return {
      kind: 'UNKNOWN',
      reasonCode: 'LOCATION_NOT_MAPPABLE'
    };
  }
  if (raw.uriBaseId !== '%SRCROOT%') {
    reasons.add('NORMALIZATION_OPENGREP_LOCATION_INVALID');
    return null;
  }
  if (!raw.uri || !raw.startLine) {
    return {
      kind: 'UNKNOWN',
      reasonCode: 'LOCATION_NOT_MAPPABLE'
    };
  }
  const decoded = decodeSarifArtifactUri(raw.uri);
  const normalizedPath = decoded
    ? normalizeArtifactPath(decoded, maximumDepth)
    : null;
  const metadata = normalizedPath
    ? coordinates?.get(normalizedPath)
    : undefined;
  if (!normalizedPath || !metadata) {
    return {
      kind: 'UNKNOWN',
      reasonCode: 'LOCATION_NOT_MAPPABLE'
    };
  }
  const location: SastFindingLocation = {
    kind: 'FILE',
    normalizedPath,
    lineStart: raw.startLine,
    lineEnd: raw.endLine ?? raw.startLine,
    columnStart: raw.startColumn ?? 1,
    ...(raw.endColumn === undefined
      ? {}
      : { columnEnd: raw.endColumn })
  };
  if (!isSastFindingLocationValid(location, metadata)) {
    reasons.add('NORMALIZATION_OPENGREP_LOCATION_INVALID');
    return null;
  }
  return location;
}

function mapSeverity(
  level: string | undefined,
  securitySeverity: string | number | undefined
):
  | {
      value: SastNormalizedFindingCandidate['severity'];
      unknown: boolean;
    }
  | null {
  if (!isSecuritySeverityValid(securitySeverity)) return null;
  if (securitySeverity !== undefined) {
    const score = Number(securitySeverity);
    return {
      value:
        score >= 9
          ? 'CRITICAL'
          : score >= 7
            ? 'HIGH'
            : score >= 4
              ? 'MEDIUM'
              : score > 0
                ? 'LOW'
                : 'INFO',
      unknown: false
    };
  }
  if (level === undefined) {
    return { value: 'INFO', unknown: true };
  }
  if (!SARIF_LEVELS.has(level)) return null;
  return {
    value:
      level === 'error'
        ? 'HIGH'
        : level === 'warning'
          ? 'MEDIUM'
          : level === 'note'
            ? 'LOW'
            : 'INFO',
    unknown: false
  };
}

function mapConfidence(
  tags: readonly string[],
  reasons: Set<SastNormalizationRejectionReasonCode>
):
  | { value: SastNormalizedFindingCandidate['confidence'] }
  | null {
  const values = new Set<'HIGH' | 'MEDIUM' | 'LOW'>();
  for (const tag of tags) {
    const match = /^(HIGH|MEDIUM|LOW) CONFIDENCE$/iu.exec(tag.trim());
    if (match) values.add(match[1]!.toUpperCase() as 'HIGH' | 'MEDIUM' | 'LOW');
  }
  if (values.size > 1) {
    reasons.add('NORMALIZATION_OPENGREP_RULE_INVALID');
    return null;
  }
  return { value: [...values][0] ?? 'UNKNOWN' };
}

function extractIdentifiers(
  tags: readonly string[],
  reasons: Set<SastNormalizationRejectionReasonCode>
): { cweIds: string[]; cveIds: string[] } | null {
  const cweIds = new Set<string>();
  const cveIds = new Set<string>();
  for (const rawTag of tags) {
    const tag = rawTag.trim();
    const cwe = /^(CWE-[1-9][0-9]{0,9})(?::|\s|$)/iu.exec(tag);
    const cve = /^(CVE-[0-9]{4}-[0-9]{4,})(?::|\s|$)/iu.exec(tag);
    if (
      cwe &&
      utf8Bytes(cwe[1]!) <=
        SAST_NORMALIZATION_LIMITS.vulnerabilityIdentifierBytes
    ) {
      cweIds.add(cwe[1]!.toUpperCase());
    } else if (cwe) {
      reasons.add('NORMALIZATION_IDENTIFIER_LIMIT_EXCEEDED');
    } else if (/^CWE-/iu.test(tag)) {
      reasons.add('NORMALIZATION_IDENTIFIER_LIMIT_EXCEEDED');
    }
    if (
      cve &&
      utf8Bytes(cve[1]!) <=
        SAST_NORMALIZATION_LIMITS.vulnerabilityIdentifierBytes
    ) {
      cveIds.add(cve[1]!.toUpperCase());
    } else if (cve) {
      reasons.add('NORMALIZATION_IDENTIFIER_LIMIT_EXCEEDED');
    } else if (/^CVE-/iu.test(tag)) {
      reasons.add('NORMALIZATION_IDENTIFIER_LIMIT_EXCEEDED');
    }
  }
  if (
    cweIds.size > SAST_NORMALIZATION_LIMITS.maximumCweIds ||
    cveIds.size > SAST_NORMALIZATION_LIMITS.maximumCveIds
  ) {
    reasons.add('NORMALIZATION_IDENTIFIER_LIMIT_EXCEEDED');
    return null;
  }
  return {
    cweIds: [...cweIds].sort(compareIdentifiers),
    cveIds: [...cveIds].sort(compareIdentifiers)
  };
}

function normalizeTitle(value: string | undefined): NormalizedText {
  if (value === undefined) {
    return { reason: 'NORMALIZATION_TEXT_INVALID' };
  }
  const normalized = normalizePlainText(value)
    ?.replace(/[\t\n]+/gu, ' ')
    .replace(/ {2,}/gu, ' ')
    .trim();
  if (!normalized) {
    return { reason: 'NORMALIZATION_TEXT_INVALID' };
  }
  if (
    utf8Bytes(normalized) > SAST_NORMALIZATION_LIMITS.titleBytes
  ) {
    return { reason: 'NORMALIZATION_FIELD_LIMIT_EXCEEDED' };
  }
  return { value: normalized };
}

function normalizeDescription(
  value: string | undefined
): NormalizedText {
  const normalized =
    value === undefined ? null : normalizePlainText(value)?.trim();
  if (!normalized) {
    return { reason: 'NORMALIZATION_TEXT_INVALID' };
  }
  if (
    utf8Bytes(normalized) >
    SAST_NORMALIZATION_LIMITS.descriptionBytes
  ) {
    return { reason: 'NORMALIZATION_FIELD_LIMIT_EXCEEDED' };
  }
  return { value: normalized };
}

function normalizePlainText(value: string): string | null {
  const normalized = value
    .replace(/\r\n?/gu, '\n')
    .normalize('NFC');
  return [...normalized].some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return (
      (codePoint <= 0x1f &&
        codePoint !== 0x09 &&
        codePoint !== 0x0a) ||
      (codePoint >= 0x7f && codePoint <= 0x9f) ||
      (codePoint >= 0xd800 && codePoint <= 0xdfff)
    );
  })
    ? null
    : normalized;
}

function normalizeIdentifier(
  value: string | undefined,
  maximumBytes: number
): string | null {
  if (value === undefined) return null;
  const normalized = value.normalize('NFC');
  return normalized.length > 0 &&
    normalized === normalized.trim() &&
    utf8Bytes(normalized) <= maximumBytes &&
    !hasUnsafeControls(normalized)
    ? normalized
    : null;
}

function normalizeIdentityHint(
  value: string | undefined
): string | null {
  const normalized = normalizeIdentifier(
    value,
    SAST_NORMALIZATION_LIMITS.scannerIdentityHintBytes
  );
  return normalized &&
    /^[A-Za-z0-9][A-Za-z0-9._:+/-]*$/u.test(normalized)
    ? normalized
    : null;
}

function isSecuritySeverityValid(
  value: string | number | undefined
): boolean {
  if (value === undefined) return true;
  if (
    typeof value === 'string' &&
    !/^(?:10(?:\.0)?|[0-9](?:\.[0-9])?)$/u.test(value)
  ) {
    return false;
  }
  const score = Number(value);
  return Number.isFinite(score) && score >= 0 && score <= 10;
}

function compareIdentifiers(left: string, right: string): number {
  return compareSastNormalizationIdentifiers(left, right);
}

function allowedKeys(path: JsonPath): ReadonlySet<string> | null {
  if (path.length === 0) return ROOT_KEYS;
  if (isRunPath(path)) return RUN_KEYS;
  if (matches(path, ['runs', '*', 'tool'])) return TOOL_KEYS;
  if (
    matches(path, ['runs', '*', 'tool', 'driver'])
  ) {
    return DRIVER_KEYS;
  }
  if (isRulePath(path)) return RULE_KEYS;
  if (
    isWithinRule(path) &&
    ['shortDescription', 'fullDescription'].includes(
      String(path.at(-1))
    )
  ) {
    return MULTIFORMAT_TEXT_KEYS;
  }
  if (isWithinRule(path) && path.at(-1) === 'help') {
    return HELP_KEYS;
  }
  if (
    isWithinRule(path) &&
    path.at(-1) === 'defaultConfiguration'
  ) {
    return RULE_CONFIGURATION_KEYS;
  }
  if (
    isWithinRule(path) &&
    path.at(-1) === 'properties'
  ) {
    return RULE_PROPERTY_KEYS;
  }
  if (isResultPath(path)) return RESULT_KEYS;
  if (
    isWithinResult(path) &&
    path.at(-1) === 'message'
  ) {
    return RESULT_MESSAGE_KEYS;
  }
  if (
    isWithinResult(path) &&
    path.at(-1) === 'fingerprints'
  ) {
    return RESULT_FINGERPRINT_KEYS;
  }
  if (
    isWithinResult(path) &&
    path.at(-1) === 'properties'
  ) {
    return RESULT_PROPERTY_KEYS;
  }
  if (isPrimaryLocationPath(path)) return LOCATION_KEYS;
  if (
    isWithinPrimaryLocation(path) &&
    path.at(-1) === 'physicalLocation'
  ) {
    return PHYSICAL_LOCATION_KEYS;
  }
  if (
    isWithinPrimaryLocation(path) &&
    path.at(-1) === 'artifactLocation'
  ) {
    return ARTIFACT_LOCATION_KEYS;
  }
  if (
    isWithinPrimaryLocation(path) &&
    path.at(-1) === 'region'
  ) {
    return REGION_KEYS;
  }
  if (isInvocationPath(path)) return INVOCATION_KEYS;
  return null;
}

function isExpectedScalarPath(path: JsonPath): boolean {
  const patterns: readonly (readonly (string | '*')[])[] = [
    ['$schema'],
    ['version'],
    ['runs', '*', 'tool', 'driver', 'name'],
    ['runs', '*', 'tool', 'driver', 'semanticVersion'],
    ['runs', '*', 'tool', 'driver', 'rules', '*', 'id'],
    ['runs', '*', 'tool', 'driver', 'rules', '*', 'name'],
    [
      'runs',
      '*',
      'tool',
      'driver',
      'rules',
      '*',
      'shortDescription',
      'text'
    ],
    [
      'runs',
      '*',
      'tool',
      'driver',
      'rules',
      '*',
      'defaultConfiguration',
      'level'
    ],
    [
      'runs',
      '*',
      'tool',
      'driver',
      'rules',
      '*',
      'properties',
      'security-severity'
    ],
    ['runs', '*', 'results', '*', 'ruleId'],
    ['runs', '*', 'results', '*', 'ruleIndex'],
    ['runs', '*', 'results', '*', 'level'],
    ['runs', '*', 'results', '*', 'message', 'text'],
    [
      'runs',
      '*',
      'results',
      '*',
      'locations',
      '*',
      'physicalLocation',
      'region',
      'startLine'
    ],
    [
      'runs',
      '*',
      'results',
      '*',
      'locations',
      '*',
      'physicalLocation',
      'region',
      'endLine'
    ],
    [
      'runs',
      '*',
      'results',
      '*',
      'locations',
      '*',
      'physicalLocation',
      'region',
      'startColumn'
    ],
    [
      'runs',
      '*',
      'results',
      '*',
      'locations',
      '*',
      'physicalLocation',
      'region',
      'endColumn'
    ],
    [
      'runs',
      '*',
      'results',
      '*',
      'fingerprints',
      OPENGREP_MATCH_ID_PROPERTY
    ],
    [
      'runs',
      '*',
      'results',
      '*',
      'locations',
      '*',
      'physicalLocation',
      'artifactLocation',
      'uri'
    ],
    [
      'runs',
      '*',
      'results',
      '*',
      'locations',
      '*',
      'physicalLocation',
      'artifactLocation',
      'uriBaseId'
    ],
    [
      'runs',
      '*',
      'invocations',
      '*',
      'executionSuccessful'
    ]
  ];
  return patterns.some((pattern) => matches(path, pattern));
}

function isExpectedContainerPath(path: JsonPath): boolean {
  if (expectedContainerKind(path) !== null) return true;
  const patterns: readonly (readonly (string | '*')[])[] = [
    ['runs'],
    ['runs', '*'],
    ['runs', '*', 'tool'],
    ['runs', '*', 'tool', 'driver'],
    ['runs', '*', 'tool', 'driver', 'rules'],
    [
      'runs',
      '*',
      'tool',
      'driver',
      'rules',
      '*'
    ],
    [
      'runs',
      '*',
      'tool',
      'driver',
      'rules',
      '*',
      'properties',
      'tags'
    ],
    ['runs', '*', 'results'],
    ['runs', '*', 'results', '*'],
    ['runs', '*', 'results', '*', 'message'],
    ['runs', '*', 'results', '*', 'fingerprints'],
    ['runs', '*', 'results', '*', 'locations'],
    [
      'runs',
      '*',
      'results',
      '*',
      'locations',
      '*'
    ],
    ['runs', '*', 'invocations'],
    ['runs', '*', 'invocations', '*'],
    [
      'runs',
      '*',
      'invocations',
      '*',
      'toolExecutionNotifications'
    ]
  ];
  return patterns.some((pattern) => matches(path, pattern));
}

function expectedContainerKind(
  path: JsonPath
): ContainerKind | null {
  const arrays: readonly (readonly (string | '*')[])[] = [
    ['runs'],
    ['runs', '*', 'tool', 'driver', 'rules'],
    [
      'runs',
      '*',
      'tool',
      'driver',
      'rules',
      '*',
      'properties',
      'tags'
    ],
    ['runs', '*', 'results'],
    ['runs', '*', 'results', '*', 'locations'],
    ['runs', '*', 'invocations'],
    [
      'runs',
      '*',
      'invocations',
      '*',
      'toolExecutionNotifications'
    ]
  ];
  if (arrays.some((pattern) => matches(path, pattern))) {
    return 'ARRAY';
  }
  const objects: readonly (readonly (string | '*')[])[] = [
    [],
    ['runs', '*'],
    ['runs', '*', 'tool'],
    ['runs', '*', 'tool', 'driver'],
    [
      'runs',
      '*',
      'tool',
      'driver',
      'rules',
      '*'
    ],
    [
      'runs',
      '*',
      'tool',
      'driver',
      'rules',
      '*',
      'shortDescription'
    ],
    [
      'runs',
      '*',
      'tool',
      'driver',
      'rules',
      '*',
      'fullDescription'
    ],
    [
      'runs',
      '*',
      'tool',
      'driver',
      'rules',
      '*',
      'help'
    ],
    [
      'runs',
      '*',
      'tool',
      'driver',
      'rules',
      '*',
      'defaultConfiguration'
    ],
    [
      'runs',
      '*',
      'tool',
      'driver',
      'rules',
      '*',
      'properties'
    ],
    ['runs', '*', 'results', '*'],
    ['runs', '*', 'results', '*', 'message'],
    ['runs', '*', 'results', '*', 'fingerprints'],
    ['runs', '*', 'results', '*', 'properties'],
    [
      'runs',
      '*',
      'results',
      '*',
      'locations',
      '*'
    ],
    [
      'runs',
      '*',
      'results',
      '*',
      'locations',
      '*',
      'physicalLocation'
    ],
    [
      'runs',
      '*',
      'results',
      '*',
      'locations',
      '*',
      'physicalLocation',
      'artifactLocation'
    ],
    [
      'runs',
      '*',
      'results',
      '*',
      'locations',
      '*',
      'physicalLocation',
      'region'
    ],
    ['runs', '*', 'invocations', '*']
  ];
  return objects.some((pattern) => matches(path, pattern))
    ? 'OBJECT'
    : null;
}

function isRunPath(path: JsonPath): boolean {
  return matches(path, ['runs', '*']);
}

function isRulePath(path: JsonPath): boolean {
  return matches(path, [
    'runs',
    '*',
    'tool',
    'driver',
    'rules',
    '*'
  ]);
}

function isRuleTagItemPath(path: JsonPath): boolean {
  return matches(path, [
    'runs',
    '*',
    'tool',
    'driver',
    'rules',
    '*',
    'properties',
    'tags',
    '*'
  ]);
}

function isWithinRule(path: JsonPath): boolean {
  return (
    path.length >= 6 &&
    path[0] === 'runs' &&
    typeof path[1] === 'number' &&
    path[2] === 'tool' &&
    path[3] === 'driver' &&
    path[4] === 'rules' &&
    typeof path[5] === 'number'
  );
}

function isResultPath(path: JsonPath): boolean {
  return matches(path, ['runs', '*', 'results', '*']);
}

function isWithinResult(path: JsonPath): boolean {
  return (
    path.length >= 4 &&
    path[0] === 'runs' &&
    typeof path[1] === 'number' &&
    path[2] === 'results' &&
    typeof path[3] === 'number'
  );
}

function isPrimaryLocationPath(path: JsonPath): boolean {
  return matches(path, [
    'runs',
    '*',
    'results',
    '*',
    'locations',
    '*'
  ]);
}

function isWithinPrimaryLocation(path: JsonPath): boolean {
  return (
    path.length >= 6 &&
    isWithinResult(path) &&
    path[4] === 'locations' &&
    typeof path[5] === 'number'
  );
}

function isInvocationPath(path: JsonPath): boolean {
  return matches(path, ['runs', '*', 'invocations', '*']);
}

function isWithinInvocation(path: JsonPath): boolean {
  return (
    path.length >= 4 &&
    path[0] === 'runs' &&
    typeof path[1] === 'number' &&
    path[2] === 'invocations' &&
    typeof path[3] === 'number'
  );
}

function isNotificationPath(path: JsonPath): boolean {
  return matches(path, [
    'runs',
    '*',
    'invocations',
    '*',
    'toolExecutionNotifications',
    '*'
  ]);
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

function omitResultDigest(
  result: Readonly<SastArtifactValidationResult>
) {
  const { resultDigest, ...core } = result;
  void resultDigest;
  return core;
}

function omitDecisionDigest(
  decision: Readonly<SastArtifactDispositionDecision>
) {
  const { decisionDigest, ...core } = decision;
  void decisionDigest;
  return core;
}

function hasUnsafeControls(value: string): boolean {
  return [...value].some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return (
      codePoint <= 0x1f ||
      (codePoint >= 0x7f && codePoint <= 0x9f) ||
      (codePoint >= 0xd800 && codePoint <= 0xdfff)
    );
  });
}

function utf8Bytes(value: string): number {
  return Buffer.byteLength(value, 'utf8');
}

function hasExactObjectKeys(
  value: object,
  expected: readonly string[]
): boolean {
  const actual = Object.keys(value);
  return (
    actual.length === expected.length &&
    actual.every((key) => expected.includes(key))
  );
}

function readReferenceTime(clock: () => Date): Date {
  try {
    return new Date(Date.prototype.getTime.call(clock()));
  } catch {
    return new Date(Number.NaN);
  }
}

function digest(value: string): `sha256:${string}` {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}
