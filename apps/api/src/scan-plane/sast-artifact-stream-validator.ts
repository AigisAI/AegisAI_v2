import { createHash } from 'node:crypto';
import { TextDecoder } from 'node:util';

import {
  SAST_ARTIFACT_SCHEMA_VERSIONS,
  SAST_ARTIFACT_VALIDATION_LIMITS,
  SAST_ARTIFACT_VALIDATION_REASON_CODES,
  SAST_ARTIFACT_VALIDATION_VERSION,
  SAST_MAX_COORDINATE_VALUE,
  canonicalizeSastArtifactValidationResult,
  deriveSastArtifactValidationChecks,
  isSastFindingLocationValid,
  isScannerArtifactEnvelopeBoundToPlan,
  type ExpectedScannerArtifactBinding,
  type SastArtifactValidationReasonCode,
  type SastArtifactValidationResult,
  type SastArtifactValidationResultCore,
  type SastFileCoordinateMetadata,
  type SastScanPlan,
  type ScannerArtifactEnvelope
} from '@aegisai/shared';
import { Tokenizer, TokenType } from '@streamparser/json';

import type { SastFileCoordinateAttestation } from './sast-file-coordinate-attestation.provider';

export type JsonPrimitive = string | number | boolean | null;
export type JsonPath = readonly (string | number)[];
export type ContainerKind = 'OBJECT' | 'ARRAY';

interface ArtifactValidationFault extends Error {
  reasonCode: SastArtifactValidationReasonCode;
}

export interface ArtifactValidationCallbacks {
  onContainer(path: JsonPath, kind: ContainerKind): void;
  onContainerEnd(path: JsonPath, kind: ContainerKind): void;
  onKey(objectPath: JsonPath, key: string): void;
  onPrimitive(path: JsonPath, value: JsonPrimitive): void;
}

interface ObjectFrame {
  kind: 'OBJECT';
  path: JsonPath;
  keys: Set<string>;
  state: 'KEY_OR_END' | 'KEY' | 'COLON' | 'VALUE' | 'COMMA_OR_END';
  currentKey?: string;
}

interface ArrayFrame {
  kind: 'ARRAY';
  path: JsonPath;
  state: 'VALUE_OR_END' | 'VALUE' | 'COMMA_OR_END';
  nextIndex: number;
}

type JsonFrame = ObjectFrame | ArrayFrame;

interface ParsedToken {
  token: TokenType;
  value: JsonPrimitive;
  partial?: boolean;
}

interface LocationState {
  path?: string;
  lineStart?: number;
  lineEnd?: number;
  columnStart?: number;
  columnEnd?: number;
}

interface RecordState extends LocationState {
  kind: string;
  keys: Set<string>;
  trivyResultIndex?: number;
}

interface RequiredObjectState {
  kind: 'SARIF_TOOL' | 'SARIF_DRIVER' | 'SARIF_RESULT_MESSAGE';
  keys: Set<string>;
}

const SARIF_ROOT_FIELDS = new Set([
  '$schema',
  'version',
  'runs',
  'inlineExternalProperties',
  'properties'
]);
const SARIF_RUN_FIELDS = new Set([
  'tool',
  'invocations',
  'conversion',
  'language',
  'versionControlProvenance',
  'originalUriBaseIds',
  'artifacts',
  'logicalLocations',
  'graphs',
  'results',
  'automationDetails',
  'baselineGuid',
  'redactionTokens',
  'defaultEncoding',
  'defaultSourceLanguage',
  'newlineSequences',
  'columnKind',
  'externalPropertyFileReferences',
  'threadFlowLocations',
  'taxonomies',
  'addresses',
  'translations',
  'policies',
  'webRequests',
  'webResponses',
  'specialLocations',
  'properties'
]);
const SARIF_RESULT_FIELDS = new Set([
  'ruleId',
  'ruleIndex',
  'rule',
  'kind',
  'level',
  'message',
  'analysisTarget',
  'locations',
  'guid',
  'correlationGuid',
  'occurrenceCount',
  'partialFingerprints',
  'fingerprints',
  'stacks',
  'codeFlows',
  'graphs',
  'graphTraversals',
  'relatedLocations',
  'suppressions',
  'baselineState',
  'rank',
  'attachments',
  'hostedViewerUri',
  'workItemUris',
  'provenance',
  'fixes',
  'taxa',
  'webRequest',
  'webResponse',
  'properties'
]);
const TRIVY_ROOT_FIELDS = new Set([
  'SchemaVersion',
  'CreatedAt',
  'ArtifactName',
  'ArtifactType',
  'Metadata',
  'Results'
]);
const TRIVY_RESULT_FIELDS = new Set([
  'Target',
  'Class',
  'Type',
  'Packages',
  'Vulnerabilities',
  'MisconfSummary',
  'Misconfigurations',
  'Secrets',
  'Licenses',
  'CustomResources',
  'ExperimentalModifiedFindings'
]);
const TRIVY_VULNERABILITY_FIELDS = new Set([
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
const TRIVY_MISCONFIGURATION_FIELDS = new Set([
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
const TRIVY_SECRET_FIELDS = new Set([
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
const TRIVY_MODIFIED_FINDING_FIELDS = new Set([
  'Type',
  'Status',
  'Statement',
  'Source',
  'Finding'
]);
const TRIVY_MODIFIED_RECORD_FIELDS = new Set([
  ...TRIVY_VULNERABILITY_FIELDS,
  ...TRIVY_MISCONFIGURATION_FIELDS,
  ...TRIVY_SECRET_FIELDS
]);
const CYCLONEDX_ROOT_FIELDS = new Set([
  '$schema',
  'bomFormat',
  'specVersion',
  'serialNumber',
  'version',
  'metadata',
  'components',
  'services',
  'externalReferences',
  'dependencies',
  'compositions',
  'vulnerabilities',
  'annotations',
  'properties',
  'formulation',
  'declarations',
  'definitions'
]);
const CYCLONEDX_COMPONENT_FIELDS = new Set([
  'type',
  'mime-type',
  'bom-ref',
  'supplier',
  'manufacturer',
  'authors',
  'author',
  'publisher',
  'group',
  'name',
  'version',
  'description',
  'scope',
  'hashes',
  'licenses',
  'copyright',
  'cpe',
  'purl',
  'swid',
  'modified',
  'pedigree',
  'externalReferences',
  'properties',
  'components',
  'evidence',
  'releaseNotes',
  'modelCard',
  'data',
  'cryptoProperties',
  'tags',
  'signature',
  'omniborId',
  'swhid'
]);
const TRIVY_RECORD_ARRAYS = new Set([
  'Vulnerabilities',
  'Misconfigurations',
  'Secrets'
]);
const SARIF_RESULT_KINDS = new Set([
  'notApplicable',
  'pass',
  'fail',
  'review',
  'open',
  'informational'
]);
const SARIF_LEVELS = new Set(['none', 'note', 'warning', 'error']);
const SARIF_COLUMN_KINDS = new Set([
  'utf16CodeUnits',
  'unicodeCodePoints'
]);
const SARIF_BASELINE_STATES = new Set([
  'new',
  'unchanged',
  'updated',
  'absent'
]);
const CYCLONEDX_COMPONENT_TYPES = new Set([
  'application',
  'framework',
  'library',
  'container',
  'platform',
  'operating-system',
  'device',
  'device-driver',
  'firmware',
  'file',
  'machine-learning-model',
  'data',
  'cryptographic-asset'
]);
const CYCLONEDX_COMPONENT_SCOPES = new Set([
  'required',
  'optional',
  'excluded'
]);
const TRIVY_SEVERITIES = new Set([
  'UNKNOWN',
  'LOW',
  'MEDIUM',
  'HIGH',
  'CRITICAL'
]);
const TRIVY_RESULT_CLASSES = new Set([
  'unknown',
  'os-pkgs',
  'lang-pkgs',
  'config',
  'secret',
  'license',
  'license-file',
  'custom'
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
const TRIVY_MISCONFIGURATION_STATUSES = new Set([
  'PASS',
  'FAIL',
  'EXCEPTION'
]);
const TRIVY_MODIFIED_FINDING_TYPES = new Set([
  'vulnerability',
  'misconfiguration',
  'secret'
]);
const TRIVY_MODIFIED_FINDING_STATUSES = new Set([
  'ignored',
  'unknown',
  'not_affected',
  'affected',
  'fixed',
  'under_investigation'
]);

export interface SastArtifactStreamValidationInput {
  envelope: Readonly<ScannerArtifactEnvelope>;
  plan: Readonly<SastScanPlan>;
  expectedBinding: Readonly<ExpectedScannerArtifactBinding>;
  envelopeDigest: `sha256:${string}`;
  coordinateAttestation: Readonly<SastFileCoordinateAttestation> | null;
}

export class SastArtifactStreamValidationSession {
  private readonly reasons = new Set<SastArtifactValidationReasonCode>();
  private readonly observedContentHash = createHash('sha256');
  private readonly decoder = new TextDecoder('utf-8', { fatal: true });
  private readonly tokenizer = new Tokenizer({ emitPartialTokens: false });
  private readonly rawLimiter = new RawJsonTokenLimiter();
  private readonly parserPending = Buffer.alloc(
    SAST_ARTIFACT_VALIDATION_LIMITS.parserSliceBytes
  );
  private readonly schemaInspector: SastArtifactSchemaInspector;
  private readonly structure: BoundedJsonStructureTracker;
  private parsingActive = true;
  private decoderActive = true;
  private observedByteSize = 0;
  private parserPendingLength = 0;
  private finished = false;

  constructor(private readonly input: Readonly<SastArtifactStreamValidationInput>) {
    const fileCoordinates = this.loadFileCoordinates(
      input.coordinateAttestation
    );
    this.schemaInspector = new SastArtifactSchemaInspector(
      input.envelope,
      input.plan,
      fileCoordinates,
      this.reasons
    );
    this.structure = new BoundedJsonStructureTracker(
      this.schemaInspector,
      this.reasons
    );
    this.tokenizer.onToken = (token) => this.acceptToken(token);
    this.tokenizer.onError = (error) => {
      throw isValidationFault(error)
        ? error
        : validationFault('ARTIFACT_JSON_MALFORMED');
    };

    if (
      !isScannerArtifactEnvelopeBoundToPlan(
        input.envelope,
        input.plan,
        input.expectedBinding
      )
    ) {
      this.reasons.add('ARTIFACT_PLAN_BINDING_MISMATCH');
    }
    if (
      input.envelope.artifactSchemaVersion !==
      SAST_ARTIFACT_SCHEMA_VERSIONS[input.envelope.artifactSchema]
    ) {
      this.reasons.add('ARTIFACT_SCHEMA_VERSION_MISMATCH');
    }
  }

  async *observe(
    body: AsyncIterable<Uint8Array>
  ): AsyncGenerator<Uint8Array> {
    for await (const chunk of body) {
      const bytes = Buffer.from(chunk);
      this.observedContentHash.update(bytes);
      this.observedByteSize += bytes.byteLength;
      this.validateEncoding(bytes);
      this.acceptParserBytes(bytes);
      yield bytes;
    }
  }

  finish(): SastArtifactValidationResult {
    if (this.finished) {
      throw new Error('Artifact validation session is already finished.');
    }
    this.finished = true;
    const observedContentDigest =
      `sha256:${this.observedContentHash.digest('hex')}` as const;
    const observedByteSize = this.observedByteSize;
    if (this.decoderActive) {
      try {
        this.decoder.decode();
      } catch {
        this.reasons.add('ARTIFACT_INVALID_UTF8');
      }
    }
    this.flushParserPending();
    if (this.parsingActive) {
      try {
        this.rawLimiter.end();
        this.tokenizer.end();
        this.structure.finish();
      } catch (error) {
        this.recordFault(error);
      }
    }
    this.schemaInspector.finish();

    if (observedContentDigest !== this.input.envelope.contentDigest) {
      this.reasons.add('ARTIFACT_CONTENT_DIGEST_MISMATCH');
    }
    if (
      observedByteSize !== this.input.envelope.byteSize ||
      observedByteSize > this.input.plan.profile.limits.maxArtifactBytes
    ) {
      this.reasons.add('ARTIFACT_BYTE_SIZE_MISMATCH');
    }
    if (
      this.schemaInspector.recordCount !== this.input.envelope.recordCount
    ) {
      this.reasons.add('ARTIFACT_RECORD_COUNT_MISMATCH');
    }
    if (
      this.schemaInspector.recordCount >
      (this.input.envelope.artifactSchema === 'CYCLONEDX_JSON'
        ? this.input.plan.profile.limits.maxArtifactRecords
        : Math.min(
            this.input.plan.profile.limits.maxArtifactRecords,
            this.input.plan.profile.limits.maxFindings
          ))
    ) {
      this.reasons.add('ARTIFACT_RECORD_LIMIT_EXCEEDED');
    }

    const reasonCodes = SAST_ARTIFACT_VALIDATION_REASON_CODES.filter(
      (reasonCode) => this.reasons.has(reasonCode)
    );
    const checks = deriveSastArtifactValidationChecks(reasonCodes);
    const core: SastArtifactValidationResultCore = {
      version: SAST_ARTIFACT_VALIDATION_VERSION,
      outcome: reasonCodes.length === 0 ? 'PASSED' : 'FAILED',
      artifactSchema: this.input.envelope.artifactSchema,
      envelopeDigest: this.input.envelopeDigest,
      observedContentDigest,
      checks,
      reasonCodes,
      statistics: {
        observedByteSize,
        observedRecordCount: this.schemaInspector.recordCount,
        maximumObservedDepth: this.structure.maximumObservedDepth,
        maximumObservedStringBytes:
          this.structure.maximumObservedStringBytes,
        normalizedPathCount: this.schemaInspector.normalizedPathCount,
        coordinateCount: this.schemaInspector.coordinateCount
      }
    };

    return {
      ...core,
      resultDigest: digest(canonicalizeSastArtifactValidationResult(core))
    };
  }

  private validateEncoding(bytes: Buffer): void {
    if (!this.decoderActive) return;
    try {
      this.decoder.decode(bytes, { stream: true });
    } catch {
      this.decoderActive = false;
      this.reasons.add('ARTIFACT_INVALID_UTF8');
    }
  }

  private acceptToken(token: ParsedToken): void {
    this.structure.accept(token);
  }

  private acceptParserBytes(bytes: Buffer): void {
    if (!this.parsingActive) return;
    const sliceBytes = SAST_ARTIFACT_VALIDATION_LIMITS.parserSliceBytes;
    let offset = 0;

    if (this.parserPendingLength > 0) {
      const take = Math.min(
        sliceBytes - this.parserPendingLength,
        bytes.byteLength
      );
      bytes.copy(
        this.parserPending,
        this.parserPendingLength,
        0,
        take
      );
      this.parserPendingLength += take;
      offset = take;
      if (this.parserPendingLength === sliceBytes) {
        this.parserPendingLength = 0;
        this.processParserSlice(this.parserPending);
      }
    }

    while (
      this.parsingActive &&
      offset + sliceBytes <= bytes.byteLength
    ) {
      this.processParserSlice(
        bytes.subarray(offset, offset + sliceBytes)
      );
      offset += sliceBytes;
    }

    if (this.parsingActive && offset < bytes.byteLength) {
      const remaining = bytes.byteLength - offset;
      bytes.copy(this.parserPending, 0, offset);
      this.parserPendingLength = remaining;
    }
  }

  private flushParserPending(): void {
    if (!this.parsingActive || this.parserPendingLength === 0) return;
    const length = this.parserPendingLength;
    this.parserPendingLength = 0;
    this.processParserSlice(this.parserPending.subarray(0, length));
  }

  private processParserSlice(slice: Buffer): void {
    try {
      this.rawLimiter.write(slice);
      this.tokenizer.write(slice);
    } catch (error) {
      this.recordFault(error);
    }
  }

  private recordFault(error: unknown): void {
    const reasonCode =
      isValidationFault(error)
        ? error.reasonCode
        : 'ARTIFACT_JSON_MALFORMED';
    this.reasons.add(reasonCode);
    this.parsingActive = false;
    this.parserPendingLength = 0;
  }

  private loadFileCoordinates(
    attestation: Readonly<SastFileCoordinateAttestation> | null
  ): ReadonlyMap<string, Readonly<SastFileCoordinateMetadata>> | null {
    if (
      !attestation ||
      attestation.verified !== true ||
      attestation.attestationRef !==
        this.input.expectedBinding.preflightAttestationRef ||
      attestation.inventoryDigest !==
        this.input.expectedBinding.preflightInventoryDigest ||
      !Array.isArray(attestation.files) ||
      attestation.files.length > this.input.plan.profile.limits.maxFileCount
    ) {
      return null;
    }

    const coordinates = new Map<
      string,
      Readonly<SastFileCoordinateMetadata>
    >();
    const foldedPaths = new Set<string>();
    let totalLineCount = 0;
    for (const rawFile of attestation.files as readonly unknown[]) {
      if (
        !rawFile ||
        typeof rawFile !== 'object' ||
        Array.isArray(rawFile) ||
        !hasOnlyObjectKeys(rawFile, [
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
        this.input.plan.profile.limits.maxPathDepth
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
          SAST_ARTIFACT_VALIDATION_LIMITS.maximumCoordinateAttestationLines -
            totalLineCount ||
        coordinates.has(normalizedPath)
      ) {
        return null;
      }
      if (
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
      totalLineCount += lineCount;
      foldedPaths.add(foldedPath);
      coordinates.set(normalizedPath, {
        normalizedPath,
        lineCount,
        maxColumnByLine: file.maxColumnByLine
      });
    }
    return coordinates;
  }

}

export class BoundedJsonStructureTracker {
  private readonly stack: JsonFrame[] = [];
  private rootState: 'VALUE' | 'CONTAINER' | 'END' = 'VALUE';
  private tokenCount = 0;
  maximumObservedDepth = 0;
  maximumObservedStringBytes = 0;

  constructor(
    private readonly callbacks: ArtifactValidationCallbacks,
    private readonly reasons: Set<SastArtifactValidationReasonCode>
  ) {}

  accept(token: ParsedToken): void {
    if (token.partial === true) {
      if (token.token === TokenType.STRING) {
        this.checkString(token.value);
      }
      return;
    }

    this.tokenCount += 1;
    if (
      this.tokenCount >
      SAST_ARTIFACT_VALIDATION_LIMITS.maximumTokenCount
    ) {
      throw validationFault('ARTIFACT_JSON_TOKEN_LIMIT_EXCEEDED');
    }

    if (token.token === TokenType.STRING) {
      this.checkString(token.value);
      const frame = this.stack.at(-1);
      if (
        frame?.kind === 'OBJECT' &&
        (frame.state === 'KEY_OR_END' || frame.state === 'KEY')
      ) {
        this.acceptKey(frame, token.value as string);
        return;
      }
    }

    switch (token.token) {
      case TokenType.LEFT_BRACE:
        this.startContainer('OBJECT');
        return;
      case TokenType.LEFT_BRACKET:
        this.startContainer('ARRAY');
        return;
      case TokenType.RIGHT_BRACE:
        this.endObject();
        return;
      case TokenType.RIGHT_BRACKET:
        this.endArray();
        return;
      case TokenType.COLON:
        this.acceptColon();
        return;
      case TokenType.COMMA:
        this.acceptComma();
        return;
      case TokenType.STRING:
      case TokenType.NUMBER:
      case TokenType.TRUE:
      case TokenType.FALSE:
      case TokenType.NULL:
        this.acceptPrimitive(token.value);
        return;
      default:
        throw validationFault('ARTIFACT_JSON_MALFORMED');
    }
  }

  finish(): void {
    if (this.stack.length !== 0 || this.rootState !== 'END') {
      throw validationFault('ARTIFACT_JSON_MALFORMED');
    }
  }

  private startContainer(kind: ContainerKind): void {
    const path = this.startValue(true);
    const frame: JsonFrame =
      kind === 'OBJECT'
        ? {
            kind,
            path,
            keys: new Set<string>(),
            state: 'KEY_OR_END'
          }
        : {
            kind,
            path,
            state: 'VALUE_OR_END',
            nextIndex: 0
          };
    this.stack.push(frame);
    this.maximumObservedDepth = Math.max(
      this.maximumObservedDepth,
      this.stack.length
    );
    if (
      this.stack.length >
      SAST_ARTIFACT_VALIDATION_LIMITS.maximumJsonDepth
    ) {
      throw validationFault('ARTIFACT_JSON_DEPTH_LIMIT_EXCEEDED');
    }
    this.callbacks.onContainer(path, kind);
  }

  private endObject(): void {
    const frame = this.stack.at(-1);
    if (
      frame?.kind !== 'OBJECT' ||
      !(
        frame.state === 'KEY_OR_END' ||
        frame.state === 'COMMA_OR_END'
      )
    ) {
      throw validationFault('ARTIFACT_JSON_MALFORMED');
    }
    this.stack.pop();
    this.callbacks.onContainerEnd(frame.path, frame.kind);
    this.completeRootContainer();
  }

  private endArray(): void {
    const frame = this.stack.at(-1);
    if (
      frame?.kind !== 'ARRAY' ||
      !(
        frame.state === 'VALUE_OR_END' ||
        frame.state === 'COMMA_OR_END'
      )
    ) {
      throw validationFault('ARTIFACT_JSON_MALFORMED');
    }
    this.stack.pop();
    this.callbacks.onContainerEnd(frame.path, frame.kind);
    this.completeRootContainer();
  }

  private acceptKey(frame: ObjectFrame, key: string): void {
    if (
      Buffer.byteLength(key, 'utf8') >
      SAST_ARTIFACT_VALIDATION_LIMITS.maximumKeyBytes
    ) {
      throw validationFault('ARTIFACT_JSON_KEY_LIMIT_EXCEEDED');
    }
    if (hasUnpairedSurrogate(key)) {
      throw validationFault('ARTIFACT_INVALID_UTF8');
    }
    if (frame.keys.has(key)) {
      throw validationFault('ARTIFACT_JSON_DUPLICATE_KEY');
    }
    if (
      frame.keys.size >=
      SAST_ARTIFACT_VALIDATION_LIMITS.maximumObjectKeys
    ) {
      throw validationFault(
        'ARTIFACT_JSON_KEY_COUNT_LIMIT_EXCEEDED'
      );
    }
    frame.keys.add(key);
    frame.currentKey = key;
    frame.state = 'COLON';
    this.callbacks.onKey(frame.path, key);
  }

  private acceptColon(): void {
    const frame = this.stack.at(-1);
    if (frame?.kind !== 'OBJECT' || frame.state !== 'COLON') {
      throw validationFault('ARTIFACT_JSON_MALFORMED');
    }
    frame.state = 'VALUE';
  }

  private acceptComma(): void {
    const frame = this.stack.at(-1);
    if (!frame || frame.state !== 'COMMA_OR_END') {
      throw validationFault('ARTIFACT_JSON_MALFORMED');
    }
    if (frame.kind === 'OBJECT') {
      frame.state = 'KEY';
      frame.currentKey = undefined;
    } else {
      frame.state = 'VALUE';
    }
  }

  private acceptPrimitive(value: JsonPrimitive): void {
    const path = this.startValue(false);
    if (
      typeof value === 'number' &&
      (!Number.isFinite(value) ||
        Math.abs(value) > Number.MAX_SAFE_INTEGER)
    ) {
      this.reasons.add('ARTIFACT_SCHEMA_FIELD_INVALID');
    }
    this.callbacks.onPrimitive(path, value);
  }

  private startValue(container: boolean): JsonPath {
    const frame = this.stack.at(-1);
    let path: JsonPath;
    if (!frame) {
      if (this.rootState !== 'VALUE') {
        throw validationFault('ARTIFACT_JSON_MALFORMED');
      }
      path = [];
      this.rootState = container ? 'CONTAINER' : 'END';
      return path;
    }

    if (frame.kind === 'OBJECT') {
      if (frame.state !== 'VALUE' || frame.currentKey === undefined) {
        throw validationFault('ARTIFACT_JSON_MALFORMED');
      }
      path = [...frame.path, frame.currentKey];
      frame.state = 'COMMA_OR_END';
    } else {
      if (
        frame.state !== 'VALUE_OR_END' &&
        frame.state !== 'VALUE'
      ) {
        throw validationFault('ARTIFACT_JSON_MALFORMED');
      }
      path = [...frame.path, frame.nextIndex];
      frame.nextIndex += 1;
      frame.state = 'COMMA_OR_END';
    }
    return path;
  }

  private completeRootContainer(): void {
    if (this.stack.length === 0) {
      if (this.rootState !== 'CONTAINER') {
        throw validationFault('ARTIFACT_JSON_MALFORMED');
      }
      this.rootState = 'END';
    }
  }

  private checkString(value: JsonPrimitive): void {
    if (typeof value !== 'string') return;
    const byteLength = Buffer.byteLength(value, 'utf8');
    this.maximumObservedStringBytes = Math.max(
      this.maximumObservedStringBytes,
      byteLength
    );
    if (
      byteLength >
      SAST_ARTIFACT_VALIDATION_LIMITS.maximumStringBytes
    ) {
      throw validationFault('ARTIFACT_JSON_STRING_LIMIT_EXCEEDED');
    }
    if (hasUnpairedSurrogate(value)) {
      throw validationFault('ARTIFACT_INVALID_UTF8');
    }
  }
}

export class RawJsonTokenLimiter {
  private offset = 0;
  private readonly prefix: number[] = [];
  private inString = false;
  private escaped = false;
  private unicodeDigitsRemaining = 0;
  private unicodeValue = 0;
  private pendingHighSurrogate = false;
  private rawStringBytes = 0;
  private inNumber = false;
  private numberBytes = 0;

  write(bytes: Uint8Array): void {
    for (const byte of bytes) {
      if (this.offset < 3) {
        this.prefix.push(byte);
        if (
          this.prefix.length === 3 &&
          this.prefix[0] === 0xef &&
          this.prefix[1] === 0xbb &&
          this.prefix[2] === 0xbf
        ) {
          throw validationFault('ARTIFACT_INVALID_UTF8');
        }
      }
      this.offset += 1;

      if (this.inString) {
        this.rawStringBytes += 1;
        if (
          this.rawStringBytes >
          SAST_ARTIFACT_VALIDATION_LIMITS.maximumStringBytes * 6 + 2
        ) {
          throw validationFault('ARTIFACT_JSON_STRING_LIMIT_EXCEEDED');
        }
        if (this.unicodeDigitsRemaining > 0) {
          const digit = hexDigitValue(byte);
          if (digit === null) {
            throw validationFault('ARTIFACT_JSON_MALFORMED');
          }
          this.unicodeValue = this.unicodeValue * 16 + digit;
          this.unicodeDigitsRemaining -= 1;
          if (this.unicodeDigitsRemaining === 0) {
            this.finishUnicodeEscape();
          }
        } else if (this.escaped) {
          this.escaped = false;
          if (byte === 0x75) {
            this.unicodeDigitsRemaining = 4;
            this.unicodeValue = 0;
          } else if (this.pendingHighSurrogate) {
            throw validationFault('ARTIFACT_INVALID_UTF8');
          }
        } else if (this.pendingHighSurrogate) {
          if (byte !== 0x5c) {
            throw validationFault('ARTIFACT_INVALID_UTF8');
          }
          this.escaped = true;
        } else if (byte === 0x5c) {
          this.escaped = true;
        } else if (byte === 0x22) {
          this.inString = false;
        }
        continue;
      }

      if (this.inNumber) {
        if (isJsonDelimiter(byte)) {
          this.inNumber = false;
          this.numberBytes = 0;
        } else {
          this.numberBytes += 1;
          if (
            this.numberBytes >
            SAST_ARTIFACT_VALIDATION_LIMITS.maximumNumberTokenBytes
          ) {
            throw validationFault('ARTIFACT_JSON_NUMBER_LIMIT_EXCEEDED');
          }
          continue;
        }
      }

      if (byte === 0x22) {
        this.inString = true;
        this.rawStringBytes = 0;
      } else if (byte === 0x2d || (byte >= 0x30 && byte <= 0x39)) {
        this.inNumber = true;
        this.numberBytes = 1;
      }
    }
  }

  end(): void {
    if (this.pendingHighSurrogate) {
      throw validationFault('ARTIFACT_INVALID_UTF8');
    }
    if (this.inString || this.escaped || this.unicodeDigitsRemaining > 0) {
      throw validationFault('ARTIFACT_JSON_MALFORMED');
    }
  }

  private finishUnicodeEscape(): void {
    if (this.unicodeValue >= 0xd800 && this.unicodeValue <= 0xdbff) {
      if (this.pendingHighSurrogate) {
        throw validationFault('ARTIFACT_INVALID_UTF8');
      }
      this.pendingHighSurrogate = true;
      return;
    }
    if (this.unicodeValue >= 0xdc00 && this.unicodeValue <= 0xdfff) {
      if (!this.pendingHighSurrogate) {
        throw validationFault('ARTIFACT_INVALID_UTF8');
      }
      this.pendingHighSurrogate = false;
      return;
    }
    if (this.pendingHighSurrogate) {
      throw validationFault('ARTIFACT_INVALID_UTF8');
    }
  }
}

class SastArtifactSchemaInspector implements ArtifactValidationCallbacks {
  private readonly rootKeys = new Set<string>();
  private readonly runKeys = new Map<string, Set<string>>();
  private readonly requiredObjects = new Map<string, RequiredObjectState>();
  private readonly recordStates = new Map<string, RecordState>();
  private readonly physicalLocations = new Map<string, LocationState>();
  private readonly trivyTargets = new Map<number, string>();
  private readonly trivyResultKeys = new Map<number, Set<string>>();
  private readonly trivyModifiedFindingKeys = new Map<
    string,
    Set<string>
  >();
  private readonly pendingTrivyLocations = new Map<
    number,
    LocationState[]
  >();
  private readonly exactPathHashes = new Set<string>();
  private readonly foldedPathHashes = new Map<string, string>();
  private rootKind?: ContainerKind;
  private runsSeen = false;
  private trivyResultsSeen = false;
  private cyclonedxComponentsSeen = false;
  private sarifVersionValid = false;
  private trivyVersionValid = false;
  private cyclonedxFormatValid = false;
  private cyclonedxVersionValid = false;
  private sarifRunCount = 0;
  recordCount = 0;
  coordinateCount = 0;

  constructor(
    private readonly envelope: Readonly<ScannerArtifactEnvelope>,
    private readonly plan: Readonly<SastScanPlan>,
    private readonly fileCoordinates:
      | ReadonlyMap<string, Readonly<SastFileCoordinateMetadata>>
      | null,
    private readonly reasons: Set<SastArtifactValidationReasonCode>
  ) {}

  get normalizedPathCount(): number {
    return this.exactPathHashes.size;
  }

  onContainer(path: JsonPath, kind: ContainerKind): void {
    if (path.length === 0) {
      this.rootKind = kind;
      if (kind !== 'OBJECT') this.schemaInvalid();
      return;
    }
    if (
      this.isRequiredScalarField(path) ||
      this.isPinnedEnumField(path)
    ) {
      this.schemaInvalid();
    }
    if (this.isArtifactPathField(path)) {
      this.reasons.add('ARTIFACT_PATH_INVALID');
    }
    if (this.isCoordinateField(path)) {
      this.coordinateCount += 1;
      this.reasons.add('ARTIFACT_COORDINATE_INVALID');
    }

    if (this.envelope.artifactSchema === 'OPENGREP_SARIF') {
      this.onSarifContainer(path, kind);
    } else if (this.envelope.artifactSchema === 'TRIVY_JSON') {
      this.onTrivyContainer(path, kind);
    } else {
      this.onCycloneDxContainer(path, kind);
    }
  }

  onContainerEnd(path: JsonPath, kind: ContainerKind): void {
    if (kind !== 'OBJECT') return;
    const pathKey = keyForPath(path);
    const runKeys = this.runKeys.get(pathKey);
    if (runKeys) {
      if (!runKeys.has('tool') || !runKeys.has('results')) {
        this.requiredFieldMissing();
      }
      this.runKeys.delete(pathKey);
    }

    const requiredObject = this.requiredObjects.get(pathKey);
    if (requiredObject) {
      const missing =
        requiredObject.kind === 'SARIF_TOOL'
          ? !requiredObject.keys.has('driver')
          : requiredObject.kind === 'SARIF_DRIVER'
            ? !requiredObject.keys.has('name')
            : !requiredObject.keys.has('text') &&
              !requiredObject.keys.has('id');
      if (missing) this.requiredFieldMissing();
      this.requiredObjects.delete(pathKey);
    }

    const record = this.recordStates.get(pathKey);
    if (record) {
      this.validateRecord(record);
      this.recordStates.delete(pathKey);
    }

    const modifiedFindingKeys =
      this.trivyModifiedFindingKeys.get(pathKey);
    if (modifiedFindingKeys) {
      if (
        !modifiedFindingKeys.has('Type') ||
        !modifiedFindingKeys.has('Status') ||
        !modifiedFindingKeys.has('Finding')
      ) {
        this.requiredFieldMissing();
      }
      this.trivyModifiedFindingKeys.delete(pathKey);
    }

    const location = this.physicalLocations.get(pathKey);
    if (location) {
      this.validateLocation(location);
      this.physicalLocations.delete(pathKey);
    }

    if (
      this.envelope.artifactSchema === 'TRIVY_JSON' &&
      isTrivyResultPath(path)
    ) {
      this.finishTrivyResult(path[1] as number);
    }
  }

  onKey(objectPath: JsonPath, key: string): void {
    if (objectPath.length === 0) {
      this.rootKeys.add(key);
      const allowed = this.allowedRootFields();
      if (!allowed.has(key)) this.unknownField();
      return;
    }

    const pathKey = keyForPath(objectPath);
    this.runKeys.get(pathKey)?.add(key);
    this.requiredObjects.get(pathKey)?.keys.add(key);
    this.recordStates.get(pathKey)?.keys.add(key);
    this.trivyModifiedFindingKeys.get(pathKey)?.add(key);
    if (
      this.envelope.artifactSchema === 'TRIVY_JSON' &&
      isTrivyResultPath(objectPath)
    ) {
      this.trivyResultKeys.get(objectPath[1] as number)?.add(key);
    }

    if (
      this.envelope.artifactSchema === 'OPENGREP_SARIF' &&
      isSarifRunPath(objectPath) &&
      !SARIF_RUN_FIELDS.has(key)
    ) {
      this.unknownField();
    }
    if (
      this.envelope.artifactSchema === 'OPENGREP_SARIF' &&
      isSarifRecordPath(objectPath) &&
      !SARIF_RESULT_FIELDS.has(key)
    ) {
      this.unknownField();
    }
    if (
      this.envelope.artifactSchema === 'OPENGREP_SARIF' &&
      objectPath.at(-1) === 'artifactLocation' &&
      objectPath.includes('physicalLocation') &&
      key === 'index'
    ) {
      this.reasons.add('ARTIFACT_PATH_INVALID');
    }
    if (
      this.envelope.artifactSchema === 'TRIVY_JSON' &&
      isTrivyResultPath(objectPath) &&
      !TRIVY_RESULT_FIELDS.has(key)
    ) {
      this.unknownField();
    }

    const trivyKind = trivyRecordKind(objectPath);
    if (trivyKind && !this.allowedTrivyRecordFields(trivyKind).has(key)) {
      this.unknownField();
    }
    if (
      this.envelope.artifactSchema === 'TRIVY_JSON' &&
      isTrivyModifiedFindingPath(objectPath) &&
      !TRIVY_MODIFIED_FINDING_FIELDS.has(key)
    ) {
      this.unknownField();
    }
    if (
      this.envelope.artifactSchema === 'CYCLONEDX_JSON' &&
      isCycloneDxComponentPath(objectPath) &&
      !CYCLONEDX_COMPONENT_FIELDS.has(key)
    ) {
      this.unknownField();
    }
  }

  onPrimitive(path: JsonPath, value: JsonPrimitive): void {
    if (path.length === 0) {
      this.schemaInvalid();
      return;
    }
    if (this.isRequiredContainerField(path)) this.schemaInvalid();
    this.captureSchemaVersion(path, value);
    this.capturePinnedEnum(path, value);

    if (this.isArtifactPathField(path)) {
      this.capturePath(path, value);
    }
    if (this.isCoordinateField(path)) {
      this.captureCoordinate(path, value);
    }
    if (this.isRecordPath(path)) {
      this.recordCount += 1;
      this.schemaInvalid();
    }
    this.captureRequiredScalar(path, value);
  }

  finish(): void {
    if (this.rootKind !== 'OBJECT') {
      this.schemaInvalid();
      return;
    }

    if (this.envelope.artifactSchema === 'OPENGREP_SARIF') {
      if (
        !this.rootKeys.has('version') ||
        !this.rootKeys.has('runs') ||
        !this.runsSeen ||
        this.sarifRunCount === 0 ||
        !this.sarifVersionValid
      ) {
        this.requiredFieldMissing();
      }
    } else if (this.envelope.artifactSchema === 'TRIVY_JSON') {
      if (
        !this.rootKeys.has('SchemaVersion') ||
        !this.rootKeys.has('Results') ||
        !this.trivyResultsSeen ||
        !this.trivyVersionValid
      ) {
        this.requiredFieldMissing();
      }
    } else if (
      !this.rootKeys.has('bomFormat') ||
      !this.rootKeys.has('specVersion') ||
      !this.rootKeys.has('version') ||
      !this.rootKeys.has('components') ||
      !this.cyclonedxComponentsSeen ||
      !this.cyclonedxFormatValid ||
      !this.cyclonedxVersionValid
    ) {
      this.requiredFieldMissing();
    }
  }

  private onSarifContainer(path: JsonPath, kind: ContainerKind): void {
    if (matchesPath(path, ['runs'])) {
      this.runsSeen = kind === 'ARRAY';
      if (kind !== 'ARRAY') this.schemaInvalid();
    } else if (isSarifRunPath(path)) {
      if (kind !== 'OBJECT') {
        this.schemaInvalid();
      } else {
        this.sarifRunCount += 1;
        this.runKeys.set(keyForPath(path), new Set());
      }
    } else if (matchesPath(path, ['runs', '*', 'tool'])) {
      if (kind !== 'OBJECT') {
        this.schemaInvalid();
      } else {
        this.requiredObjects.set(keyForPath(path), {
          kind: 'SARIF_TOOL',
          keys: new Set()
        });
      }
    } else if (
      matchesPath(path, ['runs', '*', 'tool', 'driver'])
    ) {
      if (kind !== 'OBJECT') {
        this.schemaInvalid();
      } else {
        this.requiredObjects.set(keyForPath(path), {
          kind: 'SARIF_DRIVER',
          keys: new Set()
        });
      }
    } else if (matchesPath(path, ['runs', '*', 'results'])) {
      if (kind !== 'ARRAY') this.schemaInvalid();
    } else if (isSarifRecordPath(path)) {
      this.startRecord(path, kind, 'SARIF_RESULT');
    } else if (
      matchesPath(path, ['runs', '*', 'results', '*', 'message'])
    ) {
      if (kind !== 'OBJECT') {
        this.schemaInvalid();
      } else {
        this.requiredObjects.set(keyForPath(path), {
          kind: 'SARIF_RESULT_MESSAGE',
          keys: new Set()
        });
      }
    } else if (
      matchesPath(path, ['runs', '*', 'results', '*', 'locations'])
    ) {
      if (kind !== 'ARRAY') this.schemaInvalid();
    } else if (endsWithPath(path, ['physicalLocation'])) {
      if (kind !== 'OBJECT') {
        this.schemaInvalid();
      } else {
        this.physicalLocations.set(keyForPath(path), {});
      }
    }
  }

  private onTrivyContainer(path: JsonPath, kind: ContainerKind): void {
    if (matchesPath(path, ['Results'])) {
      this.trivyResultsSeen = kind === 'ARRAY';
      if (kind !== 'ARRAY') this.schemaInvalid();
    } else if (isTrivyResultPath(path)) {
      if (kind !== 'OBJECT') {
        this.schemaInvalid();
      } else {
        this.trivyResultKeys.set(path[1] as number, new Set());
      }
    } else if (isTrivyRecordArrayPath(path)) {
      if (kind !== 'ARRAY') this.schemaInvalid();
    } else if (isTrivyModifiedFindingPath(path)) {
      if (kind !== 'OBJECT') {
        this.schemaInvalid();
      } else {
        this.trivyModifiedFindingKeys.set(
          keyForPath(path),
          new Set()
        );
      }
    } else {
      const recordKind = trivyRecordKind(path);
      if (recordKind) this.startRecord(path, kind, recordKind);
    }
  }

  private onCycloneDxContainer(path: JsonPath, kind: ContainerKind): void {
    if (matchesPath(path, ['components'])) {
      this.cyclonedxComponentsSeen = kind === 'ARRAY';
      if (kind !== 'ARRAY') this.schemaInvalid();
    } else if (isCycloneDxComponentArrayPath(path)) {
      if (kind !== 'ARRAY') this.schemaInvalid();
    } else if (isCycloneDxComponentPath(path)) {
      this.startRecord(path, kind, 'CYCLONEDX_COMPONENT');
    }
  }

  private startRecord(
    path: JsonPath,
    kind: ContainerKind,
    recordKind: string
  ): void {
    this.recordCount += 1;
    if (this.recordCount > this.maximumRecordCount()) {
      this.reasons.add('ARTIFACT_RECORD_LIMIT_EXCEEDED');
      return;
    }
    if (kind !== 'OBJECT') {
      this.schemaInvalid();
      return;
    }
    this.recordStates.set(keyForPath(path), {
      kind: recordKind,
      keys: new Set(),
      ...(recordKind.startsWith('TRIVY_') &&
      typeof path[1] === 'number'
        ? { trivyResultIndex: path[1] }
        : {})
    });
  }

  private captureSchemaVersion(path: JsonPath, value: JsonPrimitive): void {
    if (
      this.envelope.artifactSchema === 'OPENGREP_SARIF' &&
      matchesPath(path, ['version'])
    ) {
      this.sarifVersionValid =
        value === SAST_ARTIFACT_SCHEMA_VERSIONS.OPENGREP_SARIF;
      if (!this.sarifVersionValid) this.schemaInvalid();
    } else if (
      this.envelope.artifactSchema === 'TRIVY_JSON' &&
      matchesPath(path, ['SchemaVersion'])
    ) {
      this.trivyVersionValid =
        value === Number(SAST_ARTIFACT_SCHEMA_VERSIONS.TRIVY_JSON);
      if (!this.trivyVersionValid) this.schemaInvalid();
    } else if (
      this.envelope.artifactSchema === 'CYCLONEDX_JSON' &&
      matchesPath(path, ['bomFormat'])
    ) {
      this.cyclonedxFormatValid = value === 'CycloneDX';
      if (!this.cyclonedxFormatValid) this.schemaInvalid();
    } else if (
      this.envelope.artifactSchema === 'CYCLONEDX_JSON' &&
      matchesPath(path, ['specVersion'])
    ) {
      this.cyclonedxVersionValid =
        value === SAST_ARTIFACT_SCHEMA_VERSIONS.CYCLONEDX_JSON;
      if (!this.cyclonedxVersionValid) this.schemaInvalid();
    } else if (
      this.envelope.artifactSchema === 'CYCLONEDX_JSON' &&
      matchesPath(path, ['version']) &&
      (!Number.isSafeInteger(value) || (value as number) <= 0)
    ) {
      this.schemaInvalid();
    }
  }

  private capturePinnedEnum(
    path: JsonPath,
    value: JsonPrimitive
  ): void {
    const allowed = this.pinnedEnumValues(path);
    if (
      allowed &&
      (typeof value !== 'string' || !allowed.has(value))
    ) {
      this.schemaInvalid();
    }
  }

  private pinnedEnumValues(path: JsonPath): ReadonlySet<string> | null {
    const key = path.at(-1);
    if (
      this.envelope.artifactSchema === 'OPENGREP_SARIF' &&
      matchesPath(path, ['runs', '*', 'columnKind'])
    ) {
      return SARIF_COLUMN_KINDS;
    }
    if (
      this.envelope.artifactSchema === 'TRIVY_JSON' &&
      matchesPath(path, ['Results', '*', 'Class'])
    ) {
      return TRIVY_RESULT_CLASSES;
    }
    if (
      this.envelope.artifactSchema === 'TRIVY_JSON' &&
      matchesPath(path, [
        'Results',
        '*',
        'ExperimentalModifiedFindings',
        '*',
        'Type'
      ])
    ) {
      return TRIVY_MODIFIED_FINDING_TYPES;
    }
    if (
      this.envelope.artifactSchema === 'TRIVY_JSON' &&
      matchesPath(path, [
        'Results',
        '*',
        'ExperimentalModifiedFindings',
        '*',
        'Status'
      ])
    ) {
      return TRIVY_MODIFIED_FINDING_STATUSES;
    }
    const record = this.recordStates.get(
      keyForPath(path.slice(0, -1))
    );
    if (record?.kind === 'SARIF_RESULT') {
      if (key === 'kind') return SARIF_RESULT_KINDS;
      if (key === 'level') return SARIF_LEVELS;
      if (key === 'baselineState') return SARIF_BASELINE_STATES;
    }
    if (record?.kind === 'CYCLONEDX_COMPONENT') {
      if (key === 'type') return CYCLONEDX_COMPONENT_TYPES;
      if (key === 'scope') return CYCLONEDX_COMPONENT_SCOPES;
    }
    if (record?.kind.startsWith('TRIVY_')) {
      if (key === 'Severity') return TRIVY_SEVERITIES;
      if (
        record.kind === 'TRIVY_VULNERABILITY' &&
        key === 'Status'
      ) {
        return TRIVY_VULNERABILITY_STATUSES;
      }
      if (
        record.kind === 'TRIVY_MISCONFIGURATION' &&
        key === 'Status'
      ) {
        return TRIVY_MISCONFIGURATION_STATUSES;
      }
    }
    return null;
  }

  private captureRequiredScalar(
    path: JsonPath,
    value: JsonPrimitive
  ): void {
    if (
      this.envelope.artifactSchema === 'OPENGREP_SARIF' &&
      (matchesPath(path, ['runs', '*', 'tool', 'driver', 'name']) ||
        matchesPath(path, [
          'runs',
          '*',
          'results',
          '*',
          'message',
          'text'
        ]) ||
        matchesPath(path, [
          'runs',
          '*',
          'results',
          '*',
          'message',
          'id'
        ]) ||
        this.isSarifPhysicalUriBaseIdField(path)) &&
      typeof value !== 'string'
    ) {
      this.schemaInvalid();
    }
    if (
      this.envelope.artifactSchema === 'OPENGREP_SARIF' &&
      this.isSarifPhysicalUriBaseIdField(path) &&
      value !== '%SRCROOT%'
    ) {
      this.reasons.add('ARTIFACT_PATH_INVALID');
    }

    if (
      this.envelope.artifactSchema === 'TRIVY_JSON' &&
      matchesPath(path, ['Results', '*', 'Target'])
    ) {
      if (typeof value !== 'string') {
        this.schemaInvalid();
      } else if (value === '.') {
        this.trivyTargets.delete(path[1] as number);
      } else {
        const normalized = this.validatePath(value);
        if (normalized) this.trivyTargets.set(path[1] as number, normalized);
      }
    }

    const recordPath = path.slice(0, -1);
    const record = this.recordStates.get(keyForPath(recordPath));
    if (!record) return;
    const key = path.at(-1);
    if (
      (record.kind === 'SARIF_RESULT' && key === 'ruleId') ||
      (record.kind === 'TRIVY_VULNERABILITY' &&
        (key === 'VulnerabilityID' || key === 'PkgName')) ||
      (record.kind === 'TRIVY_MISCONFIGURATION' &&
        (key === 'ID' || key === 'Title')) ||
      (record.kind === 'TRIVY_SECRET' &&
        (key === 'RuleID' || key === 'Title')) ||
      (record.kind === 'CYCLONEDX_COMPONENT' &&
        (key === 'type' || key === 'name'))
    ) {
      if (
        typeof value !== 'string' ||
        value.length === 0 ||
        value !== value.trim()
      ) {
        this.schemaInvalid();
      }
    }
  }

  private capturePath(path: JsonPath, value: JsonPrimitive): void {
    if (typeof value !== 'string') {
      this.reasons.add('ARTIFACT_PATH_INVALID');
      return;
    }
    const pathValue =
      this.envelope.artifactSchema === 'OPENGREP_SARIF'
        ? decodeSarifArtifactUri(value)
        : value;
    if (!pathValue) {
      this.reasons.add('ARTIFACT_PATH_INVALID');
      return;
    }
    const normalized = this.validatePath(pathValue);
    if (!normalized) return;

    const physicalPath = path.slice(
      0,
      path.lastIndexOf('physicalLocation') + 1
    );
    const physical = this.physicalLocations.get(keyForPath(physicalPath));
    if (physical) {
      physical.path = normalized;
      return;
    }

    const record = this.findRecordState(path);
    if (record) {
      record.path = normalized;
    } else {
      this.validateLocation({ path: normalized });
    }
  }

  private captureCoordinate(path: JsonPath, value: JsonPrimitive): void {
    this.coordinateCount += 1;
    const coordinateName = path.at(-1);
    if (
      typeof coordinateName !== 'string' ||
      typeof value !== 'number' ||
      !Number.isSafeInteger(value) ||
      value <= 0 ||
      value > SAST_MAX_COORDINATE_VALUE
    ) {
      this.reasons.add('ARTIFACT_COORDINATE_INVALID');
      return;
    }

    const location =
      this.findPhysicalLocation(path) ?? this.findRecordState(path);
    if (!location) {
      this.reasons.add('ARTIFACT_COORDINATE_ATTESTATION_MISSING');
      return;
    }
    if (isLineStartKey(coordinateName)) location.lineStart = value;
    else if (isLineEndKey(coordinateName)) location.lineEnd = value;
    else if (isColumnStartKey(coordinateName)) {
      location.columnStart = value;
    } else if (isColumnEndKey(coordinateName)) {
      location.columnEnd = value;
    }
  }

  private validateRecord(record: RecordState): void {
    const required =
      record.kind === 'SARIF_RESULT'
        ? ['ruleId', 'message']
        : record.kind === 'TRIVY_VULNERABILITY'
          ? ['VulnerabilityID', 'PkgName']
          : record.kind === 'TRIVY_MISCONFIGURATION'
            ? ['ID', 'Title']
            : record.kind === 'TRIVY_SECRET'
              ? ['RuleID', 'Title', 'StartLine', 'EndLine']
              : record.kind === 'TRIVY_MODIFIED_FINDING'
                ? []
                : ['type', 'name'];
    if (required.some((key) => !record.keys.has(key))) {
      this.requiredFieldMissing();
    }

    if (record.kind.startsWith('TRIVY_')) {
      const target = this.currentTrivyTarget(record);
      if (!record.path && target) record.path = target;
      if (
        !record.path &&
        record.trivyResultIndex !== undefined &&
        !this.trivyResultKeys
          .get(record.trivyResultIndex)
          ?.has('Target')
      ) {
        const pending =
          this.pendingTrivyLocations.get(record.trivyResultIndex) ?? [];
        pending.push({
          ...(record.lineStart === undefined
            ? {}
            : { lineStart: record.lineStart }),
          ...(record.lineEnd === undefined
            ? {}
            : { lineEnd: record.lineEnd }),
          ...(record.columnStart === undefined
            ? {}
            : { columnStart: record.columnStart }),
          ...(record.columnEnd === undefined
            ? {}
            : { columnEnd: record.columnEnd })
        });
        this.pendingTrivyLocations.set(
          record.trivyResultIndex,
          pending
        );
        return;
      }
    }
    if (
      record.path ||
      record.lineStart ||
      record.lineEnd ||
      record.columnStart ||
      record.columnEnd
    ) {
      this.validateLocation(record);
    }
  }

  private currentTrivyTarget(record: RecordState): string | undefined {
    return record.trivyResultIndex === undefined
      ? undefined
      : this.trivyTargets.get(record.trivyResultIndex);
  }

  private finishTrivyResult(resultIndex: number): void {
    const keys = this.trivyResultKeys.get(resultIndex);
    if (!keys?.has('Target')) this.requiredFieldMissing();

    const target = this.trivyTargets.get(resultIndex);
    if (target) this.validateLocation({ path: target });
    for (const pending of this.pendingTrivyLocations.get(resultIndex) ??
      []) {
      if (target) pending.path = target;
      if (
        pending.path ||
        pending.lineStart ||
        pending.lineEnd ||
        pending.columnStart ||
        pending.columnEnd
      ) {
        this.validateLocation(pending);
      }
    }
    this.pendingTrivyLocations.delete(resultIndex);
    this.trivyResultKeys.delete(resultIndex);
    this.trivyTargets.delete(resultIndex);
  }

  private maximumRecordCount(): number {
    return this.envelope.artifactSchema === 'CYCLONEDX_JSON'
      ? this.plan.profile.limits.maxArtifactRecords
      : Math.min(
          this.plan.profile.limits.maxArtifactRecords,
          this.plan.profile.limits.maxFindings
        );
  }

  private validateLocation(location: LocationState): void {
    if (!location.path || !this.fileCoordinates) {
      this.reasons.add('ARTIFACT_COORDINATE_ATTESTATION_MISSING');
      return;
    }
    const metadata = this.fileCoordinates.get(location.path);
    if (!metadata) {
      this.reasons.add('ARTIFACT_COORDINATE_ATTESTATION_MISSING');
      return;
    }
    if (
      location.lineStart === undefined &&
      location.lineEnd === undefined &&
      location.columnStart === undefined &&
      location.columnEnd === undefined
    ) {
      return;
    }
    if (
      location.lineStart === undefined ||
      !isSastFindingLocationValid(
        {
          kind: 'FILE',
          normalizedPath: location.path,
          lineStart: location.lineStart,
          ...(location.lineEnd === undefined
            ? {}
            : { lineEnd: location.lineEnd }),
          ...(location.columnStart === undefined
            ? {}
            : { columnStart: location.columnStart }),
          ...(location.columnEnd === undefined
            ? {}
            : { columnEnd: location.columnEnd })
        },
        metadata
      )
    ) {
      this.reasons.add('ARTIFACT_COORDINATE_INVALID');
    }
  }

  private validatePath(value: string): string | null {
    const normalized = normalizeArtifactPath(
      value,
      this.plan.profile.limits.maxPathDepth
    );
    if (!normalized || normalized !== value) {
      this.reasons.add('ARTIFACT_PATH_INVALID');
      return null;
    }

    const exactHash = digest(normalized);
    const foldedHash = digest(
      normalized.toLocaleLowerCase('en-US').normalize('NFC')
    );
    if (
      !this.exactPathHashes.has(exactHash) &&
      this.exactPathHashes.size >=
        Math.min(
          this.plan.profile.limits.maxFileCount,
          this.plan.profile.limits.maxArtifactRecords
        )
    ) {
      this.reasons.add('ARTIFACT_PATH_LIMIT_EXCEEDED');
      return null;
    }
    const previous = this.foldedPathHashes.get(foldedHash);
    if (previous && previous !== exactHash) {
      this.reasons.add('ARTIFACT_PATH_COLLISION');
    }
    this.foldedPathHashes.set(foldedHash, exactHash);
    this.exactPathHashes.add(exactHash);
    return normalized;
  }

  private findPhysicalLocation(path: JsonPath): LocationState | undefined {
    const index = path.lastIndexOf('physicalLocation');
    return index < 0
      ? undefined
      : this.physicalLocations.get(
          keyForPath(path.slice(0, index + 1))
        );
  }

  private findRecordState(path: JsonPath): RecordState | undefined {
    for (let length = path.length - 1; length > 0; length -= 1) {
      const record = this.recordStates.get(
        keyForPath(path.slice(0, length))
      );
      if (record) return record;
    }
    return undefined;
  }

  private isArtifactPathField(path: JsonPath): boolean {
    if (this.envelope.artifactSchema === 'OPENGREP_SARIF') {
      return (
        path.at(-1) === 'uri' &&
        path.includes('artifactLocation') &&
        path.includes('physicalLocation')
      );
    }
    if (this.envelope.artifactSchema === 'TRIVY_JSON') {
      return ['PkgPath', 'FilePath'].includes(
        String(path.at(-1))
      );
    }
    return false;
  }

  private isCoordinateField(path: JsonPath): boolean {
    const key = String(path.at(-1));
    const coordinateKey =
      isLineStartKey(key) ||
      isLineEndKey(key) ||
      isColumnStartKey(key) ||
      isColumnEndKey(key);
    if (!coordinateKey) return false;
    if (this.envelope.artifactSchema === 'OPENGREP_SARIF') {
      return (
        path.includes('physicalLocation') &&
        path.includes('region') &&
        (key === 'startLine' ||
          key === 'endLine' ||
          key === 'startColumn' ||
          key === 'endColumn')
      );
    }
    if (this.envelope.artifactSchema === 'TRIVY_JSON') {
      const recordPath =
        path[2] === 'ExperimentalModifiedFindings'
          ? path.slice(0, 5)
          : path.slice(0, 4);
      const recordKind = trivyRecordKind(recordPath);
      if (!recordKind) return false;
      return (
        recordKind === 'TRIVY_SECRET' ||
        recordKind === 'TRIVY_MODIFIED_FINDING' ||
        path.includes('CauseMetadata')
      );
    }
    return false;
  }

  private isPinnedEnumField(path: JsonPath): boolean {
    return this.pinnedEnumValues(path) !== null;
  }

  private isRequiredScalarField(path: JsonPath): boolean {
    if (this.envelope.artifactSchema === 'OPENGREP_SARIF') {
      return (
        matchesPath(path, ['version']) ||
        matchesPath(path, ['runs', '*', 'tool', 'driver', 'name']) ||
        matchesPath(path, ['runs', '*', 'results', '*', 'ruleId']) ||
        matchesPath(path, [
          'runs',
          '*',
          'results',
          '*',
          'message',
          'text'
        ]) ||
        matchesPath(path, [
          'runs',
          '*',
          'results',
          '*',
          'message',
          'id'
        ]) ||
        this.isSarifPhysicalUriBaseIdField(path)
      );
    }
    if (this.envelope.artifactSchema === 'TRIVY_JSON') {
      if (
        matchesPath(path, ['SchemaVersion']) ||
        matchesPath(path, ['Results', '*', 'Target'])
      ) {
        return true;
      }
      const record = this.findRecordState(path);
      const key = path.at(-1);
      return Boolean(
        record &&
          ((record.kind === 'TRIVY_VULNERABILITY' &&
            (key === 'VulnerabilityID' || key === 'PkgName')) ||
            (record.kind === 'TRIVY_MISCONFIGURATION' &&
              (key === 'ID' || key === 'Title')) ||
            (record.kind === 'TRIVY_SECRET' &&
              (key === 'RuleID' || key === 'Title')))
      );
    }
    const component = this.findRecordState(path);
    return (
      matchesPath(path, ['bomFormat']) ||
      matchesPath(path, ['specVersion']) ||
      matchesPath(path, ['version']) ||
      Boolean(
        component?.kind === 'CYCLONEDX_COMPONENT' &&
          (path.at(-1) === 'type' || path.at(-1) === 'name')
      )
    );
  }

  private isRequiredContainerField(path: JsonPath): boolean {
    if (this.envelope.artifactSchema === 'OPENGREP_SARIF') {
      return (
        matchesPath(path, ['runs']) ||
        isSarifRunPath(path) ||
        matchesPath(path, ['runs', '*', 'tool']) ||
        matchesPath(path, ['runs', '*', 'tool', 'driver']) ||
        matchesPath(path, ['runs', '*', 'results']) ||
        matchesPath(path, [
          'runs',
          '*',
          'results',
          '*',
          'message'
        ]) ||
        matchesPath(path, [
          'runs',
          '*',
          'results',
          '*',
          'locations'
        ])
      );
    }
    if (this.envelope.artifactSchema === 'TRIVY_JSON') {
      return (
        matchesPath(path, ['Results']) ||
        isTrivyResultPath(path) ||
        isTrivyRecordArrayPath(path) ||
        isTrivyModifiedFindingPath(path)
      );
    }
    return isCycloneDxComponentArrayPath(path);
  }

  private isRecordPath(path: JsonPath): boolean {
    return (
      (this.envelope.artifactSchema === 'OPENGREP_SARIF' &&
        isSarifRecordPath(path)) ||
      (this.envelope.artifactSchema === 'TRIVY_JSON' &&
        trivyRecordKind(path) !== null) ||
      (this.envelope.artifactSchema === 'CYCLONEDX_JSON' &&
        isCycloneDxComponentPath(path))
    );
  }

  private isSarifPhysicalUriBaseIdField(path: JsonPath): boolean {
    return (
      this.envelope.artifactSchema === 'OPENGREP_SARIF' &&
      path.at(-1) === 'uriBaseId' &&
      path.at(-2) === 'artifactLocation' &&
      path.includes('physicalLocation')
    );
  }

  private allowedRootFields(): ReadonlySet<string> {
    if (this.envelope.artifactSchema === 'OPENGREP_SARIF') {
      return SARIF_ROOT_FIELDS;
    }
    if (this.envelope.artifactSchema === 'TRIVY_JSON') {
      return TRIVY_ROOT_FIELDS;
    }
    return CYCLONEDX_ROOT_FIELDS;
  }

  private allowedTrivyRecordFields(kind: string): ReadonlySet<string> {
    if (kind === 'TRIVY_VULNERABILITY') {
      return TRIVY_VULNERABILITY_FIELDS;
    }
    if (kind === 'TRIVY_MISCONFIGURATION') {
      return TRIVY_MISCONFIGURATION_FIELDS;
    }
    if (kind === 'TRIVY_MODIFIED_FINDING') {
      return TRIVY_MODIFIED_RECORD_FIELDS;
    }
    return TRIVY_SECRET_FIELDS;
  }

  private requiredFieldMissing(): void {
    this.reasons.add('ARTIFACT_SCHEMA_REQUIRED_FIELD_MISSING');
  }

  private unknownField(): void {
    this.reasons.add('ARTIFACT_SCHEMA_UNKNOWN_FIELD');
  }

  private schemaInvalid(): void {
    this.reasons.add('ARTIFACT_SCHEMA_FIELD_INVALID');
  }
}

export function decodeSarifArtifactUri(value: string): string | null {
  if (
    value.includes('?') ||
    value.includes('#') ||
    /%(?:2F|5C)/u.test(value) ||
    /%(?:3[0-9]|[46][1-9A-F]|5[0-9A]|7[0-9A])/u.test(value) ||
    /%(?:2D|2E|5F|7E)/u.test(value)
  ) {
    return null;
  }
  for (let index = 0; index < value.length; index += 1) {
    if (value[index] !== '%') continue;
    if (!/^[0-9A-F]{2}$/u.test(value.slice(index + 1, index + 3))) {
      return null;
    }
    index += 2;
  }
  try {
    return decodeURIComponent(value);
  } catch {
    return null;
  }
}

export function normalizeArtifactPath(
  value: unknown,
  maximumDepth: number
): string | null {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value !== value.normalize('NFC') ||
    Buffer.byteLength(value, 'utf8') > 1024 ||
    value.includes('\\') ||
    value.startsWith('/') ||
    value.startsWith('//') ||
    /^[A-Za-z]:/u.test(value) ||
    /^[A-Za-z][A-Za-z0-9+.-]*:/u.test(value) ||
    [...value].some((character) => {
      const codePoint = character.codePointAt(0)!;
      return (
        codePoint <= 0x1f ||
        (codePoint >= 0x7f && codePoint <= 0x9f) ||
        (codePoint >= 0xd800 && codePoint <= 0xdfff)
      );
    })
  ) {
    return null;
  }
  const segments = value.split('/');
  if (
    segments.length > maximumDepth ||
    segments.some(
      (segment) =>
        segment.length === 0 || segment === '.' || segment === '..'
    )
  ) {
    return null;
  }
  return segments.join('/');
}

function isSarifRunPath(path: JsonPath): boolean {
  return matchesPath(path, ['runs', '*']);
}

function isSarifRecordPath(path: JsonPath): boolean {
  return matchesPath(path, ['runs', '*', 'results', '*']);
}

function isTrivyResultPath(path: JsonPath): boolean {
  return matchesPath(path, ['Results', '*']);
}

function isTrivyRecordArrayPath(path: JsonPath): boolean {
  return (
    matchesPath(path, ['Results', '*', '*']) &&
    (TRIVY_RECORD_ARRAYS.has(String(path[2])) ||
      path[2] === 'ExperimentalModifiedFindings')
  );
}

function trivyRecordKind(path: JsonPath): string | null {
  if (
    path.length === 5 &&
    path[0] === 'Results' &&
    typeof path[1] === 'number' &&
    path[2] === 'ExperimentalModifiedFindings' &&
    typeof path[3] === 'number' &&
    path[4] === 'Finding'
  ) {
    return 'TRIVY_MODIFIED_FINDING';
  }
  if (
    path.length !== 4 ||
    path[0] !== 'Results' ||
    typeof path[1] !== 'number' ||
    typeof path[3] !== 'number'
  ) {
    return null;
  }
  return path[2] === 'Vulnerabilities'
    ? 'TRIVY_VULNERABILITY'
    : path[2] === 'Misconfigurations'
      ? 'TRIVY_MISCONFIGURATION'
      : path[2] === 'Secrets'
        ? 'TRIVY_SECRET'
        : null;
}

function isTrivyModifiedFindingPath(path: JsonPath): boolean {
  return (
    path.length === 4 &&
    path[0] === 'Results' &&
    typeof path[1] === 'number' &&
    path[2] === 'ExperimentalModifiedFindings' &&
    typeof path[3] === 'number'
  );
}

function isCycloneDxComponentArrayPath(path: JsonPath): boolean {
  return path.at(-1) === 'components';
}

function isCycloneDxComponentPath(path: JsonPath): boolean {
  return (
    path.length >= 2 &&
    path.at(-2) === 'components' &&
    typeof path.at(-1) === 'number'
  );
}

function matchesPath(
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

function endsWithPath(
  path: JsonPath,
  suffix: readonly string[]
): boolean {
  return (
    suffix.length <= path.length &&
    suffix.every(
      (segment, index) =>
        path[path.length - suffix.length + index] === segment
    )
  );
}

function keyForPath(path: JsonPath): string {
  return JSON.stringify(path);
}

function hasOnlyObjectKeys(
  value: object,
  expected: readonly string[]
): boolean {
  const keys = Object.keys(value);
  return (
    keys.length === expected.length &&
    keys.every((key) => expected.includes(key))
  );
}

function isLineStartKey(key: string): boolean {
  return key === 'startLine' || key === 'StartLine';
}

function isLineEndKey(key: string): boolean {
  return key === 'endLine' || key === 'EndLine';
}

function isColumnStartKey(key: string): boolean {
  return key === 'startColumn' || key === 'StartColumn';
}

function isColumnEndKey(key: string): boolean {
  return key === 'endColumn' || key === 'EndColumn';
}

function isJsonDelimiter(byte: number): boolean {
  return (
    byte === 0x20 ||
    byte === 0x09 ||
    byte === 0x0a ||
    byte === 0x0d ||
    byte === 0x2c ||
    byte === 0x5d ||
    byte === 0x7d
  );
}

function hexDigitValue(byte: number): number | null {
  if (byte >= 0x30 && byte <= 0x39) return byte - 0x30;
  if (byte >= 0x41 && byte <= 0x46) return byte - 0x41 + 10;
  if (byte >= 0x61 && byte <= 0x66) return byte - 0x61 + 10;
  return null;
}

function hasUnpairedSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function validationFault(
  reasonCode: SastArtifactValidationReasonCode
): ArtifactValidationFault {
  const error = new Error(reasonCode) as ArtifactValidationFault;
  error.name = 'ArtifactValidationFault';
  error.reasonCode = reasonCode;
  return error;
}

function isValidationFault(
  error: unknown
): error is ArtifactValidationFault {
  return (
    error instanceof Error &&
    'reasonCode' in error &&
    SAST_ARTIFACT_VALIDATION_REASON_CODES.includes(
      (error as ArtifactValidationFault).reasonCode
    )
  );
}

function digest(value: string): `sha256:${string}` {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}
