import {
  SAST_ARTIFACT_SCHEMAS,
  type SastArtifactSchema
} from './sast-runtime';

export const SAST_ARTIFACT_VALIDATION_VERSION =
  'sast-artifact-validation-v1' as const;

export const SAST_ARTIFACT_VALIDATION_LIMITS = Object.freeze({
  maximumJsonDepth: 64,
  maximumKeyBytes: 256,
  maximumObjectKeys: 4096,
  maximumStringBytes: 4096,
  maximumNumberTokenBytes: 128,
  maximumTokenCount: 5_000_000,
  maximumCoordinateAttestationLines: 5_000_000,
  parserSliceBytes: 4096
});

export const SAST_ARTIFACT_VALIDATION_REASON_CODES = [
  'ARTIFACT_PLAN_BINDING_MISMATCH',
  'ARTIFACT_SCHEMA_VERSION_MISMATCH',
  'ARTIFACT_CONTENT_DIGEST_MISMATCH',
  'ARTIFACT_BYTE_SIZE_MISMATCH',
  'ARTIFACT_RECORD_COUNT_MISMATCH',
  'ARTIFACT_RECORD_LIMIT_EXCEEDED',
  'ARTIFACT_INVALID_UTF8',
  'ARTIFACT_JSON_MALFORMED',
  'ARTIFACT_JSON_DUPLICATE_KEY',
  'ARTIFACT_JSON_DEPTH_LIMIT_EXCEEDED',
  'ARTIFACT_JSON_KEY_LIMIT_EXCEEDED',
  'ARTIFACT_JSON_KEY_COUNT_LIMIT_EXCEEDED',
  'ARTIFACT_JSON_STRING_LIMIT_EXCEEDED',
  'ARTIFACT_JSON_NUMBER_LIMIT_EXCEEDED',
  'ARTIFACT_JSON_TOKEN_LIMIT_EXCEEDED',
  'ARTIFACT_SCHEMA_REQUIRED_FIELD_MISSING',
  'ARTIFACT_SCHEMA_UNKNOWN_FIELD',
  'ARTIFACT_SCHEMA_FIELD_INVALID',
  'ARTIFACT_PATH_INVALID',
  'ARTIFACT_PATH_COLLISION',
  'ARTIFACT_PATH_LIMIT_EXCEEDED',
  'ARTIFACT_COORDINATE_INVALID',
  'ARTIFACT_COORDINATE_ATTESTATION_MISSING'
] as const;
export type SastArtifactValidationReasonCode =
  (typeof SAST_ARTIFACT_VALIDATION_REASON_CODES)[number];

export interface SastArtifactValidationChecks {
  planBinding: boolean;
  schema: boolean;
  contentDigest: boolean;
  byteSize: boolean;
  recordCount: boolean;
  encoding: boolean;
  jsonStructure: boolean;
  path: boolean;
  coordinate: boolean;
}

export interface SastArtifactValidationStatistics {
  observedByteSize: number;
  observedRecordCount: number;
  maximumObservedDepth: number;
  maximumObservedStringBytes: number;
  normalizedPathCount: number;
  coordinateCount: number;
}

export interface SastArtifactValidationResult {
  version: typeof SAST_ARTIFACT_VALIDATION_VERSION;
  outcome: 'PASSED' | 'FAILED';
  artifactSchema: SastArtifactSchema;
  envelopeDigest: `sha256:${string}`;
  observedContentDigest: `sha256:${string}`;
  checks: Readonly<SastArtifactValidationChecks>;
  reasonCodes: readonly SastArtifactValidationReasonCode[];
  statistics: Readonly<SastArtifactValidationStatistics>;
  resultDigest: `sha256:${string}`;
}

export type SastArtifactValidationResultCore = Omit<
  SastArtifactValidationResult,
  'resultDigest'
>;

export function deriveSastArtifactValidationChecks(
  reasonCodes: readonly SastArtifactValidationReasonCode[]
): SastArtifactValidationChecks {
  const reasons = new Set(reasonCodes);
  const hasAny = (
    candidates: readonly SastArtifactValidationReasonCode[]
  ) => candidates.some((reason) => reasons.has(reason));

  return {
    planBinding: !reasons.has('ARTIFACT_PLAN_BINDING_MISMATCH'),
    schema: !hasAny([
      'ARTIFACT_SCHEMA_VERSION_MISMATCH',
      'ARTIFACT_SCHEMA_REQUIRED_FIELD_MISSING',
      'ARTIFACT_SCHEMA_UNKNOWN_FIELD',
      'ARTIFACT_SCHEMA_FIELD_INVALID'
    ]),
    contentDigest: !reasons.has('ARTIFACT_CONTENT_DIGEST_MISMATCH'),
    byteSize: !reasons.has('ARTIFACT_BYTE_SIZE_MISMATCH'),
    recordCount: !hasAny([
      'ARTIFACT_RECORD_COUNT_MISMATCH',
      'ARTIFACT_RECORD_LIMIT_EXCEEDED'
    ]),
    encoding: !reasons.has('ARTIFACT_INVALID_UTF8'),
    jsonStructure: !hasAny([
      'ARTIFACT_JSON_MALFORMED',
      'ARTIFACT_JSON_DUPLICATE_KEY',
      'ARTIFACT_JSON_DEPTH_LIMIT_EXCEEDED',
      'ARTIFACT_JSON_KEY_LIMIT_EXCEEDED',
      'ARTIFACT_JSON_KEY_COUNT_LIMIT_EXCEEDED',
      'ARTIFACT_JSON_STRING_LIMIT_EXCEEDED',
      'ARTIFACT_JSON_NUMBER_LIMIT_EXCEEDED',
      'ARTIFACT_JSON_TOKEN_LIMIT_EXCEEDED'
    ]),
    path: !hasAny([
      'ARTIFACT_PATH_INVALID',
      'ARTIFACT_PATH_COLLISION',
      'ARTIFACT_PATH_LIMIT_EXCEEDED'
    ]),
    coordinate: !hasAny([
      'ARTIFACT_COORDINATE_INVALID',
      'ARTIFACT_COORDINATE_ATTESTATION_MISSING'
    ])
  };
}

export function canonicalizeSastArtifactValidationResult(
  result: Readonly<SastArtifactValidationResultCore>
): string {
  return JSON.stringify({
    version: result.version,
    outcome: result.outcome,
    artifactSchema: result.artifactSchema,
    envelopeDigest: result.envelopeDigest,
    observedContentDigest: result.observedContentDigest,
    checks: {
      planBinding: result.checks.planBinding,
      schema: result.checks.schema,
      contentDigest: result.checks.contentDigest,
      byteSize: result.checks.byteSize,
      recordCount: result.checks.recordCount,
      encoding: result.checks.encoding,
      jsonStructure: result.checks.jsonStructure,
      path: result.checks.path,
      coordinate: result.checks.coordinate
    },
    reasonCodes: [...result.reasonCodes],
    statistics: {
      observedByteSize: result.statistics.observedByteSize,
      observedRecordCount: result.statistics.observedRecordCount,
      maximumObservedDepth: result.statistics.maximumObservedDepth,
      maximumObservedStringBytes:
        result.statistics.maximumObservedStringBytes,
      normalizedPathCount: result.statistics.normalizedPathCount,
      coordinateCount: result.statistics.coordinateCount
    }
  });
}

export function isSastArtifactValidationResultShapeValid(
  value: unknown
): value is SastArtifactValidationResult {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;

  const result = value as Record<string, unknown>;
  const checks = result.checks as Record<string, unknown> | undefined;
  const statistics = result.statistics as Record<string, unknown> | undefined;
  const reasonCodes = result.reasonCodes;
  if (
    !hasOnlyKeys(result, [
      'version',
      'outcome',
      'artifactSchema',
      'envelopeDigest',
      'observedContentDigest',
      'checks',
      'reasonCodes',
      'statistics',
      'resultDigest'
    ]) ||
    result.version !== SAST_ARTIFACT_VALIDATION_VERSION ||
    (result.outcome !== 'PASSED' && result.outcome !== 'FAILED') ||
    !SAST_ARTIFACT_SCHEMAS.includes(
      result.artifactSchema as SastArtifactSchema
    ) ||
    !isSha256Digest(result.envelopeDigest) ||
    !isSha256Digest(result.observedContentDigest) ||
    !checks ||
    !statistics ||
    !Array.isArray(reasonCodes) ||
    !isSha256Digest(result.resultDigest)
  ) {
    return false;
  }

  const checkKeys: readonly (keyof SastArtifactValidationChecks)[] = [
    'planBinding',
    'schema',
    'contentDigest',
    'byteSize',
    'recordCount',
    'encoding',
    'jsonStructure',
    'path',
    'coordinate'
  ];
  const statisticKeys: readonly (keyof SastArtifactValidationStatistics)[] = [
    'observedByteSize',
    'observedRecordCount',
    'maximumObservedDepth',
    'maximumObservedStringBytes',
    'normalizedPathCount',
    'coordinateCount'
  ];
  const reasonsValid =
    reasonCodes.every((reason) =>
      SAST_ARTIFACT_VALIDATION_REASON_CODES.includes(
        reason as SastArtifactValidationReasonCode
      )
    ) &&
    reasonCodes.every(
      (reason, index) =>
        index === 0 ||
        SAST_ARTIFACT_VALIDATION_REASON_CODES.indexOf(
          reasonCodes[index - 1] as SastArtifactValidationReasonCode
        ) <
          SAST_ARTIFACT_VALIDATION_REASON_CODES.indexOf(
            reason as SastArtifactValidationReasonCode
          )
    );
  const checksValid =
    hasOnlyKeys(checks, checkKeys) &&
    checkKeys.every((key) => typeof checks[key] === 'boolean');
  const derivedChecks = reasonsValid
    ? deriveSastArtifactValidationChecks(
        reasonCodes as SastArtifactValidationReasonCode[]
      )
    : null;
  const checksConsistent =
    checksValid &&
    derivedChecks !== null &&
    checkKeys.every((key) => checks[key] === derivedChecks[key]);
  const statisticsValid =
    hasOnlyKeys(statistics, statisticKeys) &&
    statisticKeys.every(
      (key) =>
        typeof statistics[key] === 'number' &&
        Number.isSafeInteger(statistics[key]) &&
        (statistics[key] as number) >= 0
    );
  const allChecksPassed =
    checksValid && checkKeys.every((key) => checks[key] === true);

  return (
    reasonsValid &&
    checksConsistent &&
    statisticsValid &&
    (result.outcome === 'PASSED'
      ? allChecksPassed && reasonCodes.length === 0
      : !allChecksPassed && reasonCodes.length > 0)
  );
}

function hasOnlyKeys(
  value: Record<string, unknown>,
  keys: readonly string[]
): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && actual.every((key) => keys.includes(key));
}

function isSha256Digest(value: unknown): value is `sha256:${string}` {
  return (
    typeof value === 'string' && /^sha256:[a-f0-9]{64}$/u.test(value)
  );
}
