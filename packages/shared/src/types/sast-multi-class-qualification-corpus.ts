import {
  SAST_PROFILE_IDS,
  type SastProfileId
} from './sast-runtime';

export const SAST_MULTI_CLASS_QUALIFICATION_FIXTURE_VERSION =
  'sast-multi-class-qualification-fixture-v1' as const;
export const SAST_MULTI_CLASS_QUALIFICATION_CASE_VERSION =
  'sast-multi-class-qualification-case-v1' as const;
export const SAST_MULTI_CLASS_QUALIFICATION_SNAPSHOT_VERSION =
  'sast-multi-class-qualification-snapshot-v1' as const;

export const SAST_MULTI_CLASS_QUALIFICATION_CORPUS_CLASSES = [
  'SCHEMA_PARSER',
  'MALICIOUS_REPOSITORY',
  'FINGERPRINT_CORRELATION',
  'EVIDENCE_PRIVACY',
  'PERFORMANCE'
] as const;
export type SastMultiClassQualificationCorpusClass =
  (typeof SAST_MULTI_CLASS_QUALIFICATION_CORPUS_CLASSES)[number];

export const SAST_SCHEMA_PARSER_QUALIFICATION_SCENARIOS = [
  'OPENGREP_SARIF_VALID',
  'TRIVY_JSON_VALID',
  'SYFT_CYCLONEDX_VALID',
  'MALFORMED_SYNTAX',
  'ARTIFACT_BYTES_LIMIT_PLUS_ONE',
  'NESTING_DEPTH_LIMIT_PLUS_ONE',
  'RECORD_COUNT_LIMIT_PLUS_ONE',
  'STRING_BYTES_LIMIT_PLUS_ONE',
  'INVALID_UTF8',
  'UNPAIRED_SURROGATE',
  'UNKNOWN_ENUM',
  'UNSUPPORTED_SCHEMA_VERSION',
  'FOREIGN_RUN',
  'MULTIPLE_RUNS',
  'UNKNOWN_FIELD',
  'DUPLICATE_JSON_KEY'
] as const;

export const SAST_MALICIOUS_REPOSITORY_QUALIFICATION_SCENARIOS = [
  'PATH_PARENT_TRAVERSAL',
  'PATH_ABSOLUTE',
  'PATH_DRIVE_OR_UNC',
  'PATH_NUL_OR_CONTROL',
  'PATH_INVALID_UTF8',
  'PATH_CASE_COLLISION',
  'PATH_UNICODE_COLLISION',
  'PATH_DUPLICATE',
  'PATH_DEPTH_LIMIT_PLUS_ONE',
  'REPOSITORY_BYTES_LIMIT_PLUS_ONE',
  'SELECTED_BYTES_LIMIT_PLUS_ONE',
  'FILE_COUNT_LIMIT_PLUS_ONE',
  'SINGLE_FILE_BYTES_LIMIT_PLUS_ONE',
  'SYMLINK_OUTSIDE_ROOT',
  'SYMLINK_CYCLE',
  'SUBMODULE_PRESENT',
  'LFS_POINTER_PRESENT',
  'ARCHIVE_PRESENT_NO_EXPANSION',
  'FIFO_ENTRY',
  'DEVICE_ENTRY',
  'OUTPUT_BYTES_LIMIT_PLUS_ONE',
  'FINDING_COUNT_LIMIT_PLUS_ONE',
  'TIMEOUT_PLUS_ONE',
  'SECRET_SENTINEL_NO_LEAK',
  'EXECUTABLE_FILE_NO_RUN'
] as const;

export const SAST_FINGERPRINT_CORRELATION_QUALIFICATION_SCENARIOS = [
  'LINE_SHIFT_INVARIANT',
  'BRANCH_CHANGE_INVARIANT',
  'COMMIT_CHANGE_INVARIANT',
  'RENAME_ATTESTED_ALIAS',
  'RENAME_BACK_SEQUENCE',
  'UNKNOWN_LOCATION_REASON_INVARIANT',
  'MULTI_TOOL_OVERLAP_RELATED_ONLY',
  'CROSS_CAPABILITY_NO_MERGE',
  'RULE_MIGRATION_DISTINCT',
  'FIXED_SEQUENCE',
  'REOPEN_SEQUENCE',
  'FORCED_DIGEST_COLLISION_REJECT',
  'DUPLICATE_REPLAY_EQUAL',
  'TAMPERED_REPLAY_REJECT',
  'CORRELATION_EDGE_LIMIT_PLUS_ONE',
  'ZERO_FINDING_BATCH_COMPLETE',
  'SEVERITY_PRESERVED'
] as const;

export const SAST_EVIDENCE_PRIVACY_QUALIFICATION_SCENARIOS = [
  'KNOWN_FORMAT_SECRET_REDACT',
  'REGISTERED_VALUE_REDACT',
  'HIGH_ENTROPY_SECRET_REDACT',
  'PRIVATE_KEY_REDACT',
  'AUTHORIZATION_URL_CREDENTIAL_REDACT',
  'IDENTITY_FIELD_SECRET_REJECT',
  'RESERVED_MARKER_REJECT',
  'RECONSTRUCTION_FULL_FILE_REJECT',
  'RECONSTRUCTION_OVERLAP_REJECT',
  'PROMPT_INJECTION_TREATED_AS_DATA',
  'BINARY_INPUT_REJECT',
  'INVALID_ENCODING_REJECT',
  'RETENTION_EXPIRES',
  'RETENTION_BOUNDARY_ACCEPT',
  'AUDIT_LEAK_ZERO',
  'RAW_ARTIFACT_LEAK_ZERO',
  'CROSS_TENANT_REFERENCE_REJECT'
] as const;

export const SAST_PERFORMANCE_QUALIFICATION_SCENARIOS = [
  'JAVA_FAST_SMALL',
  'JAVA_FAST_MEDIUM',
  'JAVA_FAST_LARGE_LIMIT',
  'JAVA_DEEP_SMALL',
  'JAVA_DEEP_MEDIUM',
  'JAVA_DEEP_LARGE_LIMIT',
  'COMMON_DEEP_SMALL',
  'COMMON_DEEP_MEDIUM',
  'COMMON_DEEP_LARGE_LIMIT'
] as const;

export type SastMultiClassQualificationScenario =
  | (typeof SAST_SCHEMA_PARSER_QUALIFICATION_SCENARIOS)[number]
  | (typeof SAST_MALICIOUS_REPOSITORY_QUALIFICATION_SCENARIOS)[number]
  | (typeof SAST_FINGERPRINT_CORRELATION_QUALIFICATION_SCENARIOS)[number]
  | (typeof SAST_EVIDENCE_PRIVACY_QUALIFICATION_SCENARIOS)[number]
  | (typeof SAST_PERFORMANCE_QUALIFICATION_SCENARIOS)[number];

export const SAST_MULTI_CLASS_QUALIFICATION_REQUIRED_SCENARIOS: Readonly<
  Record<
    SastMultiClassQualificationCorpusClass,
    readonly SastMultiClassQualificationScenario[]
  >
> = Object.freeze({
  SCHEMA_PARSER: SAST_SCHEMA_PARSER_QUALIFICATION_SCENARIOS,
  MALICIOUS_REPOSITORY: SAST_MALICIOUS_REPOSITORY_QUALIFICATION_SCENARIOS,
  FINGERPRINT_CORRELATION:
    SAST_FINGERPRINT_CORRELATION_QUALIFICATION_SCENARIOS,
  EVIDENCE_PRIVACY: SAST_EVIDENCE_PRIVACY_QUALIFICATION_SCENARIOS,
  PERFORMANCE: SAST_PERFORMANCE_QUALIFICATION_SCENARIOS
});

export const SAST_MULTI_CLASS_QUALIFICATION_MATERIALIZATION_KINDS = [
  'ARTIFACT_STREAM',
  'REPOSITORY_RECIPE',
  'IDENTITY_SEQUENCE',
  'EVIDENCE_SEQUENCE',
  'SYNTHETIC_REPOSITORY'
] as const;
export type SastMultiClassQualificationMaterializationKind =
  (typeof SAST_MULTI_CLASS_QUALIFICATION_MATERIALIZATION_KINDS)[number];

export const SAST_MULTI_CLASS_QUALIFICATION_EXPECTED_OUTCOMES = [
  'ACCEPT',
  'REJECT',
  'RESTRICTED_ESCALATION',
  'SAFE_SUCCESS',
  'RESOURCE_KILL',
  'IDENTITY_STABLE',
  'IDENTITY_DISTINCT',
  'RELATED_ONLY',
  'FIXED',
  'REOPENED',
  'REDACT',
  'DELETE',
  'MEASURE'
] as const;
export type SastMultiClassQualificationExpectedOutcome =
  (typeof SAST_MULTI_CLASS_QUALIFICATION_EXPECTED_OUTCOMES)[number];

export const SAST_MULTI_CLASS_QUALIFICATION_EVIDENCE_STAGES = [
  'T053_ISOLATED_INTEGRATION',
  'T054_END_TO_END',
  'T054_PERFORMANCE'
] as const;
export type SastMultiClassQualificationEvidenceStage =
  (typeof SAST_MULTI_CLASS_QUALIFICATION_EVIDENCE_STAGES)[number];

export const SAST_MULTI_CLASS_QUALIFICATION_PARAMETER_TYPES = [
  'STRING',
  'INTEGER',
  'BOOLEAN'
] as const;
export type SastMultiClassQualificationParameterType =
  (typeof SAST_MULTI_CLASS_QUALIFICATION_PARAMETER_TYPES)[number];

export const SAST_MULTI_CLASS_QUALIFICATION_SEGMENT_ROLES = [
  'PREFIX',
  'UNIT',
  'SUFFIX',
  'PRIMARY',
  'SECONDARY'
] as const;
export type SastMultiClassQualificationSegmentRole =
  (typeof SAST_MULTI_CLASS_QUALIFICATION_SEGMENT_ROLES)[number];

export const SAST_MULTI_CLASS_QUALIFICATION_RECIPE_ACTIONS = [
  'EMIT_ARTIFACT_BYTES',
  'DECLARE_TREE_ENTRY',
  'DECLARE_SYMLINK',
  'DECLARE_SPECIAL_ENTRY',
  'DECLARE_SCANNER_OUTPUT',
  'DECLARE_IDENTITY_INPUT',
  'DECLARE_CORRELATION_INPUT',
  'DECLARE_LIFECYCLE_EVENT',
  'DECLARE_EVIDENCE_FRAGMENT',
  'DECLARE_RETENTION_TIME',
  'DECLARE_SYNTHETIC_FILESET',
  'ASSERT_NO_EGRESS',
  'ASSERT_NO_EXECUTION',
  'ASSERT_NO_SECRET_LEAK',
  'ASSERT_NO_AUTHORITY'
] as const;
export type SastMultiClassQualificationRecipeAction =
  (typeof SAST_MULTI_CLASS_QUALIFICATION_RECIPE_ACTIONS)[number];

export const SAST_MULTI_CLASS_QUALIFICATION_LIMITS = Object.freeze({
  expectedCaseCount: 84,
  maximumCases: 500,
  maximumFixtureBytes: 131_072,
  maximumParameters: 32,
  maximumSegments: 16,
  maximumSteps: 32,
  maximumArgumentsPerStep: 16,
  maximumInlineSegmentBytes: 65_536,
  maximumMaterializedBytes: 2_147_483_649,
  maximumMaterializedEntries: 250_001,
  maximumMaterializedPathDepth: 65,
  maximumSimulatedDurationSeconds: 3_601,
  minimumPerformanceRunsPerBucket: 30,
  performanceBucketCount: 9,
  identifierBytes: 256,
  referenceBytes: 2_048,
  parameterStringBytes: 2_048,
  stepArgumentBytes: 512
});

type Sha256Digest = `sha256:${string}`;
export type SastMultiClassQualificationCanonicalDigester = (
  canonicalValue: string
) => Sha256Digest;

export interface SastMultiClassQualificationFixtureParameter {
  name: string;
  valueType: SastMultiClassQualificationParameterType;
  stringValue: string | null;
  integerValue: number | null;
  booleanValue: boolean | null;
}

export interface SastMultiClassQualificationFixtureSegment {
  ordinal: number;
  role: SastMultiClassQualificationSegmentRole;
  encoding: 'BASE64';
  valueBase64: string;
  repeat: number;
}

export interface SastMultiClassQualificationFixtureStep {
  ordinal: number;
  action: SastMultiClassQualificationRecipeAction;
  arguments: string[];
}

export interface SastMultiClassQualificationFixtureCore {
  version: typeof SAST_MULTI_CLASS_QUALIFICATION_FIXTURE_VERSION;
  caseKey: string;
  corpusClass: SastMultiClassQualificationCorpusClass;
  scenario: SastMultiClassQualificationScenario;
  materializationKind: SastMultiClassQualificationMaterializationKind;
  parameters: SastMultiClassQualificationFixtureParameter[];
  segments: SastMultiClassQualificationFixtureSegment[];
  steps: SastMultiClassQualificationFixtureStep[];
  materializedBytes: number;
  materializedEntries: number;
  materializedPathDepth: number;
  simulatedDurationSeconds: number;
  source: 'PLATFORM_MANAGED';
  sourcePlatformOwned: true;
  customerContentAccepted: false;
  executable: false;
  packageInstallRequired: false;
  buildRequired: false;
  dynamicExecutionRequired: false;
  networkRequired: false;
  hostMutationAllowed: false;
  immutable: true;
}

export interface SastMultiClassQualificationFixture
  extends SastMultiClassQualificationFixtureCore {
  fixtureId: string;
  fixtureDigest: Sha256Digest;
}

export type SastMultiClassQualificationFixtureInput = Omit<
  SastMultiClassQualificationFixtureCore,
  | 'version'
  | 'source'
  | 'sourcePlatformOwned'
  | 'customerContentAccepted'
  | 'executable'
  | 'packageInstallRequired'
  | 'buildRequired'
  | 'dynamicExecutionRequired'
  | 'networkRequired'
  | 'hostMutationAllowed'
  | 'immutable'
>;

export interface SastMultiClassQualificationCaseCore {
  version: typeof SAST_MULTI_CLASS_QUALIFICATION_CASE_VERSION;
  caseKey: string;
  caseRevision: string;
  corpusClass: SastMultiClassQualificationCorpusClass;
  scenario: SastMultiClassQualificationScenario;
  profiles: SastProfileId[];
  fixturePath: string;
  fixtureId: string;
  fixtureDigest: Sha256Digest;
  fixtureBytes: number;
  materializationKind: SastMultiClassQualificationMaterializationKind;
  expectedOutcome: SastMultiClassQualificationExpectedOutcome;
  evidenceStage: SastMultiClassQualificationEvidenceStage;
  minimumRuns: number;
  hardwareClassRef: string | null;
  ownerRef: string;
  licenseExpression: string;
  provenanceRef: string;
  zeroProhibitedEffectsRequired: true;
  source: 'PLATFORM_MANAGED';
  immutable: true;
  customerContentAccepted: false;
  customerExecutableConfigAccepted: false;
  scannerExecutionAuthorized: false;
  findingAuthority: false;
  policyAuthority: false;
  publicationAuthority: false;
  productionReadinessAuthority: false;
  packageInstallRequired: false;
  buildRequired: false;
  dynamicExecutionRequired: false;
  networkRequired: false;
}

export interface SastMultiClassQualificationCase
  extends SastMultiClassQualificationCaseCore {
  caseId: string;
  caseDigest: Sha256Digest;
}

export type SastMultiClassQualificationCaseInput = Omit<
  SastMultiClassQualificationCaseCore,
  | 'version'
  | 'zeroProhibitedEffectsRequired'
  | 'source'
  | 'immutable'
  | 'customerContentAccepted'
  | 'customerExecutableConfigAccepted'
  | 'scannerExecutionAuthorized'
  | 'findingAuthority'
  | 'policyAuthority'
  | 'publicationAuthority'
  | 'productionReadinessAuthority'
  | 'packageInstallRequired'
  | 'buildRequired'
  | 'dynamicExecutionRequired'
  | 'networkRequired'
>;

export interface SastMultiClassQualificationClassCount {
  corpusClass: SastMultiClassQualificationCorpusClass;
  cases: number;
}

export interface SastMultiClassQualificationScenarioCount {
  corpusClass: SastMultiClassQualificationCorpusClass;
  scenario: SastMultiClassQualificationScenario;
  cases: number;
}

export interface SastMultiClassQualificationProfileCount {
  profileId: SastProfileId;
  cases: number;
  performanceBuckets: number;
}

export interface SastMultiClassQualificationSnapshotCore {
  version: typeof SAST_MULTI_CLASS_QUALIFICATION_SNAPSHOT_VERSION;
  revision: string;
  publishedAt: string;
  ownerRef: string;
  licenseExpression: string;
  provenanceRef: string;
  performanceHardwareClassRef: string;
  performanceHardwareClassDigest: Sha256Digest;
  profiles: SastProfileId[];
  requiredClasses: SastMultiClassQualificationCorpusClass[];
  cases: SastMultiClassQualificationCase[];
  caseCount: number;
  fixtureCount: number;
  caseSetDigest: Sha256Digest;
  fixtureSetDigest: Sha256Digest;
  classCounts: SastMultiClassQualificationClassCount[];
  scenarioCounts: SastMultiClassQualificationScenarioCount[];
  profileCounts: SastMultiClassQualificationProfileCount[];
  minimumPerformanceRunsPerBucket: 30;
  source: 'PLATFORM_MANAGED';
  immutable: true;
  customerContentAccepted: false;
  customerExecutableConfigAccepted: false;
  scannerExecutionAuthorized: false;
  findingAuthority: false;
  policyAuthority: false;
  publicationAuthority: false;
  productionReadinessAuthority: false;
  packageInstallRequired: false;
  buildRequired: false;
  dynamicExecutionRequired: false;
  networkRequired: false;
}

export interface SastMultiClassQualificationSnapshot
  extends SastMultiClassQualificationSnapshotCore {
  corpusId: string;
  snapshotDigest: Sha256Digest;
}

export interface SastMultiClassQualificationSnapshotInput {
  revision: string;
  publishedAt: string;
  ownerRef: string;
  licenseExpression: string;
  provenanceRef: string;
  performanceHardwareClassRef: string;
  performanceHardwareClassDigest: Sha256Digest;
  cases: readonly SastMultiClassQualificationCase[];
}

const TEXT_ENCODER = new TextEncoder();
const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const FIXTURE_ID_PATTERN =
  /^sast-multi-class-qualification-fixture:\/\/[a-f0-9]{64}$/u;
const CASE_ID_PATTERN =
  /^sast-multi-class-qualification-case:\/\/[a-f0-9]{64}$/u;
const CORPUS_ID_PATTERN =
  /^sast-multi-class-qualification-corpus:\/\/[a-f0-9]{64}$/u;
const SEMANTIC_VERSION_PATTERN =
  /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/u;
const CASE_KEY_PATTERN = /^t052\.[a-z0-9-]+\.[a-z0-9-]+$/u;
const PARAMETER_NAME_PATTERN = /^[A-Z][A-Z0-9_]{0,127}$/u;
const FORBIDDEN_RECIPE_PARAMETER_NAMES = new Set([
  'ARGV',
  'COMMAND',
  'ENVIRONMENT',
  'EXECUTABLE',
  'SCRIPT',
  'SHELL',
  'URL'
]);
const FORBIDDEN_RECIPE_ARGUMENT_PATTERN =
  /(?:^|[^A-Za-z0-9_])(?:argv|command|environment|executable|script|shell|url)=/iu;
const OWNER_REF_PATTERN = /^team:\/\/[a-z0-9][a-z0-9._/-]{0,255}$/u;
const DIGEST_BOUND_REFERENCE_PATTERN =
  /^[a-z][a-z0-9+.-]*:\/\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+\/sha256:[a-f0-9]{64}$/u;
const HARDWARE_CLASS_REF_PATTERN =
  /^hardware-class:\/\/[a-z0-9][a-z0-9._/-]{0,255}\/sha256:[a-f0-9]{64}$/u;
const LICENSE_EXPRESSION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9 .+()/-]{0,127}$/u;
const FIXTURE_PATH_PATTERN =
  /^fixtures\/(?:schema-parser|malicious-repository|fingerprint-correlation|evidence-privacy|performance)\/[a-z0-9][a-z0-9-]{0,159}\.fixture\.json$/u;
const BASE64_PATTERN =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;
const STABLE_JSON_MAXIMUM_DEPTH = 32;
const STABLE_JSON_INVALID_SENTINEL =
  '"__invalid_sast_multi_class_qualification_shape__"';

const FIXTURE_PARAMETER_KEYS = [
  'name',
  'valueType',
  'stringValue',
  'integerValue',
  'booleanValue'
] as const;
const FIXTURE_SEGMENT_KEYS = [
  'ordinal',
  'role',
  'encoding',
  'valueBase64',
  'repeat'
] as const;
const FIXTURE_STEP_KEYS = ['ordinal', 'action', 'arguments'] as const;
const FIXTURE_INPUT_KEYS = [
  'caseKey',
  'corpusClass',
  'scenario',
  'materializationKind',
  'parameters',
  'segments',
  'steps',
  'materializedBytes',
  'materializedEntries',
  'materializedPathDepth',
  'simulatedDurationSeconds'
] as const;
const FIXTURE_KEYS = [
  'version',
  'fixtureId',
  'fixtureDigest',
  ...FIXTURE_INPUT_KEYS,
  'source',
  'sourcePlatformOwned',
  'customerContentAccepted',
  'executable',
  'packageInstallRequired',
  'buildRequired',
  'dynamicExecutionRequired',
  'networkRequired',
  'hostMutationAllowed',
  'immutable'
] as const;
const CASE_INPUT_KEYS = [
  'caseKey',
  'caseRevision',
  'corpusClass',
  'scenario',
  'profiles',
  'fixturePath',
  'fixtureId',
  'fixtureDigest',
  'fixtureBytes',
  'materializationKind',
  'expectedOutcome',
  'evidenceStage',
  'minimumRuns',
  'hardwareClassRef',
  'ownerRef',
  'licenseExpression',
  'provenanceRef'
] as const;
const CASE_KEYS = [
  'version',
  'caseId',
  'caseDigest',
  ...CASE_INPUT_KEYS,
  'zeroProhibitedEffectsRequired',
  'source',
  'immutable',
  'customerContentAccepted',
  'customerExecutableConfigAccepted',
  'scannerExecutionAuthorized',
  'findingAuthority',
  'policyAuthority',
  'publicationAuthority',
  'productionReadinessAuthority',
  'packageInstallRequired',
  'buildRequired',
  'dynamicExecutionRequired',
  'networkRequired'
] as const;
const SNAPSHOT_INPUT_KEYS = [
  'revision',
  'publishedAt',
  'ownerRef',
  'licenseExpression',
  'provenanceRef',
  'performanceHardwareClassRef',
  'performanceHardwareClassDigest',
  'cases'
] as const;
const SNAPSHOT_KEYS = [
  'version',
  'corpusId',
  'snapshotDigest',
  ...SNAPSHOT_INPUT_KEYS,
  'profiles',
  'requiredClasses',
  'caseCount',
  'fixtureCount',
  'caseSetDigest',
  'fixtureSetDigest',
  'classCounts',
  'scenarioCounts',
  'profileCounts',
  'minimumPerformanceRunsPerBucket',
  'source',
  'immutable',
  'customerContentAccepted',
  'customerExecutableConfigAccepted',
  'scannerExecutionAuthorized',
  'findingAuthority',
  'policyAuthority',
  'publicationAuthority',
  'productionReadinessAuthority',
  'packageInstallRequired',
  'buildRequired',
  'dynamicExecutionRequired',
  'networkRequired'
] as const;

export function buildSastMultiClassQualificationFixture(
  input: Readonly<SastMultiClassQualificationFixtureInput>,
  digestCanonical: SastMultiClassQualificationCanonicalDigester
): SastMultiClassQualificationFixture | null {
  if (
    !hasExactKeys(input, FIXTURE_INPUT_KEYS) ||
    !Array.isArray(input.parameters) ||
    !Array.isArray(input.segments) ||
    !Array.isArray(input.steps) ||
    !input.parameters.every(isFixtureParameterValid) ||
    !input.segments.every(isFixtureSegmentValid) ||
    !input.steps.every(isFixtureStepValid)
  ) {
    return null;
  }
  const parameters = input.parameters
    .map((item) => ({ ...item }))
    .sort((left, right) => compareText(left.name, right.name));
  const segments = input.segments
    .map((item) => ({ ...item }))
    .sort((left, right) => left.ordinal - right.ordinal);
  const steps = input.steps
    .map((item) => ({ ...item, arguments: [...item.arguments].sort(compareText) }))
    .sort((left, right) => left.ordinal - right.ordinal);
  const core: SastMultiClassQualificationFixtureCore = {
    version: SAST_MULTI_CLASS_QUALIFICATION_FIXTURE_VERSION,
    caseKey: input.caseKey,
    corpusClass: input.corpusClass,
    scenario: input.scenario,
    materializationKind: input.materializationKind,
    parameters,
    segments,
    steps,
    materializedBytes: input.materializedBytes,
    materializedEntries: input.materializedEntries,
    materializedPathDepth: input.materializedPathDepth,
    simulatedDurationSeconds: input.simulatedDurationSeconds,
    source: 'PLATFORM_MANAGED',
    sourcePlatformOwned: true,
    customerContentAccepted: false,
    executable: false,
    packageInstallRequired: false,
    buildRequired: false,
    dynamicExecutionRequired: false,
    networkRequired: false,
    hostMutationAllowed: false,
    immutable: true
  };
  if (!isFixtureCoreValid(core)) return null;
  const fixtureDigest = digestCanonical(stableJson(core));
  if (!isDigest(fixtureDigest)) return null;
  return {
    ...core,
    fixtureId: `sast-multi-class-qualification-fixture://${fixtureDigest.slice('sha256:'.length)}`,
    fixtureDigest
  };
}

export function isSastMultiClassQualificationFixtureValid(
  value: unknown,
  digestCanonical: SastMultiClassQualificationCanonicalDigester
): value is SastMultiClassQualificationFixture {
  if (!hasExactKeys(value, FIXTURE_KEYS)) return false;
  const candidate = value as SastMultiClassQualificationFixture;
  if (
    typeof candidate.fixtureId !== 'string' ||
    !FIXTURE_ID_PATTERN.test(candidate.fixtureId) ||
    !isDigest(candidate.fixtureDigest) ||
    !Array.isArray(candidate.parameters) ||
    !Array.isArray(candidate.segments) ||
    !Array.isArray(candidate.steps)
  ) {
    return false;
  }
  const rebuilt = buildSastMultiClassQualificationFixture(
    fixtureInput(candidate),
    digestCanonical
  );
  return rebuilt !== null && stableJson(rebuilt) === stableJson(candidate);
}

export function buildSastMultiClassQualificationCase(
  input: Readonly<SastMultiClassQualificationCaseInput>,
  digestCanonical: SastMultiClassQualificationCanonicalDigester
): SastMultiClassQualificationCase | null {
  if (!hasExactKeys(input, CASE_INPUT_KEYS) || !Array.isArray(input.profiles)) {
    return null;
  }
  const profiles = canonicalProfiles(input.profiles);
  if (!profiles) return null;
  const core: SastMultiClassQualificationCaseCore = {
    version: SAST_MULTI_CLASS_QUALIFICATION_CASE_VERSION,
    caseKey: input.caseKey,
    caseRevision: input.caseRevision,
    corpusClass: input.corpusClass,
    scenario: input.scenario,
    profiles,
    fixturePath: input.fixturePath,
    fixtureId: input.fixtureId,
    fixtureDigest: input.fixtureDigest,
    fixtureBytes: input.fixtureBytes,
    materializationKind: input.materializationKind,
    expectedOutcome: input.expectedOutcome,
    evidenceStage: input.evidenceStage,
    minimumRuns: input.minimumRuns,
    hardwareClassRef: input.hardwareClassRef,
    ownerRef: input.ownerRef,
    licenseExpression: input.licenseExpression,
    provenanceRef: input.provenanceRef,
    zeroProhibitedEffectsRequired: true,
    source: 'PLATFORM_MANAGED',
    immutable: true,
    customerContentAccepted: false,
    customerExecutableConfigAccepted: false,
    scannerExecutionAuthorized: false,
    findingAuthority: false,
    policyAuthority: false,
    publicationAuthority: false,
    productionReadinessAuthority: false,
    packageInstallRequired: false,
    buildRequired: false,
    dynamicExecutionRequired: false,
    networkRequired: false
  };
  if (!isCaseCoreValid(core)) return null;
  const caseDigest = digestCanonical(stableJson(core));
  if (!isDigest(caseDigest)) return null;
  return {
    ...core,
    caseId: `sast-multi-class-qualification-case://${caseDigest.slice('sha256:'.length)}`,
    caseDigest
  };
}

export function isSastMultiClassQualificationCaseValid(
  value: unknown,
  digestCanonical: SastMultiClassQualificationCanonicalDigester
): value is SastMultiClassQualificationCase {
  if (!hasExactKeys(value, CASE_KEYS)) return false;
  const candidate = value as SastMultiClassQualificationCase;
  if (
    typeof candidate.caseId !== 'string' ||
    !CASE_ID_PATTERN.test(candidate.caseId) ||
    !isDigest(candidate.caseDigest) ||
    !Array.isArray(candidate.profiles)
  ) {
    return false;
  }
  const rebuilt = buildSastMultiClassQualificationCase(
    caseInput(candidate),
    digestCanonical
  );
  return rebuilt !== null && stableJson(rebuilt) === stableJson(candidate);
}

export function buildSastMultiClassQualificationSnapshot(
  input: Readonly<SastMultiClassQualificationSnapshotInput>,
  digestCanonical: SastMultiClassQualificationCanonicalDigester
): SastMultiClassQualificationSnapshot | null {
  if (
    !hasExactKeys(input, SNAPSHOT_INPUT_KEYS) ||
    !Array.isArray(input.cases) ||
    !isSemanticVersion(input.revision) ||
    !isIsoInstant(input.publishedAt) ||
    !isOwnerRef(input.ownerRef) ||
    !isLicenseExpression(input.licenseExpression) ||
    !isDigestBoundReference(input.provenanceRef) ||
    typeof input.performanceHardwareClassRef !== 'string' ||
    !HARDWARE_CLASS_REF_PATTERN.test(input.performanceHardwareClassRef) ||
    !isDigest(input.performanceHardwareClassDigest) ||
    !input.performanceHardwareClassRef.endsWith(
      `/${input.performanceHardwareClassDigest}`
    ) ||
    input.cases.length !==
      SAST_MULTI_CLASS_QUALIFICATION_LIMITS.expectedCaseCount ||
    input.cases.length > SAST_MULTI_CLASS_QUALIFICATION_LIMITS.maximumCases ||
    input.cases.some(
      (item) => !isSastMultiClassQualificationCaseValid(item, digestCanonical)
    )
  ) {
    return null;
  }
  const cases = input.cases.map(cloneCase).sort(compareCases);
  if (
    !unique(cases.map((item) => item.caseId)) ||
    !unique(cases.map((item) => item.caseDigest)) ||
    !unique(cases.map((item) => item.caseKey)) ||
    !unique(cases.map((item) => item.fixturePath)) ||
    !unique(cases.map((item) => portablePathKey(item.fixturePath))) ||
    !unique(cases.map((item) => item.fixtureId)) ||
    cases.some(
      (item) =>
        item.ownerRef !== input.ownerRef ||
        item.licenseExpression !== input.licenseExpression ||
        (item.corpusClass === 'PERFORMANCE'
          ? item.hardwareClassRef !== input.performanceHardwareClassRef
          : item.hardwareClassRef !== null)
    ) ||
    !requiredScenarioSetIsExact(cases)
  ) {
    return null;
  }
  const classCounts = SAST_MULTI_CLASS_QUALIFICATION_CORPUS_CLASSES.map(
    (corpusClass) => ({
      corpusClass,
      cases: cases.filter((item) => item.corpusClass === corpusClass).length
    })
  );
  const scenarioCounts = SAST_MULTI_CLASS_QUALIFICATION_CORPUS_CLASSES.flatMap(
    (corpusClass) =>
      SAST_MULTI_CLASS_QUALIFICATION_REQUIRED_SCENARIOS[corpusClass].map(
        (scenario) => ({
          corpusClass,
          scenario,
          cases: cases.filter(
            (item) =>
              item.corpusClass === corpusClass && item.scenario === scenario
          ).length
        })
      )
  );
  const profileCounts = SAST_PROFILE_IDS.map((profileId) => ({
    profileId,
    cases: cases.filter((item) => item.profiles.includes(profileId)).length,
    performanceBuckets: cases.filter(
      (item) =>
        item.corpusClass === 'PERFORMANCE' && item.profiles.includes(profileId)
    ).length
  }));
  if (
    classCounts.some((item) => item.cases === 0) ||
    scenarioCounts.some((item) => item.cases !== 1) ||
    profileCounts.some((item) => item.cases === 0 || item.performanceBuckets !== 3)
  ) {
    return null;
  }
  const caseBindings = cases.map((item) => ({
    caseId: item.caseId,
    caseDigest: item.caseDigest
  }));
  const fixtureBindings = cases.map((item) => ({
    fixturePath: item.fixturePath,
    fixtureId: item.fixtureId,
    fixtureDigest: item.fixtureDigest,
    fixtureBytes: item.fixtureBytes
  }));
  const caseSetDigest = digestCanonical(stableJson(caseBindings));
  const fixtureSetDigest = digestCanonical(stableJson(fixtureBindings));
  if (!isDigest(caseSetDigest) || !isDigest(fixtureSetDigest)) return null;
  const core: SastMultiClassQualificationSnapshotCore = {
    version: SAST_MULTI_CLASS_QUALIFICATION_SNAPSHOT_VERSION,
    revision: input.revision,
    publishedAt: input.publishedAt,
    ownerRef: input.ownerRef,
    licenseExpression: input.licenseExpression,
    provenanceRef: input.provenanceRef,
    performanceHardwareClassRef: input.performanceHardwareClassRef,
    performanceHardwareClassDigest: input.performanceHardwareClassDigest,
    profiles: [...SAST_PROFILE_IDS],
    requiredClasses: [...SAST_MULTI_CLASS_QUALIFICATION_CORPUS_CLASSES],
    cases,
    caseCount: cases.length,
    fixtureCount: fixtureBindings.length,
    caseSetDigest,
    fixtureSetDigest,
    classCounts,
    scenarioCounts,
    profileCounts,
    minimumPerformanceRunsPerBucket: 30,
    source: 'PLATFORM_MANAGED',
    immutable: true,
    customerContentAccepted: false,
    customerExecutableConfigAccepted: false,
    scannerExecutionAuthorized: false,
    findingAuthority: false,
    policyAuthority: false,
    publicationAuthority: false,
    productionReadinessAuthority: false,
    packageInstallRequired: false,
    buildRequired: false,
    dynamicExecutionRequired: false,
    networkRequired: false
  };
  const snapshotDigest = digestCanonical(stableJson(core));
  if (!isDigest(snapshotDigest)) return null;
  return {
    ...core,
    corpusId: `sast-multi-class-qualification-corpus://${snapshotDigest.slice('sha256:'.length)}`,
    snapshotDigest
  };
}

export function isSastMultiClassQualificationSnapshotValid(
  value: unknown,
  digestCanonical: SastMultiClassQualificationCanonicalDigester
): value is SastMultiClassQualificationSnapshot {
  if (!hasExactKeys(value, SNAPSHOT_KEYS)) return false;
  const candidate = value as SastMultiClassQualificationSnapshot;
  if (
    typeof candidate.corpusId !== 'string' ||
    !CORPUS_ID_PATTERN.test(candidate.corpusId) ||
    !isDigest(candidate.snapshotDigest) ||
    !Array.isArray(candidate.profiles) ||
    !Array.isArray(candidate.requiredClasses) ||
    !Array.isArray(candidate.cases) ||
    !Array.isArray(candidate.classCounts) ||
    !Array.isArray(candidate.scenarioCounts) ||
    !Array.isArray(candidate.profileCounts)
  ) {
    return false;
  }
  const rebuilt = buildSastMultiClassQualificationSnapshot(
    snapshotInput(candidate),
    digestCanonical
  );
  return rebuilt !== null && stableJson(rebuilt) === stableJson(candidate);
}

function isFixtureCoreValid(
  value: SastMultiClassQualificationFixtureCore
): boolean {
  const parameters = value.parameters;
  const segments = value.segments;
  const steps = value.steps;
  if (
    typeof value.caseKey !== 'string' ||
    !CASE_KEY_PATTERN.test(value.caseKey) ||
    !SAST_MULTI_CLASS_QUALIFICATION_CORPUS_CLASSES.includes(value.corpusClass) ||
    !scenarioBelongsToClass(value.scenario, value.corpusClass) ||
    !Array.isArray(parameters) ||
    !Array.isArray(segments) ||
    !Array.isArray(steps) ||
    !parameters.every(isFixtureParameterValid) ||
    !segments.every(isFixtureSegmentValid) ||
    !steps.every(isFixtureStepValid)
  ) {
    return false;
  }
  const segmentBytes = segments.reduce(
    (total, segment) =>
      total + decodedBase64Bytes(segment.valueBase64) * segment.repeat,
    0
  );
  return (
    value.version === SAST_MULTI_CLASS_QUALIFICATION_FIXTURE_VERSION &&
    value.caseKey === expectedCaseKey(value.corpusClass, value.scenario) &&
    value.materializationKind === expectedMaterializationKind(value.corpusClass) &&
    parameters.length > 0 &&
    parameters.length <= SAST_MULTI_CLASS_QUALIFICATION_LIMITS.maximumParameters &&
    parameters.every(isFixtureParameterValid) &&
    unique(parameters.map((item) => item.name)) &&
    isSorted(parameters.map((item) => item.name)) &&
    segments.length <= SAST_MULTI_CLASS_QUALIFICATION_LIMITS.maximumSegments &&
    segments.every(isFixtureSegmentValid) &&
    hasSequentialOrdinals(segments) &&
    steps.length > 0 &&
    steps.length <= SAST_MULTI_CLASS_QUALIFICATION_LIMITS.maximumSteps &&
    steps.every(isFixtureStepValid) &&
    hasSequentialOrdinals(steps) &&
    Number.isSafeInteger(value.materializedBytes) &&
    value.materializedBytes >= 0 &&
    value.materializedBytes <=
      SAST_MULTI_CLASS_QUALIFICATION_LIMITS.maximumMaterializedBytes &&
    Number.isSafeInteger(value.materializedEntries) &&
    value.materializedEntries >= 0 &&
    value.materializedEntries <=
      SAST_MULTI_CLASS_QUALIFICATION_LIMITS.maximumMaterializedEntries &&
    Number.isSafeInteger(value.materializedPathDepth) &&
    value.materializedPathDepth >= 0 &&
    value.materializedPathDepth <=
      SAST_MULTI_CLASS_QUALIFICATION_LIMITS.maximumMaterializedPathDepth &&
    Number.isSafeInteger(value.simulatedDurationSeconds) &&
    value.simulatedDurationSeconds >= 0 &&
    value.simulatedDurationSeconds <=
      SAST_MULTI_CLASS_QUALIFICATION_LIMITS.maximumSimulatedDurationSeconds &&
    (value.materializationKind === 'ARTIFACT_STREAM' ||
    value.materializationKind === 'EVIDENCE_SEQUENCE'
      ? segments.length > 0 && segmentBytes === value.materializedBytes
      : segments.length === 0) &&
    value.source === 'PLATFORM_MANAGED' &&
    value.sourcePlatformOwned === true &&
    value.customerContentAccepted === false &&
    value.executable === false &&
    value.packageInstallRequired === false &&
    value.buildRequired === false &&
    value.dynamicExecutionRequired === false &&
    value.networkRequired === false &&
    value.hostMutationAllowed === false &&
    value.immutable === true
  );
}

function isCaseCoreValid(value: SastMultiClassQualificationCaseCore): boolean {
  if (
    typeof value.caseKey !== 'string' ||
    !CASE_KEY_PATTERN.test(value.caseKey) ||
    !SAST_MULTI_CLASS_QUALIFICATION_CORPUS_CLASSES.includes(value.corpusClass) ||
    !scenarioBelongsToClass(value.scenario, value.corpusClass) ||
    !Array.isArray(value.profiles) ||
    typeof value.fixturePath !== 'string' ||
    typeof value.fixtureId !== 'string'
  ) {
    return false;
  }
  const expectedProfiles = canonicalProfiles(value.profiles);
  const expectedOutcome = expectedOutcomeForScenario(value.scenario);
  const expectedStage = expectedEvidenceStage(value.corpusClass);
  const expectedRuns =
    value.corpusClass === 'PERFORMANCE'
      ? SAST_MULTI_CLASS_QUALIFICATION_LIMITS.minimumPerformanceRunsPerBucket
      : 1;
  const expectedFixturePath = fixturePathFor(value.corpusClass, value.scenario);
  return (
    value.version === SAST_MULTI_CLASS_QUALIFICATION_CASE_VERSION &&
    value.caseKey === expectedCaseKey(value.corpusClass, value.scenario) &&
    isSemanticVersion(value.caseRevision) &&
    expectedProfiles !== null &&
    arraysEqual(value.profiles, expectedProfiles) &&
    FIXTURE_PATH_PATTERN.test(value.fixturePath) &&
    value.fixturePath === expectedFixturePath &&
    FIXTURE_ID_PATTERN.test(value.fixtureId) &&
    isDigest(value.fixtureDigest) &&
    value.fixtureId ===
      `sast-multi-class-qualification-fixture://${value.fixtureDigest.slice('sha256:'.length)}` &&
    Number.isSafeInteger(value.fixtureBytes) &&
    value.fixtureBytes > 0 &&
    value.fixtureBytes <= SAST_MULTI_CLASS_QUALIFICATION_LIMITS.maximumFixtureBytes &&
    value.materializationKind === expectedMaterializationKind(value.corpusClass) &&
    value.expectedOutcome === expectedOutcome &&
    value.evidenceStage === expectedStage &&
    value.minimumRuns === expectedRuns &&
    (value.corpusClass === 'PERFORMANCE'
      ? typeof value.hardwareClassRef === 'string' &&
        HARDWARE_CLASS_REF_PATTERN.test(value.hardwareClassRef) &&
        value.profiles.length === 1 &&
        value.profiles[0] === performanceProfileForScenario(value.scenario)
      : value.hardwareClassRef === null) &&
    isOwnerRef(value.ownerRef) &&
    isLicenseExpression(value.licenseExpression) &&
    isDigestBoundReference(value.provenanceRef) &&
    value.zeroProhibitedEffectsRequired === true &&
    value.source === 'PLATFORM_MANAGED' &&
    value.immutable === true &&
    value.customerContentAccepted === false &&
    value.customerExecutableConfigAccepted === false &&
    value.scannerExecutionAuthorized === false &&
    value.findingAuthority === false &&
    value.policyAuthority === false &&
    value.publicationAuthority === false &&
    value.productionReadinessAuthority === false &&
    value.packageInstallRequired === false &&
    value.buildRequired === false &&
    value.dynamicExecutionRequired === false &&
    value.networkRequired === false
  );
}

function isFixtureParameterValid(
  value: unknown
): value is SastMultiClassQualificationFixtureParameter {
  if (!hasExactKeys(value, FIXTURE_PARAMETER_KEYS)) return false;
  const item = value as SastMultiClassQualificationFixtureParameter;
  if (
    typeof item.name !== 'string' ||
    !PARAMETER_NAME_PATTERN.test(item.name) ||
    item.name
      .split('_')
      .some((segment) => FORBIDDEN_RECIPE_PARAMETER_NAMES.has(segment)) ||
    !SAST_MULTI_CLASS_QUALIFICATION_PARAMETER_TYPES.includes(item.valueType)
  ) {
    return false;
  }
  if (item.valueType === 'STRING') {
    return (
      isBoundedCanonicalText(
        item.stringValue,
        SAST_MULTI_CLASS_QUALIFICATION_LIMITS.parameterStringBytes
      ) &&
      item.integerValue === null &&
      item.booleanValue === null
    );
  }
  if (item.valueType === 'INTEGER') {
    return (
      item.stringValue === null &&
      Number.isSafeInteger(item.integerValue) &&
      (item.integerValue ?? -1) >= 0 &&
      (item.integerValue ?? Number.MAX_SAFE_INTEGER) <=
        SAST_MULTI_CLASS_QUALIFICATION_LIMITS.maximumMaterializedBytes &&
      item.booleanValue === null
    );
  }
  return (
    item.stringValue === null &&
    item.integerValue === null &&
    typeof item.booleanValue === 'boolean'
  );
}

function isFixtureSegmentValid(
  value: unknown
): value is SastMultiClassQualificationFixtureSegment {
  if (!hasExactKeys(value, FIXTURE_SEGMENT_KEYS)) return false;
  const item = value as SastMultiClassQualificationFixtureSegment;
  const decodedBytes = decodedBase64Bytes(item.valueBase64);
  return (
    Number.isSafeInteger(item.ordinal) &&
    item.ordinal > 0 &&
    SAST_MULTI_CLASS_QUALIFICATION_SEGMENT_ROLES.includes(item.role) &&
    item.encoding === 'BASE64' &&
    decodedBytes > 0 &&
    decodedBytes <=
      SAST_MULTI_CLASS_QUALIFICATION_LIMITS.maximumInlineSegmentBytes &&
    Number.isSafeInteger(item.repeat) &&
    item.repeat > 0 &&
    item.repeat <=
      SAST_MULTI_CLASS_QUALIFICATION_LIMITS.maximumMaterializedBytes
  );
}

function isFixtureStepValid(
  value: unknown
): value is SastMultiClassQualificationFixtureStep {
  if (!hasExactKeys(value, FIXTURE_STEP_KEYS)) return false;
  const item = value as SastMultiClassQualificationFixtureStep;
  return (
    Number.isSafeInteger(item.ordinal) &&
    item.ordinal > 0 &&
    SAST_MULTI_CLASS_QUALIFICATION_RECIPE_ACTIONS.includes(item.action) &&
    Array.isArray(item.arguments) &&
    item.arguments.length <=
      SAST_MULTI_CLASS_QUALIFICATION_LIMITS.maximumArgumentsPerStep &&
    item.arguments.every(
      (argument) =>
        isBoundedCanonicalText(
          argument,
          SAST_MULTI_CLASS_QUALIFICATION_LIMITS.stepArgumentBytes
        ) && !FORBIDDEN_RECIPE_ARGUMENT_PATTERN.test(argument)
    ) &&
    unique(item.arguments)
  );
}

function scenarioBelongsToClass(
  scenario: unknown,
  corpusClass: SastMultiClassQualificationCorpusClass
): scenario is SastMultiClassQualificationScenario {
  return SAST_MULTI_CLASS_QUALIFICATION_REQUIRED_SCENARIOS[corpusClass].includes(
    scenario as SastMultiClassQualificationScenario
  );
}

function expectedMaterializationKind(
  corpusClass: SastMultiClassQualificationCorpusClass
): SastMultiClassQualificationMaterializationKind {
  switch (corpusClass) {
    case 'SCHEMA_PARSER':
      return 'ARTIFACT_STREAM';
    case 'MALICIOUS_REPOSITORY':
      return 'REPOSITORY_RECIPE';
    case 'FINGERPRINT_CORRELATION':
      return 'IDENTITY_SEQUENCE';
    case 'EVIDENCE_PRIVACY':
      return 'EVIDENCE_SEQUENCE';
    case 'PERFORMANCE':
      return 'SYNTHETIC_REPOSITORY';
  }
}

function expectedEvidenceStage(
  corpusClass: SastMultiClassQualificationCorpusClass
): SastMultiClassQualificationEvidenceStage {
  if (
    corpusClass === 'SCHEMA_PARSER' ||
    corpusClass === 'MALICIOUS_REPOSITORY'
  ) {
    return 'T053_ISOLATED_INTEGRATION';
  }
  return corpusClass === 'PERFORMANCE'
    ? 'T054_PERFORMANCE'
    : 'T054_END_TO_END';
}

function expectedOutcomeForScenario(
  scenario: SastMultiClassQualificationScenario
): SastMultiClassQualificationExpectedOutcome {
  if (
    SAST_SCHEMA_PARSER_QUALIFICATION_SCENARIOS.includes(
      scenario as (typeof SAST_SCHEMA_PARSER_QUALIFICATION_SCENARIOS)[number]
    )
  ) {
    return scenario.endsWith('_VALID') ? 'ACCEPT' : 'REJECT';
  }
  if (
    SAST_MALICIOUS_REPOSITORY_QUALIFICATION_SCENARIOS.includes(
      scenario as (typeof SAST_MALICIOUS_REPOSITORY_QUALIFICATION_SCENARIOS)[number]
    )
  ) {
    if (scenario === 'SUBMODULE_PRESENT' || scenario === 'LFS_POINTER_PRESENT') {
      return 'RESTRICTED_ESCALATION';
    }
    if (
      scenario === 'ARCHIVE_PRESENT_NO_EXPANSION' ||
      scenario === 'SECRET_SENTINEL_NO_LEAK' ||
      scenario === 'EXECUTABLE_FILE_NO_RUN'
    ) {
      return 'SAFE_SUCCESS';
    }
    if (
      scenario === 'OUTPUT_BYTES_LIMIT_PLUS_ONE' ||
      scenario === 'FINDING_COUNT_LIMIT_PLUS_ONE' ||
      scenario === 'TIMEOUT_PLUS_ONE'
    ) {
      return 'RESOURCE_KILL';
    }
    return 'REJECT';
  }
  if (
    SAST_FINGERPRINT_CORRELATION_QUALIFICATION_SCENARIOS.includes(
      scenario as (typeof SAST_FINGERPRINT_CORRELATION_QUALIFICATION_SCENARIOS)[number]
    )
  ) {
    if (
      scenario === 'LINE_SHIFT_INVARIANT' ||
      scenario === 'BRANCH_CHANGE_INVARIANT' ||
      scenario === 'COMMIT_CHANGE_INVARIANT' ||
      scenario === 'UNKNOWN_LOCATION_REASON_INVARIANT' ||
      scenario === 'DUPLICATE_REPLAY_EQUAL'
    ) {
      return 'IDENTITY_STABLE';
    }
    if (scenario === 'RULE_MIGRATION_DISTINCT') return 'IDENTITY_DISTINCT';
    if (scenario === 'FIXED_SEQUENCE') return 'FIXED';
    if (scenario === 'REOPEN_SEQUENCE') return 'REOPENED';
    if (
      scenario === 'FORCED_DIGEST_COLLISION_REJECT' ||
      scenario === 'TAMPERED_REPLAY_REJECT' ||
      scenario === 'CORRELATION_EDGE_LIMIT_PLUS_ONE'
    ) {
      return 'REJECT';
    }
    if (scenario === 'ZERO_FINDING_BATCH_COMPLETE') return 'SAFE_SUCCESS';
    return 'RELATED_ONLY';
  }
  if (
    SAST_EVIDENCE_PRIVACY_QUALIFICATION_SCENARIOS.includes(
      scenario as (typeof SAST_EVIDENCE_PRIVACY_QUALIFICATION_SCENARIOS)[number]
    )
  ) {
    if (
      scenario === 'KNOWN_FORMAT_SECRET_REDACT' ||
      scenario === 'REGISTERED_VALUE_REDACT' ||
      scenario === 'HIGH_ENTROPY_SECRET_REDACT' ||
      scenario === 'PRIVATE_KEY_REDACT' ||
      scenario === 'AUTHORIZATION_URL_CREDENTIAL_REDACT'
    ) {
      return 'REDACT';
    }
    if (scenario === 'RETENTION_EXPIRES') return 'DELETE';
    if (
      scenario === 'PROMPT_INJECTION_TREATED_AS_DATA' ||
      scenario === 'RETENTION_BOUNDARY_ACCEPT' ||
      scenario === 'AUDIT_LEAK_ZERO' ||
      scenario === 'RAW_ARTIFACT_LEAK_ZERO'
    ) {
      return 'SAFE_SUCCESS';
    }
    return 'REJECT';
  }
  return 'MEASURE';
}

function performanceProfileForScenario(
  scenario: SastMultiClassQualificationScenario
): SastProfileId | null {
  if (scenario.startsWith('JAVA_FAST_')) return 'JAVA_FAST_V1';
  if (scenario.startsWith('JAVA_DEEP_')) return 'JAVA_DEEP_V1';
  if (scenario.startsWith('COMMON_DEEP_')) return 'COMMON_DEEP_V1';
  return null;
}

function requiredScenarioSetIsExact(
  cases: readonly SastMultiClassQualificationCase[]
): boolean {
  return SAST_MULTI_CLASS_QUALIFICATION_CORPUS_CLASSES.every((corpusClass) => {
    const actual = cases
      .filter((item) => item.corpusClass === corpusClass)
      .map((item) => item.scenario)
      .sort(compareText);
    const expected = [
      ...SAST_MULTI_CLASS_QUALIFICATION_REQUIRED_SCENARIOS[corpusClass]
    ].sort(compareText);
    return arraysEqual(actual, expected);
  });
}

function fixtureInput(
  value: SastMultiClassQualificationFixture
): SastMultiClassQualificationFixtureInput {
  return {
    caseKey: value.caseKey,
    corpusClass: value.corpusClass,
    scenario: value.scenario,
    materializationKind: value.materializationKind,
    parameters: value.parameters,
    segments: value.segments,
    steps: value.steps,
    materializedBytes: value.materializedBytes,
    materializedEntries: value.materializedEntries,
    materializedPathDepth: value.materializedPathDepth,
    simulatedDurationSeconds: value.simulatedDurationSeconds
  };
}

function caseInput(
  value: SastMultiClassQualificationCase
): SastMultiClassQualificationCaseInput {
  return {
    caseKey: value.caseKey,
    caseRevision: value.caseRevision,
    corpusClass: value.corpusClass,
    scenario: value.scenario,
    profiles: value.profiles,
    fixturePath: value.fixturePath,
    fixtureId: value.fixtureId,
    fixtureDigest: value.fixtureDigest,
    fixtureBytes: value.fixtureBytes,
    materializationKind: value.materializationKind,
    expectedOutcome: value.expectedOutcome,
    evidenceStage: value.evidenceStage,
    minimumRuns: value.minimumRuns,
    hardwareClassRef: value.hardwareClassRef,
    ownerRef: value.ownerRef,
    licenseExpression: value.licenseExpression,
    provenanceRef: value.provenanceRef
  };
}

function snapshotInput(
  value: SastMultiClassQualificationSnapshot
): SastMultiClassQualificationSnapshotInput {
  return {
    revision: value.revision,
    publishedAt: value.publishedAt,
    ownerRef: value.ownerRef,
    licenseExpression: value.licenseExpression,
    provenanceRef: value.provenanceRef,
    performanceHardwareClassRef: value.performanceHardwareClassRef,
    performanceHardwareClassDigest: value.performanceHardwareClassDigest,
    cases: value.cases
  };
}

function cloneCase(
  value: SastMultiClassQualificationCase
): SastMultiClassQualificationCase {
  return { ...value, profiles: [...value.profiles] };
}

function expectedCaseKey(
  corpusClass: SastMultiClassQualificationCorpusClass,
  scenario: SastMultiClassQualificationScenario
): string {
  return `t052.${slug(corpusClass)}.${slug(scenario)}`;
}

function fixturePathFor(
  corpusClass: SastMultiClassQualificationCorpusClass,
  scenario: SastMultiClassQualificationScenario
): string {
  return `fixtures/${slug(corpusClass)}/${slug(scenario)}.fixture.json`;
}

function slug(value: string): string {
  return value.toLowerCase().replaceAll('_', '-');
}

function canonicalProfiles(values: readonly unknown[]): SastProfileId[] | null {
  if (
    values.length === 0 ||
    values.length > SAST_PROFILE_IDS.length ||
    values.some(
      (value) =>
        typeof value !== 'string' ||
        !SAST_PROFILE_IDS.includes(value as SastProfileId)
    )
  ) {
    return null;
  }
  const profiles = [...(values as SastProfileId[])].sort(compareText);
  return unique(profiles) ? profiles : null;
}

function compareCases(
  left: SastMultiClassQualificationCase,
  right: SastMultiClassQualificationCase
): number {
  return compareText(left.caseKey, right.caseKey);
}

function portablePathKey(value: string): string {
  return value.normalize('NFC').toLowerCase();
}

function decodedBase64Bytes(value: unknown): number {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length % 4 !== 0 ||
    !BASE64_PATTERN.test(value)
  ) {
    return -1;
  }
  const padding = value.endsWith('==') ? 2 : value.endsWith('=') ? 1 : 0;
  return (value.length / 4) * 3 - padding;
}

function hasSequentialOrdinals(
  values: readonly { readonly ordinal: number }[]
): boolean {
  return values.every((item, index) => item.ordinal === index + 1);
}

function isDigest(value: unknown): value is Sha256Digest {
  return typeof value === 'string' && SHA256_PATTERN.test(value);
}

function isSemanticVersion(value: unknown): value is string {
  return typeof value === 'string' && SEMANTIC_VERSION_PATTERN.test(value);
}

function isIsoInstant(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function isOwnerRef(value: unknown): value is string {
  return typeof value === 'string' && OWNER_REF_PATTERN.test(value);
}

function isLicenseExpression(value: unknown): value is string {
  return typeof value === 'string' && LICENSE_EXPRESSION_PATTERN.test(value);
}

function isDigestBoundReference(value: unknown): value is string {
  return typeof value === 'string' && DIGEST_BOUND_REFERENCE_PATTERN.test(value);
}

function isBoundedCanonicalText(value: unknown, maximumBytes: number): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value === value.normalize('NFC') &&
    ![...value].some((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return (
        codePoint <= 31 ||
        codePoint === 127 ||
        (codePoint >= 0xd800 && codePoint <= 0xdfff)
      );
    }) &&
    TEXT_ENCODER.encode(value).byteLength <= maximumBytes
  );
}

function hasExactKeys(value: unknown, keys: readonly string[]): value is object {
  if (!isPlainRecord(value)) return false;
  const actual = Object.keys(value).sort(compareText);
  const expected = [...keys].sort(compareText);
  return arraysEqual(actual, expected);
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function unique<T>(values: readonly T[]): boolean {
  return new Set(values).size === values.length;
}

function isSorted(values: readonly string[]): boolean {
  return arraysEqual(values, [...values].sort(compareText));
}

function arraysEqual<T>(left: readonly T[], right: readonly T[]): boolean {
  return left.length === right.length && left.every((item, index) => item === right[index]);
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function stableJson(
  value: unknown,
  depth = 0,
  ancestors: WeakSet<object> = new WeakSet<object>()
): string {
  if (depth > STABLE_JSON_MAXIMUM_DEPTH) return STABLE_JSON_INVALID_SENTINEL;
  if (value === null || typeof value !== 'object') {
    try {
      return JSON.stringify(value) ?? STABLE_JSON_INVALID_SENTINEL;
    } catch {
      return STABLE_JSON_INVALID_SENTINEL;
    }
  }
  if (ancestors.has(value)) return STABLE_JSON_INVALID_SENTINEL;
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return `[${value
        .map((item) => stableJson(item, depth + 1, ancestors))
        .join(',')}]`;
    }
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort(compareText)
      .map(
        (key) =>
          `${JSON.stringify(key)}:${stableJson(record[key], depth + 1, ancestors)}`
      )
      .join(',')}}`;
  } finally {
    ancestors.delete(value);
  }
}
