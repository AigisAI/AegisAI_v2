import { FINDING_SEVERITIES, type FindingSeverity } from './production-architecture';
import {
  SAST_CAPABILITIES,
  SAST_PROFILE_IDS,
  SAST_SCANNER_KINDS,
  type SastCapability,
  type SastProfileId,
  type SastScannerKind
} from './sast-runtime';

export const SAST_QUALIFICATION_CORPUS_CASE_VERSION =
  'sast-qualification-corpus-case-v1' as const;
export const SAST_QUALIFICATION_CORPUS_SNAPSHOT_VERSION =
  'sast-qualification-corpus-snapshot-v1' as const;
export const SAST_QUALIFICATION_PRIOR_RELEASE_MANIFEST_VERSION =
  'sast-qualification-prior-release-manifest-v1' as const;

export const SAST_QUALIFICATION_CORPUS_CLASSES = [
  'GOLDEN_POSITIVE',
  'GOLDEN_NEGATIVE'
] as const;
export type SastQualificationCorpusClass =
  (typeof SAST_QUALIFICATION_CORPUS_CLASSES)[number];

export const SAST_QUALIFICATION_EXPECTED_OUTCOMES = [
  'DETECT',
  'NO_FINDING'
] as const;
export type SastQualificationExpectedOutcome =
  (typeof SAST_QUALIFICATION_EXPECTED_OUTCOMES)[number];

export const SAST_QUALIFICATION_NEGATIVE_KINDS = [
  'PATCHED',
  'SANITIZER',
  'SAFE_API',
  'COMMENT_OR_STRING',
  'GENERATED_OR_VENDOR'
] as const;
export type SastQualificationNegativeKind =
  (typeof SAST_QUALIFICATION_NEGATIVE_KINDS)[number];

export const SAST_QUALIFICATION_LANGUAGES = ['COMMON', 'JAVA'] as const;
export type SastQualificationLanguage =
  (typeof SAST_QUALIFICATION_LANGUAGES)[number];

export const SAST_QUALIFICATION_CORPUS_LIMITS = Object.freeze({
  minimumPositiveCasesPerProfile: 200,
  minimumNegativeCasesPerProfile: 200,
  minimumCasesPerRule: 10,
  minimumCriticalHighCasesPerRule: 20,
  maximumCases: 5_000,
  maximumSourceBytes: 65_536,
  maximumSourceLines: 10_000,
  identifierBytes: 256,
  referenceBytes: 2_048
});

type Sha256Digest = `sha256:${string}`;
export type SastQualificationCorpusCanonicalDigester = (
  canonicalValue: string
) => Sha256Digest;

export interface SastQualificationCorpusCaseCore {
  version: typeof SAST_QUALIFICATION_CORPUS_CASE_VERSION;
  caseKey: string;
  pairKey: string;
  caseRevision: string;
  corpusClass: SastQualificationCorpusClass;
  negativeKind: SastQualificationNegativeKind | null;
  ownerRef: string;
  licenseExpression: string;
  provenanceRef: string;
  profiles: SastProfileId[];
  language: SastQualificationLanguage;
  scanner: Extract<SastScannerKind, 'OPENGREP' | 'TRIVY'>;
  capability: Exclude<SastCapability, 'SBOM'>;
  ruleSemanticId: string;
  ruleRevision: string;
  severity: FindingSeverity;
  expectedOutcome: SastQualificationExpectedOutcome;
  expectedFindingCount: 0 | 1;
  sourcePath: string;
  scanPath: string;
  sourceDigest: Sha256Digest;
  sourceBytes: number;
  expectedAnchor: string;
  startLine: number;
  endLine: number;
  sourcePlatformOwned: true;
  customerContentAccepted: false;
  executable: false;
  packageInstallRequired: false;
  buildRequired: false;
  dynamicExecutionRequired: false;
  networkRequired: false;
  immutable: true;
}

export interface SastQualificationCorpusCase
  extends SastQualificationCorpusCaseCore {
  caseId: string;
  caseDigest: Sha256Digest;
}

export type SastQualificationCorpusCaseInput = Omit<
  SastQualificationCorpusCaseCore,
  | 'version'
  | 'sourcePlatformOwned'
  | 'customerContentAccepted'
  | 'executable'
  | 'packageInstallRequired'
  | 'buildRequired'
  | 'dynamicExecutionRequired'
  | 'networkRequired'
  | 'immutable'
>;

export interface SastQualificationCorpusProfileCount {
  profileId: SastProfileId;
  positiveCases: number;
  negativeCases: number;
  priorMustDetectCases: number;
}

export interface SastQualificationCorpusRuleCount {
  ruleSemanticId: string;
  ruleRevision: string;
  severity: FindingSeverity;
  positiveCases: number;
  negativeCases: number;
  priorMustDetectCases: number;
}

export interface SastQualificationCorpusNegativeKindCount {
  negativeKind: SastQualificationNegativeKind;
  cases: number;
}

export interface SastQualificationPriorReleaseCaseBinding {
  caseId: string;
  caseDigest: Sha256Digest;
  caseKey: string;
  caseRevision: string;
  ruleSemanticId: string;
  ruleRevision: string;
  severity: Extract<FindingSeverity, 'CRITICAL' | 'HIGH'>;
}

export interface SastQualificationPriorReleaseManifestCore {
  version: typeof SAST_QUALIFICATION_PRIOR_RELEASE_MANIFEST_VERSION;
  releaseRevision: string;
  publishedAt: string;
  ownerRef: string;
  provenanceRef: string;
  bindings: SastQualificationPriorReleaseCaseBinding[];
  caseCount: number;
  caseSetDigest: Sha256Digest;
  source: 'PLATFORM_MANAGED';
  immutable: true;
}

export interface SastQualificationPriorReleaseManifest
  extends SastQualificationPriorReleaseManifestCore {
  releaseRef: string;
  manifestDigest: Sha256Digest;
}

export interface SastQualificationPriorReleaseManifestInput {
  releaseRevision: string;
  publishedAt: string;
  ownerRef: string;
  provenanceRef: string;
  bindings: readonly SastQualificationPriorReleaseCaseBinding[];
}

export interface SastQualificationCorpusSnapshotCore {
  version: typeof SAST_QUALIFICATION_CORPUS_SNAPSHOT_VERSION;
  revision: string;
  publishedAt: string;
  ownerRef: string;
  licenseExpression: string;
  provenanceRef: string;
  priorReleaseRef: string;
  priorReleaseManifestDigest: Sha256Digest;
  profiles: SastProfileId[];
  languages: SastQualificationLanguage[];
  cases: SastQualificationCorpusCase[];
  caseCount: number;
  positiveCaseCount: number;
  negativeCaseCount: number;
  priorMustDetectCaseCount: number;
  caseSetDigest: Sha256Digest;
  priorMustDetectSetDigest: Sha256Digest;
  priorMustDetectCaseIds: string[];
  profileCounts: SastQualificationCorpusProfileCount[];
  ruleCounts: SastQualificationCorpusRuleCount[];
  negativeKindCounts: SastQualificationCorpusNegativeKindCount[];
  source: 'PLATFORM_MANAGED';
  immutable: true;
  customerContentAccepted: false;
  customerExecutableConfigAccepted: false;
  networkRequired: false;
  packageInstallRequired: false;
  buildRequired: false;
  dynamicExecutionRequired: false;
}

export interface SastQualificationCorpusSnapshot
  extends SastQualificationCorpusSnapshotCore {
  corpusId: string;
  snapshotDigest: Sha256Digest;
}

export interface SastQualificationCorpusSnapshotInput {
  revision: string;
  publishedAt: string;
  ownerRef: string;
  licenseExpression: string;
  provenanceRef: string;
  priorReleaseManifest: SastQualificationPriorReleaseManifest;
  cases: readonly SastQualificationCorpusCase[];
}

const TEXT_ENCODER = new TextEncoder();
const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const CASE_ID_PATTERN = /^sast-qualification-case:\/\/[a-f0-9]{64}$/u;
const CORPUS_ID_PATTERN = /^sast-qualification-corpus:\/\/golden\/[a-f0-9]{64}$/u;
const PRIOR_RELEASE_REF_PATTERN =
  /^sast-release:\/\/aegisai\/sast\/(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?\/sha256:[a-f0-9]{64}$/u;
const SEMANTIC_VERSION_PATTERN =
  /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/u;
const CASE_KEY_PATTERN = /^[a-z0-9][a-z0-9._-]{0,159}$/u;
const PAIR_KEY_PATTERN = /^[a-z0-9][a-z0-9._-]{0,159}$/u;
const RULE_SEMANTIC_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,159}$/u;
const ANCHOR_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/#()~-]{0,255}$/u;
const OWNER_REF_PATTERN = /^team:\/\/[a-z0-9][a-z0-9._/-]{0,255}$/u;
const DIGEST_BOUND_REFERENCE_PATTERN =
  /^[a-z][a-z0-9+.-]*:\/\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+\/sha256:[a-f0-9]{64}$/u;
const LICENSE_EXPRESSION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9 .+()/-]{0,127}$/u;
const SOURCE_PATH_PATTERN =
  /^sources\/(?:java|common)\/[A-Za-z0-9][A-Za-z0-9._/-]{0,511}$/u;
const SCAN_PATH_PATTERN =
  /^workspace\/(?:java|common)\/[A-Za-z0-9][A-Za-z0-9._/-]{0,511}$/u;
const STABLE_JSON_MAXIMUM_DEPTH = 32;
const STABLE_JSON_INVALID_SENTINEL = '"__invalid_sast_qualification_shape__"';

const CASE_INPUT_KEYS = [
  'caseKey',
  'pairKey',
  'caseRevision',
  'corpusClass',
  'negativeKind',
  'ownerRef',
  'licenseExpression',
  'provenanceRef',
  'profiles',
  'language',
  'scanner',
  'capability',
  'ruleSemanticId',
  'ruleRevision',
  'severity',
  'expectedOutcome',
  'expectedFindingCount',
  'sourcePath',
  'scanPath',
  'sourceDigest',
  'sourceBytes',
  'expectedAnchor',
  'startLine',
  'endLine'
] as const;

const CASE_KEYS = [
  'version',
  'caseId',
  'caseDigest',
  ...CASE_INPUT_KEYS,
  'sourcePlatformOwned',
  'customerContentAccepted',
  'executable',
  'packageInstallRequired',
  'buildRequired',
  'dynamicExecutionRequired',
  'networkRequired',
  'immutable'
] as const;

const SNAPSHOT_KEYS = [
  'version',
  'corpusId',
  'snapshotDigest',
  'revision',
  'publishedAt',
  'ownerRef',
  'licenseExpression',
  'provenanceRef',
  'priorReleaseRef',
  'priorReleaseManifestDigest',
  'profiles',
  'languages',
  'cases',
  'caseCount',
  'positiveCaseCount',
  'negativeCaseCount',
  'priorMustDetectCaseCount',
  'caseSetDigest',
  'priorMustDetectSetDigest',
  'priorMustDetectCaseIds',
  'profileCounts',
  'ruleCounts',
  'negativeKindCounts',
  'source',
  'immutable',
  'customerContentAccepted',
  'customerExecutableConfigAccepted',
  'networkRequired',
  'packageInstallRequired',
  'buildRequired',
  'dynamicExecutionRequired'
] as const;

const PRIOR_RELEASE_BINDING_KEYS = [
  'caseId',
  'caseDigest',
  'caseKey',
  'caseRevision',
  'ruleSemanticId',
  'ruleRevision',
  'severity'
] as const;

const PRIOR_RELEASE_MANIFEST_KEYS = [
  'version',
  'releaseRef',
  'manifestDigest',
  'releaseRevision',
  'publishedAt',
  'ownerRef',
  'provenanceRef',
  'bindings',
  'caseCount',
  'caseSetDigest',
  'source',
  'immutable'
] as const;

export function buildSastQualificationCorpusCase(
  input: Readonly<SastQualificationCorpusCaseInput>,
  digestCanonical: SastQualificationCorpusCanonicalDigester
): SastQualificationCorpusCase | null {
  if (!hasExactKeys(input, CASE_INPUT_KEYS) || !Array.isArray(input.profiles)) {
    return null;
  }
  const profiles = canonicalProfiles(input.profiles);
  if (!profiles) return null;
  const core: SastQualificationCorpusCaseCore = {
    version: SAST_QUALIFICATION_CORPUS_CASE_VERSION,
    caseKey: input.caseKey,
    pairKey: input.pairKey,
    caseRevision: input.caseRevision,
    corpusClass: input.corpusClass,
    negativeKind: input.negativeKind,
    ownerRef: input.ownerRef,
    licenseExpression: input.licenseExpression,
    provenanceRef: input.provenanceRef,
    profiles,
    language: input.language,
    scanner: input.scanner,
    capability: input.capability,
    ruleSemanticId: input.ruleSemanticId,
    ruleRevision: input.ruleRevision,
    severity: input.severity,
    expectedOutcome: input.expectedOutcome,
    expectedFindingCount: input.expectedFindingCount,
    sourcePath: input.sourcePath,
    scanPath: input.scanPath,
    sourceDigest: input.sourceDigest,
    sourceBytes: input.sourceBytes,
    expectedAnchor: input.expectedAnchor,
    startLine: input.startLine,
    endLine: input.endLine,
    sourcePlatformOwned: true,
    customerContentAccepted: false,
    executable: false,
    packageInstallRequired: false,
    buildRequired: false,
    dynamicExecutionRequired: false,
    networkRequired: false,
    immutable: true
  };
  if (!isCaseCoreValid(core)) return null;
  const caseDigest = digestCanonical(stableJson(core));
  if (!isDigest(caseDigest)) return null;
  return {
    ...core,
    caseId: `sast-qualification-case://${caseDigest.slice('sha256:'.length)}`,
    caseDigest
  };
}

export function isSastQualificationCorpusCaseValid(
  value: unknown,
  digestCanonical: SastQualificationCorpusCanonicalDigester
): value is SastQualificationCorpusCase {
  if (!hasExactKeys(value, CASE_KEYS)) return false;
  const candidate = value as SastQualificationCorpusCase;
  if (
    !CASE_ID_PATTERN.test(candidate.caseId) ||
    !isDigest(candidate.caseDigest) ||
    !Array.isArray(candidate.profiles)
  ) {
    return false;
  }
  const rebuilt = buildSastQualificationCorpusCase(caseInput(candidate), digestCanonical);
  return rebuilt !== null && stableJson(rebuilt) === stableJson(candidate);
}

export function buildSastQualificationPriorReleaseManifest(
  input: Readonly<SastQualificationPriorReleaseManifestInput>,
  digestCanonical: SastQualificationCorpusCanonicalDigester
): SastQualificationPriorReleaseManifest | null {
  if (
    !hasExactKeys(input, [
      'releaseRevision',
      'publishedAt',
      'ownerRef',
      'provenanceRef',
      'bindings'
    ]) ||
    !Array.isArray(input.bindings) ||
    !isSemanticVersion(input.releaseRevision) ||
    !isIsoInstant(input.publishedAt) ||
    !isOwnerRef(input.ownerRef) ||
    !isDigestBoundReference(input.provenanceRef) ||
    input.bindings.length === 0 ||
    input.bindings.length > SAST_QUALIFICATION_CORPUS_LIMITS.maximumCases ||
    input.bindings.some((item) => !isPriorReleaseBindingValid(item))
  ) {
    return null;
  }
  const bindings = input.bindings
    .map((item) => ({ ...item }))
    .sort((left, right) => compareText(left.caseKey, right.caseKey));
  if (
    !unique(bindings.map((item) => item.caseId)) ||
    !unique(bindings.map((item) => item.caseDigest)) ||
    !unique(bindings.map((item) => item.caseKey))
  ) {
    return null;
  }
  const caseSetDigest = digestCanonical(stableJson(bindings));
  if (!isDigest(caseSetDigest)) return null;
  const core: SastQualificationPriorReleaseManifestCore = {
    version: SAST_QUALIFICATION_PRIOR_RELEASE_MANIFEST_VERSION,
    releaseRevision: input.releaseRevision,
    publishedAt: input.publishedAt,
    ownerRef: input.ownerRef,
    provenanceRef: input.provenanceRef,
    bindings,
    caseCount: bindings.length,
    caseSetDigest,
    source: 'PLATFORM_MANAGED',
    immutable: true
  };
  const manifestDigest = digestCanonical(stableJson(core));
  if (!isDigest(manifestDigest)) return null;
  return {
    ...core,
    releaseRef: `sast-release://aegisai/sast/${input.releaseRevision}/${manifestDigest}`,
    manifestDigest
  };
}

export function isSastQualificationPriorReleaseManifestValid(
  value: unknown,
  digestCanonical: SastQualificationCorpusCanonicalDigester
): value is SastQualificationPriorReleaseManifest {
  if (!hasExactKeys(value, PRIOR_RELEASE_MANIFEST_KEYS)) return false;
  const candidate = value as SastQualificationPriorReleaseManifest;
  if (
    !PRIOR_RELEASE_REF_PATTERN.test(candidate.releaseRef) ||
    !isDigest(candidate.manifestDigest) ||
    !Array.isArray(candidate.bindings)
  ) {
    return false;
  }
  const rebuilt = buildSastQualificationPriorReleaseManifest(
    {
      releaseRevision: candidate.releaseRevision,
      publishedAt: candidate.publishedAt,
      ownerRef: candidate.ownerRef,
      provenanceRef: candidate.provenanceRef,
      bindings: candidate.bindings
    },
    digestCanonical
  );
  return rebuilt !== null && stableJson(rebuilt) === stableJson(candidate);
}

export function buildSastQualificationCorpusSnapshot(
  input: Readonly<SastQualificationCorpusSnapshotInput>,
  digestCanonical: SastQualificationCorpusCanonicalDigester
): SastQualificationCorpusSnapshot | null {
  if (
    !hasExactKeys(input, [
      'revision',
      'publishedAt',
      'ownerRef',
      'licenseExpression',
      'provenanceRef',
      'priorReleaseManifest',
      'cases'
    ]) ||
    !Array.isArray(input.cases) ||
    !isSemanticVersion(input.revision) ||
    !isIsoInstant(input.publishedAt) ||
    !isOwnerRef(input.ownerRef) ||
    !isLicenseExpression(input.licenseExpression) ||
    !isDigestBoundReference(input.provenanceRef) ||
    !isSastQualificationPriorReleaseManifestValid(
      input.priorReleaseManifest,
      digestCanonical
    ) ||
    input.cases.length === 0 ||
    input.cases.length > SAST_QUALIFICATION_CORPUS_LIMITS.maximumCases ||
    input.cases.some(
      (item) => !isSastQualificationCorpusCaseValid(item, digestCanonical)
    )
  ) {
    return null;
  }
  const cases = input.cases.map((item) => cloneCase(item)).sort(compareCases);
  const distinctSourcePaths = [...new Set(cases.map((item) => item.sourcePath))];
  if (
    !unique(cases.map((item) => item.caseId)) ||
    !unique(cases.map((item) => item.caseDigest)) ||
    !unique(cases.map((item) => item.caseKey)) ||
    !unique(cases.map((item) => item.scanPath)) ||
    !unique(cases.map((item) => portablePathKey(item.scanPath))) ||
    !unique(distinctSourcePaths.map(portablePathKey)) ||
    !unique(cases.map((item) => item.expectedAnchor)) ||
    !unique(
      cases.map(
        (item) => `${item.sourcePath}:${item.startLine}:${item.endLine}`
      )
    ) ||
    cases.some(
      (item) =>
        item.ownerRef !== input.ownerRef ||
        item.licenseExpression !== input.licenseExpression
    ) ||
    !pairsAreComplete(cases)
  ) {
    return null;
  }

  const casesById = new Map(cases.map((item) => [item.caseId, item]));
  const priorMustDetectCases = input.priorReleaseManifest.bindings.map((binding) => {
    const item = casesById.get(binding.caseId);
    return item && priorReleaseBindingMatchesCase(binding, item) ? item : null;
  });
  if (priorMustDetectCases.some((item) => item === null)) return null;
  const authenticatedPriorCases = priorMustDetectCases as SastQualificationCorpusCase[];
  const priorMustDetectCaseIds = input.priorReleaseManifest.bindings.map(
    (item) => item.caseId
  );
  const profileCounts = buildProfileCounts(cases, authenticatedPriorCases);
  const ruleCounts = buildRuleCounts(cases, authenticatedPriorCases);
  const negativeKindCounts = SAST_QUALIFICATION_NEGATIVE_KINDS.map(
    (negativeKind) => ({
      negativeKind,
      cases: cases.filter((item) => item.negativeKind === negativeKind).length
    })
  );
  if (
    ruleCounts.length === 0 ||
    profileCounts.some(
      (count) =>
        count.positiveCases <
          SAST_QUALIFICATION_CORPUS_LIMITS.minimumPositiveCasesPerProfile ||
        count.negativeCases <
          SAST_QUALIFICATION_CORPUS_LIMITS.minimumNegativeCasesPerProfile
    ) ||
    ruleCounts.some((count) => {
      const minimum =
        count.severity === 'CRITICAL' || count.severity === 'HIGH'
          ? SAST_QUALIFICATION_CORPUS_LIMITS.minimumCriticalHighCasesPerRule
          : SAST_QUALIFICATION_CORPUS_LIMITS.minimumCasesPerRule;
      return (
        count.positiveCases < minimum ||
        count.negativeCases < minimum
      );
    }) ||
    negativeKindCounts.some((count) => count.cases === 0)
  ) {
    return null;
  }

  const caseBindings = cases.map((item) => ({
    caseId: item.caseId,
    caseDigest: item.caseDigest
  }));
  const positiveCaseCount = cases.filter(
    (item) => item.corpusClass === 'GOLDEN_POSITIVE'
  ).length;
  const negativeCaseCount = cases.length - positiveCaseCount;
  const core: SastQualificationCorpusSnapshotCore = {
    version: SAST_QUALIFICATION_CORPUS_SNAPSHOT_VERSION,
    revision: input.revision,
    publishedAt: input.publishedAt,
    ownerRef: input.ownerRef,
    licenseExpression: input.licenseExpression,
    provenanceRef: input.provenanceRef,
    priorReleaseRef: input.priorReleaseManifest.releaseRef,
    priorReleaseManifestDigest: input.priorReleaseManifest.manifestDigest,
    profiles: [...SAST_PROFILE_IDS],
    languages: [...SAST_QUALIFICATION_LANGUAGES],
    cases,
    caseCount: cases.length,
    positiveCaseCount,
    negativeCaseCount,
    priorMustDetectCaseCount: authenticatedPriorCases.length,
    caseSetDigest: digestCanonical(stableJson(caseBindings)),
    priorMustDetectSetDigest: input.priorReleaseManifest.caseSetDigest,
    priorMustDetectCaseIds,
    profileCounts,
    ruleCounts,
    negativeKindCounts,
    source: 'PLATFORM_MANAGED',
    immutable: true,
    customerContentAccepted: false,
    customerExecutableConfigAccepted: false,
    networkRequired: false,
    packageInstallRequired: false,
    buildRequired: false,
    dynamicExecutionRequired: false
  };
  if (
    !isDigest(core.caseSetDigest) ||
    !isDigest(core.priorMustDetectSetDigest)
  ) {
    return null;
  }
  const snapshotDigest = digestCanonical(stableJson(core));
  if (!isDigest(snapshotDigest)) return null;
  return {
    ...core,
    corpusId: `sast-qualification-corpus://golden/${snapshotDigest.slice('sha256:'.length)}`,
    snapshotDigest
  };
}

export function isSastQualificationCorpusSnapshotValid(
  value: unknown,
  digestCanonical: SastQualificationCorpusCanonicalDigester,
  priorReleaseManifest: unknown
): value is SastQualificationCorpusSnapshot {
  if (
    !hasExactKeys(value, SNAPSHOT_KEYS) ||
    !isSastQualificationPriorReleaseManifestValid(
      priorReleaseManifest,
      digestCanonical
    )
  ) {
    return false;
  }
  const candidate = value as SastQualificationCorpusSnapshot;
  if (
    !CORPUS_ID_PATTERN.test(candidate.corpusId) ||
    !isDigest(candidate.snapshotDigest) ||
    !Array.isArray(candidate.cases) ||
    !Array.isArray(candidate.profiles) ||
    !Array.isArray(candidate.languages) ||
    !Array.isArray(candidate.priorMustDetectCaseIds) ||
    !Array.isArray(candidate.profileCounts) ||
    !Array.isArray(candidate.ruleCounts) ||
    !Array.isArray(candidate.negativeKindCounts)
  ) {
    return false;
  }
  const rebuilt = buildSastQualificationCorpusSnapshot(
    {
      revision: candidate.revision,
      publishedAt: candidate.publishedAt,
      ownerRef: candidate.ownerRef,
      licenseExpression: candidate.licenseExpression,
      provenanceRef: candidate.provenanceRef,
      priorReleaseManifest,
      cases: candidate.cases
    },
    digestCanonical
  );
  return rebuilt !== null && stableJson(rebuilt) === stableJson(candidate);
}

function isPriorReleaseBindingValid(
  value: unknown
): value is SastQualificationPriorReleaseCaseBinding {
  if (!hasExactKeys(value, PRIOR_RELEASE_BINDING_KEYS)) return false;
  const binding = value as SastQualificationPriorReleaseCaseBinding;
  return (
    CASE_ID_PATTERN.test(binding.caseId) &&
    isDigest(binding.caseDigest) &&
    binding.caseId ===
      `sast-qualification-case://${binding.caseDigest.slice('sha256:'.length)}` &&
    CASE_KEY_PATTERN.test(binding.caseKey) &&
    isSemanticVersion(binding.caseRevision) &&
    RULE_SEMANTIC_ID_PATTERN.test(binding.ruleSemanticId) &&
    isSemanticVersion(binding.ruleRevision) &&
    (binding.severity === 'CRITICAL' || binding.severity === 'HIGH')
  );
}

function priorReleaseBindingMatchesCase(
  binding: SastQualificationPriorReleaseCaseBinding,
  item: SastQualificationCorpusCase
): boolean {
  return (
    item.caseId === binding.caseId &&
    item.caseDigest === binding.caseDigest &&
    item.caseKey === binding.caseKey &&
    item.caseRevision === binding.caseRevision &&
    item.ruleSemanticId === binding.ruleSemanticId &&
    item.ruleRevision === binding.ruleRevision &&
    item.severity === binding.severity &&
    item.corpusClass === 'GOLDEN_POSITIVE' &&
    item.negativeKind === null &&
    item.expectedOutcome === 'DETECT' &&
    item.expectedFindingCount === 1
  );
}

function isCaseCoreValid(value: SastQualificationCorpusCaseCore): boolean {
  const expectedProfiles = profilesFor(value.scanner, value.capability);
  return (
    CASE_KEY_PATTERN.test(value.caseKey) &&
    PAIR_KEY_PATTERN.test(value.pairKey) &&
    isSemanticVersion(value.caseRevision) &&
    SAST_QUALIFICATION_CORPUS_CLASSES.includes(value.corpusClass) &&
    isOwnerRef(value.ownerRef) &&
    isLicenseExpression(value.licenseExpression) &&
    isDigestBoundReference(value.provenanceRef) &&
    SAST_QUALIFICATION_LANGUAGES.includes(value.language) &&
    SAST_SCANNER_KINDS.includes(value.scanner) &&
    SAST_CAPABILITIES.includes(value.capability) &&
    arraysEqual(value.profiles, expectedProfiles) &&
    scannerLanguageMatches(value.scanner, value.language, value.capability) &&
    RULE_SEMANTIC_ID_PATTERN.test(value.ruleSemanticId) &&
    isSemanticVersion(value.ruleRevision) &&
    FINDING_SEVERITIES.includes(value.severity) &&
    expectationMatches(value) &&
    isSourcePath(value.sourcePath) &&
    isScanPath(value.scanPath) &&
    pathLanguageMatches(value.sourcePath, value.scanPath, value.language) &&
    isDigest(value.sourceDigest) &&
    Number.isSafeInteger(value.sourceBytes) &&
    value.sourceBytes > 0 &&
    value.sourceBytes <= SAST_QUALIFICATION_CORPUS_LIMITS.maximumSourceBytes &&
    ANCHOR_PATTERN.test(value.expectedAnchor) &&
    isLine(value.startLine) &&
    isLine(value.endLine) &&
    value.endLine >= value.startLine &&
    value.sourcePlatformOwned === true &&
    value.customerContentAccepted === false &&
    value.executable === false &&
    value.packageInstallRequired === false &&
    value.buildRequired === false &&
    value.dynamicExecutionRequired === false &&
    value.networkRequired === false &&
    value.immutable === true
  );
}

function expectationMatches(value: SastQualificationCorpusCaseCore): boolean {
  if (value.corpusClass === 'GOLDEN_POSITIVE') {
    return (
      value.negativeKind === null &&
      value.expectedOutcome === 'DETECT' &&
      value.expectedFindingCount === 1
    );
  }
  return (
    SAST_QUALIFICATION_NEGATIVE_KINDS.includes(
      value.negativeKind as SastQualificationNegativeKind
    ) &&
    value.expectedOutcome === 'NO_FINDING' &&
    value.expectedFindingCount === 0
  );
}

function pairsAreComplete(cases: readonly SastQualificationCorpusCase[]): boolean {
  const pairs = new Map<string, SastQualificationCorpusCase[]>();
  for (const item of cases) {
    const current = pairs.get(item.pairKey) ?? [];
    current.push(item);
    pairs.set(item.pairKey, current);
  }
  for (const pair of pairs.values()) {
    if (pair.length !== 2) return false;
    const positive = pair.find((item) => item.corpusClass === 'GOLDEN_POSITIVE');
    const negative = pair.find((item) => item.corpusClass === 'GOLDEN_NEGATIVE');
    if (
      !positive ||
      !negative ||
      positive.ruleSemanticId !== negative.ruleSemanticId ||
      positive.ruleRevision !== negative.ruleRevision ||
      positive.scanner !== negative.scanner ||
      positive.capability !== negative.capability ||
      positive.language !== negative.language ||
      positive.severity !== negative.severity ||
      !arraysEqual(positive.profiles, negative.profiles)
    ) {
      return false;
    }
  }
  return true;
}

function buildProfileCounts(
  cases: readonly SastQualificationCorpusCase[],
  prior: readonly SastQualificationCorpusCase[]
): SastQualificationCorpusProfileCount[] {
  return SAST_PROFILE_IDS.map((profileId) => ({
    profileId,
    positiveCases: cases.filter(
      (item) =>
        item.corpusClass === 'GOLDEN_POSITIVE' && item.profiles.includes(profileId)
    ).length,
    negativeCases: cases.filter(
      (item) =>
        item.corpusClass === 'GOLDEN_NEGATIVE' && item.profiles.includes(profileId)
    ).length,
    priorMustDetectCases: prior.filter((item) => item.profiles.includes(profileId))
      .length
  }));
}

function buildRuleCounts(
  cases: readonly SastQualificationCorpusCase[],
  prior: readonly SastQualificationCorpusCase[]
): SastQualificationCorpusRuleCount[] {
  const rules = new Map<
    string,
    { ruleRevision: string; severity: FindingSeverity }
  >();
  for (const item of cases) {
    const existing = rules.get(item.ruleSemanticId);
    if (
      existing &&
      (existing.ruleRevision !== item.ruleRevision ||
        existing.severity !== item.severity)
    ) {
      return [];
    }
    rules.set(item.ruleSemanticId, {
      ruleRevision: item.ruleRevision,
      severity: item.severity
    });
  }
  return [...rules.entries()]
    .sort(([left], [right]) => compareText(left, right))
    .map(([ruleSemanticId, rule]) => ({
      ruleSemanticId,
      ruleRevision: rule.ruleRevision,
      severity: rule.severity,
      positiveCases: cases.filter(
        (item) =>
          item.ruleSemanticId === ruleSemanticId &&
          item.corpusClass === 'GOLDEN_POSITIVE'
      ).length,
      negativeCases: cases.filter(
        (item) =>
          item.ruleSemanticId === ruleSemanticId &&
          item.corpusClass === 'GOLDEN_NEGATIVE'
      ).length,
      priorMustDetectCases: prior.filter(
        (item) => item.ruleSemanticId === ruleSemanticId
      ).length
    }));
}

function profilesFor(
  scanner: SastQualificationCorpusCaseCore['scanner'],
  capability: SastQualificationCorpusCaseCore['capability']
): SastProfileId[] {
  if (scanner === 'OPENGREP' && capability === 'SAST') {
    return ['JAVA_FAST_V1', 'JAVA_DEEP_V1'];
  }
  if (
    scanner === 'TRIVY' &&
    (capability === 'DEPENDENCY_VULNERABILITY' ||
      capability === 'SECRET_DETECTION')
  ) {
    return ['JAVA_FAST_V1', 'JAVA_DEEP_V1', 'COMMON_DEEP_V1'];
  }
  if (scanner === 'TRIVY' && capability === 'IAC_MISCONFIGURATION') {
    return ['JAVA_DEEP_V1', 'COMMON_DEEP_V1'];
  }
  return [];
}

function scannerLanguageMatches(
  scanner: SastQualificationCorpusCaseCore['scanner'],
  language: SastQualificationLanguage,
  capability: SastQualificationCorpusCaseCore['capability']
): boolean {
  return scanner === 'OPENGREP'
    ? language === 'JAVA' && capability === 'SAST'
    : scanner === 'TRIVY' && language === 'COMMON' && capability !== 'SAST';
}

function canonicalProfiles(value: readonly SastProfileId[]): SastProfileId[] | null {
  if (
    value.length === 0 ||
    !value.every((item) => SAST_PROFILE_IDS.includes(item)) ||
    !unique(value)
  ) {
    return null;
  }
  return SAST_PROFILE_IDS.filter((profileId) => value.includes(profileId));
}

function caseInput(
  value: SastQualificationCorpusCase
): SastQualificationCorpusCaseInput {
  return {
    caseKey: value.caseKey,
    pairKey: value.pairKey,
    caseRevision: value.caseRevision,
    corpusClass: value.corpusClass,
    negativeKind: value.negativeKind,
    ownerRef: value.ownerRef,
    licenseExpression: value.licenseExpression,
    provenanceRef: value.provenanceRef,
    profiles: [...value.profiles],
    language: value.language,
    scanner: value.scanner,
    capability: value.capability,
    ruleSemanticId: value.ruleSemanticId,
    ruleRevision: value.ruleRevision,
    severity: value.severity,
    expectedOutcome: value.expectedOutcome,
    expectedFindingCount: value.expectedFindingCount,
    sourcePath: value.sourcePath,
    scanPath: value.scanPath,
    sourceDigest: value.sourceDigest,
    sourceBytes: value.sourceBytes,
    expectedAnchor: value.expectedAnchor,
    startLine: value.startLine,
    endLine: value.endLine
  };
}

function cloneCase(value: SastQualificationCorpusCase): SastQualificationCorpusCase {
  return { ...value, profiles: [...value.profiles] };
}

function compareCases(
  left: SastQualificationCorpusCase,
  right: SastQualificationCorpusCase
): number {
  return compareText(left.caseKey, right.caseKey);
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function portablePathKey(value: string): string {
  return value.toLowerCase();
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
  return (
    isBoundedText(value, SAST_QUALIFICATION_CORPUS_LIMITS.referenceBytes) &&
    OWNER_REF_PATTERN.test(value)
  );
}

function isDigestBoundReference(value: unknown): value is string {
  return (
    isBoundedText(value, SAST_QUALIFICATION_CORPUS_LIMITS.referenceBytes) &&
    DIGEST_BOUND_REFERENCE_PATTERN.test(value)
  );
}

function isLicenseExpression(value: unknown): value is string {
  return (
    isBoundedText(value, SAST_QUALIFICATION_CORPUS_LIMITS.identifierBytes) &&
    LICENSE_EXPRESSION_PATTERN.test(value)
  );
}

function isSourcePath(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value === value.normalize('NFC') &&
    SOURCE_PATH_PATTERN.test(value) &&
    !value.includes('//') &&
    !value.split('/').some((part) => part === '.' || part === '..')
  );
}

function isScanPath(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value === value.normalize('NFC') &&
    SCAN_PATH_PATTERN.test(value) &&
    !value.includes('//') &&
    !value.split('/').some((part) => part === '.' || part === '..')
  );
}

function pathLanguageMatches(
  sourcePath: string,
  scanPath: string,
  language: SastQualificationLanguage
): boolean {
  const segment = language.toLowerCase();
  return (
    sourcePath.startsWith(`sources/${segment}/`) &&
    scanPath.startsWith(`workspace/${segment}/`)
  );
}

function isLine(value: unknown): value is number {
  return (
    Number.isSafeInteger(value) &&
    (value as number) > 0 &&
    (value as number) <= SAST_QUALIFICATION_CORPUS_LIMITS.maximumSourceLines
  );
}

function isBoundedText(value: unknown, maximumBytes: number): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value === value.normalize('NFC') &&
    ![...value].some((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return codePoint <= 31 || codePoint === 127;
    }) &&
    TEXT_ENCODER.encode(value).byteLength <= maximumBytes
  );
}

function arraysEqual<T>(left: readonly T[], right: readonly T[]): boolean {
  return left.length === right.length && left.every((item, index) => item === right[index]);
}

function unique<T>(values: readonly T[]): boolean {
  return new Set(values).size === values.length;
}

function hasExactKeys(value: unknown, keys: readonly string[]): value is object {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const actual = Object.keys(value).sort(compareText);
  const expected = [...keys].sort(compareText);
  return arraysEqual(actual, expected);
}

function stableJson(
  value: unknown,
  depth = 0,
  ancestors: WeakSet<object> = new WeakSet<object>()
): string {
  if (depth > STABLE_JSON_MAXIMUM_DEPTH) return STABLE_JSON_INVALID_SENTINEL;
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value) ?? STABLE_JSON_INVALID_SENTINEL;
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
