import {
  SAST_SCAN_PROFILES,
  SAST_SCANNER_KINDS,
  isSastScanProfileValid,
  type SastProfileId,
  type SastScanLane,
  type SastScanPlan,
  type SastScanProfile,
  type ScannerSetDescriptor,
  type VerifiedScannerSetDescriptor
} from './sast-runtime';

export const SAST_PLANNING_STATES = ['ADMITTED', 'DEFERRED', 'REJECTED'] as const;
export type SastPlanningState = (typeof SAST_PLANNING_STATES)[number];

export const SAST_COVERAGE_CLAIMS = [
  'LANGUAGE_SAST_COMPLETE',
  'COMMON_STATIC_COVERAGE_ONLY',
  'NONE'
] as const;
export type SastCoverageClaim = (typeof SAST_COVERAGE_CLAIMS)[number];

export const SAST_PLANNING_REASON_CODES = [
  'TRUSTED_METADATA_INVALID',
  'TRUSTED_METADATA_SCOPE_MISMATCH',
  'FIXED_COMMIT_REQUIRED',
  'PROFILE_POLICY_INVALID',
  'PROFILE_POLICY_VERSION_MISMATCH',
  'PROFILE_NOT_ALLOWED_BY_POLICY',
  'UNSUPPORTED_LANGUAGE_FOR_FAST',
  'UNSUPPORTED_POLYGLOT_PROFILE',
  'LANGUAGE_SPECIFIC_SAST_UNAVAILABLE',
  'LANGUAGE_SPECIFIC_SAST_REQUIRED',
  'REPOSITORY_BYTES_LIMIT_EXCEEDED',
  'SELECTED_BYTES_LIMIT_EXCEEDED',
  'FILE_COUNT_LIMIT_EXCEEDED',
  'SINGLE_FILE_BYTES_LIMIT_EXCEEDED',
  'PATH_DEPTH_LIMIT_EXCEEDED',
  'SCANNER_SET_VERSION_MISMATCH',
  'SCANNER_SET_INVALID',
  'REQUIRED_SCANNER_MISSING',
  'REQUIRED_RULE_BUNDLE_MISSING',
  'RULE_BUNDLE_MANIFEST_UNVERIFIED',
  'RULE_BUNDLE_MANIFEST_MISMATCH',
  'RULE_BUNDLE_COMPATIBILITY_UNSUPPORTED',
  'RULE_BUNDLE_VERIFICATION_UNAVAILABLE',
  'VULNERABILITY_DATABASE_INVALID',
  'SCHEMA_BUNDLE_INVALID',
  'NORMALIZER_BUNDLE_INVALID',
  'QUEUE_POLICY_INVALID',
  'QUEUE_USAGE_INVALID',
  'QUEUE_USAGE_STALE',
  'TENANT_CONCURRENCY_LIMIT',
  'TENANT_QUEUED_LIMIT',
  'TENANT_DAILY_BUDGET_EXHAUSTED',
  'REPOSITORY_CONCURRENCY_LIMIT',
  'REPOSITORY_FREQUENCY_LIMIT',
  'LANE_QUEUE_CAPACITY_EXHAUSTED',
  'PLAN_CONTRACT_INVALID'
] as const;
export type SastPlanningReasonCode = (typeof SAST_PLANNING_REASON_CODES)[number];

export interface TrustedSastLanguageSignal {
  language: string;
  sourceFileCount: number;
  sourceBytes: number;
}

export interface TrustedSastRepositoryMetadata {
  repositoryBindingId: string;
  fixedCommitSha: string;
  inventoryDigest: `sha256:${string}`;
  attestationRef: string;
  collectedAt: string;
  sourceLanguages: readonly TrustedSastLanguageSignal[];
  manifestNames: readonly string[];
  repositoryBytes: number;
  selectedBytes: number;
  fileCount: number;
  maxSingleFileBytes: number;
  maxPathDepth: number;
}

export interface SastProfileSelectionPolicy {
  policyVersion: string;
  allowedProfileIds: readonly SastProfileId[];
  requireLanguageSpecificSast: boolean;
}

export interface SastProfileSelectionDecision {
  state: 'SELECTED' | 'REJECTED';
  profile?: SastScanProfile;
  coverageClaim: SastCoverageClaim;
  reasonCodes: SastPlanningReasonCode[];
}

export interface SastLaneQueuePolicy {
  lane: SastScanLane;
  queueName: 'scan.fast.v1' | 'scan.deep.v1';
  maxActivePerTenant: number;
  maxQueuedPerTenant: number;
  maxDailyAdmissionsPerTenant: number;
  maxActivePerRepository: number;
  minimumRepositoryIntervalSeconds: number;
  maxQueuedInLane: number;
  capacityRetrySeconds: number;
}

export interface SastQueuePolicySet {
  policyVersion: string;
  digest: `sha256:${string}`;
  signatureRef: string;
  provenanceRef: string;
  fairnessStrategy: 'TENANT_ROUND_ROBIN';
  lanes: Readonly<Record<SastScanLane, SastLaneQueuePolicy>>;
}

export interface SastQueueUsageSnapshot {
  snapshotVersion: number;
  tenantId: string;
  repositoryBindingId: string;
  lane: SastScanLane;
  dailyWindowStartedAt: string;
  activeForTenant: number;
  queuedForTenant: number;
  admittedTodayForTenant: number;
  activeForRepository: number;
  queuedInLane: number;
  lastRepositoryAdmissionAt?: string;
}

export interface SastQueueAdmissionDecision {
  state: 'ADMITTED' | 'DEFERRED' | 'REJECTED';
  queueName?: SastLaneQueuePolicy['queueName'];
  fairnessKey?: string;
  queuePolicyVersion?: string;
  queuePolicyDigest?: `sha256:${string}`;
  reasonCodes: SastPlanningReasonCode[];
  retryAfterSeconds?: number;
}

export interface SastQueueCandidate {
  lane: SastScanLane;
  tenantId: string;
  scanRequestId: string;
  enqueuedAt: string;
}

export interface SastCanonicalScanKeyInput {
  tenantId: string;
  repositoryBindingId: string;
  lane: SastScanLane;
  targetRef: string;
  fixedCommitSha: string;
  inventoryDigest: `sha256:${string}`;
  attestationRef: string;
  policyVersion: string;
  profile: SastScanProfile;
  profileDigest: `sha256:${string}`;
  scannerSet: VerifiedScannerSetDescriptor;
  isolationClass: 'HARDENED' | 'RESTRICTED';
}

export interface SastUserVisiblePlanningState {
  state: SastPlanningState;
  profileId?: SastProfileId;
  coverageClaim: SastCoverageClaim;
  queueName?: SastLaneQueuePolicy['queueName'];
  queuePolicyVersion?: string;
  queuePolicyDigest?: `sha256:${string}`;
  canonicalScanKey?: `sha256:${string}`;
  reasonCodes: SastPlanningReasonCode[];
  retryAfterSeconds?: number;
  updatedAt: string;
}

export interface SastScanPlanningInput {
  tenantId: string;
  scanRequestId: string;
  repositoryMetadata: TrustedSastRepositoryMetadata;
  profilePolicy: SastProfileSelectionPolicy;
  scannerSet: ScannerSetDescriptor;
  queuePolicySet: SastQueuePolicySet;
  queueUsage: SastQueueUsageSnapshot;
  requestedAt: string;
}

export interface SastScanPlanningResult {
  planning: SastUserVisiblePlanningState;
  plan?: SastScanPlan;
}

export function isTrustedSastRepositoryMetadataValid(
  metadata: TrustedSastRepositoryMetadata
): boolean {
  if (!metadata || !Array.isArray(metadata.sourceLanguages) || !Array.isArray(metadata.manifestNames)) {
    return false;
  }

  if (
    metadata.sourceLanguages.some(
      (signal) => signal === null || typeof signal !== 'object'
    )
  ) {
    return false;
  }

  const languages = metadata.sourceLanguages.map((signal) => signal.language);
  const sourceFileCount = metadata.sourceLanguages.reduce(
    (total, signal) => total + signal.sourceFileCount,
    0
  );
  const sourceBytes = metadata.sourceLanguages.reduce(
    (total, signal) => total + signal.sourceBytes,
    0
  );

  return (
    isNonBlank(metadata.repositoryBindingId) &&
    isFullGitCommitSha(metadata.fixedCommitSha) &&
    isSha256Digest(metadata.inventoryDigest) &&
    isNonBlank(metadata.attestationRef) &&
    isIsoTimestamp(metadata.collectedAt) &&
    hasUniqueValues(languages) &&
    metadata.sourceLanguages.every(
      (signal) =>
        /^[A-Z][A-Z0-9_]{0,63}$/.test(signal.language) &&
        isNonNegativeSafeInteger(signal.sourceFileCount) &&
        isNonNegativeSafeInteger(signal.sourceBytes) &&
        (signal.sourceFileCount > 0 || signal.sourceBytes === 0) &&
        (signal.sourceBytes > 0 || signal.sourceFileCount === 0)
    ) &&
    hasUniqueValues(metadata.manifestNames) &&
    metadata.manifestNames.every(isSafeManifestName) &&
    isNonNegativeSafeInteger(metadata.repositoryBytes) &&
    isNonNegativeSafeInteger(metadata.selectedBytes) &&
    isNonNegativeSafeInteger(metadata.fileCount) &&
    isNonNegativeSafeInteger(metadata.maxSingleFileBytes) &&
    isNonNegativeSafeInteger(metadata.maxPathDepth) &&
    metadata.selectedBytes <= metadata.repositoryBytes &&
    metadata.maxSingleFileBytes <= metadata.repositoryBytes &&
    sourceFileCount <= metadata.fileCount &&
    sourceBytes <= metadata.repositoryBytes
  );
}

export function isSastProfileSelectionPolicyValid(
  policy: SastProfileSelectionPolicy
): boolean {
  return (
    Boolean(policy) &&
    isNonBlank(policy.policyVersion) &&
    Array.isArray(policy.allowedProfileIds) &&
    policy.allowedProfileIds.length > 0 &&
    hasUniqueValues(policy.allowedProfileIds) &&
    policy.allowedProfileIds.every((profileId) =>
      Object.prototype.hasOwnProperty.call(SAST_SCAN_PROFILES, profileId)
    ) &&
    typeof policy.requireLanguageSpecificSast === 'boolean'
  );
}

export function selectSastScanProfile(input: {
  lane: SastScanLane;
  metadata: TrustedSastRepositoryMetadata;
  policy: SastProfileSelectionPolicy;
}): SastProfileSelectionDecision {
  if (input.lane !== 'FAST' && input.lane !== 'DEEP') {
    return rejectedProfileSelection('PROFILE_POLICY_INVALID');
  }

  if (!isTrustedSastRepositoryMetadataValid(input.metadata)) {
    return rejectedProfileSelection('TRUSTED_METADATA_INVALID');
  }

  if (!isSastProfileSelectionPolicyValid(input.policy)) {
    return rejectedProfileSelection('PROFILE_POLICY_INVALID');
  }

  const detectedLanguages = input.metadata.sourceLanguages
    .filter((signal) => signal.sourceFileCount > 0 || signal.sourceBytes > 0)
    .map((signal) => signal.language)
    .sort();
  const javaDetected = detectedLanguages.includes('JAVA');
  const unsupportedLanguages = detectedLanguages.filter((language) => language !== 'JAVA');

  if (javaDetected && unsupportedLanguages.length > 0) {
    return rejectedProfileSelection('UNSUPPORTED_POLYGLOT_PROFILE');
  }

  let profile: SastScanProfile;
  let coverageClaim: SastCoverageClaim;
  const reasonCodes: SastPlanningReasonCode[] = [];

  if (input.lane === 'FAST') {
    if (!javaDetected) {
      return rejectedProfileSelection('UNSUPPORTED_LANGUAGE_FOR_FAST');
    }

    profile = SAST_SCAN_PROFILES.JAVA_FAST_V1;
    coverageClaim = 'LANGUAGE_SAST_COMPLETE';
  } else if (javaDetected) {
    profile = SAST_SCAN_PROFILES.JAVA_DEEP_V1;
    coverageClaim = 'LANGUAGE_SAST_COMPLETE';
  } else {
    profile = SAST_SCAN_PROFILES.COMMON_DEEP_V1;
    coverageClaim = 'COMMON_STATIC_COVERAGE_ONLY';
    reasonCodes.push('LANGUAGE_SPECIFIC_SAST_UNAVAILABLE');
  }

  if (!input.policy.allowedProfileIds.includes(profile.id)) {
    return rejectedProfileSelection('PROFILE_NOT_ALLOWED_BY_POLICY');
  }

  if (profile.id === 'COMMON_DEEP_V1' && input.policy.requireLanguageSpecificSast) {
    return rejectedProfileSelection('LANGUAGE_SPECIFIC_SAST_REQUIRED');
  }

  if (!isSastScanProfileValid(profile)) {
    return rejectedProfileSelection('PROFILE_POLICY_INVALID');
  }

  return {
    state: 'SELECTED',
    profile,
    coverageClaim,
    reasonCodes
  };
}

export function findSastProfileLimitReasonCodes(
  metadata: TrustedSastRepositoryMetadata,
  profile: SastScanProfile
): SastPlanningReasonCode[] {
  const reasonCodes: SastPlanningReasonCode[] = [];

  if (metadata.repositoryBytes > profile.limits.maxRepositoryBytes) {
    reasonCodes.push('REPOSITORY_BYTES_LIMIT_EXCEEDED');
  }
  if (metadata.selectedBytes > profile.limits.maxSelectedBytes) {
    reasonCodes.push('SELECTED_BYTES_LIMIT_EXCEEDED');
  }
  if (metadata.fileCount > profile.limits.maxFileCount) {
    reasonCodes.push('FILE_COUNT_LIMIT_EXCEEDED');
  }
  if (metadata.maxSingleFileBytes > profile.limits.maxSingleFileBytes) {
    reasonCodes.push('SINGLE_FILE_BYTES_LIMIT_EXCEEDED');
  }
  if (metadata.maxPathDepth > profile.limits.maxPathDepth) {
    reasonCodes.push('PATH_DEPTH_LIMIT_EXCEEDED');
  }

  return reasonCodes;
}

export function isSastQueuePolicySetValid(policySet: SastQueuePolicySet): boolean {
  if (!policySet || !policySet.lanes) {
    return false;
  }

  const fast = policySet.lanes.FAST;
  const deep = policySet.lanes.DEEP;

  return (
    isNonBlank(policySet.policyVersion) &&
    isSha256Digest(policySet.digest) &&
    isNonBlank(policySet.signatureRef) &&
    isNonBlank(policySet.provenanceRef) &&
    policySet.fairnessStrategy === 'TENANT_ROUND_ROBIN' &&
    isSastLaneQueuePolicyValid(fast, 'FAST', 'scan.fast.v1') &&
    isSastLaneQueuePolicyValid(deep, 'DEEP', 'scan.deep.v1') &&
    fast.queueName !== deep.queueName
  );
}

export function evaluateSastQueueAdmission(input: {
  lane: SastScanLane;
  tenantId: string;
  repositoryBindingId: string;
  requestedAt: string;
  policySet: SastQueuePolicySet;
  usage: SastQueueUsageSnapshot;
}): SastQueueAdmissionDecision {
  if (input.lane !== 'FAST' && input.lane !== 'DEEP') {
    return rejectedQueueAdmission('QUEUE_POLICY_INVALID');
  }

  if (!isSastQueuePolicySetValid(input.policySet)) {
    return rejectedQueueAdmission('QUEUE_POLICY_INVALID');
  }

  const policy = input.policySet.lanes[input.lane];
  const capacityRetry = policy.capacityRetrySeconds;
  const policyIdentity = {
    queuePolicyVersion: input.policySet.policyVersion,
    queuePolicyDigest: input.policySet.digest
  };

  if (
    !isNonBlank(input.tenantId) ||
    !isNonBlank(input.repositoryBindingId) ||
    !isIsoTimestamp(input.requestedAt) ||
    !isSastQueueUsageSnapshotValid(input.usage) ||
    input.usage.tenantId !== input.tenantId ||
    input.usage.repositoryBindingId !== input.repositoryBindingId ||
    input.usage.lane !== input.lane ||
    Date.parse(input.usage.dailyWindowStartedAt) !== Date.parse(utcDayStart(input.requestedAt)) ||
    Date.parse(input.usage.dailyWindowStartedAt) > Date.parse(input.requestedAt)
  ) {
    return rejectedQueueAdmission('QUEUE_USAGE_INVALID', policyIdentity);
  }

  if (input.usage.activeForRepository >= policy.maxActivePerRepository) {
    return deferredQueueAdmission(
      policy.queueName,
      'REPOSITORY_CONCURRENCY_LIMIT',
      capacityRetry,
      policyIdentity
    );
  }
  if (input.usage.activeForTenant >= policy.maxActivePerTenant) {
    return deferredQueueAdmission(
      policy.queueName,
      'TENANT_CONCURRENCY_LIMIT',
      capacityRetry,
      policyIdentity
    );
  }
  if (input.usage.queuedForTenant >= policy.maxQueuedPerTenant) {
    return deferredQueueAdmission(
      policy.queueName,
      'TENANT_QUEUED_LIMIT',
      capacityRetry,
      policyIdentity
    );
  }
  if (input.usage.admittedTodayForTenant >= policy.maxDailyAdmissionsPerTenant) {
    return deferredQueueAdmission(
      policy.queueName,
      'TENANT_DAILY_BUDGET_EXHAUSTED',
      secondsUntilNextUtcDay(input.requestedAt),
      policyIdentity
    );
  }
  if (input.usage.queuedInLane >= policy.maxQueuedInLane) {
    return deferredQueueAdmission(
      policy.queueName,
      'LANE_QUEUE_CAPACITY_EXHAUSTED',
      capacityRetry,
      policyIdentity
    );
  }

  if (input.usage.lastRepositoryAdmissionAt) {
    const requestedAtMs = Date.parse(input.requestedAt);
    const lastAdmissionMs = Date.parse(input.usage.lastRepositoryAdmissionAt);
    if (!Number.isFinite(lastAdmissionMs) || lastAdmissionMs > requestedAtMs) {
      return rejectedQueueAdmission('QUEUE_USAGE_INVALID', policyIdentity);
    }

    const elapsedSeconds = Math.floor((requestedAtMs - lastAdmissionMs) / 1000);
    if (elapsedSeconds < policy.minimumRepositoryIntervalSeconds) {
      return deferredQueueAdmission(
        policy.queueName,
        'REPOSITORY_FREQUENCY_LIMIT',
        policy.minimumRepositoryIntervalSeconds - elapsedSeconds,
        policyIdentity
      );
    }
  }

  return {
    state: 'ADMITTED',
    queueName: policy.queueName,
    fairnessKey: input.tenantId,
    ...policyIdentity,
    reasonCodes: []
  };
}

export function orderSastQueueCandidatesFairly(
  lane: SastScanLane,
  candidates: readonly SastQueueCandidate[],
  lastServedTenantId?: string
): SastQueueCandidate[] {
  const groups = new Map<string, SastQueueCandidate[]>();

  for (const candidate of candidates) {
    if (
      candidate.lane !== lane ||
      !isNonBlank(candidate.tenantId) ||
      !isNonBlank(candidate.scanRequestId) ||
      !isIsoTimestamp(candidate.enqueuedAt)
    ) {
      continue;
    }

    const group = groups.get(candidate.tenantId) ?? [];
    group.push(candidate);
    groups.set(candidate.tenantId, group);
  }

  for (const group of groups.values()) {
    group.sort(compareQueueCandidates);
  }

  const tenantIds = Array.from(groups.keys()).sort((left, right) => {
    const candidateOrder = compareQueueCandidates(groups.get(left)![0], groups.get(right)![0]);
    return candidateOrder === 0 ? compareStrings(left, right) : candidateOrder;
  });
  const rotatedTenantIds = rotateAfterTenant(tenantIds, lastServedTenantId);
  const result: SastQueueCandidate[] = [];
  let remaining = true;

  while (remaining) {
    remaining = false;
    for (const tenantId of rotatedTenantIds) {
      const next = groups.get(tenantId)?.shift();
      if (next) {
        result.push(next);
        remaining = true;
      }
    }
  }

  return result;
}

export function buildSastProfileDigestPreimage(profile: SastScanProfile): string {
  return canonicalJson({ version: 'sast-profile-digest-v1', profile });
}

export function buildSastCanonicalScanKeyPreimage(
  input: SastCanonicalScanKeyInput
): string {
  const scannerAssets = SAST_SCANNER_KINDS.map((scanner) => {
    const descriptor = input.scannerSet.scanners[scanner];
    return {
      scanner,
      version: descriptor.version,
      imageDigest: descriptor.digest,
      wrapperDigest: descriptor.wrapper.digest
    };
  });
  const ruleBundles = input.scannerSet.ruleBundles
    .map((bundle) => ({
      scanner: bundle.scanner,
      bundleId: bundle.bundleId,
      version: bundle.version,
      digest: bundle.digest,
      manifestDigest: bundle.manifestDigest,
      verificationDigest: bundle.verificationDigest,
      compatibilityReceiptDigest: bundle.compatibilityReceiptDigest
    }))
    .sort((left, right) =>
      compareStrings(
        [left.scanner, left.bundleId, left.version, left.digest].join(':'),
        [right.scanner, right.bundleId, right.version, right.digest].join(':')
      )
    );

  return canonicalJson({
    version: 'sast-canonical-scan-key-v1',
    tenantId: input.tenantId,
    repositoryBindingId: input.repositoryBindingId,
    lane: input.lane,
    targetRef: input.targetRef,
    fixedCommitSha: input.fixedCommitSha.toLowerCase(),
    inventoryDigest: input.inventoryDigest,
    attestationRef: input.attestationRef,
    policyVersion: input.policyVersion,
    profileId: input.profile.id,
    profileDigest: input.profileDigest,
    scannerSetVersion: input.scannerSet.scannerSetVersion,
    scannerSetDigest: input.scannerSet.scannerSetDigest,
    scannerAssets,
    ruleBundles,
    vulnerabilityDatabaseVersion: input.scannerSet.vulnerabilityDatabase.databaseVersion,
    vulnerabilityDatabaseDigest: input.scannerSet.vulnerabilityDatabase.digest,
    schemaBundleDigest: input.scannerSet.schemaBundle.digest,
    normalizerBundleDigest: input.scannerSet.normalizerBundle.digest,
    sbomSchema: input.scannerSet.sbomSchema,
    isolationClass: input.isolationClass
  });
}

function rejectedProfileSelection(
  reasonCode: SastPlanningReasonCode
): SastProfileSelectionDecision {
  return {
    state: 'REJECTED',
    coverageClaim: 'NONE',
    reasonCodes: [reasonCode]
  };
}

function isSastLaneQueuePolicyValid(
  policy: SastLaneQueuePolicy,
  lane: SastScanLane,
  queueName: SastLaneQueuePolicy['queueName']
): boolean {
  return (
    Boolean(policy) &&
    policy.lane === lane &&
    policy.queueName === queueName &&
    [
      policy.maxActivePerTenant,
      policy.maxQueuedPerTenant,
      policy.maxDailyAdmissionsPerTenant,
      policy.maxActivePerRepository,
      policy.maxQueuedInLane,
      policy.capacityRetrySeconds
    ].every(isPositiveSafeInteger) &&
    isNonNegativeSafeInteger(policy.minimumRepositoryIntervalSeconds)
  );
}

export function isSastQueueUsageSnapshotValid(usage: SastQueueUsageSnapshot): boolean {
  return (
    Boolean(usage) &&
    isNonBlank(usage.tenantId) &&
    isNonBlank(usage.repositoryBindingId) &&
    (usage.lane === 'FAST' || usage.lane === 'DEEP') &&
    isIsoTimestamp(usage.dailyWindowStartedAt) &&
    [
      usage.snapshotVersion,
      usage.activeForTenant,
      usage.queuedForTenant,
      usage.admittedTodayForTenant,
      usage.activeForRepository,
      usage.queuedInLane
    ].every(isNonNegativeSafeInteger) &&
    usage.activeForRepository <= usage.activeForTenant &&
    usage.queuedForTenant <= usage.queuedInLane &&
    (usage.lastRepositoryAdmissionAt === undefined ||
      isIsoTimestamp(usage.lastRepositoryAdmissionAt))
  );
}

function rejectedQueueAdmission(
  reasonCode: SastPlanningReasonCode,
  policyIdentity: Pick<
    SastQueueAdmissionDecision,
    'queuePolicyVersion' | 'queuePolicyDigest'
  > = {}
): SastQueueAdmissionDecision {
  return { state: 'REJECTED', ...policyIdentity, reasonCodes: [reasonCode] };
}

function deferredQueueAdmission(
  queueName: SastLaneQueuePolicy['queueName'],
  reasonCode: SastPlanningReasonCode,
  retryAfterSeconds: number,
  policyIdentity: Pick<
    SastQueueAdmissionDecision,
    'queuePolicyVersion' | 'queuePolicyDigest'
  >
): SastQueueAdmissionDecision {
  return {
    state: 'DEFERRED',
    queueName,
    ...policyIdentity,
    reasonCodes: [reasonCode],
    retryAfterSeconds
  };
}

function secondsUntilNextUtcDay(timestamp: string): number {
  const current = new Date(timestamp);
  const next = Date.UTC(
    current.getUTCFullYear(),
    current.getUTCMonth(),
    current.getUTCDate() + 1
  );
  return Math.max(1, Math.ceil((next - current.getTime()) / 1000));
}

function utcDayStart(timestamp: string): string {
  const current = new Date(timestamp);
  return new Date(
    Date.UTC(current.getUTCFullYear(), current.getUTCMonth(), current.getUTCDate())
  ).toISOString();
}

function compareQueueCandidates(left: SastQueueCandidate, right: SastQueueCandidate): number {
  const timestampOrder = Date.parse(left.enqueuedAt) - Date.parse(right.enqueuedAt);
  return timestampOrder === 0
    ? compareStrings(left.scanRequestId, right.scanRequestId)
    : timestampOrder;
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function rotateAfterTenant(tenantIds: string[], lastServedTenantId?: string): string[] {
  if (!lastServedTenantId) {
    return tenantIds;
  }

  const index = tenantIds.indexOf(lastServedTenantId);
  if (index < 0) {
    return tenantIds;
  }

  return [...tenantIds.slice(index + 1), ...tenantIds.slice(0, index + 1)];
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalJson(entry)).join(',')}]`;
  }

  const record = value as Record<string, unknown>;
  const entries = Object.keys(record)
    .filter((key) => record[key] !== undefined)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`);
  return `{${entries.join(',')}}`;
}

function hasUniqueValues(values: readonly string[]): boolean {
  return new Set(values).size === values.length;
}

function isNonBlank(value: string): boolean {
  return typeof value === 'string' && value.trim().length > 0;
}

function isSha256Digest(value: string): value is `sha256:${string}` {
  return /^sha256:[a-f0-9]{64}$/i.test(value);
}

function isFullGitCommitSha(value: string): boolean {
  return /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/i.test(value);
}

function isIsoTimestamp(value: string): boolean {
  return (
    typeof value === 'string' &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u.test(value) &&
    Number.isFinite(Date.parse(value))
  );
}

function isNonNegativeSafeInteger(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0;
}

function isPositiveSafeInteger(value: number): boolean {
  return Number.isSafeInteger(value) && value > 0;
}

function isSafeManifestName(value: string): boolean {
  return (
    isNonBlank(value) &&
    value.length <= 255 &&
    !/[\\/]/u.test(value) &&
    !hasControlCharacters(value) &&
    value !== '.' &&
    value !== '..'
  );
}

function hasControlCharacters(value: string): boolean {
  return [...value].some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 31 || codePoint === 127;
  });
}
