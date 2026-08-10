import {
  SAST_CAPABILITIES,
  SAST_FINDING_FINGERPRINT_VERSION,
  SAST_PROFILE_IDS,
  type SastCapability,
  type SastProfileId
} from './sast-runtime';
import {
  hasExactKeys,
  isBoundedReference,
  isCommitSha,
  isRecord,
  isSha256Digest
} from './sast-normalization-validation';

export const SAST_SCAN_FRESHNESS_VERSION =
  'sast-scan-freshness-v1' as const;
export const SAST_LATEST_TARGET_OBSERVATION_VERSION =
  'sast-latest-target-observation-v1' as const;
export const SAST_SCAN_RETRY_DECISION_VERSION =
  'sast-scan-retry-decision-v1' as const;

export const SAST_SCM_PROVIDERS = ['GITHUB', 'GITLAB'] as const;
export type SastScmProvider = (typeof SAST_SCM_PROVIDERS)[number];

export const SAST_PROFILE_FAMILIES = ['JAVA', 'COMMON'] as const;
export type SastProfileFamily =
  (typeof SAST_PROFILE_FAMILIES)[number];

export const SAST_LATEST_TARGET_AUTHORITIES = [
  'VERIFIED',
  'UNAVAILABLE',
  'INVALID'
] as const;
export type SastLatestTargetAuthority =
  (typeof SAST_LATEST_TARGET_AUTHORITIES)[number];

export const SAST_STALE_STATUSES = [
  'FRESH',
  'STALE',
  'UNKNOWN'
] as const;
export type SastStaleStatus = (typeof SAST_STALE_STATUSES)[number];

export const SAST_COMPARABILITY_STATUSES = [
  'COMPARABLE',
  'INCOMPARABLE',
  'UNKNOWN'
] as const;
export type SastComparabilityStatus =
  (typeof SAST_COMPARABILITY_STATUSES)[number];

export const SAST_SCAN_FRESHNESS_REASON_CODES = [
  'COVERAGE_NOT_COMPLETE',
  'LATEST_TARGET_AUTHORITY_UNAVAILABLE',
  'LATEST_TARGET_OBSERVATION_INVALID',
  'LATEST_TARGET_OBSERVATION_NON_MONOTONIC',
  'TARGET_HEAD_MISMATCH',
  'COMPARISON_SOURCE_UNAVAILABLE',
  'COMPARISON_SCOPE_MISMATCH',
  'PROFILE_FAMILY_INCOMPATIBLE',
  'REQUIRED_CAPABILITY_SET_INCOMPATIBLE',
  'FINGERPRINT_VERSION_INCOMPATIBLE',
  'LIFECYCLE_ELIGIBILITY_SCOPE_INCOMPATIBLE',
  'PUBLICATION_FAIL_CLOSED'
] as const;
export type SastScanFreshnessReasonCode =
  (typeof SAST_SCAN_FRESHNESS_REASON_CODES)[number];

export const SAST_SCAN_RETRY_REASON_CODES = [
  'RETRY_ATTEMPT_LIMIT_EXCEEDED',
  'PREVIOUS_ATTEMPT_NOT_IMMEDIATE',
  'PREVIOUS_ATTEMPT_NOT_FAILED',
  'FAILURE_NOT_RETRYABLE_INFRASTRUCTURE',
  'PREVIOUS_ATTEMPT_NOT_RETRY_ELIGIBLE',
  'FINAL_AUDIT_BINDING_MISSING',
  'PREVIOUS_COMPLETION_MISSING',
  'IMMUTABLE_SCAN_INTENT_CHANGED',
  'SCANNER_SET_UNAVAILABLE',
  'SCANNER_SET_CHANGED',
  'KILL_SWITCH_AUTHORITY_UNAVAILABLE',
  'KILL_SWITCH_ACTIVE',
  'SANDBOX_IDENTITY_REUSED',
  'RETRY_PERSISTENCE_CONFLICT'
] as const;
export type SastScanRetryReasonCode =
  (typeof SAST_SCAN_RETRY_REASON_CODES)[number];

export type SastScanFreshnessCanonicalDigester = (
  canonicalValue: string
) => `sha256:${string}`;

export interface SastScanFreshnessScope {
  tenantId: string;
  repositoryBindingId: string;
  provider: SastScmProvider;
  targetRef: string;
  commitSha: string;
  scanRequestId: string;
  attemptId: string;
  attemptNumber: 1 | 2;
  coverageDecisionId: string;
  coverageDecisionDigest: `sha256:${string}`;
  lifecycleContextKey: `sha256:${string}`;
  canonicalScanKey: `sha256:${string}`;
  planDigest: `sha256:${string}`;
  profileId: SastProfileId;
  profileDigest: `sha256:${string}`;
  profileFamily: SastProfileFamily;
  requiredCapabilities: SastCapability[];
  fingerprintVersion: typeof SAST_FINDING_FINGERPRINT_VERSION;
  lifecycleEligibilityScope: `sha256:${string}`;
}

export interface SastLatestTargetObservation {
  version: typeof SAST_LATEST_TARGET_OBSERVATION_VERSION;
  observationId: string;
  tenantId: string;
  repositoryBindingId: string;
  provider: SastScmProvider;
  targetRef: string;
  headCommitSha: string;
  sequence: number;
  observerRef: string;
  observedAt: string;
  observationDigest: `sha256:${string}`;
}

export type SastLatestTargetObservationCore = Omit<
  SastLatestTargetObservation,
  'observationDigest'
>;

export interface SastScanComparisonSource {
  coverageDecisionId: string;
  coverageDecisionDigest: `sha256:${string}`;
  scanRequestId: string;
  commitSha: string;
  tenantId: string;
  repositoryBindingId: string;
  targetRef: string;
  profileId: SastProfileId;
  profileDigest: `sha256:${string}`;
  profileFamily: SastProfileFamily;
  requiredCapabilities: SastCapability[];
  fingerprintVersion: typeof SAST_FINDING_FINGERPRINT_VERSION;
  lifecycleEligibilityScope: `sha256:${string}`;
  completedAt: string;
}

export interface SastScanFreshnessDecision {
  version: typeof SAST_SCAN_FRESHNESS_VERSION;
  freshnessDecisionId: string;
  scope: SastScanFreshnessScope;
  observationId: string | null;
  observationDigest: `sha256:${string}` | null;
  observedHeadCommitSha: string | null;
  observationSequence: number | null;
  previousCoverageDecisionId: string | null;
  previousCoverageDecisionDigest: `sha256:${string}` | null;
  previousScanRequestId: string | null;
  previousCommitSha: string | null;
  latestTargetAuthority: SastLatestTargetAuthority;
  staleStatus: SastStaleStatus;
  comparabilityStatus: SastComparabilityStatus;
  externalCommentEligible: boolean;
  blockingStatusEligible: boolean;
  lifecycleMutationAllowed: boolean;
  aiAdvisoryAllowed: false;
  publicationAttempted: false;
  reasonCodes: SastScanFreshnessReasonCode[];
  decidedAt: string;
  decisionDigest: `sha256:${string}`;
}

export type SastScanFreshnessDecisionCore = Omit<
  SastScanFreshnessDecision,
  'decisionDigest'
>;

export interface SastScanRetryScope {
  tenantId: string;
  repositoryBindingId: string;
  scanRequestId: string;
  canonicalScanKey: `sha256:${string}`;
  planDigest: `sha256:${string}`;
  originalScannerSetDigest: `sha256:${string}`;
  previousAttemptId: string;
  previousAttemptNumber: number;
  previousSandboxId: string;
  previousWorkloadIdentityRef: string;
  requestedAttemptId: string;
  requestedAttemptNumber: number;
  requestedSandboxId: string;
  requestedWorkloadIdentityRef: string;
}

export interface SastScanRetryEvaluation {
  scope: SastScanRetryScope;
  previousStage: string;
  previousFailureClass: string | null;
  previousRetryEligible: boolean;
  previousCompletedAt: string | null;
  previousFinalAuditEventId: string | null;
  previousFinalAuditValid: boolean;
  durableCanonicalScanKey: `sha256:${string}`;
  durablePlanDigest: `sha256:${string}`;
  currentScannerSetDigest: `sha256:${string}` | null;
  scannerSetAvailable: boolean;
  killSwitchStatus: 'CLEAR' | 'ACTIVE' | 'UNAVAILABLE';
  killSwitchSnapshotDigest: `sha256:${string}` | null;
}

export interface SastScanRetryDecision {
  version: typeof SAST_SCAN_RETRY_DECISION_VERSION;
  retryDecisionId: string;
  scope: SastScanRetryScope;
  retryAllowed: boolean;
  previousFailureClass: string | null;
  previousCompletedAt: string | null;
  previousFinalAuditEventId: string | null;
  currentScannerSetDigest: `sha256:${string}` | null;
  scannerSetAvailable: boolean;
  killSwitchStatus: 'CLEAR' | 'ACTIVE' | 'UNAVAILABLE';
  killSwitchSnapshotDigest: `sha256:${string}` | null;
  reasonCodes: SastScanRetryReasonCode[];
  decidedAt: string;
  decisionDigest: `sha256:${string}`;
}

export type SastScanRetryDecisionCore = Omit<
  SastScanRetryDecision,
  'decisionDigest'
>;

export function sastProfileFamily(
  profileId: SastProfileId
): SastProfileFamily {
  return profileId.startsWith('JAVA_') ? 'JAVA' : 'COMMON';
}

export function canonicalizeSastLatestTargetObservation(
  observation: Readonly<SastLatestTargetObservationCore>
): string {
  return stableJson(observation);
}

export function canonicalizeSastScanFreshnessDecision(
  decision: Readonly<SastScanFreshnessDecisionCore>
): string {
  return stableJson(decision);
}

export function canonicalizeSastScanRetryDecision(
  decision: Readonly<SastScanRetryDecisionCore>
): string {
  return stableJson(decision);
}

export function orderSastScanFreshnessReasons(
  reasons: readonly SastScanFreshnessReasonCode[]
): SastScanFreshnessReasonCode[] {
  return orderByCanonical(
    reasons,
    SAST_SCAN_FRESHNESS_REASON_CODES
  );
}

export function orderSastScanRetryReasons(
  reasons: readonly SastScanRetryReasonCode[]
): SastScanRetryReasonCode[] {
  return orderByCanonical(reasons, SAST_SCAN_RETRY_REASON_CODES);
}

export function evaluateSastScanFreshness(input: {
  coverageComplete: boolean;
  scope: Readonly<SastScanFreshnessScope>;
  observation: Readonly<SastLatestTargetObservation> | null;
  observationAuthority: SastLatestTargetAuthority;
  observationMonotonic: boolean;
  comparison: Readonly<SastScanComparisonSource> | null;
}): {
  latestTargetAuthority: SastLatestTargetAuthority;
  staleStatus: SastStaleStatus;
  comparabilityStatus: SastComparabilityStatus;
  reasonCodes: SastScanFreshnessReasonCode[];
  authorityEligible: boolean;
} {
  const reasons: SastScanFreshnessReasonCode[] = [];
  if (!input.coverageComplete) reasons.push('COVERAGE_NOT_COMPLETE');

  let latestTargetAuthority = input.observationAuthority;
  let staleStatus: SastStaleStatus = 'UNKNOWN';
  if (latestTargetAuthority === 'UNAVAILABLE') {
    reasons.push('LATEST_TARGET_AUTHORITY_UNAVAILABLE');
  } else if (
    latestTargetAuthority !== 'VERIFIED' ||
    !input.observation
  ) {
    latestTargetAuthority = 'INVALID';
    reasons.push('LATEST_TARGET_OBSERVATION_INVALID');
  } else if (!input.observationMonotonic) {
    latestTargetAuthority = 'INVALID';
    reasons.push('LATEST_TARGET_OBSERVATION_NON_MONOTONIC');
  } else if (
    input.observation.headCommitSha !== input.scope.commitSha
  ) {
    staleStatus = 'STALE';
    reasons.push('TARGET_HEAD_MISMATCH');
  } else {
    staleStatus = 'FRESH';
  }

  let comparabilityStatus: SastComparabilityStatus = 'UNKNOWN';
  if (!input.comparison) {
    reasons.push('COMPARISON_SOURCE_UNAVAILABLE');
  } else {
    comparabilityStatus = 'COMPARABLE';
    const previous = input.comparison;
    if (
      previous.tenantId !== input.scope.tenantId ||
      previous.repositoryBindingId !== input.scope.repositoryBindingId ||
      previous.targetRef !== input.scope.targetRef ||
      previous.scanRequestId === input.scope.scanRequestId
    ) {
      reasons.push('COMPARISON_SCOPE_MISMATCH');
      comparabilityStatus = 'INCOMPARABLE';
    }
    if (previous.profileFamily !== input.scope.profileFamily) {
      reasons.push('PROFILE_FAMILY_INCOMPATIBLE');
      comparabilityStatus = 'INCOMPARABLE';
    }
    if (
      !sameStrings(
        previous.requiredCapabilities,
        input.scope.requiredCapabilities
      )
    ) {
      reasons.push('REQUIRED_CAPABILITY_SET_INCOMPATIBLE');
      comparabilityStatus = 'INCOMPARABLE';
    }
    if (previous.fingerprintVersion !== input.scope.fingerprintVersion) {
      reasons.push('FINGERPRINT_VERSION_INCOMPATIBLE');
      comparabilityStatus = 'INCOMPARABLE';
    }
    if (
      previous.lifecycleEligibilityScope !==
      input.scope.lifecycleEligibilityScope
    ) {
      reasons.push('LIFECYCLE_ELIGIBILITY_SCOPE_INCOMPATIBLE');
      comparabilityStatus = 'INCOMPARABLE';
    }
  }

  const authorityEligible =
    input.coverageComplete &&
    latestTargetAuthority === 'VERIFIED' &&
    staleStatus === 'FRESH' &&
    comparabilityStatus === 'COMPARABLE';
  if (!authorityEligible) reasons.push('PUBLICATION_FAIL_CLOSED');
  return {
    latestTargetAuthority,
    staleStatus,
    comparabilityStatus,
    reasonCodes: orderSastScanFreshnessReasons(reasons),
    authorityEligible
  };
}

export function buildSastScanFreshnessDecision(input: {
  freshnessDecisionId: string;
  coverageComplete: boolean;
  scope: Readonly<SastScanFreshnessScope>;
  observation: Readonly<SastLatestTargetObservation> | null;
  observationAuthority: SastLatestTargetAuthority;
  observationMonotonic: boolean;
  comparison: Readonly<SastScanComparisonSource> | null;
  decidedAt: string;
  digestCanonical: SastScanFreshnessCanonicalDigester;
}): SastScanFreshnessDecision {
  const evaluation = evaluateSastScanFreshness(input);
  const core: SastScanFreshnessDecisionCore = {
    version: SAST_SCAN_FRESHNESS_VERSION,
    freshnessDecisionId: input.freshnessDecisionId,
    scope: { ...input.scope, requiredCapabilities: [
      ...input.scope.requiredCapabilities
    ] },
    observationId: input.observation?.observationId ?? null,
    observationDigest: input.observation?.observationDigest ?? null,
    observedHeadCommitSha: input.observation?.headCommitSha ?? null,
    observationSequence: input.observation?.sequence ?? null,
    previousCoverageDecisionId:
      input.comparison?.coverageDecisionId ?? null,
    previousCoverageDecisionDigest:
      input.comparison?.coverageDecisionDigest ?? null,
    previousScanRequestId: input.comparison?.scanRequestId ?? null,
    previousCommitSha: input.comparison?.commitSha ?? null,
    latestTargetAuthority: evaluation.latestTargetAuthority,
    staleStatus: evaluation.staleStatus,
    comparabilityStatus: evaluation.comparabilityStatus,
    externalCommentEligible: evaluation.authorityEligible,
    blockingStatusEligible: evaluation.authorityEligible,
    lifecycleMutationAllowed: evaluation.authorityEligible,
    aiAdvisoryAllowed: false,
    publicationAttempted: false,
    reasonCodes: evaluation.reasonCodes,
    decidedAt: input.decidedAt
  };
  return {
    ...core,
    decisionDigest: input.digestCanonical(
      canonicalizeSastScanFreshnessDecision(core)
    )
  };
}

export function evaluateSastScanRetry(
  input: Readonly<SastScanRetryEvaluation>
): SastScanRetryReasonCode[] {
  const reasons: SastScanRetryReasonCode[] = [];
  if (
    input.scope.requestedAttemptNumber !== 2 ||
    input.scope.previousAttemptNumber !== 1
  ) {
    reasons.push('RETRY_ATTEMPT_LIMIT_EXCEEDED');
  }
  if (
    input.scope.requestedAttemptNumber !==
    input.scope.previousAttemptNumber + 1
  ) {
    reasons.push('PREVIOUS_ATTEMPT_NOT_IMMEDIATE');
  }
  if (input.previousStage !== 'FAILED') {
    reasons.push('PREVIOUS_ATTEMPT_NOT_FAILED');
  }
  if (
    input.previousFailureClass !== 'RETRYABLE_INFRASTRUCTURE'
  ) {
    reasons.push('FAILURE_NOT_RETRYABLE_INFRASTRUCTURE');
  }
  if (!input.previousRetryEligible) {
    reasons.push('PREVIOUS_ATTEMPT_NOT_RETRY_ELIGIBLE');
  }
  if (!input.previousFinalAuditEventId || !input.previousFinalAuditValid) {
    reasons.push('FINAL_AUDIT_BINDING_MISSING');
  }
  if (!input.previousCompletedAt) {
    reasons.push('PREVIOUS_COMPLETION_MISSING');
  }
  if (
    input.scope.canonicalScanKey !== input.durableCanonicalScanKey ||
    input.scope.planDigest !== input.durablePlanDigest
  ) {
    reasons.push('IMMUTABLE_SCAN_INTENT_CHANGED');
  }
  if (!input.scannerSetAvailable) {
    reasons.push('SCANNER_SET_UNAVAILABLE');
  }
  if (
    input.currentScannerSetDigest !==
    input.scope.originalScannerSetDigest
  ) {
    reasons.push('SCANNER_SET_CHANGED');
  }
  if (input.killSwitchStatus === 'UNAVAILABLE') {
    reasons.push('KILL_SWITCH_AUTHORITY_UNAVAILABLE');
  } else if (input.killSwitchStatus === 'ACTIVE') {
    reasons.push('KILL_SWITCH_ACTIVE');
  } else if (!input.killSwitchSnapshotDigest) {
    reasons.push('KILL_SWITCH_AUTHORITY_UNAVAILABLE');
  }
  if (
    input.scope.requestedAttemptId === input.scope.previousAttemptId ||
    input.scope.requestedSandboxId === input.scope.previousSandboxId ||
    input.scope.requestedWorkloadIdentityRef ===
      input.scope.previousWorkloadIdentityRef
  ) {
    reasons.push('SANDBOX_IDENTITY_REUSED');
  }
  return orderSastScanRetryReasons(reasons);
}

export function buildSastScanRetryDecision(input: {
  retryDecisionId: string;
  evaluation: Readonly<SastScanRetryEvaluation>;
  decidedAt: string;
  digestCanonical: SastScanFreshnessCanonicalDigester;
}): SastScanRetryDecision {
  const reasonCodes = evaluateSastScanRetry(input.evaluation);
  const core: SastScanRetryDecisionCore = {
    version: SAST_SCAN_RETRY_DECISION_VERSION,
    retryDecisionId: input.retryDecisionId,
    scope: { ...input.evaluation.scope },
    retryAllowed: reasonCodes.length === 0,
    previousFailureClass: input.evaluation.previousFailureClass,
    previousCompletedAt: input.evaluation.previousCompletedAt,
    previousFinalAuditEventId:
      input.evaluation.previousFinalAuditEventId,
    currentScannerSetDigest:
      input.evaluation.currentScannerSetDigest,
    scannerSetAvailable: input.evaluation.scannerSetAvailable,
    killSwitchStatus: input.evaluation.killSwitchStatus,
    killSwitchSnapshotDigest:
      input.evaluation.killSwitchSnapshotDigest,
    reasonCodes,
    decidedAt: input.decidedAt
  };
  return {
    ...core,
    decisionDigest: input.digestCanonical(
      canonicalizeSastScanRetryDecision(core)
    )
  };
}

export function isSastLatestTargetObservationShapeValid(
  value: unknown,
  digestCanonical: SastScanFreshnessCanonicalDigester
): value is SastLatestTargetObservation {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'version',
      'observationId',
      'tenantId',
      'repositoryBindingId',
      'provider',
      'targetRef',
      'headCommitSha',
      'sequence',
      'observerRef',
      'observedAt',
      'observationDigest'
    ]) ||
    value.version !== SAST_LATEST_TARGET_OBSERVATION_VERSION ||
    !isContractId(value.observationId, 'sast-target-observation') ||
    !isBoundedReference(value.tenantId) ||
    !isBoundedReference(value.repositoryBindingId) ||
    !SAST_SCM_PROVIDERS.includes(value.provider as SastScmProvider) ||
    !isBoundedReference(value.targetRef) ||
    !isCommitSha(value.headCommitSha) ||
    !Number.isSafeInteger(value.sequence) ||
    (value.sequence as number) <= 0 ||
    !isBoundedReference(value.observerRef) ||
    !isCanonicalIsoTimestamp(value.observedAt) ||
    !isSha256Digest(value.observationDigest)
  ) {
    return false;
  }
  const observation = value as unknown as SastLatestTargetObservation;
  const { observationDigest, ...core } = observation;
  return (
    digestCanonical(canonicalizeSastLatestTargetObservation(core)) ===
    observationDigest
  );
}

export function isSastScanFreshnessDecisionShapeValid(
  value: unknown,
  digestCanonical: SastScanFreshnessCanonicalDigester
): value is SastScanFreshnessDecision {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'version',
      'freshnessDecisionId',
      'scope',
      'observationId',
      'observationDigest',
      'observedHeadCommitSha',
      'observationSequence',
      'previousCoverageDecisionId',
      'previousCoverageDecisionDigest',
      'previousScanRequestId',
      'previousCommitSha',
      'latestTargetAuthority',
      'staleStatus',
      'comparabilityStatus',
      'externalCommentEligible',
      'blockingStatusEligible',
      'lifecycleMutationAllowed',
      'aiAdvisoryAllowed',
      'publicationAttempted',
      'reasonCodes',
      'decidedAt',
      'decisionDigest'
    ]) ||
    value.version !== SAST_SCAN_FRESHNESS_VERSION ||
    !isContractId(value.freshnessDecisionId, 'sast-freshness') ||
    !isSastScanFreshnessScopeValid(value.scope) ||
    !isNullableContractId(value.observationId, 'sast-target-observation') ||
    !isNullableDigest(value.observationDigest) ||
    !isNullableCommit(value.observedHeadCommitSha) ||
    !isNullablePositiveInteger(value.observationSequence) ||
    !isNullableContractId(value.previousCoverageDecisionId, 'sast-coverage') ||
    !isNullableDigest(value.previousCoverageDecisionDigest) ||
    !isNullableReference(value.previousScanRequestId) ||
    !isNullableCommit(value.previousCommitSha) ||
    !SAST_LATEST_TARGET_AUTHORITIES.includes(
      value.latestTargetAuthority as SastLatestTargetAuthority
    ) ||
    !SAST_STALE_STATUSES.includes(value.staleStatus as SastStaleStatus) ||
    !SAST_COMPARABILITY_STATUSES.includes(
      value.comparabilityStatus as SastComparabilityStatus
    ) ||
    typeof value.externalCommentEligible !== 'boolean' ||
    typeof value.blockingStatusEligible !== 'boolean' ||
    typeof value.lifecycleMutationAllowed !== 'boolean' ||
    value.aiAdvisoryAllowed !== false ||
    value.publicationAttempted !== false ||
    !isCanonicalReasonArray(
      value.reasonCodes,
      SAST_SCAN_FRESHNESS_REASON_CODES
    ) ||
    !isCanonicalIsoTimestamp(value.decidedAt) ||
    !isSha256Digest(value.decisionDigest)
  ) {
    return false;
  }
  const decision = value as unknown as SastScanFreshnessDecision;
  const eligible =
    decision.latestTargetAuthority === 'VERIFIED' &&
    decision.staleStatus === 'FRESH' &&
    decision.comparabilityStatus === 'COMPARABLE' &&
    decision.observationId !== null &&
    decision.previousCoverageDecisionId !== null &&
    decision.reasonCodes.length === 0;
  if (
    decision.externalCommentEligible !== eligible ||
    decision.blockingStatusEligible !== eligible ||
    decision.lifecycleMutationAllowed !== eligible ||
    (!eligible && decision.reasonCodes.length === 0) ||
    !sameNullableObservationTuple(decision) ||
    !sameNullableComparisonTuple(decision)
  ) {
    return false;
  }
  const { decisionDigest, ...core } = decision;
  return (
    digestCanonical(canonicalizeSastScanFreshnessDecision(core)) ===
    decisionDigest
  );
}

export function isSastScanRetryDecisionShapeValid(
  value: unknown,
  digestCanonical: SastScanFreshnessCanonicalDigester
): value is SastScanRetryDecision {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'version',
      'retryDecisionId',
      'scope',
      'retryAllowed',
      'previousFailureClass',
      'previousCompletedAt',
      'previousFinalAuditEventId',
      'currentScannerSetDigest',
      'scannerSetAvailable',
      'killSwitchStatus',
      'killSwitchSnapshotDigest',
      'reasonCodes',
      'decidedAt',
      'decisionDigest'
    ]) ||
    value.version !== SAST_SCAN_RETRY_DECISION_VERSION ||
    !isContractId(value.retryDecisionId, 'sast-retry') ||
    !isSastScanRetryScopeValid(value.scope) ||
    typeof value.retryAllowed !== 'boolean' ||
    !isNullableReference(value.previousFailureClass) ||
    !isNullableTimestamp(value.previousCompletedAt) ||
    !isNullableReference(value.previousFinalAuditEventId) ||
    !isNullableDigest(value.currentScannerSetDigest) ||
    typeof value.scannerSetAvailable !== 'boolean' ||
    !['CLEAR', 'ACTIVE', 'UNAVAILABLE'].includes(
      value.killSwitchStatus as string
    ) ||
    !isNullableDigest(value.killSwitchSnapshotDigest) ||
    !isCanonicalReasonArray(
      value.reasonCodes,
      SAST_SCAN_RETRY_REASON_CODES
    ) ||
    value.retryAllowed !==
      ((value.reasonCodes as unknown[]).length === 0) ||
    !isCanonicalIsoTimestamp(value.decidedAt) ||
    !isSha256Digest(value.decisionDigest)
  ) {
    return false;
  }
  const decision = value as unknown as SastScanRetryDecision;
  if (
    decision.retryAllowed &&
    (decision.scope.previousAttemptNumber !== 1 ||
      decision.scope.requestedAttemptNumber !== 2 ||
      decision.scope.requestedAttemptNumber !==
        decision.scope.previousAttemptNumber + 1 ||
      decision.previousFailureClass !==
        'RETRYABLE_INFRASTRUCTURE' ||
      !decision.previousCompletedAt ||
      !decision.previousFinalAuditEventId ||
      !decision.scannerSetAvailable ||
      decision.currentScannerSetDigest !==
        decision.scope.originalScannerSetDigest ||
      decision.killSwitchStatus !== 'CLEAR' ||
      !decision.killSwitchSnapshotDigest ||
      decision.scope.previousAttemptId ===
        decision.scope.requestedAttemptId ||
      decision.scope.previousSandboxId ===
        decision.scope.requestedSandboxId ||
      decision.scope.previousWorkloadIdentityRef ===
        decision.scope.requestedWorkloadIdentityRef)
  ) {
    return false;
  }
  const { decisionDigest, ...core } = decision;
  return (
    digestCanonical(canonicalizeSastScanRetryDecision(core)) ===
    decisionDigest
  );
}

export function isSastScanFreshnessScopeValid(
  value: unknown
): value is SastScanFreshnessScope {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      'tenantId',
      'repositoryBindingId',
      'provider',
      'targetRef',
      'commitSha',
      'scanRequestId',
      'attemptId',
      'attemptNumber',
      'coverageDecisionId',
      'coverageDecisionDigest',
      'lifecycleContextKey',
      'canonicalScanKey',
      'planDigest',
      'profileId',
      'profileDigest',
      'profileFamily',
      'requiredCapabilities',
      'fingerprintVersion',
      'lifecycleEligibilityScope'
    ]) &&
    isBoundedReference(value.tenantId) &&
    isBoundedReference(value.repositoryBindingId) &&
    SAST_SCM_PROVIDERS.includes(value.provider as SastScmProvider) &&
    isBoundedReference(value.targetRef) &&
    isCommitSha(value.commitSha) &&
    isBoundedReference(value.scanRequestId) &&
    isBoundedReference(value.attemptId) &&
    (value.attemptNumber === 1 || value.attemptNumber === 2) &&
    isContractId(value.coverageDecisionId, 'sast-coverage') &&
    isSha256Digest(value.coverageDecisionDigest) &&
    isSha256Digest(value.lifecycleContextKey) &&
    isSha256Digest(value.canonicalScanKey) &&
    isSha256Digest(value.planDigest) &&
    SAST_PROFILE_IDS.includes(value.profileId as SastProfileId) &&
    isSha256Digest(value.profileDigest) &&
    SAST_PROFILE_FAMILIES.includes(
      value.profileFamily as SastProfileFamily
    ) &&
    value.profileFamily === sastProfileFamily(value.profileId as SastProfileId) &&
    isCanonicalCapabilityArray(value.requiredCapabilities) &&
    value.fingerprintVersion === SAST_FINDING_FINGERPRINT_VERSION &&
    isSha256Digest(value.lifecycleEligibilityScope)
  );
}

export function isSastScanRetryScopeValid(
  value: unknown
): value is SastScanRetryScope {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      'tenantId',
      'repositoryBindingId',
      'scanRequestId',
      'canonicalScanKey',
      'planDigest',
      'originalScannerSetDigest',
      'previousAttemptId',
      'previousAttemptNumber',
      'previousSandboxId',
      'previousWorkloadIdentityRef',
      'requestedAttemptId',
      'requestedAttemptNumber',
      'requestedSandboxId',
      'requestedWorkloadIdentityRef'
    ]) &&
    isBoundedReference(value.tenantId) &&
    isBoundedReference(value.repositoryBindingId) &&
    isBoundedReference(value.scanRequestId) &&
    isSha256Digest(value.canonicalScanKey) &&
    isSha256Digest(value.planDigest) &&
    isSha256Digest(value.originalScannerSetDigest) &&
    isBoundedReference(value.previousAttemptId) &&
    Number.isSafeInteger(value.previousAttemptNumber) &&
    (value.previousAttemptNumber as number) > 0 &&
    isBoundedReference(value.previousSandboxId) &&
    isBoundedReference(value.previousWorkloadIdentityRef) &&
    isBoundedReference(value.requestedAttemptId) &&
    Number.isSafeInteger(value.requestedAttemptNumber) &&
    (value.requestedAttemptNumber as number) > 0 &&
    (value.requestedAttemptNumber as number) <= 100 &&
    isBoundedReference(value.requestedSandboxId) &&
    isBoundedReference(value.requestedWorkloadIdentityRef)
  );
}

function sameNullableObservationTuple(
  decision: Readonly<SastScanFreshnessDecision>
): boolean {
  const values = [
    decision.observationId,
    decision.observationDigest,
    decision.observedHeadCommitSha,
    decision.observationSequence
  ];
  return values.every((value) => value === null) ||
    values.every((value) => value !== null);
}

function sameNullableComparisonTuple(
  decision: Readonly<SastScanFreshnessDecision>
): boolean {
  const values = [
    decision.previousCoverageDecisionId,
    decision.previousCoverageDecisionDigest,
    decision.previousScanRequestId,
    decision.previousCommitSha
  ];
  return values.every((value) => value === null) ||
    values.every((value) => value !== null);
}

function isCanonicalCapabilityArray(
  value: unknown
): value is SastCapability[] {
  return (
    Array.isArray(value) &&
    value.length > 0 &&
    value.every(
      (capability, index) =>
        SAST_CAPABILITIES.includes(capability as SastCapability) &&
        (index === 0 ||
          SAST_CAPABILITIES.indexOf(
            value[index - 1] as SastCapability
          ) < SAST_CAPABILITIES.indexOf(capability as SastCapability))
    )
  );
}

function isCanonicalReasonArray(
  value: unknown,
  allowed: readonly string[]
): boolean {
  return (
    Array.isArray(value) &&
    value.every(
      (reason, index) =>
        typeof reason === 'string' &&
        allowed.includes(reason) &&
        (index === 0 ||
          allowed.indexOf(value[index - 1] as string) <
            allowed.indexOf(reason))
    )
  );
}

function orderByCanonical<T extends string>(
  values: readonly T[],
  canonical: readonly T[]
): T[] {
  return [...new Set(values)].sort(
    (left, right) => canonical.indexOf(left) - canonical.indexOf(right)
  );
}

function isContractId(value: unknown, prefix: string): value is string {
  return typeof value === 'string' &&
    new RegExp(`^${prefix}:\\/\\/[a-f0-9]{64}$`, 'u').test(value);
}

function isNullableContractId(value: unknown, prefix: string): boolean {
  return value === null || isContractId(value, prefix);
}

function isNullableReference(value: unknown): value is string | null {
  return value === null || isBoundedReference(value);
}

function isNullableDigest(
  value: unknown
): value is `sha256:${string}` | null {
  return value === null || isSha256Digest(value);
}

function isNullableCommit(value: unknown): value is string | null {
  return value === null || isCommitSha(value);
}

function isNullablePositiveInteger(value: unknown): boolean {
  return value === null ||
    (Number.isSafeInteger(value) && (value as number) > 0);
}

function isNullableTimestamp(value: unknown): value is string | null {
  return value === null || isCanonicalIsoTimestamp(value);
}

function isCanonicalIsoTimestamp(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) &&
    new Date(timestamp).toISOString() === value;
}

function sameStrings(
  left: readonly string[],
  right: readonly string[]
): boolean {
  return left.length === right.length &&
    left.every((value, index) => value === right[index]);
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(stableJson).join(',')}]`;
  }
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort(compareStrings)
      .map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
