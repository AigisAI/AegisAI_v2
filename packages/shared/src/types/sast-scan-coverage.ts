import {
  SCANNER_EXECUTION_STATUSES,
  SAST_CAPABILITIES,
  SAST_COVERAGE_STATES,
  SAST_PROFILE_IDS,
  SAST_SCAN_LANES,
  SAST_SCAN_PROFILES,
  SAST_SCANNER_KINDS,
  SAST_SCANNER_RESPONSIBILITIES,
  type SastCapability,
  type SastCoverageState,
  type SastProfileId,
  type SastScanLane,
  type SastScannerKind
} from './sast-runtime';
import {
  hasExactKeys,
  isBoundedReference,
  isCommitSha,
  isRecord,
  isSha256Digest
} from './sast-normalization-validation';

export const SAST_SCAN_COVERAGE_VERSION =
  'sast-scan-coverage-v1' as const;
export const SAST_SCANNER_COVERAGE_VERSION =
  'sast-scanner-coverage-v1' as const;
export const SAST_EXTERNAL_PUBLICATION_DECISION_VERSION =
  'sast-external-publication-v1' as const;

export const SAST_SCANNER_COVERAGE_EXECUTION_STATUSES = [
  'NOT_STARTED',
  ...SCANNER_EXECUTION_STATUSES
] as const;
export type SastScannerCoverageExecutionStatus =
  (typeof SAST_SCANNER_COVERAGE_EXECUTION_STATUSES)[number];

export const SAST_SCANNER_COVERAGE_REASON_CODES = [
  'SCANNER_NOT_STARTED',
  'SCANNER_PENDING',
  'SCANNER_FAILED',
  'SCANNER_TIMED_OUT',
  'SCANNER_SKIPPED',
  'SCANNER_QUARANTINED',
  'SCANNER_KILLED',
  'SCANNER_PROVENANCE_MISMATCH',
  'ARTIFACT_MISSING',
  'ARTIFACT_NOT_ACCEPTED',
  'ARTIFACT_NOT_NORMALIZATION_ELIGIBLE',
  'ARTIFACT_BINDING_INVALID',
  'CORRELATION_SOURCE_MISSING',
  'CORRELATION_SOURCE_INVALID'
] as const;
export type SastScannerCoverageReasonCode =
  (typeof SAST_SCANNER_COVERAGE_REASON_CODES)[number];

export const SAST_SCAN_COVERAGE_REASON_CODES = [
  'REQUIRED_SCANNER_MISSING',
  'REQUIRED_SCANNER_PENDING',
  'REQUIRED_SCANNER_INCOMPLETE',
  'REQUIRED_CAPABILITY_MISSING',
  'DUPLICATE_SCANNER_RECORD',
  'SCANNER_PROVENANCE_INVALID',
  'ARTIFACT_AUTHORITY_INVALID',
  'CORRELATION_SOURCE_SET_INCOMPLETE',
  'SECURITY_BLOCKED',
  'OPTIONAL_SCANNER_INCOMPLETE'
] as const;
export type SastScanCoverageReasonCode =
  (typeof SAST_SCAN_COVERAGE_REASON_CODES)[number];

export const SAST_EXTERNAL_PUBLICATION_REASON_CODES = [
  'COVERAGE_NOT_COMPLETE',
  'LATEST_TARGET_AUTHORITY_UNAVAILABLE',
  'STALE_STATUS_UNKNOWN',
  'COMPARABILITY_STATUS_UNKNOWN',
  'PROFILE_AI_INELIGIBLE',
  'EXTERNAL_PUBLICATION_FAIL_CLOSED'
] as const;
export type SastExternalPublicationReasonCode =
  (typeof SAST_EXTERNAL_PUBLICATION_REASON_CODES)[number];

export const SAST_SCAN_COVERAGE_REJECTION_REASON_CODES = [
  'SCAN_COVERAGE_INPUT_INVALID',
  'SCAN_COVERAGE_CORRELATION_INVALID',
  'SCAN_COVERAGE_DURABLE_SCOPE_INVALID',
  'SCAN_COVERAGE_SCANNER_SET_INVALID',
  'SCAN_COVERAGE_SOURCE_SET_INCOMPLETE',
  'SCAN_COVERAGE_REPLAY_CONFLICT',
  'SCAN_COVERAGE_PERSISTENCE_FAILED'
] as const;
export type SastScanCoverageRejectionReasonCode =
  (typeof SAST_SCAN_COVERAGE_REJECTION_REASON_CODES)[number];

export type SastScanCoverageCanonicalDigester = (
  canonicalValue: string
) => `sha256:${string}`;

export interface SastScanCoverageScope {
  tenantId: string;
  repositoryBindingId: string;
  scanRequestId: string;
  attemptId: string;
  lifecycleContextKey: `sha256:${string}`;
  targetRef: string;
  commitSha: string;
  lane: SastScanLane;
  profileId: SastProfileId;
  profileDigest: `sha256:${string}`;
  canonicalScanKey: `sha256:${string}`;
  planDigest: `sha256:${string}`;
  scannerSetDigest: `sha256:${string}`;
  correlationBatchId: string;
  correlationSourceSetDigest: `sha256:${string}`;
}

export interface SastScannerCoverageRecord {
  version: typeof SAST_SCANNER_COVERAGE_VERSION;
  scannerCoverageId: string;
  scanner: SastScannerKind;
  required: boolean;
  executionStatus: SastScannerCoverageExecutionStatus;
  authoritativeCapabilities: SastCapability[];
  requiredCapabilities: SastCapability[];
  achievedCapabilities: SastCapability[];
  scannerRunId: string | null;
  scannerVersion: string | null;
  scannerImageDigest: `sha256:${string}` | null;
  wrapperDigest: `sha256:${string}` | null;
  ruleBundleDigest: `sha256:${string}` | null;
  vulnerabilityDatabaseDigest: `sha256:${string}` | null;
  schemaBundleDigest: `sha256:${string}` | null;
  normalizerBundleDigest: `sha256:${string}` | null;
  artifactIngestionId: string | null;
  artifactEnvelopeDigest: `sha256:${string}` | null;
  artifactDigest: `sha256:${string}` | null;
  dispositionDecisionId: string | null;
  dispositionDecisionDigest: `sha256:${string}` | null;
  correlationSourceId: string | null;
  observationBatchId: string | null;
  correlationSourceBindingDigest: `sha256:${string}` | null;
  artifactAccepted: boolean;
  normalizationEligible: boolean;
  findingObservationRequired: boolean;
  findingObservationClosed: boolean;
  reasonCodes: SastScannerCoverageReasonCode[];
  recordDigest: `sha256:${string}`;
}

export type SastScannerCoverageRecordCore = Omit<
  SastScannerCoverageRecord,
  'recordDigest'
>;

export interface SastScanCoverageAuthority {
  coverageCalculationAuthority: true;
  scannerExecutionAuthority: false;
  artifactAcceptanceAuthority: false;
  correlationAuthority: false;
  lifecycleAuthority: false;
  evidenceAuthority: false;
  policyAuthority: false;
  publicationAuthority: false;
  aiPayloadEligible: false;
}

export interface SastScanCoverageDecision {
  version: typeof SAST_SCAN_COVERAGE_VERSION;
  coverageDecisionId: string;
  scope: SastScanCoverageScope;
  state: SastCoverageState;
  requiredScanners: SastScannerKind[];
  optionalScanners: SastScannerKind[];
  missingRequiredScanners: SastScannerKind[];
  pendingRequiredScanners: SastScannerKind[];
  failedRequiredScanners: SastScannerKind[];
  achievedRequiredCapabilities: SastCapability[];
  missingRequiredCapabilities: SastCapability[];
  duplicateScanners: SastScannerKind[];
  optionalIncompleteScanners: SastScannerKind[];
  reasonCodes: SastScanCoverageReasonCode[];
  recordsDigest: `sha256:${string}`;
  authority: SastScanCoverageAuthority;
  decidedAt: string;
  decisionDigest: `sha256:${string}`;
}

export type SastScanCoverageDecisionCore = Omit<
  SastScanCoverageDecision,
  'decisionDigest'
>;

export interface SastExternalPublicationDecision {
  version: typeof SAST_EXTERNAL_PUBLICATION_DECISION_VERSION;
  publicationDecisionId: string;
  coverageDecisionId: string;
  coverageDecisionDigest: `sha256:${string}`;
  coverageState: SastCoverageState;
  externalCommentAllowed: false;
  blockingStatusAllowed: false;
  aiAdvisoryAllowed: false;
  lifecycleMutationAllowed: false;
  latestTargetAuthority: 'UNAVAILABLE';
  staleStatus: 'UNKNOWN';
  comparabilityStatus: 'UNKNOWN';
  reasonCodes: SastExternalPublicationReasonCode[];
  decidedAt: string;
  decisionDigest: `sha256:${string}`;
}

export type SastExternalPublicationDecisionCore = Omit<
  SastExternalPublicationDecision,
  'decisionDigest'
>;

export interface SastScanCoverageResult {
  version: typeof SAST_SCAN_COVERAGE_VERSION;
  outcome: 'EVALUATED';
  records: SastScannerCoverageRecord[];
  decision: SastScanCoverageDecision;
  publication: SastExternalPublicationDecision;
  replayed: boolean;
  resultDigest: `sha256:${string}`;
}

export type SastScanCoverageResultCore = Omit<
  SastScanCoverageResult,
  'resultDigest'
>;

export interface SastScanCoverageRejection {
  version: typeof SAST_SCAN_COVERAGE_VERSION;
  outcome: 'REJECTED';
  reasonCodes: SastScanCoverageRejectionReasonCode[];
  scannerRunIdsStored: false;
  artifactReferencesStored: false;
  correlationReferencesStored: false;
  publicationAttempted: false;
  secretValueStored: false;
  rejectionDigest: `sha256:${string}`;
}

export type SastScanCoverageRejectionCore = Omit<
  SastScanCoverageRejection,
  'rejectionDigest'
>;

export type SastScanCoverageOutcome =
  | SastScanCoverageResult
  | SastScanCoverageRejection;

export type SastScanCoverageAuditMetadata =
  | {
      version: typeof SAST_SCAN_COVERAGE_VERSION;
      outcome: 'EVALUATED';
      coverageDecisionId: string;
      publicationDecisionId: string;
      state: SastCoverageState;
      decisionDigest: `sha256:${string}`;
      publicationDecisionDigest: `sha256:${string}`;
      replayed: boolean;
    }
  | {
      version: typeof SAST_SCAN_COVERAGE_VERSION;
      outcome: 'REJECTED';
      reasonCodes: SastScanCoverageRejectionReasonCode[];
      rejectionDigest: `sha256:${string}`;
    };

export interface SastScanCoverageEvaluation {
  state: SastCoverageState;
  missingRequiredScanners: SastScannerKind[];
  pendingRequiredScanners: SastScannerKind[];
  failedRequiredScanners: SastScannerKind[];
  achievedRequiredCapabilities: SastCapability[];
  missingRequiredCapabilities: SastCapability[];
  duplicateScanners: SastScannerKind[];
  optionalIncompleteScanners: SastScannerKind[];
  reasonCodes: SastScanCoverageReasonCode[];
}

const SECURITY_RECORD_REASONS = new Set<SastScannerCoverageReasonCode>([
  'SCANNER_QUARANTINED',
  'SCANNER_KILLED',
  'SCANNER_PROVENANCE_MISMATCH',
  'ARTIFACT_BINDING_INVALID',
  'CORRELATION_SOURCE_INVALID'
]);

const COVERAGE_AUTHORITY: Readonly<SastScanCoverageAuthority> =
  Object.freeze({
    coverageCalculationAuthority: true,
    scannerExecutionAuthority: false,
    artifactAcceptanceAuthority: false,
    correlationAuthority: false,
    lifecycleAuthority: false,
    evidenceAuthority: false,
    policyAuthority: false,
    publicationAuthority: false,
    aiPayloadEligible: false
  });

export function sastScanCoverageAuthority(): SastScanCoverageAuthority {
  return { ...COVERAGE_AUTHORITY };
}

export function canonicalizeSastScannerCoverageRecord(
  record: Readonly<SastScannerCoverageRecordCore>
): string {
  return stableJson(record);
}

export function canonicalizeSastScanCoverageScope(
  scope: Readonly<SastScanCoverageScope>
): string {
  return stableJson(scope);
}

export function buildSastScanCoverageRecordsPreimage(
  records: readonly Readonly<SastScannerCoverageRecord>[]
): string {
  return stableJson(
    records.map((record) => ({
      scannerCoverageId: record.scannerCoverageId,
      scanner: record.scanner,
      recordDigest: record.recordDigest
    }))
  );
}

export function buildSastScanCoverageDecisionKeyPreimage(input: {
  scope: Readonly<SastScanCoverageScope>;
  recordsDigest: `sha256:${string}`;
}): string {
  return stableJson({
    version: SAST_SCAN_COVERAGE_VERSION,
    scope: input.scope,
    recordsDigest: input.recordsDigest
  });
}

export function canonicalizeSastScanCoverageDecision(
  decision: Readonly<SastScanCoverageDecisionCore>
): string {
  return stableJson(decision);
}

export function canonicalizeSastExternalPublicationDecision(
  decision: Readonly<SastExternalPublicationDecisionCore>
): string {
  return stableJson(decision);
}

export function canonicalizeSastScanCoverageResult(
  result: Readonly<SastScanCoverageResultCore>
): string {
  return stableJson(result);
}

export function canonicalizeSastScanCoverageRejection(
  rejection: Readonly<SastScanCoverageRejectionCore>
): string {
  return stableJson(rejection);
}

export function orderSastScannerCoverageReasons(
  reasons: readonly SastScannerCoverageReasonCode[]
): SastScannerCoverageReasonCode[] {
  return orderByCanonical(reasons, SAST_SCANNER_COVERAGE_REASON_CODES);
}

export function orderSastScanCoverageReasons(
  reasons: readonly SastScanCoverageReasonCode[]
): SastScanCoverageReasonCode[] {
  return orderByCanonical(reasons, SAST_SCAN_COVERAGE_REASON_CODES);
}

export function orderSastExternalPublicationReasons(
  reasons: readonly SastExternalPublicationReasonCode[]
): SastExternalPublicationReasonCode[] {
  return orderByCanonical(reasons, SAST_EXTERNAL_PUBLICATION_REASON_CODES);
}

export function orderSastScanCoverageRejectionReasons(
  reasons: readonly SastScanCoverageRejectionReasonCode[]
): SastScanCoverageRejectionReasonCode[] {
  return orderByCanonical(
    reasons,
    SAST_SCAN_COVERAGE_REJECTION_REASON_CODES
  );
}

export function evaluateSastScanCoverageRecords(input: {
  profileId: SastProfileId;
  records: readonly Readonly<SastScannerCoverageRecord>[];
}): SastScanCoverageEvaluation {
  const profile = SAST_SCAN_PROFILES[input.profileId];
  const byScanner = new Map<
    SastScannerKind,
    Readonly<SastScannerCoverageRecord>
  >();
  const duplicateScanners = new Set<SastScannerKind>();
  for (const record of input.records) {
    if (byScanner.has(record.scanner)) {
      duplicateScanners.add(record.scanner);
    }
    byScanner.set(record.scanner, record);
  }

  const missingRequiredScanners = profile.requiredScanners.filter(
    (scanner) =>
      !byScanner.has(scanner) ||
      byScanner.get(scanner)?.executionStatus === 'NOT_STARTED'
  );
  const pendingRequiredScanners = profile.requiredScanners.filter(
    (scanner) => {
      const status = byScanner.get(scanner)?.executionStatus;
      return status === 'PENDING' || status === 'RUNNING';
    }
  );
  const failedRequiredScanners = profile.requiredScanners.filter(
    (scanner) => {
      const record = byScanner.get(scanner);
      return (
        record !== undefined &&
        record.executionStatus !== 'NOT_STARTED' &&
        record.executionStatus !== 'PENDING' &&
        record.executionStatus !== 'RUNNING' &&
        !isCoverageRecordComplete(record)
      );
    }
  );
  const achieved = new Set<SastCapability>();
  for (const scanner of profile.requiredScanners) {
    const record = byScanner.get(scanner);
    if (record && isCoverageRecordComplete(record)) {
      for (const capability of record.achievedCapabilities) {
        if (profile.requiredCapabilities.includes(capability)) {
          achieved.add(capability);
        }
      }
    }
  }
  const achievedRequiredCapabilities = SAST_CAPABILITIES.filter(
    (capability) => achieved.has(capability)
  );
  const missingRequiredCapabilities = profile.requiredCapabilities.filter(
    (capability) => !achieved.has(capability)
  );
  const optionalIncompleteScanners = profile.optionalScanners.filter(
    (scanner) => {
      const record = byScanner.get(scanner);
      return !record || !isCoverageRecordComplete(record);
    }
  );
  const hasProvenanceFailure = input.records.some((record) =>
    record.reasonCodes.includes('SCANNER_PROVENANCE_MISMATCH')
  );
  const hasArtifactFailure = input.records.some((record) =>
    record.reasonCodes.some(
      (reason) =>
        reason === 'ARTIFACT_BINDING_INVALID' ||
        (record.executionStatus === 'SUCCEEDED' &&
          (reason === 'ARTIFACT_MISSING' ||
            reason === 'ARTIFACT_NOT_ACCEPTED' ||
            reason === 'ARTIFACT_NOT_NORMALIZATION_ELIGIBLE'))
    )
  );
  const hasCorrelationFailure = input.records.some((record) =>
    record.reasonCodes.some(
      (reason) =>
        reason === 'CORRELATION_SOURCE_INVALID' ||
        (record.required && reason === 'CORRELATION_SOURCE_MISSING')
    )
  );
  const securityBlocked =
    duplicateScanners.size > 0 ||
    input.records.some((record) =>
      record.reasonCodes.some((reason) =>
        SECURITY_RECORD_REASONS.has(reason)
      )
    ) ||
    hasArtifactFailure ||
    hasCorrelationFailure;

  let state: SastCoverageState;
  if (securityBlocked) {
    state = 'FAILED';
  } else if (missingRequiredScanners.length > 0) {
    state = 'PARTIAL';
  } else if (pendingRequiredScanners.length > 0) {
    state = 'PENDING';
  } else if (
    failedRequiredScanners.length > 0 ||
    missingRequiredCapabilities.length > 0
  ) {
    state = 'PARTIAL';
  } else {
    state = 'COMPLETE';
  }

  const reasons = new Set<SastScanCoverageReasonCode>();
  if (missingRequiredScanners.length > 0) {
    reasons.add('REQUIRED_SCANNER_MISSING');
  }
  if (pendingRequiredScanners.length > 0) {
    reasons.add('REQUIRED_SCANNER_PENDING');
  }
  if (failedRequiredScanners.length > 0) {
    reasons.add('REQUIRED_SCANNER_INCOMPLETE');
  }
  if (missingRequiredCapabilities.length > 0) {
    reasons.add('REQUIRED_CAPABILITY_MISSING');
  }
  if (duplicateScanners.size > 0) {
    reasons.add('DUPLICATE_SCANNER_RECORD');
  }
  if (hasProvenanceFailure) {
    reasons.add('SCANNER_PROVENANCE_INVALID');
  }
  if (hasArtifactFailure) {
    reasons.add('ARTIFACT_AUTHORITY_INVALID');
  }
  if (hasCorrelationFailure) {
    reasons.add('CORRELATION_SOURCE_SET_INCOMPLETE');
  }
  if (securityBlocked) reasons.add('SECURITY_BLOCKED');
  if (optionalIncompleteScanners.length > 0) {
    reasons.add('OPTIONAL_SCANNER_INCOMPLETE');
  }

  return {
    state,
    missingRequiredScanners: orderScanners(missingRequiredScanners),
    pendingRequiredScanners: orderScanners(pendingRequiredScanners),
    failedRequiredScanners: orderScanners(failedRequiredScanners),
    achievedRequiredCapabilities,
    missingRequiredCapabilities: orderCapabilities(
      missingRequiredCapabilities
    ),
    duplicateScanners: orderScanners([...duplicateScanners]),
    optionalIncompleteScanners: orderScanners(
      optionalIncompleteScanners
    ),
    reasonCodes: orderSastScanCoverageReasons([...reasons])
  };
}

export function buildFailClosedSastExternalPublicationDecision(input: {
  publicationDecisionId: string;
  decision: Readonly<SastScanCoverageDecision>;
  profileAiAdvisoryEligible: boolean;
  digestCanonical: SastScanCoverageCanonicalDigester;
}): SastExternalPublicationDecision {
  const reasons: SastExternalPublicationReasonCode[] = [];
  if (input.decision.state !== 'COMPLETE') {
    reasons.push('COVERAGE_NOT_COMPLETE');
  }
  reasons.push(
    'LATEST_TARGET_AUTHORITY_UNAVAILABLE',
    'STALE_STATUS_UNKNOWN',
    'COMPARABILITY_STATUS_UNKNOWN'
  );
  if (!input.profileAiAdvisoryEligible) {
    reasons.push('PROFILE_AI_INELIGIBLE');
  }
  reasons.push('EXTERNAL_PUBLICATION_FAIL_CLOSED');
  const core: SastExternalPublicationDecisionCore = {
    version: SAST_EXTERNAL_PUBLICATION_DECISION_VERSION,
    publicationDecisionId: input.publicationDecisionId,
    coverageDecisionId: input.decision.coverageDecisionId,
    coverageDecisionDigest: input.decision.decisionDigest,
    coverageState: input.decision.state,
    externalCommentAllowed: false,
    blockingStatusAllowed: false,
    aiAdvisoryAllowed: false,
    lifecycleMutationAllowed: false,
    latestTargetAuthority: 'UNAVAILABLE',
    staleStatus: 'UNKNOWN',
    comparabilityStatus: 'UNKNOWN',
    reasonCodes: orderSastExternalPublicationReasons(reasons),
    decidedAt: input.decision.decidedAt
  };
  return {
    ...core,
    decisionDigest: input.digestCanonical(
      canonicalizeSastExternalPublicationDecision(core)
    )
  };
}

export function isSastScanCoverageScopeValid(
  value: unknown
): value is SastScanCoverageScope {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      'tenantId',
      'repositoryBindingId',
      'scanRequestId',
      'attemptId',
      'lifecycleContextKey',
      'targetRef',
      'commitSha',
      'lane',
      'profileId',
      'profileDigest',
      'canonicalScanKey',
      'planDigest',
      'scannerSetDigest',
      'correlationBatchId',
      'correlationSourceSetDigest'
    ]) &&
    isBoundedReference(value.tenantId) &&
    isBoundedReference(value.repositoryBindingId) &&
    isBoundedReference(value.scanRequestId) &&
    isBoundedReference(value.attemptId) &&
    isSha256Digest(value.lifecycleContextKey) &&
    isBoundedReference(value.targetRef) &&
    isCommitSha(value.commitSha) &&
    SAST_SCAN_LANES.includes(value.lane as SastScanLane) &&
    SAST_PROFILE_IDS.includes(value.profileId as SastProfileId) &&
    isSha256Digest(value.profileDigest) &&
    isSha256Digest(value.canonicalScanKey) &&
    isSha256Digest(value.planDigest) &&
    isSha256Digest(value.scannerSetDigest) &&
    isCoverageId(value.correlationBatchId, 'finding-correlation') &&
    isSha256Digest(value.correlationSourceSetDigest)
  );
}

export function isSastScannerCoverageRecordShapeValid(
  value: unknown,
  digestCanonical: SastScanCoverageCanonicalDigester
): value is SastScannerCoverageRecord {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'version',
      'scannerCoverageId',
      'scanner',
      'required',
      'executionStatus',
      'authoritativeCapabilities',
      'requiredCapabilities',
      'achievedCapabilities',
      'scannerRunId',
      'scannerVersion',
      'scannerImageDigest',
      'wrapperDigest',
      'ruleBundleDigest',
      'vulnerabilityDatabaseDigest',
      'schemaBundleDigest',
      'normalizerBundleDigest',
      'artifactIngestionId',
      'artifactEnvelopeDigest',
      'artifactDigest',
      'dispositionDecisionId',
      'dispositionDecisionDigest',
      'correlationSourceId',
      'observationBatchId',
      'correlationSourceBindingDigest',
      'artifactAccepted',
      'normalizationEligible',
      'findingObservationRequired',
      'findingObservationClosed',
      'reasonCodes',
      'recordDigest'
    ]) ||
    value.version !== SAST_SCANNER_COVERAGE_VERSION ||
    !isCoverageId(value.scannerCoverageId, 'sast-scanner-coverage') ||
    !SAST_SCANNER_KINDS.includes(value.scanner as SastScannerKind) ||
    typeof value.required !== 'boolean' ||
    !SAST_SCANNER_COVERAGE_EXECUTION_STATUSES.includes(
      value.executionStatus as SastScannerCoverageExecutionStatus
    ) ||
    !isCanonicalCapabilityArray(value.authoritativeCapabilities) ||
    !isCanonicalCapabilityArray(value.requiredCapabilities) ||
    !isCanonicalCapabilityArray(value.achievedCapabilities) ||
    !isNullableReference(value.scannerRunId) ||
    !isNullableReference(value.scannerVersion) ||
    !isNullableDigest(value.scannerImageDigest) ||
    !isNullableDigest(value.wrapperDigest) ||
    !isNullableDigest(value.ruleBundleDigest) ||
    !isNullableDigest(value.vulnerabilityDatabaseDigest) ||
    !isNullableDigest(value.schemaBundleDigest) ||
    !isNullableDigest(value.normalizerBundleDigest) ||
    !isNullableReference(value.artifactIngestionId) ||
    !isNullableDigest(value.artifactEnvelopeDigest) ||
    !isNullableDigest(value.artifactDigest) ||
    !isNullableReference(value.dispositionDecisionId) ||
    !isNullableDigest(value.dispositionDecisionDigest) ||
    !isNullableReference(value.correlationSourceId) ||
    !isNullableCoverageId(value.observationBatchId, 'finding-observation') ||
    !isNullableDigest(value.correlationSourceBindingDigest) ||
    typeof value.artifactAccepted !== 'boolean' ||
    typeof value.normalizationEligible !== 'boolean' ||
    typeof value.findingObservationRequired !== 'boolean' ||
    typeof value.findingObservationClosed !== 'boolean' ||
    !isCanonicalReasonArray(
      value.reasonCodes,
      SAST_SCANNER_COVERAGE_REASON_CODES
    ) ||
    !isSha256Digest(value.recordDigest)
  ) {
    return false;
  }
  const record = value as unknown as SastScannerCoverageRecord;
  const responsibilities = SAST_SCANNER_RESPONSIBILITIES[record.scanner];
  if (
    !sameStrings(
      record.authoritativeCapabilities,
      orderCapabilities([
        ...responsibilities.authoritativeCapabilities
      ])
    ) ||
    record.requiredCapabilities.some(
      (capability) =>
        !record.authoritativeCapabilities.includes(capability)
    ) ||
    record.achievedCapabilities.some(
      (capability) =>
        !record.authoritativeCapabilities.includes(capability)
    ) ||
    record.findingObservationRequired !==
      responsibilities.mayCreateFindings ||
    (record.executionStatus === 'NOT_STARTED' &&
      record.scannerRunId !== null)
  ) {
    return false;
  }
  const { recordDigest, ...core } = record;
  return (
    digestCanonical(canonicalizeSastScannerCoverageRecord(core)) ===
    recordDigest
  );
}

export function isSastScanCoverageDecisionShapeValid(
  value: unknown,
  digestCanonical: SastScanCoverageCanonicalDigester
): value is SastScanCoverageDecision {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'version',
      'coverageDecisionId',
      'scope',
      'state',
      'requiredScanners',
      'optionalScanners',
      'missingRequiredScanners',
      'pendingRequiredScanners',
      'failedRequiredScanners',
      'achievedRequiredCapabilities',
      'missingRequiredCapabilities',
      'duplicateScanners',
      'optionalIncompleteScanners',
      'reasonCodes',
      'recordsDigest',
      'authority',
      'decidedAt',
      'decisionDigest'
    ]) ||
    value.version !== SAST_SCAN_COVERAGE_VERSION ||
    !isCoverageId(value.coverageDecisionId, 'sast-coverage') ||
    !isSastScanCoverageScopeValid(value.scope) ||
    !SAST_COVERAGE_STATES.includes(value.state as SastCoverageState) ||
    !isCanonicalScannerArray(value.requiredScanners) ||
    !isCanonicalScannerArray(value.optionalScanners) ||
    !isCanonicalScannerArray(value.missingRequiredScanners) ||
    !isCanonicalScannerArray(value.pendingRequiredScanners) ||
    !isCanonicalScannerArray(value.failedRequiredScanners) ||
    !isCanonicalCapabilityArray(value.achievedRequiredCapabilities) ||
    !isCanonicalCapabilityArray(value.missingRequiredCapabilities) ||
    !isCanonicalScannerArray(value.duplicateScanners) ||
    !isCanonicalScannerArray(value.optionalIncompleteScanners) ||
    !isCanonicalReasonArray(
      value.reasonCodes,
      SAST_SCAN_COVERAGE_REASON_CODES
    ) ||
    !isSha256Digest(value.recordsDigest) ||
    !isCoverageAuthority(value.authority) ||
    !isCanonicalIsoTimestamp(value.decidedAt) ||
    !isSha256Digest(value.decisionDigest)
  ) {
    return false;
  }
  const decision = value as unknown as SastScanCoverageDecision;
  const profile = SAST_SCAN_PROFILES[decision.scope.profileId];
  if (
    !sameStrings(decision.requiredScanners, profile.requiredScanners) ||
    !sameStrings(decision.optionalScanners, profile.optionalScanners)
  ) {
    return false;
  }
  const { decisionDigest, ...core } = decision;
  return (
    digestCanonical(canonicalizeSastScanCoverageDecision(core)) ===
    decisionDigest
  );
}

export function isSastExternalPublicationDecisionShapeValid(
  value: unknown,
  digestCanonical: SastScanCoverageCanonicalDigester
): value is SastExternalPublicationDecision {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'version',
      'publicationDecisionId',
      'coverageDecisionId',
      'coverageDecisionDigest',
      'coverageState',
      'externalCommentAllowed',
      'blockingStatusAllowed',
      'aiAdvisoryAllowed',
      'lifecycleMutationAllowed',
      'latestTargetAuthority',
      'staleStatus',
      'comparabilityStatus',
      'reasonCodes',
      'decidedAt',
      'decisionDigest'
    ]) ||
    value.version !== SAST_EXTERNAL_PUBLICATION_DECISION_VERSION ||
    !isCoverageId(value.publicationDecisionId, 'sast-publication') ||
    !isCoverageId(value.coverageDecisionId, 'sast-coverage') ||
    !isSha256Digest(value.coverageDecisionDigest) ||
    !SAST_COVERAGE_STATES.includes(value.coverageState as SastCoverageState) ||
    value.externalCommentAllowed !== false ||
    value.blockingStatusAllowed !== false ||
    value.aiAdvisoryAllowed !== false ||
    value.lifecycleMutationAllowed !== false ||
    value.latestTargetAuthority !== 'UNAVAILABLE' ||
    value.staleStatus !== 'UNKNOWN' ||
    value.comparabilityStatus !== 'UNKNOWN' ||
    !isCanonicalReasonArray(
      value.reasonCodes,
      SAST_EXTERNAL_PUBLICATION_REASON_CODES
    ) ||
    !(value.reasonCodes as unknown[]).includes(
      'LATEST_TARGET_AUTHORITY_UNAVAILABLE'
    ) ||
    !(value.reasonCodes as unknown[]).includes(
      'EXTERNAL_PUBLICATION_FAIL_CLOSED'
    ) ||
    !isCanonicalIsoTimestamp(value.decidedAt) ||
    !isSha256Digest(value.decisionDigest)
  ) {
    return false;
  }
  const decision = value as unknown as SastExternalPublicationDecision;
  const { decisionDigest, ...core } = decision;
  return (
    digestCanonical(
      canonicalizeSastExternalPublicationDecision(core)
    ) === decisionDigest
  );
}

export function isSastScanCoverageResultShapeValid(
  value: unknown,
  digestCanonical: SastScanCoverageCanonicalDigester
): value is SastScanCoverageResult {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'version',
      'outcome',
      'records',
      'decision',
      'publication',
      'replayed',
      'resultDigest'
    ]) ||
    value.version !== SAST_SCAN_COVERAGE_VERSION ||
    value.outcome !== 'EVALUATED' ||
    !Array.isArray(value.records) ||
    value.records.length !== SAST_SCANNER_KINDS.length ||
    value.records.some(
      (record) =>
        !isSastScannerCoverageRecordShapeValid(
          record,
          digestCanonical
        )
    ) ||
    !isSastScanCoverageDecisionShapeValid(
      value.decision,
      digestCanonical
    ) ||
    !isSastExternalPublicationDecisionShapeValid(
      value.publication,
      digestCanonical
    ) ||
    typeof value.replayed !== 'boolean' ||
    !isSha256Digest(value.resultDigest)
  ) {
    return false;
  }
  const result = value as unknown as SastScanCoverageResult;
  if (
    !sameStrings(
      result.records.map((record) => record.scanner),
      SAST_SCANNER_KINDS
    ) ||
    digestCanonical(
      buildSastScanCoverageRecordsPreimage(result.records)
    ) !== result.decision.recordsDigest ||
    result.publication.coverageDecisionId !==
      result.decision.coverageDecisionId ||
    result.publication.coverageDecisionDigest !==
      result.decision.decisionDigest ||
    result.publication.coverageState !== result.decision.state ||
    result.publication.decidedAt !== result.decision.decidedAt
  ) {
    return false;
  }
  const evaluation = evaluateSastScanCoverageRecords({
    profileId: result.decision.scope.profileId,
    records: result.records
  });
  if (
    evaluation.state !== result.decision.state ||
    !sameStrings(
      evaluation.missingRequiredScanners,
      result.decision.missingRequiredScanners
    ) ||
    !sameStrings(
      evaluation.pendingRequiredScanners,
      result.decision.pendingRequiredScanners
    ) ||
    !sameStrings(
      evaluation.failedRequiredScanners,
      result.decision.failedRequiredScanners
    ) ||
    !sameStrings(
      evaluation.achievedRequiredCapabilities,
      result.decision.achievedRequiredCapabilities
    ) ||
    !sameStrings(
      evaluation.missingRequiredCapabilities,
      result.decision.missingRequiredCapabilities
    ) ||
    !sameStrings(
      evaluation.duplicateScanners,
      result.decision.duplicateScanners
    ) ||
    !sameStrings(
      evaluation.optionalIncompleteScanners,
      result.decision.optionalIncompleteScanners
    ) ||
    !sameStrings(
      evaluation.reasonCodes,
      result.decision.reasonCodes
    )
  ) {
    return false;
  }
  const { resultDigest, ...core } = result;
  return (
    digestCanonical(canonicalizeSastScanCoverageResult(core)) ===
    resultDigest
  );
}

export function isSastScanCoverageRejectionShapeValid(
  value: unknown,
  digestCanonical: SastScanCoverageCanonicalDigester
): value is SastScanCoverageRejection {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'version',
      'outcome',
      'reasonCodes',
      'scannerRunIdsStored',
      'artifactReferencesStored',
      'correlationReferencesStored',
      'publicationAttempted',
      'secretValueStored',
      'rejectionDigest'
    ]) ||
    value.version !== SAST_SCAN_COVERAGE_VERSION ||
    value.outcome !== 'REJECTED' ||
    !isCanonicalReasonArray(
      value.reasonCodes,
      SAST_SCAN_COVERAGE_REJECTION_REASON_CODES
    ) ||
    (value.reasonCodes as unknown[]).length === 0 ||
    value.scannerRunIdsStored !== false ||
    value.artifactReferencesStored !== false ||
    value.correlationReferencesStored !== false ||
    value.publicationAttempted !== false ||
    value.secretValueStored !== false ||
    !isSha256Digest(value.rejectionDigest)
  ) {
    return false;
  }
  const rejection = value as unknown as SastScanCoverageRejection;
  const { rejectionDigest, ...core } = rejection;
  return (
    digestCanonical(canonicalizeSastScanCoverageRejection(core)) ===
    rejectionDigest
  );
}

export function toSastScanCoverageAuditMetadata(
  outcome: Readonly<SastScanCoverageOutcome>,
  digestCanonical: SastScanCoverageCanonicalDigester
): SastScanCoverageAuditMetadata {
  if (
    outcome.outcome === 'EVALUATED' &&
    isSastScanCoverageResultShapeValid(outcome, digestCanonical)
  ) {
    return {
      version: outcome.version,
      outcome: outcome.outcome,
      coverageDecisionId: outcome.decision.coverageDecisionId,
      publicationDecisionId:
        outcome.publication.publicationDecisionId,
      state: outcome.decision.state,
      decisionDigest: outcome.decision.decisionDigest,
      publicationDecisionDigest: outcome.publication.decisionDigest,
      replayed: outcome.replayed
    };
  }
  if (
    outcome.outcome === 'REJECTED' &&
    isSastScanCoverageRejectionShapeValid(outcome, digestCanonical)
  ) {
    return {
      version: outcome.version,
      outcome: outcome.outcome,
      reasonCodes: [...outcome.reasonCodes],
      rejectionDigest: outcome.rejectionDigest
    };
  }
  throw new TypeError('SAST scan-coverage outcome is invalid.');
}

function isCoverageRecordComplete(
  record: Readonly<SastScannerCoverageRecord>
): boolean {
  return (
    record.executionStatus === 'SUCCEEDED' &&
    record.artifactAccepted &&
    record.normalizationEligible &&
    record.findingObservationClosed &&
    record.reasonCodes.length === 0 &&
    sameStrings(
      record.achievedCapabilities,
      record.authoritativeCapabilities
    )
  );
}

function isCoverageAuthority(value: unknown): boolean {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      'coverageCalculationAuthority',
      'scannerExecutionAuthority',
      'artifactAcceptanceAuthority',
      'correlationAuthority',
      'lifecycleAuthority',
      'evidenceAuthority',
      'policyAuthority',
      'publicationAuthority',
      'aiPayloadEligible'
    ]) &&
    value.coverageCalculationAuthority === true &&
    value.scannerExecutionAuthority === false &&
    value.artifactAcceptanceAuthority === false &&
    value.correlationAuthority === false &&
    value.lifecycleAuthority === false &&
    value.evidenceAuthority === false &&
    value.policyAuthority === false &&
    value.publicationAuthority === false &&
    value.aiPayloadEligible === false
  );
}

function isCanonicalCapabilityArray(
  value: unknown
): value is SastCapability[] {
  return (
    Array.isArray(value) &&
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

function isCanonicalScannerArray(
  value: unknown
): value is SastScannerKind[] {
  return (
    Array.isArray(value) &&
    value.every(
      (scanner, index) =>
        SAST_SCANNER_KINDS.includes(scanner as SastScannerKind) &&
        (index === 0 ||
          SAST_SCANNER_KINDS.indexOf(
            value[index - 1] as SastScannerKind
          ) < SAST_SCANNER_KINDS.indexOf(scanner as SastScannerKind))
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

function orderScanners(
  scanners: readonly SastScannerKind[]
): SastScannerKind[] {
  return orderByCanonical(scanners, SAST_SCANNER_KINDS);
}

function orderCapabilities(
  capabilities: readonly SastCapability[]
): SastCapability[] {
  return orderByCanonical(capabilities, SAST_CAPABILITIES);
}

function orderByCanonical<T extends string>(
  values: readonly T[],
  canonical: readonly T[]
): T[] {
  return [...new Set(values)].sort(
    (left, right) =>
      canonical.indexOf(left) - canonical.indexOf(right)
  );
}

function isNullableReference(value: unknown): value is string | null {
  return value === null || isBoundedReference(value);
}

function isNullableDigest(
  value: unknown
): value is `sha256:${string}` | null {
  return value === null || isSha256Digest(value);
}

function isNullableCoverageId(
  value: unknown,
  prefix: string
): value is string | null {
  return value === null || isCoverageId(value, prefix);
}

function isCoverageId(value: unknown, prefix: string): value is string {
  return (
    typeof value === 'string' &&
    new RegExp(`^${prefix}:\\/\\/[a-f0-9]{64}$`, 'u').test(value)
  );
}

function isCanonicalIsoTimestamp(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const timestamp = Date.parse(value);
  return (
    Number.isFinite(timestamp) &&
    new Date(timestamp).toISOString() === value
  );
}

function sameStrings(
  left: readonly string[],
  right: readonly string[]
): boolean {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(stableJson).join(',')}]`;
  }
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort(compareStrings)
      .map(
        (key) =>
          `${JSON.stringify(key)}:${stableJson(record[key])}`
      )
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
