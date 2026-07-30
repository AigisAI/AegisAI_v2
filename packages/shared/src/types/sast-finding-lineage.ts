import {
  SAST_CAPABILITIES,
  SAST_FINDING_FINGERPRINT_VERSION,
  SAST_PROFILE_IDS,
  buildFindingFingerprintPreimage,
  type FindingFingerprintInput,
  type SastCapability,
  type SastProfileId
} from './sast-runtime';
import type {
  SastFindingFingerprintDecision,
  SastFingerprintedFinding
} from './sast-finding-identity';
import {
  hasExactKeys,
  isRecord,
  isSha256Digest
} from './sast-normalization-validation';

export const SAST_FINDING_LINEAGE_VERSION =
  'sast-finding-lineage-v1' as const;
export const SAST_FINDING_LIFECYCLE_CONTEXT_VERSION =
  'sast-finding-lifecycle-context-v1' as const;
export const SAST_FINDING_RENAME_ATTESTATION_VERSION =
  'sast-finding-rename-attestation-v1' as const;
export const SAST_FINDING_LIFECYCLE_COVERAGE_VERSION =
  'sast-finding-lifecycle-coverage-v1' as const;

export const SAST_FINDING_LINEAGE_LIMITS = Object.freeze({
  maximumFindings: 25_000,
  maximumRenameEntries: 25_000,
  maximumEligibleLineages: 25_000,
  maximumObservationBatches: 16,
  maximumReferenceUtf8Bytes: 2_048,
  maximumTargetRefUtf8Bytes: 2_048,
  maximumNormalizedPathUtf8Bytes: 4_096,
  yieldFindingInterval: 64
});

export const SAST_FINDING_LINEAGE_REJECTION_REASON_CODES = [
  'FINDING_LINEAGE_INPUT_INVALID',
  'FINDING_LINEAGE_RETENTION_INVALID',
  'FINDING_LINEAGE_RETENTION_EXPIRED',
  'FINDING_LINEAGE_DURABLE_SCOPE_INVALID',
  'FINDING_LINEAGE_RENAME_ATTESTATION_INVALID',
  'FINDING_LINEAGE_RENAME_AUTHORITY_UNAVAILABLE',
  'FINDING_LINEAGE_RENAME_AMBIGUOUS',
  'FINDING_LINEAGE_REPLAY_CONFLICT',
  'FINDING_LINEAGE_COVERAGE_AUTHORITY_UNAVAILABLE',
  'FINDING_LINEAGE_COVERAGE_DECISION_INVALID',
  'FINDING_LINEAGE_SCAN_NOT_COMPARABLE',
  'FINDING_LINEAGE_SCAN_STALE',
  'FINDING_LINEAGE_SCAN_INCOMPLETE',
  'FINDING_LINEAGE_RECONCILIATION_OUT_OF_ORDER',
  'FINDING_LINEAGE_OBSERVATION_INCOMPLETE',
  'FINDING_LINEAGE_PERSISTENCE_FAILED'
] as const;
export type SastFindingLineageRejectionReasonCode =
  (typeof SAST_FINDING_LINEAGE_REJECTION_REASON_CODES)[number];

export const SAST_FINDING_LIFECYCLE_STATUSES = [
  'OPEN',
  'FIXED'
] as const;
export type SastFindingLifecycleStatus =
  (typeof SAST_FINDING_LIFECYCLE_STATUSES)[number];

export const SAST_FINDING_LIFECYCLE_EVENT_KINDS = [
  'CREATED',
  'RENAMED',
  'FIXED',
  'REOPENED'
] as const;
export type SastFindingLifecycleEventKind =
  (typeof SAST_FINDING_LIFECYCLE_EVENT_KINDS)[number];

export type SastFindingLineageCanonicalDigester = (
  canonicalValue: string
) => `sha256:${string}`;

export interface SastFindingLifecycleContextInput {
  tenantId: string;
  repositoryBindingId: string;
  targetRef: string;
}

export interface SastFindingLineageKeyInput {
  tenantId: string;
  repositoryBindingId: string;
  capability: FindingFingerprintInput['capability'];
  fingerprintVersion: typeof SAST_FINDING_FINGERPRINT_VERSION;
  stableFingerprint: `sha256:${string}`;
}

export interface SastFindingRenameEntry {
  fromNormalizedPath: string;
  toNormalizedPath: string;
}

export interface SastFindingRenameCandidate {
  capability: Exclude<SastCapability, 'SBOM'>;
  currentStableFingerprint: `sha256:${string}`;
  previousStableFingerprint: `sha256:${string}`;
  fromNormalizedPath: string;
  toNormalizedPath: string;
}

export interface SastFindingRenameAttestation {
  version: typeof SAST_FINDING_RENAME_ATTESTATION_VERSION;
  tenantId: string;
  repositoryBindingId: string;
  lifecycleContextKey: `sha256:${string}`;
  fromScanRequestId: string;
  fromCommitSha: string;
  toScanRequestId: string;
  toCommitSha: string;
  profileId: SastProfileId;
  profileDigest: `sha256:${string}`;
  entries: SastFindingRenameEntry[];
  issuedAt: string;
  attestationRef: string;
  signatureRef: string;
  provenanceRef: string;
  attestationDigest: `sha256:${string}`;
}

export type SastFindingRenameAttestationCore = Omit<
  SastFindingRenameAttestation,
  'attestationDigest'
>;

export interface SastFindingLifecycleCoverageDecision {
  version: typeof SAST_FINDING_LIFECYCLE_COVERAGE_VERSION;
  tenantId: string;
  repositoryBindingId: string;
  scanRequestId: string;
  attemptId: string;
  canonicalScanKey: `sha256:${string}`;
  planDigest: `sha256:${string}`;
  commitSha: string;
  lifecycleContextKey: `sha256:${string}`;
  profileId: SastProfileId;
  profileDigest: `sha256:${string}`;
  state: 'COMPLETE';
  stale: false;
  comparable: true;
  sequence: number;
  previousScanRequestId: string;
  previousCommitSha: string;
  completeCapabilities: Exclude<SastCapability, 'SBOM'>[];
  eligibleLineageIds: string[];
  expectedObservationBatchDigests: `sha256:${string}`[];
  sourceCoverageDecisionDigest: `sha256:${string}`;
  sourceCoverageDecisionRef: string;
  completedAt: string;
  decidedAt: string;
  decisionDigest: `sha256:${string}`;
}

export type SastFindingLifecycleCoverageDecisionCore = Omit<
  SastFindingLifecycleCoverageDecision,
  'decisionDigest'
>;

export interface SastFindingLineageAuthority {
  normalizedFindingPersistenceAuthority: true;
  occurrenceAuthority: true;
  lifecycleAuthority: true;
  renameAuthority: true;
  correlationAuthority: false;
  coverageCalculationAuthority: false;
  evidenceAuthority: false;
  policyAuthority: false;
  publicationAuthority: false;
  aiPayloadEligible: false;
}

export interface SastFindingLineageObservationResult {
  version: typeof SAST_FINDING_LINEAGE_VERSION;
  outcome: 'OBSERVED';
  operation: 'OBSERVE';
  observationBatchId: string;
  sourceIdentityBatchDigest: `sha256:${string}`;
  lifecycleContextKey: `sha256:${string}`;
  findingCount: number;
  occurrenceCount: number;
  distinctFingerprintCount: number;
  createdLineageCount: number;
  exactMatchCount: number;
  renamedMatchCount: number;
  replayed: boolean;
  observedAt: string;
  authority: SastFindingLineageAuthority;
  resultDigest: `sha256:${string}`;
}

export type SastFindingLineageObservationResultCore = Omit<
  SastFindingLineageObservationResult,
  'resultDigest'
>;

export interface SastFindingLifecycleReconciliationResult {
  version: typeof SAST_FINDING_LINEAGE_VERSION;
  outcome: 'RECONCILED';
  operation: 'RECONCILE';
  reconciliationId: string;
  coverageDecisionDigest: `sha256:${string}`;
  lifecycleContextKey: `sha256:${string}`;
  sequence: number;
  eligibleLineageCount: number;
  observedLineageCount: number;
  fixedCount: number;
  reopenedCount: number;
  unchangedOpenCount: number;
  unchangedFixedCount: number;
  replayed: boolean;
  reconciledAt: string;
  authority: SastFindingLineageAuthority;
  resultDigest: `sha256:${string}`;
}

export type SastFindingLifecycleReconciliationResultCore = Omit<
  SastFindingLifecycleReconciliationResult,
  'resultDigest'
>;

export type SastFindingLineageOperation =
  | 'OBSERVE'
  | 'RECONCILE';

export interface SastFindingLineageRejection {
  version: typeof SAST_FINDING_LINEAGE_VERSION;
  outcome: 'REJECTED';
  operation: SastFindingLineageOperation;
  reasonCodes: SastFindingLineageRejectionReasonCode[];
  sourceBatchDigestStored: false;
  sourceFindingStored: false;
  renamePathsStored: false;
  eligibleLineageIdsStored: false;
  secretValueStored: false;
  rejectionDigest: `sha256:${string}`;
}

export type SastFindingLineageRejectionCore = Omit<
  SastFindingLineageRejection,
  'rejectionDigest'
>;

export type SastFindingLineageObservationOutcome =
  | SastFindingLineageObservationResult
  | SastFindingLineageRejection;

export type SastFindingLifecycleReconciliationOutcome =
  | SastFindingLifecycleReconciliationResult
  | SastFindingLineageRejection;

export type SastFindingLineageAuditMetadata =
  | {
      version: typeof SAST_FINDING_LINEAGE_VERSION;
      outcome: 'OBSERVED';
      operation: 'OBSERVE';
      resultDigest: `sha256:${string}`;
      observationBatchId: string;
      findingCount: number;
      occurrenceCount: number;
      distinctFingerprintCount: number;
      createdLineageCount: number;
      exactMatchCount: number;
      renamedMatchCount: number;
      replayed: boolean;
    }
  | {
      version: typeof SAST_FINDING_LINEAGE_VERSION;
      outcome: 'RECONCILED';
      operation: 'RECONCILE';
      resultDigest: `sha256:${string}`;
      reconciliationId: string;
      sequence: number;
      eligibleLineageCount: number;
      observedLineageCount: number;
      fixedCount: number;
      reopenedCount: number;
      replayed: boolean;
    }
  | {
      version: typeof SAST_FINDING_LINEAGE_VERSION;
      outcome: 'REJECTED';
      operation: SastFindingLineageOperation;
      reasonCodes: SastFindingLineageRejectionReasonCode[];
      rejectionDigest: `sha256:${string}`;
    };

const FINDING_CAPABILITIES = SAST_CAPABILITIES.filter(
  (capability): capability is Exclude<SastCapability, 'SBOM'> =>
    capability !== 'SBOM'
);

const AUTHORITY: Readonly<SastFindingLineageAuthority> =
  Object.freeze({
    normalizedFindingPersistenceAuthority: true,
    occurrenceAuthority: true,
    lifecycleAuthority: true,
    renameAuthority: true,
    correlationAuthority: false,
    coverageCalculationAuthority: false,
    evidenceAuthority: false,
    policyAuthority: false,
    publicationAuthority: false,
    aiPayloadEligible: false
  });

export function buildSastFindingLifecycleContextPreimage(
  input: Readonly<SastFindingLifecycleContextInput>
): string {
  return `${SAST_FINDING_LIFECYCLE_CONTEXT_VERSION}\0${[
    input.tenantId,
    input.repositoryBindingId,
    input.targetRef
  ]
    .map(encodeCanonicalField)
    .join('')}`;
}

export function isSastFindingLifecycleContextInputValid(
  value: unknown
): value is SastFindingLifecycleContextInput {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      'tenantId',
      'repositoryBindingId',
      'targetRef'
    ]) &&
    isBoundedReference(value.tenantId) &&
    isBoundedReference(value.repositoryBindingId) &&
    isBoundedTargetRef(value.targetRef)
  );
}

export function buildSastFindingLineageKeyPreimage(
  input: Readonly<SastFindingLineageKeyInput>
): string {
  return `${SAST_FINDING_LINEAGE_VERSION}\0${[
    input.tenantId,
    input.repositoryBindingId,
    input.capability,
    input.fingerprintVersion,
    input.stableFingerprint
  ]
    .map(encodeCanonicalField)
    .join('')}`;
}

export function projectRenamedSastFindingFingerprintInput(
  decision: Readonly<SastFindingFingerprintDecision>,
  normalizedPath: string
): FindingFingerprintInput {
  return {
    repositoryBindingId:
      decision.repositoryBindingId.normalize('NFC'),
    capability: decision.capability,
    ruleSemanticId: decision.ruleSemanticId.normalize('NFC'),
    normalizedPath: normalizedPath.normalize('NFC'),
    symbolAnchor: decision.symbolAnchor.normalize('NFC'),
    sinkKind: decision.sinkKind.normalize('NFC'),
    structuralHash: decision.structuralHash.normalize('NFC')
  };
}

export function buildSastFindingRenameCandidate(
  finding: Readonly<SastFingerprintedFinding>,
  entry: Readonly<SastFindingRenameEntry>,
  digestFingerprint: SastFindingLineageCanonicalDigester
): SastFindingRenameCandidate | null {
  if (
    finding.fingerprint.normalizedPath !==
    entry.toNormalizedPath
  ) {
    return null;
  }
  return {
    capability: finding.capability,
    currentStableFingerprint:
      finding.fingerprint.stableFingerprint,
    previousStableFingerprint: digestFingerprint(
      buildFindingFingerprintPreimage(
        projectRenamedSastFindingFingerprintInput(
          finding.fingerprint,
          entry.fromNormalizedPath
        )
      )
    ),
    fromNormalizedPath: entry.fromNormalizedPath,
    toNormalizedPath: entry.toNormalizedPath
  };
}

export function orderSastFindingRenameCandidates(
  candidates: Iterable<Readonly<SastFindingRenameCandidate>>
): SastFindingRenameCandidate[] {
  const unique = new Map<string, SastFindingRenameCandidate>();
  for (const candidate of candidates) {
    unique.set(renameCandidateKey(candidate), {
      ...candidate
    });
  }
  return [...unique.values()].sort((left, right) => {
    const leftKey = renameCandidateKey(left);
    const rightKey = renameCandidateKey(right);
    return leftKey < rightKey
      ? -1
      : leftKey > rightKey
        ? 1
        : 0;
  });
}

export function canonicalizeSastFindingRenameAttestation(
  attestation: Readonly<SastFindingRenameAttestationCore>
): string {
  return JSON.stringify({
    version: attestation.version,
    tenantId: attestation.tenantId,
    repositoryBindingId: attestation.repositoryBindingId,
    lifecycleContextKey: attestation.lifecycleContextKey,
    fromScanRequestId: attestation.fromScanRequestId,
    fromCommitSha: attestation.fromCommitSha,
    toScanRequestId: attestation.toScanRequestId,
    toCommitSha: attestation.toCommitSha,
    profileId: attestation.profileId,
    profileDigest: attestation.profileDigest,
    entries: attestation.entries.map((entry) => ({
      fromNormalizedPath: entry.fromNormalizedPath,
      toNormalizedPath: entry.toNormalizedPath
    })),
    issuedAt: attestation.issuedAt,
    attestationRef: attestation.attestationRef,
    signatureRef: attestation.signatureRef,
    provenanceRef: attestation.provenanceRef
  });
}

export function canonicalizeSastFindingLifecycleCoverageDecision(
  decision: Readonly<SastFindingLifecycleCoverageDecisionCore>
): string {
  return JSON.stringify({
    version: decision.version,
    tenantId: decision.tenantId,
    repositoryBindingId: decision.repositoryBindingId,
    scanRequestId: decision.scanRequestId,
    attemptId: decision.attemptId,
    canonicalScanKey: decision.canonicalScanKey,
    planDigest: decision.planDigest,
    commitSha: decision.commitSha,
    lifecycleContextKey: decision.lifecycleContextKey,
    profileId: decision.profileId,
    profileDigest: decision.profileDigest,
    state: 'COMPLETE',
    stale: false,
    comparable: true,
    sequence: decision.sequence,
    previousScanRequestId: decision.previousScanRequestId,
    previousCommitSha: decision.previousCommitSha,
    completeCapabilities: [...decision.completeCapabilities],
    eligibleLineageIds: [...decision.eligibleLineageIds],
    expectedObservationBatchDigests: [
      ...decision.expectedObservationBatchDigests
    ],
    sourceCoverageDecisionDigest:
      decision.sourceCoverageDecisionDigest,
    sourceCoverageDecisionRef:
      decision.sourceCoverageDecisionRef,
    completedAt: decision.completedAt,
    decidedAt: decision.decidedAt
  });
}

export function canonicalizeSastFindingLineageObservationResult(
  result: Readonly<SastFindingLineageObservationResultCore>
): string {
  return JSON.stringify({
    version: result.version,
    outcome: 'OBSERVED',
    operation: 'OBSERVE',
    observationBatchId: result.observationBatchId,
    sourceIdentityBatchDigest:
      result.sourceIdentityBatchDigest,
    lifecycleContextKey: result.lifecycleContextKey,
    findingCount: result.findingCount,
    occurrenceCount: result.occurrenceCount,
    distinctFingerprintCount:
      result.distinctFingerprintCount,
    createdLineageCount: result.createdLineageCount,
    exactMatchCount: result.exactMatchCount,
    renamedMatchCount: result.renamedMatchCount,
    replayed: result.replayed,
    observedAt: result.observedAt,
    authority: canonicalAuthority()
  });
}

export function canonicalizeSastFindingLifecycleReconciliationResult(
  result: Readonly<SastFindingLifecycleReconciliationResultCore>
): string {
  return JSON.stringify({
    version: result.version,
    outcome: 'RECONCILED',
    operation: 'RECONCILE',
    reconciliationId: result.reconciliationId,
    coverageDecisionDigest: result.coverageDecisionDigest,
    lifecycleContextKey: result.lifecycleContextKey,
    sequence: result.sequence,
    eligibleLineageCount: result.eligibleLineageCount,
    observedLineageCount: result.observedLineageCount,
    fixedCount: result.fixedCount,
    reopenedCount: result.reopenedCount,
    unchangedOpenCount: result.unchangedOpenCount,
    unchangedFixedCount: result.unchangedFixedCount,
    replayed: result.replayed,
    reconciledAt: result.reconciledAt,
    authority: canonicalAuthority()
  });
}

export function canonicalizeSastFindingLineageRejection(
  rejection: Readonly<SastFindingLineageRejectionCore>
): string {
  return JSON.stringify({
    version: rejection.version,
    outcome: 'REJECTED',
    operation: rejection.operation,
    reasonCodes: [...rejection.reasonCodes],
    sourceBatchDigestStored: false,
    sourceFindingStored: false,
    renamePathsStored: false,
    eligibleLineageIdsStored: false,
    secretValueStored: false
  });
}

export function orderSastFindingLineageRejectionReasons(
  reasons: Iterable<SastFindingLineageRejectionReasonCode>
): SastFindingLineageRejectionReasonCode[] {
  const found = new Set(reasons);
  return SAST_FINDING_LINEAGE_REJECTION_REASON_CODES.filter(
    (reason) => found.has(reason)
  );
}

export function isSastFindingRenameAttestationShapeValid(
  value: unknown,
  digestCanonical: SastFindingLineageCanonicalDigester
): value is SastFindingRenameAttestation {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'version',
      'tenantId',
      'repositoryBindingId',
      'lifecycleContextKey',
      'fromScanRequestId',
      'fromCommitSha',
      'toScanRequestId',
      'toCommitSha',
      'profileId',
      'profileDigest',
      'entries',
      'issuedAt',
      'attestationRef',
      'signatureRef',
      'provenanceRef',
      'attestationDigest'
    ]) ||
    value.version !==
      SAST_FINDING_RENAME_ATTESTATION_VERSION ||
    !isBoundedReference(value.tenantId) ||
    !isBoundedReference(value.repositoryBindingId) ||
    !isSha256Digest(value.lifecycleContextKey) ||
    !isBoundedReference(value.fromScanRequestId) ||
    !isBoundedReference(value.toScanRequestId) ||
    value.fromScanRequestId === value.toScanRequestId ||
    !isCommitSha(value.fromCommitSha) ||
    !isCommitSha(value.toCommitSha) ||
    value.fromCommitSha === value.toCommitSha ||
    !SAST_PROFILE_IDS.includes(value.profileId as SastProfileId) ||
    !isSha256Digest(value.profileDigest) ||
    !Array.isArray(value.entries) ||
    value.entries.length === 0 ||
    value.entries.length >
      SAST_FINDING_LINEAGE_LIMITS.maximumRenameEntries ||
    !isIsoTimestamp(value.issuedAt) ||
    !isBoundedReference(value.attestationRef) ||
    !isBoundedReference(value.signatureRef) ||
    !isBoundedReference(value.provenanceRef) ||
    !isSha256Digest(value.attestationDigest)
  ) {
    return false;
  }

  const entries = value.entries as unknown[];
  const fromPaths = new Set<string>();
  const toPaths = new Set<string>();
  let previousKey: string | undefined;
  for (const candidate of entries) {
    if (
      !isRecord(candidate) ||
      !hasExactKeys(candidate, [
        'fromNormalizedPath',
        'toNormalizedPath'
      ]) ||
      !isSafeNormalizedPath(candidate.fromNormalizedPath) ||
      !isSafeNormalizedPath(candidate.toNormalizedPath) ||
      candidate.fromNormalizedPath === candidate.toNormalizedPath
    ) {
      return false;
    }
    const from = candidate.fromNormalizedPath;
    const to = candidate.toNormalizedPath;
    const key = JSON.stringify([from, to]);
    if (
      fromPaths.has(from) ||
      toPaths.has(to) ||
      (previousKey !== undefined && previousKey >= key)
    ) {
      return false;
    }
    fromPaths.add(from);
    toPaths.add(to);
    previousKey = key;
  }
  if ([...fromPaths].some((path) => toPaths.has(path))) {
    return false;
  }

  const attestation =
    value as unknown as SastFindingRenameAttestation;
  const {
    attestationDigest,
    ...core
  } = attestation;
  return canonicalDigestMatches(
    digestCanonical,
    canonicalizeSastFindingRenameAttestation(core),
    attestationDigest
  );
}

export function isSastFindingLifecycleCoverageDecisionShapeValid(
  value: unknown,
  digestCanonical: SastFindingLineageCanonicalDigester
): value is SastFindingLifecycleCoverageDecision {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'version',
      'tenantId',
      'repositoryBindingId',
      'scanRequestId',
      'attemptId',
      'canonicalScanKey',
      'planDigest',
      'commitSha',
      'lifecycleContextKey',
      'profileId',
      'profileDigest',
      'state',
      'stale',
      'comparable',
      'sequence',
      'previousScanRequestId',
      'previousCommitSha',
      'completeCapabilities',
      'eligibleLineageIds',
      'expectedObservationBatchDigests',
      'sourceCoverageDecisionDigest',
      'sourceCoverageDecisionRef',
      'completedAt',
      'decidedAt',
      'decisionDigest'
    ]) ||
    value.version !==
      SAST_FINDING_LIFECYCLE_COVERAGE_VERSION ||
    !isBoundedReference(value.tenantId) ||
    !isBoundedReference(value.repositoryBindingId) ||
    !isBoundedReference(value.scanRequestId) ||
    !isBoundedReference(value.attemptId) ||
    !isSha256Digest(value.canonicalScanKey) ||
    !isSha256Digest(value.planDigest) ||
    !isCommitSha(value.commitSha) ||
    !isSha256Digest(value.lifecycleContextKey) ||
    !SAST_PROFILE_IDS.includes(value.profileId as SastProfileId) ||
    !isSha256Digest(value.profileDigest) ||
    value.state !== 'COMPLETE' ||
    value.stale !== false ||
    value.comparable !== true ||
    !Number.isSafeInteger(value.sequence) ||
    (value.sequence as number) <= 0 ||
    !isBoundedReference(value.previousScanRequestId) ||
    value.previousScanRequestId === value.scanRequestId ||
    !isCommitSha(value.previousCommitSha) ||
    !Array.isArray(value.completeCapabilities) ||
    value.completeCapabilities.length === 0 ||
    !isCanonicalCapabilityList(value.completeCapabilities) ||
    !Array.isArray(value.eligibleLineageIds) ||
    value.eligibleLineageIds.length >
      SAST_FINDING_LINEAGE_LIMITS.maximumEligibleLineages ||
    !isSortedUniqueStringArray(
      value.eligibleLineageIds,
      isFindingLineageId
    ) ||
    !Array.isArray(value.expectedObservationBatchDigests) ||
    value.expectedObservationBatchDigests.length === 0 ||
    value.expectedObservationBatchDigests.length >
      SAST_FINDING_LINEAGE_LIMITS.maximumObservationBatches ||
    !isSortedUniqueStringArray(
      value.expectedObservationBatchDigests,
      isSha256Digest
    ) ||
    !isSha256Digest(value.sourceCoverageDecisionDigest) ||
    !isBoundedReference(value.sourceCoverageDecisionRef) ||
    !isIsoTimestamp(value.completedAt) ||
    !isIsoTimestamp(value.decidedAt) ||
    Date.parse(value.decidedAt as string) <
      Date.parse(value.completedAt as string) ||
    !isSha256Digest(value.decisionDigest)
  ) {
    return false;
  }

  const decision =
    value as unknown as SastFindingLifecycleCoverageDecision;
  const {
    decisionDigest,
    ...core
  } = decision;
  return canonicalDigestMatches(
    digestCanonical,
    canonicalizeSastFindingLifecycleCoverageDecision(core),
    decisionDigest
  );
}

export function isSastFindingLineageObservationResultShapeValid(
  value: unknown,
  digestCanonical: SastFindingLineageCanonicalDigester
): value is SastFindingLineageObservationResult {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'version',
      'outcome',
      'operation',
      'observationBatchId',
      'sourceIdentityBatchDigest',
      'lifecycleContextKey',
      'findingCount',
      'occurrenceCount',
      'distinctFingerprintCount',
      'createdLineageCount',
      'exactMatchCount',
      'renamedMatchCount',
      'replayed',
      'observedAt',
      'authority',
      'resultDigest'
    ]) ||
    value.version !== SAST_FINDING_LINEAGE_VERSION ||
    value.outcome !== 'OBSERVED' ||
    value.operation !== 'OBSERVE' ||
    !isObservationBatchId(value.observationBatchId) ||
    !isSha256Digest(value.sourceIdentityBatchDigest) ||
    !isSha256Digest(value.lifecycleContextKey) ||
    !isNonNegativeSafeInteger(value.findingCount) ||
    value.findingCount >
      SAST_FINDING_LINEAGE_LIMITS.maximumFindings ||
    value.occurrenceCount !== value.findingCount ||
    !isNonNegativeSafeInteger(value.distinctFingerprintCount) ||
    value.distinctFingerprintCount > value.findingCount ||
    (value.findingCount > 0 &&
      value.distinctFingerprintCount === 0) ||
    !isNonNegativeSafeInteger(value.createdLineageCount) ||
    !isNonNegativeSafeInteger(value.exactMatchCount) ||
    !isNonNegativeSafeInteger(value.renamedMatchCount) ||
    value.createdLineageCount +
      value.exactMatchCount +
      value.renamedMatchCount !==
      value.distinctFingerprintCount ||
    typeof value.replayed !== 'boolean' ||
    !isIsoTimestamp(value.observedAt) ||
    !isAuthorityValid(value.authority) ||
    !isSha256Digest(value.resultDigest)
  ) {
    return false;
  }

  const result =
    value as unknown as SastFindingLineageObservationResult;
  const {
    resultDigest,
    ...core
  } = result;
  return canonicalDigestMatches(
    digestCanonical,
    canonicalizeSastFindingLineageObservationResult(core),
    resultDigest
  );
}

export function isSastFindingLifecycleReconciliationResultShapeValid(
  value: unknown,
  digestCanonical: SastFindingLineageCanonicalDigester
): value is SastFindingLifecycleReconciliationResult {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'version',
      'outcome',
      'operation',
      'reconciliationId',
      'coverageDecisionDigest',
      'lifecycleContextKey',
      'sequence',
      'eligibleLineageCount',
      'observedLineageCount',
      'fixedCount',
      'reopenedCount',
      'unchangedOpenCount',
      'unchangedFixedCount',
      'replayed',
      'reconciledAt',
      'authority',
      'resultDigest'
    ]) ||
    value.version !== SAST_FINDING_LINEAGE_VERSION ||
    value.outcome !== 'RECONCILED' ||
    value.operation !== 'RECONCILE' ||
    !isReconciliationId(value.reconciliationId) ||
    !isSha256Digest(value.coverageDecisionDigest) ||
    !isSha256Digest(value.lifecycleContextKey) ||
    !Number.isSafeInteger(value.sequence) ||
    (value.sequence as number) <= 0 ||
    ![
      value.eligibleLineageCount,
      value.observedLineageCount,
      value.fixedCount,
      value.reopenedCount,
      value.unchangedOpenCount,
      value.unchangedFixedCount
    ].every(isNonNegativeSafeInteger) ||
    (value.eligibleLineageCount as number) >
      SAST_FINDING_LINEAGE_LIMITS.maximumEligibleLineages ||
    (value.observedLineageCount as number) >
      (value.eligibleLineageCount as number) ||
    (value.fixedCount as number) +
      (value.reopenedCount as number) +
      (value.unchangedOpenCount as number) +
      (value.unchangedFixedCount as number) !==
      (value.eligibleLineageCount as number) ||
    (value.reopenedCount as number) +
      (value.unchangedOpenCount as number) !==
      (value.observedLineageCount as number) ||
    (value.fixedCount as number) +
      (value.unchangedFixedCount as number) !==
      (value.eligibleLineageCount as number) -
        (value.observedLineageCount as number) ||
    typeof value.replayed !== 'boolean' ||
    !isIsoTimestamp(value.reconciledAt) ||
    !isAuthorityValid(value.authority) ||
    !isSha256Digest(value.resultDigest)
  ) {
    return false;
  }

  const result =
    value as unknown as SastFindingLifecycleReconciliationResult;
  const {
    resultDigest,
    ...core
  } = result;
  return canonicalDigestMatches(
    digestCanonical,
    canonicalizeSastFindingLifecycleReconciliationResult(core),
    resultDigest
  );
}

export function isSastFindingLineageRejectionShapeValid(
  value: unknown,
  digestCanonical: SastFindingLineageCanonicalDigester
): value is SastFindingLineageRejection {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'version',
      'outcome',
      'operation',
      'reasonCodes',
      'sourceBatchDigestStored',
      'sourceFindingStored',
      'renamePathsStored',
      'eligibleLineageIdsStored',
      'secretValueStored',
      'rejectionDigest'
    ]) ||
    value.version !== SAST_FINDING_LINEAGE_VERSION ||
    value.outcome !== 'REJECTED' ||
    !isLineageOperation(value.operation) ||
    !Array.isArray(value.reasonCodes) ||
    value.reasonCodes.length === 0 ||
    value.reasonCodes.length >
      SAST_FINDING_LINEAGE_REJECTION_REASON_CODES.length ||
    value.sourceBatchDigestStored !== false ||
    value.sourceFindingStored !== false ||
    value.renamePathsStored !== false ||
    value.eligibleLineageIdsStored !== false ||
    value.secretValueStored !== false ||
    !isSha256Digest(value.rejectionDigest)
  ) {
    return false;
  }
  const reasonCodes =
    value.reasonCodes as SastFindingLineageRejectionReasonCode[];
  const orderedReasonCodes =
    orderSastFindingLineageRejectionReasons(reasonCodes);
  if (
    reasonCodes.length !== orderedReasonCodes.length ||
    reasonCodes.some(
      (reason, index) =>
        reason !== orderedReasonCodes[index]
    )
  ) {
    return false;
  }

  const rejection =
    value as unknown as SastFindingLineageRejection;
  const {
    rejectionDigest,
    ...core
  } = rejection;
  return canonicalDigestMatches(
    digestCanonical,
    canonicalizeSastFindingLineageRejection(core),
    rejectionDigest
  );
}

export function toSastFindingLineageAuditMetadata(
  result:
    | Readonly<SastFindingLineageObservationOutcome>
    | Readonly<SastFindingLifecycleReconciliationOutcome>,
  digestCanonical: SastFindingLineageCanonicalDigester
): SastFindingLineageAuditMetadata {
  if (
    result.outcome === 'REJECTED' &&
    isSastFindingLineageRejectionShapeValid(
      result,
      digestCanonical
    )
  ) {
    return {
      version: result.version,
      outcome: result.outcome,
      operation: result.operation,
      reasonCodes: [...result.reasonCodes],
      rejectionDigest: result.rejectionDigest
    };
  }
  if (
    result.outcome === 'OBSERVED' &&
    isSastFindingLineageObservationResultShapeValid(
      result,
      digestCanonical
    )
  ) {
    return {
      version: result.version,
      outcome: result.outcome,
      operation: result.operation,
      resultDigest: result.resultDigest,
      observationBatchId: result.observationBatchId,
      findingCount: result.findingCount,
      occurrenceCount: result.occurrenceCount,
      distinctFingerprintCount:
        result.distinctFingerprintCount,
      createdLineageCount: result.createdLineageCount,
      exactMatchCount: result.exactMatchCount,
      renamedMatchCount: result.renamedMatchCount,
      replayed: result.replayed
    };
  }
  if (
    result.outcome === 'RECONCILED' &&
    isSastFindingLifecycleReconciliationResultShapeValid(
      result,
      digestCanonical
    )
  ) {
    return {
      version: result.version,
      outcome: result.outcome,
      operation: result.operation,
      resultDigest: result.resultDigest,
      reconciliationId: result.reconciliationId,
      sequence: result.sequence,
      eligibleLineageCount: result.eligibleLineageCount,
      observedLineageCount: result.observedLineageCount,
      fixedCount: result.fixedCount,
      reopenedCount: result.reopenedCount,
      replayed: result.replayed
    };
  }
  throw new TypeError('SAST finding-lineage result is invalid.');
}

export function sastFindingLineageAuthority(): SastFindingLineageAuthority {
  return { ...AUTHORITY };
}

function canonicalAuthority(): SastFindingLineageAuthority {
  return {
    normalizedFindingPersistenceAuthority: true,
    occurrenceAuthority: true,
    lifecycleAuthority: true,
    renameAuthority: true,
    correlationAuthority: false,
    coverageCalculationAuthority: false,
    evidenceAuthority: false,
    policyAuthority: false,
    publicationAuthority: false,
    aiPayloadEligible: false
  };
}

function isAuthorityValid(value: unknown): boolean {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      'normalizedFindingPersistenceAuthority',
      'occurrenceAuthority',
      'lifecycleAuthority',
      'renameAuthority',
      'correlationAuthority',
      'coverageCalculationAuthority',
      'evidenceAuthority',
      'policyAuthority',
      'publicationAuthority',
      'aiPayloadEligible'
    ]) &&
    value.normalizedFindingPersistenceAuthority === true &&
    value.occurrenceAuthority === true &&
    value.lifecycleAuthority === true &&
    value.renameAuthority === true &&
    value.correlationAuthority === false &&
    value.coverageCalculationAuthority === false &&
    value.evidenceAuthority === false &&
    value.policyAuthority === false &&
    value.publicationAuthority === false &&
    value.aiPayloadEligible === false
  );
}

function isCanonicalCapabilityList(value: unknown[]): boolean {
  const candidate = value as string[];
  return (
    candidate.every((capability) =>
      FINDING_CAPABILITIES.includes(
        capability as Exclude<SastCapability, 'SBOM'>
      )
    ) &&
    candidate.every(
      (capability, index) =>
        index === 0 ||
        FINDING_CAPABILITIES.indexOf(
          candidate[index - 1] as Exclude<
            SastCapability,
            'SBOM'
          >
        ) <
          FINDING_CAPABILITIES.indexOf(
            capability as Exclude<SastCapability, 'SBOM'>
          )
    )
  );
}

function isSortedUniqueStringArray(
  value: unknown[],
  predicate: (candidate: unknown) => boolean
): boolean {
  return value.every(
    (candidate, index) =>
      predicate(candidate) &&
      (index === 0 ||
        (value[index - 1] as string) < (candidate as string))
  );
}

function isSafeNormalizedPath(value: unknown): value is string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value !== value.normalize('NFC') ||
    utf8ByteLength(value) >
      SAST_FINDING_LINEAGE_LIMITS.maximumNormalizedPathUtf8Bytes ||
    hasControlCharacters(value) ||
    value.includes('\\') ||
    value.startsWith('/') ||
    /^[A-Za-z]:/u.test(value)
  ) {
    return false;
  }
  const segments = value.split('/');
  return segments.every(
    (segment) =>
      segment.length > 0 &&
      segment !== '.' &&
      segment !== '..'
  );
}

function isBoundedReference(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value === value.normalize('NFC') &&
    !hasControlCharacters(value) &&
    utf8ByteLength(value) <=
      SAST_FINDING_LINEAGE_LIMITS.maximumReferenceUtf8Bytes
  );
}

function isBoundedTargetRef(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value === value.normalize('NFC') &&
    !hasControlCharacters(value) &&
    utf8ByteLength(value) <=
      SAST_FINDING_LINEAGE_LIMITS.maximumTargetRefUtf8Bytes
  );
}

function isCommitSha(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/u.test(value)
  );
}

function isIsoTimestamp(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const parsed = Date.parse(value);
  return (
    Number.isFinite(parsed) &&
    new Date(parsed).toISOString() === value
  );
}

function isFindingLineageId(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^finding-lineage:\/\/[a-f0-9]{64}$/u.test(value)
  );
}

function renameCandidateKey(
  candidate: Readonly<SastFindingRenameCandidate>
): string {
  return `${candidate.capability}\0${candidate.currentStableFingerprint}`;
}

function isObservationBatchId(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^finding-observation:\/\/[a-f0-9]{64}$/u.test(value)
  );
}

function isReconciliationId(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^finding-reconciliation:\/\/[a-f0-9]{64}$/u.test(value)
  );
}

function isLineageOperation(
  value: unknown
): value is SastFindingLineageOperation {
  return value === 'OBSERVE' || value === 'RECONCILE';
}

function isNonNegativeSafeInteger(
  value: unknown
): value is number {
  return (
    Number.isSafeInteger(value) &&
    (value as number) >= 0
  );
}

function canonicalDigestMatches(
  digester: SastFindingLineageCanonicalDigester,
  canonicalValue: string,
  expected: string
): boolean {
  try {
    return digester(canonicalValue) === expected;
  } catch {
    return false;
  }
}

function encodeCanonicalField(value: string): string {
  const normalized = value.normalize('NFC');
  return `${utf8ByteLength(normalized)}:${normalized}`;
}

function utf8ByteLength(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function hasControlCharacters(value: string): boolean {
  return [...value].some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return (
      codePoint <= 0x1f ||
      (codePoint >= 0x7f && codePoint <= 0x9f) ||
      (codePoint >= 0xd800 && codePoint <= 0xdfff)
    );
  });
}
