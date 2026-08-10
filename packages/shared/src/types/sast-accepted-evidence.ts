import {
  DEFAULT_SAST_EVIDENCE_POLICY,
  SAST_CAPABILITIES,
  SAST_FINDING_FINGERPRINT_VERSION,
  SAST_PROFILE_IDS,
  isSastEvidencePolicySafe,
  type SastCapability,
  type SastEvidencePolicy,
  type SastProfileId
} from './sast-runtime';
import {
  hasExactKeys,
  isBoundedReference,
  isCommitSha,
  isRecord,
  isSha256Digest,
  utf8Length
} from './sast-normalization-validation';

export const SAST_ACCEPTED_EVIDENCE_VERSION =
  'sast-accepted-finding-evidence-v1' as const;
export const SAST_EVIDENCE_BUILD_DECISION_VERSION =
  'sast-evidence-build-decision-v1' as const;
export const SAST_EVIDENCE_RECONSTRUCTION_VERSION =
  'sast-evidence-reconstruction-v1' as const;

export const SAST_ACCEPTED_EVIDENCE_POLICY =
  DEFAULT_SAST_EVIDENCE_POLICY;

export const SAST_ACCEPTED_EVIDENCE_LIMITS = Object.freeze({
  maximumSourceCandidates: 64,
  maximumFragmentsPerFile: 2,
  maximumReconstructedFileCoverageBasisPoints: 2500,
  yieldCandidateInterval: 16
});

export const SAST_EVIDENCE_FRAGMENT_ROLES = [
  'PRIMARY',
  'RELATED'
] as const;
export type SastEvidenceFragmentRole =
  (typeof SAST_EVIDENCE_FRAGMENT_ROLES)[number];

export const SAST_EVIDENCE_BUILD_OUTCOMES = [
  'ACCEPTED',
  'REJECTED'
] as const;
export type SastEvidenceBuildOutcome =
  (typeof SAST_EVIDENCE_BUILD_OUTCOMES)[number];

export const SAST_EVIDENCE_RECONSTRUCTION_STATUSES = [
  'SAFE',
  'RISK',
  'NOT_CHECKED'
] as const;
export type SastEvidenceReconstructionStatus =
  (typeof SAST_EVIDENCE_RECONSTRUCTION_STATUSES)[number];

export const SAST_EVIDENCE_REASON_CODES = [
  'EVIDENCE_INPUT_INVALID',
  'EVIDENCE_CONTEXT_UNAVAILABLE',
  'EVIDENCE_FINDING_NOT_ACCEPTED',
  'EVIDENCE_SOURCE_UNAVAILABLE',
  'EVIDENCE_SOURCE_INVALID',
  'EVIDENCE_REDACTION_INVALID',
  'EVIDENCE_PRIMARY_FRAGMENT_INVALID',
  'EVIDENCE_CONTEXT_EXCEEDED',
  'EVIDENCE_FULL_FILE_FORBIDDEN',
  'EVIDENCE_RECONSTRUCTION_FRAGMENT_COUNT',
  'EVIDENCE_RECONSTRUCTION_OVERLAP',
  'EVIDENCE_RECONSTRUCTION_ADJACENT',
  'EVIDENCE_RECONSTRUCTION_COVERAGE',
  'EVIDENCE_OUTPUT_INVALID',
  'EVIDENCE_PERSISTENCE_CONFLICT'
] as const;
export type SastEvidenceReasonCode =
  (typeof SAST_EVIDENCE_REASON_CODES)[number];

export type SastEvidenceDigest = string;
export type SastEvidenceCanonicalDigester = (
  canonicalValue: string
) => SastEvidenceDigest;

export interface SastAcceptedEvidenceScope {
  tenantId: string;
  repositoryBindingId: string;
  scanRequestId: string;
  attemptId: string;
  targetRef: string;
  commitSha: string;
  canonicalScanKey: SastEvidenceDigest;
  planDigest: SastEvidenceDigest;
  profileId: SastProfileId;
  profileDigest: SastEvidenceDigest;
  freshnessDecisionId: string;
  freshnessDecisionDigest: SastEvidenceDigest;
  coverageDecisionId: string;
  coverageDecisionDigest: SastEvidenceDigest;
  occurrenceId: string;
  observationBatchId: string;
  normalizedFindingId: string;
  lineageId: string;
  findingFingerprint: SastEvidenceDigest;
  fingerprintVersion: typeof SAST_FINDING_FINGERPRINT_VERSION;
  capability: Exclude<SastCapability, 'SBOM'>;
  normalizedPath: string;
  findingStartLine: number;
  findingEndLine: number;
  policyVersion: string;
}

export interface SastEvidenceFragmentRequest {
  candidateId: string;
  role: SastEvidenceFragmentRole;
  normalizedPath: string;
  startLine: number;
  endLine: number;
}

export interface SastRedactedEvidenceCandidate
  extends SastEvidenceFragmentRequest {
  anchorStartLine: number;
  anchorEndLine: number;
  sourceFileLineCount: number;
  redactedContent: string;
  byteSize: number;
  sourceContentDigest: SastEvidenceDigest;
  contentDigest: SastEvidenceDigest;
  sourceAttestationRef: string;
  scannerRedactionDecisionRef: string;
  platformRedactionDecisionRef: string;
  secretRedactionApplied: true;
  rawSourceStored: false;
  candidateDigest: SastEvidenceDigest;
}

export type SastRedactedEvidenceCandidateCore = Omit<
  SastRedactedEvidenceCandidate,
  'candidateDigest'
>;

export interface SastAcceptedEvidenceFragment
  extends SastRedactedEvidenceCandidate {
  fragmentId: string;
  evidencePackId: string;
  ordinal: number;
  isFullFile: false;
  fragmentDigest: SastEvidenceDigest;
}

export type SastAcceptedEvidenceFragmentCore = Omit<
  SastAcceptedEvidenceFragment,
  'fragmentDigest'
>;

export interface SastEvidenceReconstructionDecision {
  version: typeof SAST_EVIDENCE_RECONSTRUCTION_VERSION;
  reconstructionDecisionId: string;
  candidateSetDigest: SastEvidenceDigest;
  status: SastEvidenceReconstructionStatus;
  reasonCodes: SastEvidenceReasonCode[];
  intervalSetDigest: SastEvidenceDigest | null;
  maximumFileCoverageBasisPoints: number;
  checkedAt: string;
  decisionDigest: SastEvidenceDigest;
}

export type SastEvidenceReconstructionDecisionCore = Omit<
  SastEvidenceReconstructionDecision,
  'decisionDigest'
>;

export interface SastAcceptedEvidenceAuthority {
  evidenceConstructionAuthority: true;
  dashboardAccessAllowed: false;
  aiPayloadAllowed: false;
  policyAuthority: false;
  publicationAuthority: false;
  lifecycleMutationAuthority: false;
}

export interface SastAcceptedEvidencePack {
  version: typeof SAST_ACCEPTED_EVIDENCE_VERSION;
  evidencePackId: string;
  scope: SastAcceptedEvidenceScope;
  candidateSetDigest: SastEvidenceDigest;
  fragments: SastAcceptedEvidenceFragment[];
  totalBytes: number;
  truncated: boolean;
  suppressedFragmentCount: number;
  reconstructionRiskChecked: true;
  reconstructionRiskDecisionRef: string;
  reconstructionRiskDecisionDigest: SastEvidenceDigest;
  classificationDecisionRef: null;
  deletionScheduleRef: null;
  dashboardSafe: false;
  aiSafe: false;
  createdAt: string;
  expiresAt: string;
  authority: SastAcceptedEvidenceAuthority;
  packDigest: SastEvidenceDigest;
}

export type SastAcceptedEvidencePackCore = Omit<
  SastAcceptedEvidencePack,
  'packDigest'
>;

export interface SastEvidenceAuditProjection {
  rawSourceStored: false;
  secretValuesStored: false;
  dashboardPayloadCreated: false;
  aiPayloadCreated: false;
  publicationAttempted: false;
}

export interface SastEvidenceBuildDecision {
  version: typeof SAST_EVIDENCE_BUILD_DECISION_VERSION;
  buildDecisionId: string;
  scope: SastAcceptedEvidenceScope;
  candidateSetDigest: SastEvidenceDigest;
  outcome: SastEvidenceBuildOutcome;
  reasonCodes: SastEvidenceReasonCode[];
  selectedFragmentCount: number;
  suppressedFragmentCount: number;
  reconstruction: SastEvidenceReconstructionDecision;
  evidencePackId: string | null;
  evidencePackDigest: SastEvidenceDigest | null;
  authority: {
    evidenceConstructionAuthority: boolean;
    dashboardAccessAllowed: false;
    aiPayloadAllowed: false;
    policyAuthority: false;
    publicationAuthority: false;
    lifecycleMutationAuthority: false;
  };
  audit: SastEvidenceAuditProjection;
  decidedAt: string;
  decisionDigest: SastEvidenceDigest;
}

export type SastEvidenceBuildDecisionCore = Omit<
  SastEvidenceBuildDecision,
  'decisionDigest'
>;

export interface SastAcceptedEvidenceBuildResult {
  decision: SastEvidenceBuildDecision;
  pack: SastAcceptedEvidencePack | null;
}

export function canonicalizeSastEvidenceCandidate(
  candidate: Readonly<SastRedactedEvidenceCandidateCore>
): string {
  return stableJson(candidate);
}

export function canonicalizeSastEvidenceCandidateSet(
  candidates: readonly SastRedactedEvidenceCandidate[]
): string {
  return stableJson(
    [...candidates]
      .sort(compareSastEvidenceCandidates)
      .map((candidate) => candidate)
  );
}

export function canonicalizeSastEvidenceReconstructionDecision(
  decision: Readonly<SastEvidenceReconstructionDecisionCore>
): string {
  return stableJson(decision);
}

export function canonicalizeSastAcceptedEvidenceFragment(
  fragment: Readonly<SastAcceptedEvidenceFragmentCore>
): string {
  return stableJson(fragment);
}

export function canonicalizeSastAcceptedEvidencePack(
  pack: Readonly<SastAcceptedEvidencePackCore>
): string {
  return stableJson(pack);
}

export function canonicalizeSastEvidenceBuildDecision(
  decision: Readonly<SastEvidenceBuildDecisionCore>
): string {
  return stableJson(decision);
}

export function canonicalizeSastEvidenceFragmentRequests(
  requests: readonly SastEvidenceFragmentRequest[]
): string {
  return stableJson([...requests].sort(compareSastEvidenceRequests));
}

export function compareSastEvidenceRequests(
  left: Readonly<SastEvidenceFragmentRequest>,
  right: Readonly<SastEvidenceFragmentRequest>
): number {
  return compareStrings(left.role, right.role) ||
    compareStrings(left.normalizedPath, right.normalizedPath) ||
    left.startLine - right.startLine ||
    left.endLine - right.endLine ||
    compareStrings(left.candidateId, right.candidateId);
}

export function compareSastEvidenceCandidates(
  left: Readonly<SastRedactedEvidenceCandidate>,
  right: Readonly<SastRedactedEvidenceCandidate>
): number {
  return compareSastEvidenceRequests(left, right) ||
    compareStrings(left.candidateDigest, right.candidateDigest);
}

export function buildSastAcceptedEvidence(input: {
  scope: Readonly<SastAcceptedEvidenceScope>;
  candidates: readonly SastRedactedEvidenceCandidate[];
  policy?: Readonly<SastEvidencePolicy>;
  decidedAt: string;
  digestCanonical: SastEvidenceCanonicalDigester;
}): SastAcceptedEvidenceBuildResult {
  const policy = input.policy ?? SAST_ACCEPTED_EVIDENCE_POLICY;
  const ordered = [...input.candidates].sort(
    compareSastEvidenceCandidates
  );
  const candidateSetDigest = input.digestCanonical(
    canonicalizeSastEvidenceCandidateSet(ordered)
  );
  const structuralReasons = validateCandidateSet(
    input.scope,
    ordered,
    policy,
    input.digestCanonical
  );
  const selected: SastRedactedEvidenceCandidate[] = [];
  let selectedBytes = 0;
  if (structuralReasons.length === 0) {
    for (const candidate of ordered) {
      if (
        selected.length >= policy.maxFragmentCount ||
        selectedBytes + candidate.byteSize > policy.maxTotalBytes
      ) {
        continue;
      }
      selected.push(candidate);
      selectedBytes += candidate.byteSize;
    }
  }
  const suppressedFragmentCount =
    structuralReasons.length > 0
      ? ordered.length
      : ordered.length - selected.length;
  const reconstruction = buildReconstructionDecision({
    candidates: selected,
    candidateSetDigest,
    checkedAt: input.decidedAt,
    skippedReasons: structuralReasons,
    digestCanonical: input.digestCanonical
  });
  const reasonCodes = orderSastEvidenceReasons([
    ...structuralReasons,
    ...reconstruction.reasonCodes
  ]);
  if (reasonCodes.length > 0) {
    return {
      decision: buildDecision({
        scope: input.scope,
        candidateSetDigest,
        reasonCodes,
        selectedFragmentCount: 0,
        suppressedFragmentCount,
        reconstruction,
        pack: null,
        decidedAt: input.decidedAt,
        digestCanonical: input.digestCanonical
      }),
      pack: null
    };
  }

  const evidencePackId = contractId(
    'sast-evidence-pack',
    input.digestCanonical(
      stableJson({
        scope: input.scope,
        candidateSetDigest,
        policy: input.scope.policyVersion
      })
    )
  );
  const fragments = selected.map((candidate, ordinal) =>
    buildFragment(
      candidate,
      evidencePackId,
      ordinal,
      input.digestCanonical
    )
  );
  const createdAtMilliseconds = Date.parse(input.decidedAt);
  const expiresAt = new Date(
    createdAtMilliseconds + policy.maxRetentionSeconds * 1000
  ).toISOString();
  const authority: SastAcceptedEvidenceAuthority = {
    evidenceConstructionAuthority: true,
    dashboardAccessAllowed: false,
    aiPayloadAllowed: false,
    policyAuthority: false,
    publicationAuthority: false,
    lifecycleMutationAuthority: false
  };
  const packCore: SastAcceptedEvidencePackCore = {
    version: SAST_ACCEPTED_EVIDENCE_VERSION,
    evidencePackId,
    scope: { ...input.scope },
    candidateSetDigest,
    fragments,
    totalBytes: selectedBytes,
    truncated: suppressedFragmentCount > 0,
    suppressedFragmentCount,
    reconstructionRiskChecked: true,
    reconstructionRiskDecisionRef:
      reconstruction.reconstructionDecisionId,
    reconstructionRiskDecisionDigest:
      reconstruction.decisionDigest,
    classificationDecisionRef: null,
    deletionScheduleRef: null,
    dashboardSafe: false,
    aiSafe: false,
    createdAt: input.decidedAt,
    expiresAt,
    authority
  };
  const pack: SastAcceptedEvidencePack = {
    ...packCore,
    packDigest: input.digestCanonical(
      canonicalizeSastAcceptedEvidencePack(packCore)
    )
  };
  return {
    decision: buildDecision({
      scope: input.scope,
      candidateSetDigest,
      reasonCodes: [],
      selectedFragmentCount: fragments.length,
      suppressedFragmentCount,
      reconstruction,
      pack,
      decidedAt: input.decidedAt,
      digestCanonical: input.digestCanonical
    }),
    pack
  };
}

export function buildSastEvidenceEarlyRejection(input: {
  scope: Readonly<SastAcceptedEvidenceScope>;
  requestDigest: SastEvidenceDigest;
  reasonCode: SastEvidenceReasonCode;
  decidedAt: string;
  digestCanonical: SastEvidenceCanonicalDigester;
}): SastEvidenceBuildDecision {
  const reconstructionCore: SastEvidenceReconstructionDecisionCore = {
    version: SAST_EVIDENCE_RECONSTRUCTION_VERSION,
    reconstructionDecisionId: contractId(
      'sast-evidence-reconstruction',
      input.digestCanonical(
        stableJson({
          scope: input.scope,
          candidateSetDigest: input.requestDigest,
          status: 'NOT_CHECKED'
        })
      )
    ),
    candidateSetDigest: input.requestDigest,
    status: 'NOT_CHECKED',
    reasonCodes: [input.reasonCode],
    intervalSetDigest: null,
    maximumFileCoverageBasisPoints: 0,
    checkedAt: input.decidedAt
  };
  const reconstruction: SastEvidenceReconstructionDecision = {
    ...reconstructionCore,
    decisionDigest: input.digestCanonical(
      canonicalizeSastEvidenceReconstructionDecision(
        reconstructionCore
      )
    )
  };
  return buildDecision({
    scope: input.scope,
    candidateSetDigest: input.requestDigest,
    reasonCodes: [input.reasonCode],
    selectedFragmentCount: 0,
    suppressedFragmentCount: 0,
    reconstruction,
    pack: null,
    decidedAt: input.decidedAt,
    digestCanonical: input.digestCanonical
  });
}

export function isSastAcceptedEvidenceScopeValid(
  value: unknown
): value is SastAcceptedEvidenceScope {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      'tenantId',
      'repositoryBindingId',
      'scanRequestId',
      'attemptId',
      'targetRef',
      'commitSha',
      'canonicalScanKey',
      'planDigest',
      'profileId',
      'profileDigest',
      'freshnessDecisionId',
      'freshnessDecisionDigest',
      'coverageDecisionId',
      'coverageDecisionDigest',
      'occurrenceId',
      'observationBatchId',
      'normalizedFindingId',
      'lineageId',
      'findingFingerprint',
      'fingerprintVersion',
      'capability',
      'normalizedPath',
      'findingStartLine',
      'findingEndLine',
      'policyVersion'
    ]) &&
    isBoundedReference(value.tenantId) &&
    isBoundedReference(value.repositoryBindingId) &&
    isBoundedReference(value.scanRequestId) &&
    isBoundedReference(value.attemptId) &&
    isBoundedReference(value.targetRef) &&
    isCommitSha(value.commitSha) &&
    isSha256Digest(value.canonicalScanKey) &&
    isSha256Digest(value.planDigest) &&
    SAST_PROFILE_IDS.includes(value.profileId as SastProfileId) &&
    isSha256Digest(value.profileDigest) &&
    isContractId(value.freshnessDecisionId, 'sast-freshness') &&
    isSha256Digest(value.freshnessDecisionDigest) &&
    isContractId(value.coverageDecisionId, 'sast-coverage') &&
    isSha256Digest(value.coverageDecisionDigest) &&
    isContractId(value.occurrenceId, 'finding-occurrence') &&
    isContractId(value.observationBatchId, 'finding-observation') &&
    isBoundedReference(value.normalizedFindingId) &&
    isContractId(value.lineageId, 'finding-lineage') &&
    isSha256Digest(value.findingFingerprint) &&
    value.fingerprintVersion === SAST_FINDING_FINGERPRINT_VERSION &&
    SAST_CAPABILITIES.includes(value.capability as SastCapability) &&
    value.capability !== 'SBOM' &&
    isSafeNormalizedPath(value.normalizedPath) &&
    isPositiveInteger(value.findingStartLine) &&
    isPositiveInteger(value.findingEndLine) &&
    (value.findingEndLine as number) >=
      (value.findingStartLine as number) &&
    isBoundedReference(value.policyVersion)
  );
}

export function isSastEvidenceFragmentRequestValid(
  value: unknown
): value is SastEvidenceFragmentRequest {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      'candidateId',
      'role',
      'normalizedPath',
      'startLine',
      'endLine'
    ]) &&
    isContractId(value.candidateId, 'sast-evidence-candidate') &&
    SAST_EVIDENCE_FRAGMENT_ROLES.includes(
      value.role as SastEvidenceFragmentRole
    ) &&
    isSafeNormalizedPath(value.normalizedPath) &&
    isPositiveInteger(value.startLine) &&
    isPositiveInteger(value.endLine) &&
    (value.endLine as number) >= (value.startLine as number)
  );
}

export function isSastRedactedEvidenceCandidateShapeValid(
  value: unknown,
  digestCanonical: SastEvidenceCanonicalDigester
): value is SastRedactedEvidenceCandidate {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'candidateId',
      'role',
      'normalizedPath',
      'startLine',
      'endLine',
      'anchorStartLine',
      'anchorEndLine',
      'sourceFileLineCount',
      'redactedContent',
      'byteSize',
      'sourceContentDigest',
      'contentDigest',
      'sourceAttestationRef',
      'scannerRedactionDecisionRef',
      'platformRedactionDecisionRef',
      'secretRedactionApplied',
      'rawSourceStored',
      'candidateDigest'
    ]) ||
    !isSastEvidenceFragmentRequestValid({
      candidateId: value.candidateId,
      role: value.role,
      normalizedPath: value.normalizedPath,
      startLine: value.startLine,
      endLine: value.endLine
    }) ||
    !isPositiveInteger(value.anchorStartLine) ||
    !isPositiveInteger(value.anchorEndLine) ||
    !isPositiveInteger(value.sourceFileLineCount) ||
    (value.anchorEndLine as number) <
      (value.anchorStartLine as number) ||
    (value.startLine as number) >
      (value.anchorStartLine as number) ||
    (value.endLine as number) < (value.anchorEndLine as number) ||
    (value.sourceFileLineCount as number) <
      (value.endLine as number) ||
    typeof value.redactedContent !== 'string' ||
    !isCanonicalEvidenceText(value.redactedContent) ||
    lineCount(value.redactedContent) !==
      (value.endLine as number) -
        (value.startLine as number) +
        1 ||
    !isPositiveInteger(value.byteSize) ||
    value.byteSize !== utf8Length(value.redactedContent) ||
    !isSha256Digest(value.sourceContentDigest) ||
    !isSha256Digest(value.contentDigest) ||
    digestCanonical(value.redactedContent) !== value.contentDigest ||
    !isBoundedReference(value.sourceAttestationRef) ||
    !isBoundedReference(value.scannerRedactionDecisionRef) ||
    !isBoundedReference(value.platformRedactionDecisionRef) ||
    value.secretRedactionApplied !== true ||
    value.rawSourceStored !== false ||
    !isSha256Digest(value.candidateDigest)
  ) {
    return false;
  }
  const candidate =
    value as unknown as SastRedactedEvidenceCandidate;
  const { candidateDigest, ...core } = candidate;
  return (
    digestCanonical(canonicalizeSastEvidenceCandidate(core)) ===
    candidateDigest
  );
}

export function isSastEvidenceReconstructionDecisionShapeValid(
  value: unknown,
  digestCanonical: SastEvidenceCanonicalDigester
): value is SastEvidenceReconstructionDecision {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'version',
      'reconstructionDecisionId',
      'candidateSetDigest',
      'status',
      'reasonCodes',
      'intervalSetDigest',
      'maximumFileCoverageBasisPoints',
      'checkedAt',
      'decisionDigest'
    ]) ||
    value.version !== SAST_EVIDENCE_RECONSTRUCTION_VERSION ||
    !isContractId(
      value.reconstructionDecisionId,
      'sast-evidence-reconstruction'
    ) ||
    !isSha256Digest(value.candidateSetDigest) ||
    !SAST_EVIDENCE_RECONSTRUCTION_STATUSES.includes(
      value.status as SastEvidenceReconstructionStatus
    ) ||
    !isCanonicalReasonArray(value.reasonCodes) ||
    !(
      value.intervalSetDigest === null ||
      isSha256Digest(value.intervalSetDigest)
    ) ||
    !Number.isSafeInteger(value.maximumFileCoverageBasisPoints) ||
    (value.maximumFileCoverageBasisPoints as number) < 0 ||
    (value.maximumFileCoverageBasisPoints as number) > 10000 ||
    !isCanonicalTimestamp(value.checkedAt) ||
    !isSha256Digest(value.decisionDigest)
  ) {
    return false;
  }
  const decision =
    value as unknown as SastEvidenceReconstructionDecision;
  if (
    (decision.status === 'SAFE' &&
      (decision.reasonCodes.length > 0 ||
        decision.intervalSetDigest === null)) ||
    (decision.status === 'RISK' &&
      (decision.reasonCodes.length === 0 ||
        decision.intervalSetDigest === null)) ||
    (decision.status === 'NOT_CHECKED' &&
      (decision.reasonCodes.length === 0 ||
        decision.intervalSetDigest !== null))
  ) {
    return false;
  }
  const { decisionDigest, ...core } = decision;
  return (
    digestCanonical(
      canonicalizeSastEvidenceReconstructionDecision(core)
    ) === decisionDigest
  );
}

export function isSastAcceptedEvidenceFragmentShapeValid(
  value: unknown,
  digestCanonical: SastEvidenceCanonicalDigester
): value is SastAcceptedEvidenceFragment {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'candidateId',
      'role',
      'normalizedPath',
      'startLine',
      'endLine',
      'anchorStartLine',
      'anchorEndLine',
      'sourceFileLineCount',
      'redactedContent',
      'byteSize',
      'sourceContentDigest',
      'contentDigest',
      'sourceAttestationRef',
      'scannerRedactionDecisionRef',
      'platformRedactionDecisionRef',
      'secretRedactionApplied',
      'rawSourceStored',
      'candidateDigest',
      'fragmentId',
      'evidencePackId',
      'ordinal',
      'isFullFile',
      'fragmentDigest'
    ]) ||
    !isSastRedactedEvidenceCandidateShapeValid(
      pickCandidate(value),
      digestCanonical
    ) ||
    !isContractId(value.fragmentId, 'sast-evidence-fragment') ||
    !isContractId(value.evidencePackId, 'sast-evidence-pack') ||
    !Number.isSafeInteger(value.ordinal) ||
    (value.ordinal as number) < 0 ||
    value.isFullFile !== false ||
    !isSha256Digest(value.fragmentDigest)
  ) {
    return false;
  }
  const fragment =
    value as unknown as SastAcceptedEvidenceFragment;
  const { fragmentDigest, ...core } = fragment;
  return (
    digestCanonical(
      canonicalizeSastAcceptedEvidenceFragment(core)
    ) === fragmentDigest
  );
}

export function isSastAcceptedEvidencePackShapeValid(
  value: unknown,
  digestCanonical: SastEvidenceCanonicalDigester,
  policy: Readonly<SastEvidencePolicy> =
    SAST_ACCEPTED_EVIDENCE_POLICY
): value is SastAcceptedEvidencePack {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'version',
      'evidencePackId',
      'scope',
      'candidateSetDigest',
      'fragments',
      'totalBytes',
      'truncated',
      'suppressedFragmentCount',
      'reconstructionRiskChecked',
      'reconstructionRiskDecisionRef',
      'reconstructionRiskDecisionDigest',
      'classificationDecisionRef',
      'deletionScheduleRef',
      'dashboardSafe',
      'aiSafe',
      'createdAt',
      'expiresAt',
      'authority',
      'packDigest'
    ]) ||
    value.version !== SAST_ACCEPTED_EVIDENCE_VERSION ||
    !isContractId(value.evidencePackId, 'sast-evidence-pack') ||
    !isSastAcceptedEvidenceScopeValid(value.scope) ||
    !isSha256Digest(value.candidateSetDigest) ||
    !Array.isArray(value.fragments) ||
    value.fragments.length === 0 ||
    value.fragments.length > policy.maxFragmentCount ||
    !value.fragments.every((fragment, index) =>
      isSastAcceptedEvidenceFragmentShapeValid(
        fragment,
        digestCanonical
      ) &&
      fragment.evidencePackId === value.evidencePackId &&
      fragment.ordinal === index
    ) ||
    !Number.isSafeInteger(value.totalBytes) ||
    typeof value.truncated !== 'boolean' ||
    !Number.isSafeInteger(value.suppressedFragmentCount) ||
    (value.suppressedFragmentCount as number) < 0 ||
    value.truncated !==
      ((value.suppressedFragmentCount as number) > 0) ||
    value.reconstructionRiskChecked !== true ||
    !isContractId(
      value.reconstructionRiskDecisionRef,
      'sast-evidence-reconstruction'
    ) ||
    !isSha256Digest(value.reconstructionRiskDecisionDigest) ||
    value.classificationDecisionRef !== null ||
    value.deletionScheduleRef !== null ||
    value.dashboardSafe !== false ||
    value.aiSafe !== false ||
    !isCanonicalTimestamp(value.createdAt) ||
    !isCanonicalTimestamp(value.expiresAt) ||
    !isAcceptedAuthority(value.authority) ||
    !isSha256Digest(value.packDigest) ||
    !isSastEvidencePolicySafe(policy)
  ) {
    return false;
  }
  const pack = value as unknown as SastAcceptedEvidencePack;
  const candidates = pack.fragments.map(
    (fragment) =>
      pickCandidate(fragment as unknown as Record<string, unknown>) as unknown as
        SastRedactedEvidenceCandidate
  );
  const reconstruction = buildReconstructionDecision({
    candidates,
    candidateSetDigest: pack.candidateSetDigest,
    checkedAt: pack.createdAt,
    skippedReasons: [],
    digestCanonical
  });
  if (
    pack.totalBytes !==
      pack.fragments.reduce(
        (sum, fragment) => sum + fragment.byteSize,
        0
      ) ||
    pack.totalBytes > policy.maxTotalBytes ||
    pack.fragments.some(
      (fragment) => fragment.byteSize > policy.maxFragmentBytes
    ) ||
    validateCandidateSet(
      pack.scope,
      candidates,
      policy,
      digestCanonical
    ).length > 0 ||
    reconstruction.status !== 'SAFE' ||
    reconstruction.reconstructionDecisionId !==
      pack.reconstructionRiskDecisionRef ||
    reconstruction.decisionDigest !==
      pack.reconstructionRiskDecisionDigest ||
    Date.parse(pack.expiresAt) <= Date.parse(pack.createdAt) ||
    Date.parse(pack.expiresAt) - Date.parse(pack.createdAt) >
      policy.maxRetentionSeconds * 1000
  ) {
    return false;
  }
  const { packDigest, ...core } = pack;
  return (
    digestCanonical(canonicalizeSastAcceptedEvidencePack(core)) ===
    packDigest
  );
}

export function isSastEvidenceBuildDecisionShapeValid(
  value: unknown,
  digestCanonical: SastEvidenceCanonicalDigester
): value is SastEvidenceBuildDecision {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'version',
      'buildDecisionId',
      'scope',
      'candidateSetDigest',
      'outcome',
      'reasonCodes',
      'selectedFragmentCount',
      'suppressedFragmentCount',
      'reconstruction',
      'evidencePackId',
      'evidencePackDigest',
      'authority',
      'audit',
      'decidedAt',
      'decisionDigest'
    ]) ||
    value.version !== SAST_EVIDENCE_BUILD_DECISION_VERSION ||
    !isContractId(value.buildDecisionId, 'sast-evidence-build') ||
    !isSastAcceptedEvidenceScopeValid(value.scope) ||
    !isSha256Digest(value.candidateSetDigest) ||
    !SAST_EVIDENCE_BUILD_OUTCOMES.includes(
      value.outcome as SastEvidenceBuildOutcome
    ) ||
    !isCanonicalReasonArray(value.reasonCodes) ||
    !Number.isSafeInteger(value.selectedFragmentCount) ||
    (value.selectedFragmentCount as number) < 0 ||
    !Number.isSafeInteger(value.suppressedFragmentCount) ||
    (value.suppressedFragmentCount as number) < 0 ||
    !isSastEvidenceReconstructionDecisionShapeValid(
      value.reconstruction,
      digestCanonical
    ) ||
    !isDecisionAuthority(value.authority) ||
    !isAuditProjection(value.audit) ||
    !isCanonicalTimestamp(value.decidedAt) ||
    !isSha256Digest(value.decisionDigest)
  ) {
    return false;
  }
  const decision = value as unknown as SastEvidenceBuildDecision;
  const accepted =
    decision.outcome === 'ACCEPTED' &&
    decision.reasonCodes.length === 0 &&
    decision.selectedFragmentCount > 0 &&
    decision.reconstruction.status === 'SAFE' &&
    decision.evidencePackId !== null &&
    decision.evidencePackDigest !== null &&
    decision.authority.evidenceConstructionAuthority;
  if (
    accepted !==
      (decision.outcome === 'ACCEPTED') ||
    decision.selectedFragmentCount >
      SAST_ACCEPTED_EVIDENCE_POLICY.maxFragmentCount ||
    decision.reconstruction.candidateSetDigest !==
      decision.candidateSetDigest ||
    decision.reconstruction.checkedAt !== decision.decidedAt ||
    stableJson(decision.reconstruction.reasonCodes) !==
      stableJson(decision.reasonCodes) ||
    (decision.evidencePackId !== null &&
      !isContractId(
        decision.evidencePackId,
        'sast-evidence-pack'
      )) ||
    (decision.evidencePackDigest !== null &&
      !isSha256Digest(decision.evidencePackDigest)) ||
    (decision.outcome === 'REJECTED' &&
      (decision.reasonCodes.length === 0 ||
        decision.selectedFragmentCount !== 0 ||
        decision.evidencePackId !== null ||
        decision.evidencePackDigest !== null ||
        decision.authority.evidenceConstructionAuthority))
  ) {
    return false;
  }
  const { decisionDigest, ...core } = decision;
  return (
    digestCanonical(canonicalizeSastEvidenceBuildDecision(core)) ===
    decisionDigest
  );
}

export function isSastAcceptedEvidenceBuildResultShapeValid(
  value: unknown,
  digestCanonical: SastEvidenceCanonicalDigester,
  policy: Readonly<SastEvidencePolicy> =
    SAST_ACCEPTED_EVIDENCE_POLICY
): value is SastAcceptedEvidenceBuildResult {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ['decision', 'pack']) ||
    !isSastEvidenceBuildDecisionShapeValid(
      value.decision,
      digestCanonical
    )
  ) {
    return false;
  }
  const decision = value.decision;
  if (decision.outcome === 'REJECTED') {
    return value.pack === null;
  }
  if (
    !isSastAcceptedEvidencePackShapeValid(
      value.pack,
      digestCanonical,
      policy
    )
  ) {
    return false;
  }
  const pack = value.pack;
  return (
    stableJson(pack.scope) === stableJson(decision.scope) &&
    pack.candidateSetDigest === decision.candidateSetDigest &&
    pack.evidencePackId === decision.evidencePackId &&
    pack.packDigest === decision.evidencePackDigest &&
    pack.fragments.length === decision.selectedFragmentCount &&
    pack.suppressedFragmentCount ===
      decision.suppressedFragmentCount &&
    pack.reconstructionRiskDecisionRef ===
      decision.reconstruction.reconstructionDecisionId &&
    pack.reconstructionRiskDecisionDigest ===
      decision.reconstruction.decisionDigest &&
    pack.createdAt === decision.decidedAt
  );
}

export function orderSastEvidenceReasons(
  reasons: readonly SastEvidenceReasonCode[]
): SastEvidenceReasonCode[] {
  return [...new Set(reasons)].sort(
    (left, right) =>
      SAST_EVIDENCE_REASON_CODES.indexOf(left) -
      SAST_EVIDENCE_REASON_CODES.indexOf(right)
  );
}

function validateCandidateSet(
  scope: Readonly<SastAcceptedEvidenceScope>,
  candidates: readonly SastRedactedEvidenceCandidate[],
  policy: Readonly<SastEvidencePolicy>,
  digestCanonical: SastEvidenceCanonicalDigester
): SastEvidenceReasonCode[] {
  const reasons: SastEvidenceReasonCode[] = [];
  if (
    !isSastAcceptedEvidenceScopeValid(scope) ||
    !isSastEvidencePolicySafe(policy) ||
    candidates.length === 0 ||
    candidates.length >
      SAST_ACCEPTED_EVIDENCE_LIMITS.maximumSourceCandidates ||
    !hasUnique(candidates.map((candidate) => candidate.candidateId)) ||
    !hasUnique(candidates.map((candidate) => candidate.candidateDigest)) ||
    candidates.some(
      (candidate) =>
        !isSastRedactedEvidenceCandidateShapeValid(
          candidate,
          digestCanonical
        ) ||
        candidate.byteSize > policy.maxFragmentBytes
    )
  ) {
    reasons.push('EVIDENCE_SOURCE_INVALID');
    return reasons;
  }
  const primary = candidates.filter(
    (candidate) => candidate.role === 'PRIMARY'
  );
  if (
    primary.length !== 1 ||
    primary[0]?.normalizedPath !== scope.normalizedPath ||
    primary[0]?.anchorStartLine !== scope.findingStartLine ||
    primary[0]?.anchorEndLine !== scope.findingEndLine
  ) {
    reasons.push('EVIDENCE_PRIMARY_FRAGMENT_INVALID');
  }
  for (const candidate of candidates) {
    if (
      candidate.anchorStartLine - candidate.startLine >
        policy.contextLinesBefore ||
      candidate.endLine - candidate.anchorEndLine >
        policy.contextLinesAfter
    ) {
      reasons.push('EVIDENCE_CONTEXT_EXCEEDED');
    }
    if (
      candidate.startLine === 1 &&
      candidate.endLine === candidate.sourceFileLineCount
    ) {
      reasons.push('EVIDENCE_FULL_FILE_FORBIDDEN');
    }
  }
  const lineCounts = new Map<string, number>();
  for (const candidate of candidates) {
    const existing = lineCounts.get(candidate.normalizedPath);
    if (
      existing !== undefined &&
      existing !== candidate.sourceFileLineCount
    ) {
      reasons.push('EVIDENCE_SOURCE_INVALID');
    }
    lineCounts.set(
      candidate.normalizedPath,
      candidate.sourceFileLineCount
    );
  }
  return orderSastEvidenceReasons(reasons);
}

function buildReconstructionDecision(input: {
  candidates: readonly SastRedactedEvidenceCandidate[];
  candidateSetDigest: SastEvidenceDigest;
  checkedAt: string;
  skippedReasons: readonly SastEvidenceReasonCode[];
  digestCanonical: SastEvidenceCanonicalDigester;
}): SastEvidenceReconstructionDecision {
  const intervalProjection = input.candidates
    .map((candidate) => ({
      normalizedPath: candidate.normalizedPath,
      startLine: candidate.startLine,
      endLine: candidate.endLine,
      sourceFileLineCount: candidate.sourceFileLineCount
    }))
    .sort(
      (left, right) =>
        compareStrings(
          left.normalizedPath,
          right.normalizedPath
        ) ||
        left.startLine - right.startLine ||
        left.endLine - right.endLine
    );
  const intervalSetDigest =
    input.skippedReasons.length > 0
      ? null
      : input.digestCanonical(stableJson(intervalProjection));
  const reasons: SastEvidenceReasonCode[] = [];
  let maximumFileCoverageBasisPoints = 0;
  if (input.skippedReasons.length === 0) {
    const byPath = new Map<
      string,
      SastRedactedEvidenceCandidate[]
    >();
    for (const candidate of input.candidates) {
      const values = byPath.get(candidate.normalizedPath) ?? [];
      values.push(candidate);
      byPath.set(candidate.normalizedPath, values);
    }
    for (const values of byPath.values()) {
      values.sort(
        (left, right) =>
          left.startLine - right.startLine ||
          left.endLine - right.endLine
      );
      if (
        values.length >
        SAST_ACCEPTED_EVIDENCE_LIMITS.maximumFragmentsPerFile
      ) {
        reasons.push('EVIDENCE_RECONSTRUCTION_FRAGMENT_COUNT');
      }
      let coveredLines = 0;
      let previousEnd = 0;
      for (const value of values) {
        if (previousEnd > 0) {
          if (value.startLine <= previousEnd) {
            reasons.push('EVIDENCE_RECONSTRUCTION_OVERLAP');
          } else if (value.startLine === previousEnd + 1) {
            reasons.push('EVIDENCE_RECONSTRUCTION_ADJACENT');
          }
        }
        coveredLines += value.endLine - value.startLine + 1;
        previousEnd = Math.max(previousEnd, value.endLine);
      }
      const sourceFileLineCount =
        values[0]?.sourceFileLineCount ?? 1;
      const coverageBasisPoints = Math.floor(
        (coveredLines * 10000) / sourceFileLineCount
      );
      maximumFileCoverageBasisPoints = Math.max(
        maximumFileCoverageBasisPoints,
        coverageBasisPoints
      );
      if (
        coverageBasisPoints >=
        SAST_ACCEPTED_EVIDENCE_LIMITS
          .maximumReconstructedFileCoverageBasisPoints
      ) {
        reasons.push('EVIDENCE_RECONSTRUCTION_COVERAGE');
      }
    }
  }
  const orderedReasons = orderSastEvidenceReasons(
    input.skippedReasons.length > 0
      ? input.skippedReasons
      : reasons
  );
  const status: SastEvidenceReconstructionStatus =
    input.skippedReasons.length > 0
      ? 'NOT_CHECKED'
      : orderedReasons.length > 0
        ? 'RISK'
        : 'SAFE';
  const core: SastEvidenceReconstructionDecisionCore = {
    version: SAST_EVIDENCE_RECONSTRUCTION_VERSION,
    reconstructionDecisionId: contractId(
      'sast-evidence-reconstruction',
      input.digestCanonical(
        stableJson({
          candidateSetDigest: input.candidateSetDigest,
          intervalSetDigest,
          status,
          reasons: orderedReasons
        })
      )
    ),
    candidateSetDigest: input.candidateSetDigest,
    status,
    reasonCodes: orderedReasons,
    intervalSetDigest,
    maximumFileCoverageBasisPoints,
    checkedAt: input.checkedAt
  };
  return {
    ...core,
    decisionDigest: input.digestCanonical(
      canonicalizeSastEvidenceReconstructionDecision(core)
    )
  };
}

function buildFragment(
  candidate: Readonly<SastRedactedEvidenceCandidate>,
  evidencePackId: string,
  ordinal: number,
  digestCanonical: SastEvidenceCanonicalDigester
): SastAcceptedEvidenceFragment {
  const fragmentId = contractId(
    'sast-evidence-fragment',
    digestCanonical(
      stableJson({
        evidencePackId,
        ordinal,
        candidateDigest: candidate.candidateDigest
      })
    )
  );
  const core: SastAcceptedEvidenceFragmentCore = {
    ...candidate,
    fragmentId,
    evidencePackId,
    ordinal,
    isFullFile: false
  };
  return {
    ...core,
    fragmentDigest: digestCanonical(
      canonicalizeSastAcceptedEvidenceFragment(core)
    )
  };
}

function buildDecision(input: {
  scope: Readonly<SastAcceptedEvidenceScope>;
  candidateSetDigest: SastEvidenceDigest;
  reasonCodes: readonly SastEvidenceReasonCode[];
  selectedFragmentCount: number;
  suppressedFragmentCount: number;
  reconstruction: Readonly<SastEvidenceReconstructionDecision>;
  pack: Readonly<SastAcceptedEvidencePack> | null;
  decidedAt: string;
  digestCanonical: SastEvidenceCanonicalDigester;
}): SastEvidenceBuildDecision {
  const reasonCodes = orderSastEvidenceReasons(input.reasonCodes);
  const accepted = input.pack !== null && reasonCodes.length === 0;
  const core: SastEvidenceBuildDecisionCore = {
    version: SAST_EVIDENCE_BUILD_DECISION_VERSION,
    buildDecisionId: contractId(
      'sast-evidence-build',
      input.digestCanonical(
        stableJson({
          scope: input.scope,
          candidateSetDigest: input.candidateSetDigest
        })
      )
    ),
    scope: { ...input.scope },
    candidateSetDigest: input.candidateSetDigest,
    outcome: accepted ? 'ACCEPTED' : 'REJECTED',
    reasonCodes,
    selectedFragmentCount: accepted
      ? input.selectedFragmentCount
      : 0,
    suppressedFragmentCount: input.suppressedFragmentCount,
    reconstruction: { ...input.reconstruction },
    evidencePackId: input.pack?.evidencePackId ?? null,
    evidencePackDigest: input.pack?.packDigest ?? null,
    authority: {
      evidenceConstructionAuthority: accepted,
      dashboardAccessAllowed: false,
      aiPayloadAllowed: false,
      policyAuthority: false,
      publicationAuthority: false,
      lifecycleMutationAuthority: false
    },
    audit: {
      rawSourceStored: false,
      secretValuesStored: false,
      dashboardPayloadCreated: false,
      aiPayloadCreated: false,
      publicationAttempted: false
    },
    decidedAt: input.decidedAt
  };
  return {
    ...core,
    decisionDigest: input.digestCanonical(
      canonicalizeSastEvidenceBuildDecision(core)
    )
  };
}

function pickCandidate(
  value: Record<string, unknown>
): Record<string, unknown> {
  const keys = [
    'candidateId',
    'role',
    'normalizedPath',
    'startLine',
    'endLine',
    'anchorStartLine',
    'anchorEndLine',
    'sourceFileLineCount',
    'redactedContent',
    'byteSize',
    'sourceContentDigest',
    'contentDigest',
    'sourceAttestationRef',
    'scannerRedactionDecisionRef',
    'platformRedactionDecisionRef',
    'secretRedactionApplied',
    'rawSourceStored',
    'candidateDigest'
  ];
  return Object.fromEntries(keys.map((key) => [key, value[key]]));
}

function isAcceptedAuthority(
  value: unknown
): value is SastAcceptedEvidenceAuthority {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      'evidenceConstructionAuthority',
      'dashboardAccessAllowed',
      'aiPayloadAllowed',
      'policyAuthority',
      'publicationAuthority',
      'lifecycleMutationAuthority'
    ]) &&
    value.evidenceConstructionAuthority === true &&
    value.dashboardAccessAllowed === false &&
    value.aiPayloadAllowed === false &&
    value.policyAuthority === false &&
    value.publicationAuthority === false &&
    value.lifecycleMutationAuthority === false
  );
}

function isDecisionAuthority(value: unknown): boolean {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      'evidenceConstructionAuthority',
      'dashboardAccessAllowed',
      'aiPayloadAllowed',
      'policyAuthority',
      'publicationAuthority',
      'lifecycleMutationAuthority'
    ]) &&
    typeof value.evidenceConstructionAuthority === 'boolean' &&
    value.dashboardAccessAllowed === false &&
    value.aiPayloadAllowed === false &&
    value.policyAuthority === false &&
    value.publicationAuthority === false &&
    value.lifecycleMutationAuthority === false
  );
}

function isAuditProjection(value: unknown): boolean {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      'rawSourceStored',
      'secretValuesStored',
      'dashboardPayloadCreated',
      'aiPayloadCreated',
      'publicationAttempted'
    ]) &&
    Object.values(value).every((entry) => entry === false)
  );
}

function isCanonicalReasonArray(value: unknown): boolean {
  return (
    Array.isArray(value) &&
    value.every(
      (reason, index) =>
        SAST_EVIDENCE_REASON_CODES.includes(
          reason as SastEvidenceReasonCode
        ) &&
        (index === 0 ||
          SAST_EVIDENCE_REASON_CODES.indexOf(
            value[index - 1] as SastEvidenceReasonCode
          ) <
            SAST_EVIDENCE_REASON_CODES.indexOf(
              reason as SastEvidenceReasonCode
            ))
    )
  );
}

function isCanonicalTimestamp(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) &&
    new Date(milliseconds).toISOString() === value;
}

function isPositiveInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) > 0;
}

function isSafeNormalizedPath(value: unknown): value is string {
  return (
    isBoundedReference(value) &&
    value === value.normalize('NFC') &&
    !value.startsWith('/') &&
    !value.endsWith('/') &&
    !value.includes('\\') &&
    !value.split('/').some(
      (segment) =>
        segment.length === 0 ||
        segment === '.' ||
        segment === '..'
    )
  );
}

function isCanonicalEvidenceText(value: string): boolean {
  if (
    value.length === 0 ||
    value !== value.normalize('NFC') ||
    value.includes('\r') ||
    value.includes('\u0000')
  ) {
    return false;
  }
  return ![...value].some((character) => {
    const point = character.codePointAt(0) ?? 0;
    return (
      (point >= 0xd800 && point <= 0xdfff) ||
      (point < 0x20 && point !== 0x09 && point !== 0x0a) ||
      (point >= 0x7f && point <= 0x9f)
    );
  });
}

function lineCount(value: string): number {
  return value.split('\n').length;
}

function hasUnique(values: readonly string[]): boolean {
  return new Set(values).size === values.length;
}

function isContractId(value: unknown, prefix: string): value is string {
  return (
    typeof value === 'string' &&
    new RegExp(
      '^' + prefix + '://[a-f0-9]{64}$',
      'u'
    ).test(value)
  );
}

function contractId(
  prefix: string,
  digestValue: SastEvidenceDigest
): string {
  return prefix + '://' + digestValue.replace(/^sha256:/u, '');
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) {
    return '[' + value.map(stableJson).join(',') + ']';
  }
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return (
      '{' +
      Object.keys(record)
        .sort(compareStrings)
        .map(
          (key) =>
            JSON.stringify(key) + ':' + stableJson(record[key])
        )
        .join(',') +
      '}'
    );
  }
  return JSON.stringify(value);
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
