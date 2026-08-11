import {
  hasExactKeys,
  isBoundedReference,
  isRecord,
  isSha256Digest,
  utf8Length
} from './sast-normalization-validation';
import {
  SAST_PROFILE_IDS,
  type SastProfileId
} from './sast-runtime';
import { SAST_ACCEPTED_EVIDENCE_POLICY } from './sast-accepted-evidence';

export const SAST_EVIDENCE_ACCESS_DECISION_VERSION =
  'sast-evidence-access-decision-v1' as const;
export const SAST_EVIDENCE_DELETION_SCHEDULE_VERSION =
  'sast-evidence-deletion-schedule-v1' as const;
export const SAST_EVIDENCE_DELETION_PROOF_VERSION =
  'sast-evidence-deletion-proof-v1' as const;
export const SAST_DASHBOARD_EVIDENCE_VERSION =
  'sast-dashboard-evidence-v1' as const;
export const SAST_REDUCED_EVIDENCE_REFERENCE_VERSION =
  'sast-reduced-evidence-reference-v1' as const;
export const SAST_EVIDENCE_ACCESS_POLICY_VERSION =
  'sast-evidence-access-policy-v1' as const;

export const SAST_EVIDENCE_MAX_RETENTION_SECONDS =
  7 * 24 * 60 * 60;
export const SAST_AI_PAYLOAD_MAX_RETENTION_SECONDS =
  24 * 60 * 60;

export const SAST_EVIDENCE_ACCESS_PURPOSES = [
  'DASHBOARD',
  'AI_ADVISORY'
] as const;
export type SastEvidenceAccessPurpose =
  (typeof SAST_EVIDENCE_ACCESS_PURPOSES)[number];

export const SAST_EVIDENCE_ACCESS_OUTCOMES = [
  'ALLOWED',
  'DENIED'
] as const;
export type SastEvidenceAccessOutcome =
  (typeof SAST_EVIDENCE_ACCESS_OUTCOMES)[number];

export const SAST_EVIDENCE_CLASSIFICATIONS = [
  'DASHBOARD_SAFE',
  'AI_REDUCED_REFERENCE_SAFE',
  'DENIED'
] as const;
export type SastEvidenceClassification =
  (typeof SAST_EVIDENCE_CLASSIFICATIONS)[number];

export const SAST_EVIDENCE_ACCESS_REASON_CODES = [
  'EVIDENCE_ACCESS_INPUT_INVALID',
  'EVIDENCE_ACCESS_CONTEXT_UNAVAILABLE',
  'EVIDENCE_ACCESS_CONTEXT_DRIFT',
  'EVIDENCE_ACCESS_TAMPERED',
  'EVIDENCE_ACCESS_PATH_UNSAFE',
  'EVIDENCE_ACCESS_IDENTIFIER_UNSAFE',
  'EVIDENCE_ACCESS_SECRET_AUTHORITY_UNAVAILABLE',
  'EVIDENCE_ACCESS_REDACTION_FAILED',
  'EVIDENCE_ACCESS_PROFILE_UNAPPROVED',
  'EVIDENCE_ACCESS_COVERAGE_INELIGIBLE',
  'EVIDENCE_ACCESS_OPT_IN_REQUIRED',
  'EVIDENCE_ACCESS_EXPIRED',
  'EVIDENCE_ACCESS_DELETION_PENDING',
  'EVIDENCE_ACCESS_DELETED',
  'EVIDENCE_ACCESS_CLASSIFICATION_STALE',
  'EVIDENCE_ACCESS_OUTPUT_INVALID',
  'EVIDENCE_ACCESS_PERSISTENCE_CONFLICT'
] as const;
export type SastEvidenceAccessReasonCode =
  (typeof SAST_EVIDENCE_ACCESS_REASON_CODES)[number];

export interface SastEvidenceAccessScope {
  tenantId: string;
  repositoryBindingId: string;
  scanRequestId: string;
  attemptId: string;
  occurrenceId: string;
  buildDecisionId: string;
  evidencePackId: string;
  findingFingerprint: `sha256:${string}`;
  profileId: SastProfileId;
  profileDigest: `sha256:${string}`;
  freshnessDecisionId: string;
  freshnessDecisionDigest: `sha256:${string}`;
  coverageDecisionId: string;
  coverageDecisionDigest: `sha256:${string}`;
  sourcePackDigest: `sha256:${string}`;
}

export interface SastEvidenceDeletionSchedule {
  version: typeof SAST_EVIDENCE_DELETION_SCHEDULE_VERSION;
  deletionScheduleId: string;
  operationId: string;
  scope: SastEvidenceAccessScope;
  scheduledAt: string;
  deleteAfter: string;
  maximumRetentionSeconds: typeof SAST_EVIDENCE_MAX_RETENTION_SECONDS;
  scheduleDigest: `sha256:${string}`;
}

export type SastEvidenceDeletionScheduleCore = Omit<
  SastEvidenceDeletionSchedule,
  'scheduleDigest'
>;

export interface SastEvidenceAccessAuthority {
  dashboardReadAllowed: boolean;
  reducedEvidenceReferenceAllowed: boolean;
  aiPayloadAllowed: false;
  aiProviderCallAllowed: false;
  retrievalAllowed: false;
  toolsAllowed: false;
  policyAuthority: false;
  publicationAuthority: false;
  lifecycleMutationAuthority: false;
  scmWriteAuthority: false;
}

export interface SastEvidenceAccessAuditProjection {
  secondPassRedactionApplied: boolean;
  rawSourceStored: false;
  secretValueStored: false;
  preRedactionPayloadStored: false;
  matchedValueDigestStored: false;
  dashboardPayloadPersisted: false;
  aiPayloadCreated: false;
  aiProviderCalled: false;
}

export interface SastEvidenceAccessDecision {
  version: typeof SAST_EVIDENCE_ACCESS_DECISION_VERSION;
  accessDecisionId: string;
  accessPolicyVersion: typeof SAST_EVIDENCE_ACCESS_POLICY_VERSION;
  purpose: SastEvidenceAccessPurpose;
  scope: SastEvidenceAccessScope;
  deletionScheduleId: string;
  deletionScheduleDigest: `sha256:${string}`;
  secretRegistryVersion: string;
  outcome: SastEvidenceAccessOutcome;
  classification: SastEvidenceClassification;
  reasonCodes: SastEvidenceAccessReasonCode[];
  secondPassRedactionDecisionRef: string | null;
  redactedProjectionDigest: `sha256:${string}` | null;
  redactedFragmentCount: number;
  redactedTotalBytes: number;
  redactionCount: number;
  reducedEvidenceRef: string | null;
  aiPayloadExpiresAt: string | null;
  evidenceExpiresAt: string;
  authority: SastEvidenceAccessAuthority;
  audit: SastEvidenceAccessAuditProjection;
  decidedAt: string;
  decisionDigest: `sha256:${string}`;
}

export type SastEvidenceAccessDecisionCore = Omit<
  SastEvidenceAccessDecision,
  'decisionDigest'
>;

export interface SastEvidenceSafeFragment {
  fragmentId: string;
  ordinal: number;
  role: 'PRIMARY' | 'RELATED';
  normalizedPath: string;
  startLine: number;
  endLine: number;
  redactedContent: string;
  byteSize: number;
  contentDigest: `sha256:${string}`;
}

export interface SastDashboardEvidence {
  version: typeof SAST_DASHBOARD_EVIDENCE_VERSION;
  accessDecisionId: string;
  accessDecisionDigest: `sha256:${string}`;
  evidencePackId: string;
  findingFingerprint: `sha256:${string}`;
  fragments: SastEvidenceSafeFragment[];
  totalBytes: number;
  truncated: boolean;
  expiresAt: string;
  advisoryOnly: true;
}

export interface SastReducedEvidenceReference {
  version: typeof SAST_REDUCED_EVIDENCE_REFERENCE_VERSION;
  reducedEvidenceRef: string;
  accessDecisionId: string;
  accessDecisionDigest: `sha256:${string}`;
  evidencePackId: string;
  findingFingerprint: `sha256:${string}`;
  redactedProjectionDigest: `sha256:${string}`;
  fragmentCount: number;
  payloadExpiresAt: string;
  aiPayloadCreated: false;
  aiProviderCalled: false;
  retrievalAllowed: false;
  toolsAllowed: false;
  advisoryOnly: true;
}

export interface SastEvidenceDeletionReceipt {
  operationId: string;
  providerReceiptRef: string;
  providerReceiptDigest: `sha256:${string}`;
  completedAt: string;
}

export interface SastEvidenceDeletionProof {
  version: typeof SAST_EVIDENCE_DELETION_PROOF_VERSION;
  deletionProofId: string;
  deletionScheduleId: string;
  deletionScheduleDigest: `sha256:${string}`;
  operationId: string;
  scope: SastEvidenceAccessScope;
  providerReceiptRef: string;
  providerReceiptDigest: `sha256:${string}`;
  contentDeleted: true;
  fragmentsDeleted: true;
  buildDecisionRetained: true;
  accessAuthorityRevoked: true;
  completedAt: string;
  proofDigest: `sha256:${string}`;
}

export type SastEvidenceDeletionProofCore = Omit<
  SastEvidenceDeletionProof,
  'proofDigest'
>;

export type SastEvidenceAccessCanonicalDigester = (
  canonicalValue: string
) => `sha256:${string}`;

export function canonicalizeSastEvidenceDeletionSchedule(
  value: Readonly<SastEvidenceDeletionScheduleCore>
): string {
  return stableJson(value);
}

export function canonicalizeSastEvidenceAccessDecision(
  value: Readonly<SastEvidenceAccessDecisionCore>
): string {
  return stableJson(value);
}

export function canonicalizeSastEvidenceSafeFragments(
  value: readonly SastEvidenceSafeFragment[]
): string {
  return stableJson([...value].sort((left, right) => left.ordinal - right.ordinal));
}

export function canonicalizeSastEvidenceDeletionProof(
  value: Readonly<SastEvidenceDeletionProofCore>
): string {
  return stableJson(value);
}

export function buildSastEvidenceDeletionSchedule(input: {
  scope: Readonly<SastEvidenceAccessScope>;
  scheduledAt: string;
  deleteAfter: string;
  digestCanonical: SastEvidenceAccessCanonicalDigester;
}): SastEvidenceDeletionSchedule {
  const identity = stableJson({
    scope: input.scope,
    deleteAfter: input.deleteAfter,
    policyVersion: SAST_EVIDENCE_ACCESS_POLICY_VERSION
  });
  const suffix = stripDigest(input.digestCanonical(identity));
  const core: SastEvidenceDeletionScheduleCore = {
    version: SAST_EVIDENCE_DELETION_SCHEDULE_VERSION,
    deletionScheduleId: `sast-evidence-deletion://${suffix}`,
    operationId: `sast-evidence-delete://${suffix}`,
    scope: { ...input.scope },
    scheduledAt: input.scheduledAt,
    deleteAfter: input.deleteAfter,
    maximumRetentionSeconds: SAST_EVIDENCE_MAX_RETENTION_SECONDS
  };
  return {
    ...core,
    scheduleDigest: input.digestCanonical(
      canonicalizeSastEvidenceDeletionSchedule(core)
    )
  };
}

export function buildSastEvidenceAccessDecision(input: {
  purpose: SastEvidenceAccessPurpose;
  scope: Readonly<SastEvidenceAccessScope>;
  schedule: Readonly<SastEvidenceDeletionSchedule>;
  secretRegistryVersion: string;
  outcome: SastEvidenceAccessOutcome;
  reasonCodes: readonly SastEvidenceAccessReasonCode[];
  redactedProjectionDigest: `sha256:${string}` | null;
  redactedFragmentCount: number;
  redactedTotalBytes: number;
  redactionCount: number;
  evidenceExpiresAt: string;
  decidedAt: string;
  digestCanonical: SastEvidenceAccessCanonicalDigester;
}): SastEvidenceAccessDecision {
  const allowed = input.outcome === 'ALLOWED';
  const identity = stableJson({
    purpose: input.purpose,
    scope: input.scope,
    scheduleDigest: input.schedule.scheduleDigest,
    secretRegistryVersion: input.secretRegistryVersion,
    outcome: input.outcome,
    reasonCodes: input.reasonCodes,
    redactedProjectionDigest: input.redactedProjectionDigest,
    classificationEpoch: input.decidedAt.slice(0, 10),
    policyVersion: SAST_EVIDENCE_ACCESS_POLICY_VERSION
  });
  const suffix = stripDigest(input.digestCanonical(identity));
  const accessDecisionId = `sast-evidence-access://${suffix}`;
  const secondPassRedactionDecisionRef = allowed
    ? `sast-evidence-access-redaction://${suffix}`
    : null;
  const reducedEvidenceRef =
    allowed && input.purpose === 'AI_ADVISORY'
      ? `sast-reduced-evidence://${suffix}`
      : null;
  const aiPayloadExpiresAt =
    allowed && input.purpose === 'AI_ADVISORY'
      ? new Date(
          Math.min(
            Date.parse(input.evidenceExpiresAt),
            Date.parse(input.decidedAt) +
              SAST_AI_PAYLOAD_MAX_RETENTION_SECONDS * 1000
          )
        ).toISOString()
      : null;
  const core: SastEvidenceAccessDecisionCore = {
    version: SAST_EVIDENCE_ACCESS_DECISION_VERSION,
    accessDecisionId,
    accessPolicyVersion: SAST_EVIDENCE_ACCESS_POLICY_VERSION,
    purpose: input.purpose,
    scope: { ...input.scope },
    deletionScheduleId: input.schedule.deletionScheduleId,
    deletionScheduleDigest: input.schedule.scheduleDigest,
    secretRegistryVersion: input.secretRegistryVersion,
    outcome: input.outcome,
    classification: allowed
      ? input.purpose === 'DASHBOARD'
        ? 'DASHBOARD_SAFE'
        : 'AI_REDUCED_REFERENCE_SAFE'
      : 'DENIED',
    reasonCodes: [...input.reasonCodes],
    secondPassRedactionDecisionRef,
    redactedProjectionDigest: allowed
      ? input.redactedProjectionDigest
      : null,
    redactedFragmentCount: allowed
      ? input.redactedFragmentCount
      : 0,
    redactedTotalBytes: allowed ? input.redactedTotalBytes : 0,
    redactionCount: allowed ? input.redactionCount : 0,
    reducedEvidenceRef,
    aiPayloadExpiresAt,
    evidenceExpiresAt: input.evidenceExpiresAt,
    authority: accessAuthority(input.purpose, allowed),
    audit: {
      secondPassRedactionApplied: allowed,
      rawSourceStored: false,
      secretValueStored: false,
      preRedactionPayloadStored: false,
      matchedValueDigestStored: false,
      dashboardPayloadPersisted: false,
      aiPayloadCreated: false,
      aiProviderCalled: false
    },
    decidedAt: input.decidedAt
  };
  return {
    ...core,
    decisionDigest: input.digestCanonical(
      canonicalizeSastEvidenceAccessDecision(core)
    )
  };
}

export function buildSastEvidenceDeletionProof(input: {
  schedule: Readonly<SastEvidenceDeletionSchedule>;
  receipt: Readonly<SastEvidenceDeletionReceipt>;
  digestCanonical: SastEvidenceAccessCanonicalDigester;
}): SastEvidenceDeletionProof {
  const identity = stableJson({
    scheduleDigest: input.schedule.scheduleDigest,
    operationId: input.receipt.operationId
  });
  const core: SastEvidenceDeletionProofCore = {
    version: SAST_EVIDENCE_DELETION_PROOF_VERSION,
    deletionProofId:
      `sast-evidence-deletion-proof://${stripDigest(
        input.digestCanonical(identity)
      )}`,
    deletionScheduleId: input.schedule.deletionScheduleId,
    deletionScheduleDigest: input.schedule.scheduleDigest,
    operationId: input.receipt.operationId,
    scope: { ...input.schedule.scope },
    providerReceiptRef: input.receipt.providerReceiptRef,
    providerReceiptDigest: input.receipt.providerReceiptDigest,
    contentDeleted: true,
    fragmentsDeleted: true,
    buildDecisionRetained: true,
    accessAuthorityRevoked: true,
    completedAt: input.receipt.completedAt
  };
  return {
    ...core,
    proofDigest: input.digestCanonical(
      canonicalizeSastEvidenceDeletionProof(core)
    )
  };
}

export function isSastEvidenceAccessScopeValid(
  value: unknown
): value is SastEvidenceAccessScope {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      'tenantId',
      'repositoryBindingId',
      'scanRequestId',
      'attemptId',
      'occurrenceId',
      'buildDecisionId',
      'evidencePackId',
      'findingFingerprint',
      'profileId',
      'profileDigest',
      'freshnessDecisionId',
      'freshnessDecisionDigest',
      'coverageDecisionId',
      'coverageDecisionDigest',
      'sourcePackDigest'
    ]) &&
    [
      value.tenantId,
      value.repositoryBindingId,
      value.scanRequestId,
      value.attemptId
    ].every(isBoundedReference) &&
    isContractId(value.occurrenceId, 'finding-occurrence') &&
    isContractId(value.buildDecisionId, 'sast-evidence-build') &&
    isContractId(value.evidencePackId, 'sast-evidence-pack') &&
    isSha256Digest(value.findingFingerprint) &&
    SAST_PROFILE_IDS.includes(value.profileId as SastProfileId) &&
    isSha256Digest(value.profileDigest) &&
    isContractId(value.freshnessDecisionId, 'sast-freshness') &&
    isSha256Digest(value.freshnessDecisionDigest) &&
    isContractId(value.coverageDecisionId, 'sast-coverage') &&
    isSha256Digest(value.coverageDecisionDigest) &&
    isSha256Digest(value.sourcePackDigest)
  );
}

export function isSastEvidenceDeletionScheduleShapeValid(
  value: unknown,
  digestCanonical?: SastEvidenceAccessCanonicalDigester
): value is SastEvidenceDeletionSchedule {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'version',
      'deletionScheduleId',
      'operationId',
      'scope',
      'scheduledAt',
      'deleteAfter',
      'maximumRetentionSeconds',
      'scheduleDigest'
    ]) ||
    value.version !== SAST_EVIDENCE_DELETION_SCHEDULE_VERSION ||
    !isContractId(value.deletionScheduleId, 'sast-evidence-deletion') ||
    !isContractId(value.operationId, 'sast-evidence-delete') ||
    !isSastEvidenceAccessScopeValid(value.scope) ||
    !isCanonicalTimestamp(value.scheduledAt) ||
    !isCanonicalTimestamp(value.deleteAfter) ||
    value.maximumRetentionSeconds !== SAST_EVIDENCE_MAX_RETENTION_SECONDS ||
    !isSha256Digest(value.scheduleDigest)
  ) {
    return false;
  }
  const duration = Date.parse(value.deleteAfter) - Date.parse(value.scheduledAt);
  if (
    duration <= 0 ||
    duration > SAST_EVIDENCE_MAX_RETENTION_SECONDS * 1000
  ) {
    return false;
  }
  if (digestCanonical) {
    const { scheduleDigest: _digest, ...core } =
      value as unknown as SastEvidenceDeletionSchedule;
    void _digest;
    return (
      digestCanonical(canonicalizeSastEvidenceDeletionSchedule(core)) ===
      value.scheduleDigest
    );
  }
  return true;
}

export function isSastEvidenceAccessDecisionShapeValid(
  value: unknown,
  digestCanonical?: SastEvidenceAccessCanonicalDigester
): value is SastEvidenceAccessDecision {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'version',
      'accessDecisionId',
      'accessPolicyVersion',
      'purpose',
      'scope',
      'deletionScheduleId',
      'deletionScheduleDigest',
      'secretRegistryVersion',
      'outcome',
      'classification',
      'reasonCodes',
      'secondPassRedactionDecisionRef',
      'redactedProjectionDigest',
      'redactedFragmentCount',
      'redactedTotalBytes',
      'redactionCount',
      'reducedEvidenceRef',
      'aiPayloadExpiresAt',
      'evidenceExpiresAt',
      'authority',
      'audit',
      'decidedAt',
      'decisionDigest'
    ]) ||
    value.version !== SAST_EVIDENCE_ACCESS_DECISION_VERSION ||
    value.accessPolicyVersion !== SAST_EVIDENCE_ACCESS_POLICY_VERSION ||
    !isContractId(value.accessDecisionId, 'sast-evidence-access') ||
    !SAST_EVIDENCE_ACCESS_PURPOSES.includes(
      value.purpose as SastEvidenceAccessPurpose
    ) ||
    !isSastEvidenceAccessScopeValid(value.scope) ||
    !isContractId(value.deletionScheduleId, 'sast-evidence-deletion') ||
    !isSha256Digest(value.deletionScheduleDigest) ||
    !isBoundedReference(value.secretRegistryVersion) ||
    !SAST_EVIDENCE_ACCESS_OUTCOMES.includes(
      value.outcome as SastEvidenceAccessOutcome
    ) ||
    !SAST_EVIDENCE_CLASSIFICATIONS.includes(
      value.classification as SastEvidenceClassification
    ) ||
    !isReasonCodes(value.reasonCodes) ||
    !Number.isSafeInteger(value.redactedFragmentCount) ||
    !Number.isSafeInteger(value.redactedTotalBytes) ||
    !Number.isSafeInteger(value.redactionCount) ||
    (value.redactedFragmentCount as number) < 0 ||
    (value.redactedTotalBytes as number) < 0 ||
    (value.redactionCount as number) < 0 ||
    (value.redactedFragmentCount as number) >
      SAST_ACCEPTED_EVIDENCE_POLICY.maxFragmentCount ||
    (value.redactedTotalBytes as number) >
      SAST_ACCEPTED_EVIDENCE_POLICY.maxTotalBytes ||
    (value.redactionCount as number) >
      SAST_ACCEPTED_EVIDENCE_POLICY.maxTotalBytes ||
    !isCanonicalTimestamp(value.evidenceExpiresAt) ||
    !isCanonicalTimestamp(value.decidedAt) ||
    !isAccessAuthority(value.authority) ||
    !isAccessAudit(value.audit) ||
    !isSha256Digest(value.decisionDigest)
  ) {
    return false;
  }
  const allowed = value.outcome === 'ALLOWED';
  if (
    allowed !== (value.reasonCodes.length === 0) ||
    (!allowed &&
      (value.secondPassRedactionDecisionRef !== null ||
        value.reducedEvidenceRef !== null ||
        value.aiPayloadExpiresAt !== null)) ||
    allowed !== isContractId(
      value.secondPassRedactionDecisionRef,
      'sast-evidence-access-redaction'
    ) ||
    allowed !== isSha256Digest(value.redactedProjectionDigest) ||
    value.authority.dashboardReadAllowed !==
      (allowed && value.purpose === 'DASHBOARD') ||
    value.authority.reducedEvidenceReferenceAllowed !==
      (allowed && value.purpose === 'AI_ADVISORY') ||
    value.audit.secondPassRedactionApplied !== allowed ||
    (!allowed &&
      (value.redactedFragmentCount !== 0 ||
        value.redactedTotalBytes !== 0 ||
        value.redactionCount !== 0)) ||
    (allowed &&
      ((value.redactedFragmentCount as number) <= 0 ||
        (value.redactedTotalBytes as number) <= 0)) ||
    (value.purpose === 'DASHBOARD' &&
      (value.classification !== (allowed ? 'DASHBOARD_SAFE' : 'DENIED') ||
        value.reducedEvidenceRef !== null ||
        value.aiPayloadExpiresAt !== null)) ||
    (value.purpose === 'AI_ADVISORY' &&
      (value.classification !==
        (allowed ? 'AI_REDUCED_REFERENCE_SAFE' : 'DENIED') ||
        allowed !==
          isContractId(value.reducedEvidenceRef, 'sast-reduced-evidence') ||
        allowed !== isCanonicalTimestamp(value.aiPayloadExpiresAt))) ||
    (allowed &&
      Date.parse(value.decidedAt as string) >=
        Date.parse(value.evidenceExpiresAt as string))
  ) {
    return false;
  }
  if (allowed && value.aiPayloadExpiresAt !== null) {
    const payloadDuration =
      Date.parse(value.aiPayloadExpiresAt as string) -
      Date.parse(value.decidedAt as string);
    if (
      payloadDuration <= 0 ||
      payloadDuration > SAST_AI_PAYLOAD_MAX_RETENTION_SECONDS * 1000 ||
      Date.parse(value.aiPayloadExpiresAt as string) >
        Date.parse(value.evidenceExpiresAt as string)
    ) {
      return false;
    }
  }
  if (digestCanonical) {
    const { decisionDigest: _digest, ...core } =
      value as unknown as SastEvidenceAccessDecision;
    void _digest;
    return (
      digestCanonical(canonicalizeSastEvidenceAccessDecision(core)) ===
      value.decisionDigest
    );
  }
  return true;
}

export function isSastEvidenceDeletionProofShapeValid(
  value: unknown,
  digestCanonical?: SastEvidenceAccessCanonicalDigester
): value is SastEvidenceDeletionProof {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'version',
      'deletionProofId',
      'deletionScheduleId',
      'deletionScheduleDigest',
      'operationId',
      'scope',
      'providerReceiptRef',
      'providerReceiptDigest',
      'contentDeleted',
      'fragmentsDeleted',
      'buildDecisionRetained',
      'accessAuthorityRevoked',
      'completedAt',
      'proofDigest'
    ]) ||
    value.version !== SAST_EVIDENCE_DELETION_PROOF_VERSION ||
    !isContractId(value.deletionProofId, 'sast-evidence-deletion-proof') ||
    !isContractId(value.deletionScheduleId, 'sast-evidence-deletion') ||
    !isSha256Digest(value.deletionScheduleDigest) ||
    !isContractId(value.operationId, 'sast-evidence-delete') ||
    !isSastEvidenceAccessScopeValid(value.scope) ||
    !isContractId(
      value.providerReceiptRef,
      'sast-evidence-delete-receipt'
    ) ||
    !isSha256Digest(value.providerReceiptDigest) ||
    value.contentDeleted !== true ||
    value.fragmentsDeleted !== true ||
    value.buildDecisionRetained !== true ||
    value.accessAuthorityRevoked !== true ||
    !isCanonicalTimestamp(value.completedAt) ||
    !isSha256Digest(value.proofDigest)
  ) {
    return false;
  }
  if (digestCanonical) {
    const { proofDigest: _digest, ...core } =
      value as unknown as SastEvidenceDeletionProof;
    void _digest;
    return (
      digestCanonical(canonicalizeSastEvidenceDeletionProof(core)) ===
      value.proofDigest
    );
  }
  return true;
}

export function isSastEvidenceSafeFragmentShapeValid(
  value: unknown
): value is SastEvidenceSafeFragment {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      'fragmentId',
      'ordinal',
      'role',
      'normalizedPath',
      'startLine',
      'endLine',
      'redactedContent',
      'byteSize',
      'contentDigest'
    ]) &&
    isContractId(value.fragmentId, 'sast-evidence-fragment') &&
    Number.isSafeInteger(value.ordinal) &&
    (value.ordinal as number) >= 0 &&
    (value.role === 'PRIMARY' || value.role === 'RELATED') &&
    isSafeNormalizedPath(value.normalizedPath) &&
    Number.isSafeInteger(value.startLine) &&
    Number.isSafeInteger(value.endLine) &&
    (value.startLine as number) > 0 &&
    (value.endLine as number) >= (value.startLine as number) &&
    typeof value.redactedContent === 'string' &&
    value.redactedContent === value.redactedContent.normalize('NFC') &&
    !value.redactedContent.includes('\r') &&
    Number.isSafeInteger(value.byteSize) &&
    value.byteSize === utf8Length(value.redactedContent) &&
    value.byteSize > 0 &&
    value.byteSize <= SAST_ACCEPTED_EVIDENCE_POLICY.maxFragmentBytes &&
    isSha256Digest(value.contentDigest)
  );
}

export function isSafeNormalizedPath(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value === value.normalize('NFC') &&
    value === value.trim() &&
    utf8Length(value) <= 4096 &&
    !value.includes('\\') &&
    !value.startsWith('/') &&
    !/^[A-Za-z]:/u.test(value) &&
    !/(^|\/)\.{1,2}(\/|$)/u.test(value) &&
    !/(^|\/)\.git(?:\/|$)/iu.test(value) &&
    !/\p{Cc}/u.test(value)
  );
}

function accessAuthority(
  purpose: SastEvidenceAccessPurpose,
  allowed: boolean
): SastEvidenceAccessAuthority {
  return {
    dashboardReadAllowed: allowed && purpose === 'DASHBOARD',
    reducedEvidenceReferenceAllowed:
      allowed && purpose === 'AI_ADVISORY',
    aiPayloadAllowed: false,
    aiProviderCallAllowed: false,
    retrievalAllowed: false,
    toolsAllowed: false,
    policyAuthority: false,
    publicationAuthority: false,
    lifecycleMutationAuthority: false,
    scmWriteAuthority: false
  };
}

function isAccessAuthority(
  value: unknown
): value is SastEvidenceAccessAuthority {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      'dashboardReadAllowed',
      'reducedEvidenceReferenceAllowed',
      'aiPayloadAllowed',
      'aiProviderCallAllowed',
      'retrievalAllowed',
      'toolsAllowed',
      'policyAuthority',
      'publicationAuthority',
      'lifecycleMutationAuthority',
      'scmWriteAuthority'
    ]) &&
    typeof value.dashboardReadAllowed === 'boolean' &&
    typeof value.reducedEvidenceReferenceAllowed === 'boolean' &&
    value.aiPayloadAllowed === false &&
    value.aiProviderCallAllowed === false &&
    value.retrievalAllowed === false &&
    value.toolsAllowed === false &&
    value.policyAuthority === false &&
    value.publicationAuthority === false &&
    value.lifecycleMutationAuthority === false &&
    value.scmWriteAuthority === false &&
    !(value.dashboardReadAllowed && value.reducedEvidenceReferenceAllowed)
  );
}

function isAccessAudit(
  value: unknown
): value is SastEvidenceAccessAuditProjection {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      'secondPassRedactionApplied',
      'rawSourceStored',
      'secretValueStored',
      'preRedactionPayloadStored',
      'matchedValueDigestStored',
      'dashboardPayloadPersisted',
      'aiPayloadCreated',
      'aiProviderCalled'
    ]) &&
    typeof value.secondPassRedactionApplied === 'boolean' &&
    value.rawSourceStored === false &&
    value.secretValueStored === false &&
    value.preRedactionPayloadStored === false &&
    value.matchedValueDigestStored === false &&
    value.dashboardPayloadPersisted === false &&
    value.aiPayloadCreated === false &&
    value.aiProviderCalled === false
  );
}

function isReasonCodes(
  value: unknown
): value is SastEvidenceAccessReasonCode[] {
  return (
    Array.isArray(value) &&
    value.length <= SAST_EVIDENCE_ACCESS_REASON_CODES.length &&
    value.every((reason) =>
      SAST_EVIDENCE_ACCESS_REASON_CODES.includes(
        reason as SastEvidenceAccessReasonCode
      )
    ) &&
    new Set(value).size === value.length
  );
}

const CONTRACT_ID_PATTERNS = Object.freeze({
  'finding-occurrence': /^finding-occurrence:\/\/[a-f0-9]{64}$/u,
  'sast-evidence-build': /^sast-evidence-build:\/\/[a-f0-9]{64}$/u,
  'sast-evidence-pack': /^sast-evidence-pack:\/\/[a-f0-9]{64}$/u,
  'sast-freshness': /^sast-freshness:\/\/[a-f0-9]{64}$/u,
  'sast-coverage': /^sast-coverage:\/\/[a-f0-9]{64}$/u,
  'sast-evidence-deletion': /^sast-evidence-deletion:\/\/[a-f0-9]{64}$/u,
  'sast-evidence-delete': /^sast-evidence-delete:\/\/[a-f0-9]{64}$/u,
  'sast-evidence-access': /^sast-evidence-access:\/\/[a-f0-9]{64}$/u,
  'sast-evidence-access-redaction':
    /^sast-evidence-access-redaction:\/\/[a-f0-9]{64}$/u,
  'sast-reduced-evidence': /^sast-reduced-evidence:\/\/[a-f0-9]{64}$/u,
  'sast-evidence-deletion-proof':
    /^sast-evidence-deletion-proof:\/\/[a-f0-9]{64}$/u,
  'sast-evidence-delete-receipt':
    /^sast-evidence-delete-receipt:\/\/[a-f0-9]{64}$/u,
  'sast-evidence-fragment': /^sast-evidence-fragment:\/\/[a-f0-9]{64}$/u
});

type ContractIdPrefix = keyof typeof CONTRACT_ID_PATTERNS;

function isContractId(
  value: unknown,
  prefix: ContractIdPrefix
): value is string {
  return (
    typeof value === 'string' &&
    CONTRACT_ID_PATTERNS[prefix].test(value)
  );
}

function isCanonicalTimestamp(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const milliseconds = Date.parse(value);
  return (
    Number.isFinite(milliseconds) &&
    new Date(milliseconds).toISOString() === value
  );
}

function stripDigest(value: `sha256:${string}`): string {
  return value.slice('sha256:'.length);
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
        .sort()
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
