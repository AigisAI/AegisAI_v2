import {
  isSastEvidenceAccessDecisionShapeValid,
  isSastReducedEvidenceReferenceShapeValid,
  type SastEvidenceAccessDecision,
  type SastReducedEvidenceReference
} from './sast-evidence-access';
import type {
  SastCapability,
  SastFindingLocation
} from './sast-runtime';

export const SAST_AI_ADVISORY_HANDOFF_VERSION =
  'sast-ai-advisory-handoff-v1' as const;

export const SAST_AI_ADVISORY_HANDOFF_LIMITS = Object.freeze({
  modelVersionBytes: 128,
  titleBytes: 512,
  identifierBytes: 512,
  maximumCweIds: 32,
  maximumCveIds: 32
});

const CONTRACT_ID_PATTERNS = {
  'sast-ai-handoff': /^sast-ai-handoff:\/\/[a-f0-9]{64}$/u,
  'sast-ai-request': /^sast-ai-request:\/\/[a-f0-9]{64}$/u,
  'sast-ai-advisory': /^sast-ai-advisory:\/\/[a-f0-9]{64}$/u,
  'sast-reduced-evidence': /^sast-reduced-evidence:\/\/[a-f0-9]{64}$/u,
  'sast-evidence-access': /^sast-evidence-access:\/\/[a-f0-9]{64}$/u,
  'sast-evidence-pack': /^sast-evidence-pack:\/\/[a-f0-9]{64}$/u
} as const;

export interface SastAiAdvisoryIntent {
  tenantId: string;
  repositoryBindingId: string;
  evidencePackId: string;
  modelVersion: string;
}

export interface SastAiAdvisoryNormalizedFinding {
  normalizedFindingId: string;
  occurrenceId: string;
  tenantId: string;
  repositoryBindingId: string;
  scanRequestId: string;
  attemptId: string;
  scannerRunId: string;
  findingFingerprint: `sha256:${string}`;
  capability: Exclude<SastCapability, 'SBOM'>;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  confidence: 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  cweIds: string[];
  cveIds: string[];
  location: SastFindingLocation;
  scanner: 'OPENGREP' | 'TRIVY';
  ruleSemanticId: string;
  ruleRevision: string;
  secretRedactionApplied: true;
}

export interface SastAiAdvisoryHandoffAuthority {
  normalizedFindingAllowed: true;
  reducedEvidenceReferenceAllowed: true;
  aiPayloadAllowed: true;
  aiProviderCallAllowed: true;
  retrievalAllowed: false;
  toolsAllowed: false;
  policyAuthority: false;
  publicationAuthority: false;
  lifecycleMutationAuthority: false;
  scmWriteAuthority: false;
  advisoryOnly: true;
}

export interface SastAiAdvisoryHandoffAudit {
  callerFindingAccepted: false;
  callerEvidenceAccepted: false;
  callerPromptAccepted: false;
  rawSourceStored: false;
  secretValueStored: false;
  evidenceFragmentStored: false;
  requestPayloadStored: false;
  retrievalAttempted: false;
  toolsInvoked: false;
}

export interface SastAiAdvisoryHandoff {
  version: typeof SAST_AI_ADVISORY_HANDOFF_VERSION;
  handoffId: string;
  requestId: string;
  advisoryId: string;
  tenantId: string;
  repositoryBindingId: string;
  scanRequestId: string;
  attemptId: string;
  modelVersion: string;
  normalizedFinding: SastAiAdvisoryNormalizedFinding;
  reducedEvidenceReference: SastReducedEvidenceReference;
  accessDecisionId: string;
  accessDecisionDigest: `sha256:${string}`;
  evidencePackId: string;
  payloadExpiresAt: string;
  authority: SastAiAdvisoryHandoffAuthority;
  audit: SastAiAdvisoryHandoffAudit;
  createdAt: string;
  requestDigest: `sha256:${string}`;
  handoffDigest: `sha256:${string}`;
}

export type SastAiAdvisoryHandoffCore = Omit<
  SastAiAdvisoryHandoff,
  'handoffDigest'
>;

export type SastAiAdvisoryCanonicalDigester = (
  canonicalValue: string
) => `sha256:${string}`;

const AUTHORITY: SastAiAdvisoryHandoffAuthority = Object.freeze({
  normalizedFindingAllowed: true,
  reducedEvidenceReferenceAllowed: true,
  aiPayloadAllowed: true,
  aiProviderCallAllowed: true,
  retrievalAllowed: false,
  toolsAllowed: false,
  policyAuthority: false,
  publicationAuthority: false,
  lifecycleMutationAuthority: false,
  scmWriteAuthority: false,
  advisoryOnly: true
});

const AUDIT: SastAiAdvisoryHandoffAudit = Object.freeze({
  callerFindingAccepted: false,
  callerEvidenceAccepted: false,
  callerPromptAccepted: false,
  rawSourceStored: false,
  secretValueStored: false,
  evidenceFragmentStored: false,
  requestPayloadStored: false,
  retrievalAttempted: false,
  toolsInvoked: false
});

export function canonicalizeSastAiAdvisoryRequest(value: {
  tenantId: string;
  repositoryBindingId: string;
  scanRequestId: string;
  attemptId: string;
  modelVersion: string;
  normalizedFinding: Readonly<SastAiAdvisoryNormalizedFinding>;
  reducedEvidenceReference: Readonly<SastReducedEvidenceReference>;
  accessDecisionId: string;
  accessDecisionDigest: `sha256:${string}`;
  evidencePackId: string;
  payloadExpiresAt: string;
  createdAt: string;
}): string {
  return stableJson(value);
}

export function canonicalizeSastAiAdvisoryHandoff(
  value: Readonly<SastAiAdvisoryHandoffCore>
): string {
  return stableJson(value);
}

export function buildSastAiAdvisoryHandoff(input: {
  decision: Readonly<SastEvidenceAccessDecision>;
  reducedEvidenceReference: Readonly<SastReducedEvidenceReference>;
  normalizedFinding: Readonly<SastAiAdvisoryNormalizedFinding>;
  modelVersion: string;
  createdAt: string;
  digestCanonical: SastAiAdvisoryCanonicalDigester;
}): SastAiAdvisoryHandoff | null {
  if (
    !isSastEvidenceAccessDecisionShapeValid(
      input.decision,
      input.digestCanonical
    ) ||
    input.decision.purpose !== 'AI_ADVISORY' ||
    input.decision.outcome !== 'ALLOWED' ||
    input.decision.classification !== 'AI_REDUCED_REFERENCE_SAFE' ||
    !input.decision.authority.reducedEvidenceReferenceAllowed ||
    input.decision.authority.aiPayloadAllowed ||
    input.decision.authority.aiProviderCallAllowed ||
    !isSastReducedEvidenceReferenceShapeValid(
      input.reducedEvidenceReference
    ) ||
    !isSastAiAdvisoryNormalizedFindingShapeValid(
      input.normalizedFinding
    ) ||
    !isBoundedModelVersion(input.modelVersion) ||
    !isIsoInstant(input.createdAt)
  ) {
    return null;
  }

  const scope = input.decision.scope;
  const finding = input.normalizedFinding;
  const reference = input.reducedEvidenceReference;
  const createdAt = Date.parse(input.createdAt);
  const payloadExpiresAt = Date.parse(reference.payloadExpiresAt);
  const evidenceExpiresAt = Date.parse(
    input.decision.evidenceExpiresAt
  );

  if (
    finding.tenantId !== scope.tenantId ||
    finding.repositoryBindingId !== scope.repositoryBindingId ||
    finding.scanRequestId !== scope.scanRequestId ||
    finding.attemptId !== scope.attemptId ||
    finding.occurrenceId !== scope.occurrenceId ||
    finding.findingFingerprint !== scope.findingFingerprint ||
    reference.accessDecisionId !== input.decision.accessDecisionId ||
    reference.accessDecisionDigest !== input.decision.decisionDigest ||
    reference.evidencePackId !== scope.evidencePackId ||
    reference.findingFingerprint !== scope.findingFingerprint ||
    reference.reducedEvidenceRef !== input.decision.reducedEvidenceRef ||
    reference.redactedProjectionDigest !==
      input.decision.redactedProjectionDigest ||
    reference.payloadExpiresAt !== input.decision.aiPayloadExpiresAt ||
    !Number.isFinite(createdAt) ||
    !Number.isFinite(payloadExpiresAt) ||
    !Number.isFinite(evidenceExpiresAt) ||
    createdAt < Date.parse(input.decision.decidedAt) ||
    createdAt >= payloadExpiresAt ||
    payloadExpiresAt > evidenceExpiresAt
  ) {
    return null;
  }

  // Bind the durable handoff timestamp to the immutable access decision rather
  // than the caller's invocation clock. Exact retries therefore derive the
  // same request, handoff, and advisory identifiers while the invocation clock
  // is still used above to enforce expiry.
  const requestCore = {
    tenantId: scope.tenantId,
    repositoryBindingId: scope.repositoryBindingId,
    scanRequestId: scope.scanRequestId,
    attemptId: scope.attemptId,
    modelVersion: input.modelVersion,
    normalizedFinding: cloneFinding(finding),
    reducedEvidenceReference: { ...reference },
    accessDecisionId: input.decision.accessDecisionId,
    accessDecisionDigest: input.decision.decisionDigest,
    evidencePackId: scope.evidencePackId,
    payloadExpiresAt: reference.payloadExpiresAt,
    createdAt: input.decision.decidedAt
  };
  const requestDigest = input.digestCanonical(
    canonicalizeSastAiAdvisoryRequest(requestCore)
  );
  const suffix = stripDigest(requestDigest);
  if (!suffix) return null;

  const core: SastAiAdvisoryHandoffCore = {
    version: SAST_AI_ADVISORY_HANDOFF_VERSION,
    handoffId: `sast-ai-handoff://${suffix}`,
    requestId: `sast-ai-request://${suffix}`,
    advisoryId: `sast-ai-advisory://${suffix}`,
    ...requestCore,
    authority: { ...AUTHORITY },
    audit: { ...AUDIT },
    requestDigest
  };
  const handoff: SastAiAdvisoryHandoff = {
    ...core,
    handoffDigest: input.digestCanonical(
      canonicalizeSastAiAdvisoryHandoff(core)
    )
  };
  return isSastAiAdvisoryHandoffShapeValid(
    handoff,
    input.digestCanonical
  )
    ? handoff
    : null;
}

export function isSastAiAdvisoryIntentShapeValid(
  value: unknown
): value is SastAiAdvisoryIntent {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      'tenantId',
      'repositoryBindingId',
      'evidencePackId',
      'modelVersion'
    ]) &&
    isBoundedReference(value.tenantId) &&
    isBoundedReference(value.repositoryBindingId) &&
    isBoundedReference(value.evidencePackId) &&
    isBoundedModelVersion(value.modelVersion)
  );
}

export function isSastAiAdvisoryNormalizedFindingShapeValid(
  value: unknown
): value is SastAiAdvisoryNormalizedFinding {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'normalizedFindingId',
      'occurrenceId',
      'tenantId',
      'repositoryBindingId',
      'scanRequestId',
      'attemptId',
      'scannerRunId',
      'findingFingerprint',
      'capability',
      'title',
      'severity',
      'confidence',
      'cweIds',
      'cveIds',
      'location',
      'scanner',
      'ruleSemanticId',
      'ruleRevision',
      'secretRedactionApplied'
    ]) ||
    ![
      value.normalizedFindingId,
      value.occurrenceId,
      value.tenantId,
      value.repositoryBindingId,
      value.scanRequestId,
      value.attemptId,
      value.scannerRunId,
      value.ruleSemanticId,
      value.ruleRevision
    ].every(isBoundedReference) ||
    !isSha256Digest(value.findingFingerprint) ||
    ![
      'SAST',
      'DEPENDENCY_VULNERABILITY',
      'SECRET_DETECTION',
      'IAC_MISCONFIGURATION'
    ].includes(String(value.capability)) ||
    !isBoundedText(value.title, SAST_AI_ADVISORY_HANDOFF_LIMITS.titleBytes) ||
    hasAsciiControl(value.title) ||
    !['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(
      String(value.severity)
    ) ||
    !['HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'].includes(
      String(value.confidence)
    ) ||
    (value.scanner !== 'OPENGREP' && value.scanner !== 'TRIVY') ||
    (value.scanner === 'OPENGREP') !== (value.capability === 'SAST') ||
    value.secretRedactionApplied !== true ||
    !isBoundedIdentifierArray(
      value.cweIds,
      SAST_AI_ADVISORY_HANDOFF_LIMITS.maximumCweIds
    ) ||
    !isBoundedIdentifierArray(
      value.cveIds,
      SAST_AI_ADVISORY_HANDOFF_LIMITS.maximumCveIds
    ) ||
    !isFindingLocationValid(value.location)
  ) {
    return false;
  }
  return true;
}

export function isSastAiAdvisoryHandoffShapeValid(
  value: unknown,
  digestCanonical: SastAiAdvisoryCanonicalDigester
): value is SastAiAdvisoryHandoff {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'version',
      'handoffId',
      'requestId',
      'advisoryId',
      'tenantId',
      'repositoryBindingId',
      'scanRequestId',
      'attemptId',
      'modelVersion',
      'normalizedFinding',
      'reducedEvidenceReference',
      'accessDecisionId',
      'accessDecisionDigest',
      'evidencePackId',
      'payloadExpiresAt',
      'authority',
      'audit',
      'createdAt',
      'requestDigest',
      'handoffDigest'
    ]) ||
    value.version !== SAST_AI_ADVISORY_HANDOFF_VERSION ||
    !isContractId(value.handoffId, 'sast-ai-handoff') ||
    !isContractId(value.requestId, 'sast-ai-request') ||
    !isContractId(value.advisoryId, 'sast-ai-advisory') ||
    !isSastAiAdvisoryNormalizedFindingShapeValid(
      value.normalizedFinding
    ) ||
    !isSastReducedEvidenceReferenceShapeValid(
      value.reducedEvidenceReference
    ) ||
    !isBoundedReference(value.tenantId) ||
    !isBoundedReference(value.repositoryBindingId) ||
    !isBoundedReference(value.scanRequestId) ||
    !isBoundedReference(value.attemptId) ||
    !isBoundedModelVersion(value.modelVersion) ||
    !isBoundedReference(value.accessDecisionId) ||
    !isSha256Digest(value.accessDecisionDigest) ||
    !isBoundedReference(value.evidencePackId) ||
    !isIsoInstant(value.payloadExpiresAt) ||
    !isIsoInstant(value.createdAt) ||
    !isSha256Digest(value.requestDigest) ||
    !isSha256Digest(value.handoffDigest) ||
    !isExactAuthority(value.authority) ||
    !isExactAudit(value.audit)
  ) {
    return false;
  }

  const core = { ...value } as Record<string, unknown>;
  delete core.handoffDigest;
  const requestCore = {
    tenantId: value.tenantId,
    repositoryBindingId: value.repositoryBindingId,
    scanRequestId: value.scanRequestId,
    attemptId: value.attemptId,
    modelVersion: value.modelVersion,
    normalizedFinding: value.normalizedFinding,
    reducedEvidenceReference: value.reducedEvidenceReference,
    accessDecisionId: value.accessDecisionId,
    accessDecisionDigest: value.accessDecisionDigest,
    evidencePackId: value.evidencePackId,
    payloadExpiresAt: value.payloadExpiresAt,
    createdAt: value.createdAt
  };
  const suffix = stripDigest(value.requestDigest);
  const createdAt = Date.parse(value.createdAt);
  const payloadExpiresAt = Date.parse(value.payloadExpiresAt);
  return (
    value.tenantId === value.normalizedFinding.tenantId &&
    value.repositoryBindingId ===
      value.normalizedFinding.repositoryBindingId &&
    value.scanRequestId === value.normalizedFinding.scanRequestId &&
    value.attemptId === value.normalizedFinding.attemptId &&
    value.accessDecisionId ===
      value.reducedEvidenceReference.accessDecisionId &&
    value.accessDecisionDigest ===
      value.reducedEvidenceReference.accessDecisionDigest &&
    value.evidencePackId ===
      value.reducedEvidenceReference.evidencePackId &&
    value.normalizedFinding.findingFingerprint ===
      value.reducedEvidenceReference.findingFingerprint &&
    value.payloadExpiresAt ===
      value.reducedEvidenceReference.payloadExpiresAt &&
    createdAt < payloadExpiresAt &&
    payloadExpiresAt - createdAt <= 24 * 60 * 60 * 1000 &&
    value.handoffId === `sast-ai-handoff://${suffix}` &&
    value.requestId === `sast-ai-request://${suffix}` &&
    value.advisoryId === `sast-ai-advisory://${suffix}` &&
    digestCanonical(canonicalizeSastAiAdvisoryRequest(requestCore)) ===
      value.requestDigest &&
    digestCanonical(
      canonicalizeSastAiAdvisoryHandoff(
        core as unknown as SastAiAdvisoryHandoffCore
      )
    ) === value.handoffDigest
  );
}

function cloneFinding(
  value: Readonly<SastAiAdvisoryNormalizedFinding>
): SastAiAdvisoryNormalizedFinding {
  return {
    ...value,
    cweIds: [...value.cweIds],
    cveIds: [...value.cveIds],
    location: { ...value.location }
  };
}

function isExactAuthority(
  value: unknown
): value is SastAiAdvisoryHandoffAuthority {
  return isRecord(value) &&
    hasExactKeys(value, Object.keys(AUTHORITY)) &&
    Object.entries(AUTHORITY).every(([key, expected]) =>
      value[key] === expected
    );
}

function isExactAudit(
  value: unknown
): value is SastAiAdvisoryHandoffAudit {
  return isRecord(value) &&
    hasExactKeys(value, Object.keys(AUDIT)) &&
    Object.entries(AUDIT).every(([key, expected]) =>
      value[key] === expected
    );
}

function isFindingLocationValid(value: unknown): value is SastFindingLocation {
  if (!isRecord(value)) return false;
  if (value.kind === 'UNKNOWN') {
    return (
      hasExactKeys(value, ['kind', 'reasonCode']) &&
      (value.reasonCode === 'SCANNER_LOCATION_OMITTED' ||
        value.reasonCode === 'LOCATION_NOT_MAPPABLE')
    );
  }
  if (value.kind !== 'FILE') return false;
  const allowed = [
    'kind',
    'normalizedPath',
    'lineStart',
    'lineEnd',
    'columnStart',
    'columnEnd'
  ];
  return (
    Object.keys(value).every((key) => allowed.includes(key)) &&
    typeof value.normalizedPath === 'string' &&
    value.normalizedPath.length > 0 &&
    value.normalizedPath.length <= 1024 &&
    !value.normalizedPath.includes('\\') &&
    !value.normalizedPath.split('/').includes('..') &&
    isPositiveInteger(value.lineStart) &&
    (value.lineEnd === undefined ||
      (isPositiveInteger(value.lineEnd) &&
        Number(value.lineEnd) >= Number(value.lineStart))) &&
    (value.columnStart === undefined ||
      isPositiveInteger(value.columnStart)) &&
    (value.columnEnd === undefined ||
      (value.columnStart !== undefined &&
        isPositiveInteger(value.columnEnd) &&
        (value.lineEnd !== undefined &&
        value.lineEnd !== value.lineStart
          ? true
          : Number(value.columnEnd) >= Number(value.columnStart))))
  );
}

function isBoundedIdentifierArray(
  value: unknown,
  maximum: number
): value is string[] {
  return Array.isArray(value) &&
    value.length <= maximum &&
    value.every((item) =>
      typeof item === 'string' &&
      /^[A-Z0-9][A-Z0-9._:-]{0,127}$/u.test(item)
    ) &&
    new Set(value).size === value.length &&
    value.every((item, index) =>
      index === 0 || String(value[index - 1]) < item
    );
}

function isBoundedModelVersion(value: unknown): value is string {
  return typeof value === 'string' &&
    /^[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,127}$/u.test(value) &&
    utf8Length(value) <= SAST_AI_ADVISORY_HANDOFF_LIMITS.modelVersionBytes;
}

function isBoundedReference(value: unknown): value is string {
  return isBoundedText(
    value,
    SAST_AI_ADVISORY_HANDOFF_LIMITS.identifierBytes
  ) &&
    value.trim() === value &&
    !hasAsciiControl(value);
}

function isBoundedText(value: unknown, maximumBytes: number): value is string {
  return typeof value === 'string' &&
    value.length > 0 &&
    !value.includes('\u0000') &&
    utf8Length(value) <= maximumBytes;
}

function isContractId(
  value: unknown,
  prefix: keyof typeof CONTRACT_ID_PATTERNS
): value is string {
  return typeof value === 'string' &&
    CONTRACT_ID_PATTERNS[prefix].test(value);
}

function isSha256Digest(value: unknown): value is `sha256:${string}` {
  return typeof value === 'string' && /^sha256:[a-f0-9]{64}$/u.test(value);
}

function stripDigest(value: string): string | null {
  return isSha256Digest(value) ? value.slice('sha256:'.length) : null;
}

function isIsoInstant(value: unknown): value is string {
  return typeof value === 'string' &&
    Number.isFinite(Date.parse(value)) &&
    new Date(value).toISOString() === value;
}

function isPositiveInteger(value: unknown): boolean {
  return Number.isInteger(value) && Number(value) > 0;
}

function hasExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[]
): boolean {
  const actual = Object.keys(value).sort();
  const ordered = [...expected].sort();
  return actual.length === ordered.length &&
    actual.every((key, index) => key === ordered[index]);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function utf8Length(value: string): number {
  return new TextEncoder().encode(value).length;
}

function hasAsciiControl(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function stableJson(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableJson(item)).join(',')}]`;
  }
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .filter((key) => record[key] !== undefined)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`)
    .join(',')}}`;
}
