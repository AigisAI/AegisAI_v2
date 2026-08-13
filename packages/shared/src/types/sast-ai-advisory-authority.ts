export const SAST_AI_ADVISORY_AUTHORITY_PROOF_VERSION =
  'sast-ai-advisory-authority-proof-v1' as const;

export const SAST_AI_ADVISORY_POLICY_REFERENCE_VERSION =
  'sast-ai-advisory-policy-reference-v1' as const;

export const SAST_AI_ADVISORY_AUTHORITY_LIMITS = Object.freeze({
  identifierBytes: 512,
  maximumNormalizedFindings: 25_000,
  maximumPolicyDecisions: 1_024,
  maximumWaivers: 1_024,
  maximumSuppressions: 1_024
});

type Sha256Digest = `sha256:${string}`;

const CONTRACT_ID_PATTERNS = {
  advisory: /^sast-ai-advisory:\/\/[a-f0-9]{64}$/u,
  handoff: /^sast-ai-handoff:\/\/[a-f0-9]{64}$/u,
  occurrence: /^finding-occurrence:\/\/[a-f0-9]{64}$/u,
  proof: /^sast-ai-authority-proof:\/\/[a-f0-9]{64}$/u
} as const;

export interface SastAiAdvisoryAuthorityProofIntent {
  tenantId: string;
  advisoryId: string;
}

export interface SastAiAdvisoryAuthorityStateSnapshot {
  normalizedFindingCount: number;
  normalizedFindingSetDigest: Sha256Digest;
  targetFindingDigest: Sha256Digest;
  lifecycleStateCount: 1;
  lifecycleStateSetDigest: Sha256Digest;
  policyDecisionCount: number;
  policyDecisionSetDigest: Sha256Digest;
  waiverCount: number;
  waiverSetDigest: Sha256Digest;
  suppressionCount: number;
  suppressionSetDigest: Sha256Digest;
  stateDigest: Sha256Digest;
}

export interface SastAiAdvisoryAuthorityProofScope {
  tenantId: string;
  repositoryBindingId: string;
  scanRequestId: string;
  attemptId: string;
  advisoryId: string;
  handoffId: string;
  requestDigest: Sha256Digest;
  handoffDigest: Sha256Digest;
  normalizedFindingId: string;
  occurrenceId: string;
  findingFingerprint: Sha256Digest;
}

export interface SastAiAdvisoryZeroAuthority {
  findingCreateAuthority: false;
  findingStatusMutationAuthority: false;
  findingSeverityMutationAuthority: false;
  lifecycleMutationAuthority: false;
  waiverMutationAuthority: false;
  suppressionMutationAuthority: false;
  policyOverrideAuthority: false;
  blockDecisionAuthority: false;
  publicationAuthority: false;
  scmWriteAuthority: false;
  advisoryOnly: true;
}

export interface SastAiAdvisoryAuthorityAudit {
  proofLedgerWritten: true;
  authoritativeFindingWritten: false;
  lifecycleStateWritten: false;
  policyDecisionWritten: false;
  waiverWritten: false;
  suppressionWritten: false;
  callerAuthorityFieldsAccepted: false;
  advisoryContentStored: false;
  sourceContentStored: false;
  secretValueStored: false;
}

export interface SastAiAdvisoryAuthorityProof {
  version: typeof SAST_AI_ADVISORY_AUTHORITY_PROOF_VERSION;
  proofId: string;
  scope: SastAiAdvisoryAuthorityProofScope;
  before: SastAiAdvisoryAuthorityStateSnapshot;
  after: SastAiAdvisoryAuthorityStateSnapshot;
  authority: SastAiAdvisoryZeroAuthority;
  audit: SastAiAdvisoryAuthorityAudit;
  verifiedAt: string;
  proofDigest: Sha256Digest;
}

export interface SastAiAdvisoryPolicyReference {
  version: typeof SAST_AI_ADVISORY_POLICY_REFERENCE_VERSION;
  advisoryId: string;
  authorityProofId: string;
  authorityProofDigest: Sha256Digest;
  advisoryOnly: true;
}

export type SastAiAdvisoryAuthorityCanonicalDigester = (
  canonicalValue: string
) => Sha256Digest;

const ZERO_AUTHORITY: SastAiAdvisoryZeroAuthority = Object.freeze({
  findingCreateAuthority: false,
  findingStatusMutationAuthority: false,
  findingSeverityMutationAuthority: false,
  lifecycleMutationAuthority: false,
  waiverMutationAuthority: false,
  suppressionMutationAuthority: false,
  policyOverrideAuthority: false,
  blockDecisionAuthority: false,
  publicationAuthority: false,
  scmWriteAuthority: false,
  advisoryOnly: true
});

const AUDIT: SastAiAdvisoryAuthorityAudit = Object.freeze({
  proofLedgerWritten: true,
  authoritativeFindingWritten: false,
  lifecycleStateWritten: false,
  policyDecisionWritten: false,
  waiverWritten: false,
  suppressionWritten: false,
  callerAuthorityFieldsAccepted: false,
  advisoryContentStored: false,
  sourceContentStored: false,
  secretValueStored: false
});

export function buildSastAiAdvisoryAuthorityStateSnapshot(input: {
  normalizedFindingDigests: readonly Sha256Digest[];
  targetFindingDigest: Sha256Digest;
  lifecycleStateDigests: readonly Sha256Digest[];
  policyDecisionDigests: readonly Sha256Digest[];
  waiverDigests: readonly Sha256Digest[];
  suppressionDigests: readonly Sha256Digest[];
  digestCanonical: SastAiAdvisoryAuthorityCanonicalDigester;
}): SastAiAdvisoryAuthorityStateSnapshot | null {
  if (
    !isCanonicalDigestSet(
      input.normalizedFindingDigests,
      1,
      SAST_AI_ADVISORY_AUTHORITY_LIMITS.maximumNormalizedFindings
    ) ||
    !input.normalizedFindingDigests.includes(input.targetFindingDigest) ||
    !isCanonicalDigestSet(input.lifecycleStateDigests, 1, 1) ||
    !isCanonicalDigestSet(
      input.policyDecisionDigests,
      0,
      SAST_AI_ADVISORY_AUTHORITY_LIMITS.maximumPolicyDecisions
    ) ||
    !isCanonicalDigestSet(
      input.waiverDigests,
      0,
      SAST_AI_ADVISORY_AUTHORITY_LIMITS.maximumWaivers
    ) ||
    !isCanonicalDigestSet(
      input.suppressionDigests,
      0,
      SAST_AI_ADVISORY_AUTHORITY_LIMITS.maximumSuppressions
    )
  ) {
    return null;
  }

  const core = {
    normalizedFindingCount: input.normalizedFindingDigests.length,
    normalizedFindingSetDigest: input.digestCanonical(
      stableJson(input.normalizedFindingDigests)
    ),
    targetFindingDigest: input.targetFindingDigest,
    lifecycleStateCount: 1 as const,
    lifecycleStateSetDigest: input.digestCanonical(
      stableJson(input.lifecycleStateDigests)
    ),
    policyDecisionCount: input.policyDecisionDigests.length,
    policyDecisionSetDigest: input.digestCanonical(
      stableJson(input.policyDecisionDigests)
    ),
    waiverCount: input.waiverDigests.length,
    waiverSetDigest: input.digestCanonical(
      stableJson(input.waiverDigests)
    ),
    suppressionCount: input.suppressionDigests.length,
    suppressionSetDigest: input.digestCanonical(
      stableJson(input.suppressionDigests)
    )
  };
  return {
    ...core,
    stateDigest: input.digestCanonical(stableJson(core))
  };
}

export function buildSastAiAdvisoryAuthorityProof(input: {
  scope: Readonly<SastAiAdvisoryAuthorityProofScope>;
  before: Readonly<SastAiAdvisoryAuthorityStateSnapshot>;
  after: Readonly<SastAiAdvisoryAuthorityStateSnapshot>;
  verifiedAt: string;
  digestCanonical: SastAiAdvisoryAuthorityCanonicalDigester;
}): SastAiAdvisoryAuthorityProof | null {
  if (
    !isSastAiAdvisoryAuthorityProofScopeValid(input.scope) ||
    !isSastAiAdvisoryAuthorityStateSnapshotShapeValid(
      input.before,
      input.digestCanonical
    ) ||
    !isSastAiAdvisoryAuthorityStateSnapshotShapeValid(
      input.after,
      input.digestCanonical
    ) ||
    stableJson(input.before) !== stableJson(input.after) ||
    !isIsoInstant(input.verifiedAt)
  ) {
    return null;
  }

  const identityDigest = input.digestCanonical(
    stableJson({
      version: SAST_AI_ADVISORY_AUTHORITY_PROOF_VERSION,
      tenantId: input.scope.tenantId,
      advisoryId: input.scope.advisoryId,
      handoffId: input.scope.handoffId,
      requestDigest: input.scope.requestDigest
    })
  );
  const suffix = stripDigest(identityDigest);
  if (!suffix) return null;

  const core = {
    version: SAST_AI_ADVISORY_AUTHORITY_PROOF_VERSION,
    proofId: `sast-ai-authority-proof://${suffix}`,
    scope: { ...input.scope },
    before: { ...input.before },
    after: { ...input.after },
    authority: { ...ZERO_AUTHORITY },
    audit: { ...AUDIT },
    verifiedAt: input.verifiedAt
  };
  const proof: SastAiAdvisoryAuthorityProof = {
    ...core,
    proofDigest: input.digestCanonical(stableJson(core))
  };
  return isSastAiAdvisoryAuthorityProofShapeValid(
    proof,
    input.digestCanonical
  )
    ? proof
    : null;
}

export function buildSastAiAdvisoryPolicyReference(
  proof: Readonly<SastAiAdvisoryAuthorityProof>,
  digestCanonical: SastAiAdvisoryAuthorityCanonicalDigester
): SastAiAdvisoryPolicyReference | null {
  if (
    !isSastAiAdvisoryAuthorityProofShapeValid(
      proof,
      digestCanonical
    )
  ) {
    return null;
  }
  return {
    version: SAST_AI_ADVISORY_POLICY_REFERENCE_VERSION,
    advisoryId: proof.scope.advisoryId,
    authorityProofId: proof.proofId,
    authorityProofDigest: proof.proofDigest,
    advisoryOnly: true
  };
}

export function isSastAiAdvisoryAuthorityProofIntentShapeValid(
  value: unknown
): value is SastAiAdvisoryAuthorityProofIntent {
  return isRecord(value) &&
    hasExactKeys(value, ['tenantId', 'advisoryId']) &&
    isBoundedReference(value.tenantId) &&
    isContractId(value.advisoryId, 'advisory');
}

export function isSastAiAdvisoryPolicyReferenceShapeValid(
  value: unknown
): value is SastAiAdvisoryPolicyReference {
  return isRecord(value) &&
    hasExactKeys(value, [
      'version',
      'advisoryId',
      'authorityProofId',
      'authorityProofDigest',
      'advisoryOnly'
    ]) &&
    value.version === SAST_AI_ADVISORY_POLICY_REFERENCE_VERSION &&
    isContractId(value.advisoryId, 'advisory') &&
    isContractId(value.authorityProofId, 'proof') &&
    isSha256Digest(value.authorityProofDigest) &&
    value.advisoryOnly === true;
}

export function isSastAiAdvisoryAuthorityStateSnapshotShapeValid(
  value: unknown,
  digestCanonical: SastAiAdvisoryAuthorityCanonicalDigester
): value is SastAiAdvisoryAuthorityStateSnapshot {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'normalizedFindingCount',
      'normalizedFindingSetDigest',
      'targetFindingDigest',
      'lifecycleStateCount',
      'lifecycleStateSetDigest',
      'policyDecisionCount',
      'policyDecisionSetDigest',
      'waiverCount',
      'waiverSetDigest',
      'suppressionCount',
      'suppressionSetDigest',
      'stateDigest'
    ]) ||
    !isBoundedCount(
      value.normalizedFindingCount,
      1,
      SAST_AI_ADVISORY_AUTHORITY_LIMITS.maximumNormalizedFindings
    ) ||
    value.lifecycleStateCount !== 1 ||
    !isBoundedCount(
      value.policyDecisionCount,
      0,
      SAST_AI_ADVISORY_AUTHORITY_LIMITS.maximumPolicyDecisions
    ) ||
    !isBoundedCount(
      value.waiverCount,
      0,
      SAST_AI_ADVISORY_AUTHORITY_LIMITS.maximumWaivers
    ) ||
    !isBoundedCount(
      value.suppressionCount,
      0,
      SAST_AI_ADVISORY_AUTHORITY_LIMITS.maximumSuppressions
    ) ||
    ![
      value.normalizedFindingSetDigest,
      value.targetFindingDigest,
      value.lifecycleStateSetDigest,
      value.policyDecisionSetDigest,
      value.waiverSetDigest,
      value.suppressionSetDigest,
      value.stateDigest
    ].every(isSha256Digest)
  ) {
    return false;
  }
  const core = { ...value } as Record<string, unknown>;
  delete core.stateDigest;
  return digestCanonical(stableJson(core)) === value.stateDigest;
}

export function isSastAiAdvisoryAuthorityProofShapeValid(
  value: unknown,
  digestCanonical: SastAiAdvisoryAuthorityCanonicalDigester
): value is SastAiAdvisoryAuthorityProof {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'version',
      'proofId',
      'scope',
      'before',
      'after',
      'authority',
      'audit',
      'verifiedAt',
      'proofDigest'
    ]) ||
    value.version !== SAST_AI_ADVISORY_AUTHORITY_PROOF_VERSION ||
    !isContractId(value.proofId, 'proof') ||
    !isSastAiAdvisoryAuthorityProofScopeValid(value.scope) ||
    !isSastAiAdvisoryAuthorityStateSnapshotShapeValid(
      value.before,
      digestCanonical
    ) ||
    !isSastAiAdvisoryAuthorityStateSnapshotShapeValid(
      value.after,
      digestCanonical
    ) ||
    stableJson(value.before) !== stableJson(value.after) ||
    !isExactObject(value.authority, ZERO_AUTHORITY) ||
    !isExactObject(value.audit, AUDIT) ||
    !isIsoInstant(value.verifiedAt) ||
    !isSha256Digest(value.proofDigest)
  ) {
    return false;
  }

  const identityDigest = digestCanonical(
    stableJson({
      version: value.version,
      tenantId: value.scope.tenantId,
      advisoryId: value.scope.advisoryId,
      handoffId: value.scope.handoffId,
      requestDigest: value.scope.requestDigest
    })
  );
  const core = { ...value } as Record<string, unknown>;
  delete core.proofDigest;
  return (
    value.proofId ===
      `sast-ai-authority-proof://${stripDigest(identityDigest)}` &&
    digestCanonical(stableJson(core)) === value.proofDigest
  );
}

function isSastAiAdvisoryAuthorityProofScopeValid(
  value: unknown
): value is SastAiAdvisoryAuthorityProofScope {
  return isRecord(value) &&
    hasExactKeys(value, [
      'tenantId',
      'repositoryBindingId',
      'scanRequestId',
      'attemptId',
      'advisoryId',
      'handoffId',
      'requestDigest',
      'handoffDigest',
      'normalizedFindingId',
      'occurrenceId',
      'findingFingerprint'
    ]) &&
    [
      value.tenantId,
      value.repositoryBindingId,
      value.scanRequestId,
      value.attemptId,
      value.normalizedFindingId
    ].every(isBoundedReference) &&
    isContractId(value.advisoryId, 'advisory') &&
    isContractId(value.handoffId, 'handoff') &&
    isContractId(value.occurrenceId, 'occurrence') &&
    isSha256Digest(value.requestDigest) &&
    isSha256Digest(value.handoffDigest) &&
    isSha256Digest(value.findingFingerprint);
}

function isCanonicalDigestSet(
  value: readonly Sha256Digest[],
  minimum: number,
  maximum: number
): boolean {
  return Array.isArray(value) &&
    value.length >= minimum &&
    value.length <= maximum &&
    value.every(isSha256Digest) &&
    new Set(value).size === value.length &&
    value.every(
      (item, index) => index === 0 || String(value[index - 1]) < item
    );
}

function isBoundedCount(
  value: unknown,
  minimum: number,
  maximum: number
): boolean {
  return Number.isInteger(value) &&
    Number(value) >= minimum &&
    Number(value) <= maximum;
}

function isExactObject(
  value: unknown,
  expected: object
): boolean {
  const expectedRecord = expected as Record<string, boolean>;
  return isRecord(value) &&
    hasExactKeys(value, Object.keys(expectedRecord)) &&
    Object.entries(expectedRecord).every(
      ([key, expectedValue]) => value[key] === expectedValue
    );
}

function isBoundedReference(value: unknown): value is string {
  return typeof value === 'string' &&
    value.length > 0 &&
    value.trim() === value &&
    !hasAsciiControl(value) &&
    new TextEncoder().encode(value).length <=
      SAST_AI_ADVISORY_AUTHORITY_LIMITS.identifierBytes;
}

function isContractId(
  value: unknown,
  kind: keyof typeof CONTRACT_ID_PATTERNS
): value is string {
  return typeof value === 'string' &&
    CONTRACT_ID_PATTERNS[kind].test(value);
}

function isSha256Digest(value: unknown): value is Sha256Digest {
  return typeof value === 'string' &&
    /^sha256:[a-f0-9]{64}$/u.test(value);
}

function stripDigest(value: string): string | null {
  return isSha256Digest(value) ? value.slice('sha256:'.length) : null;
}

function isIsoInstant(value: unknown): value is string {
  return typeof value === 'string' &&
    Number.isFinite(Date.parse(value)) &&
    new Date(value).toISOString() === value;
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

function hasAsciiControl(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value);
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
