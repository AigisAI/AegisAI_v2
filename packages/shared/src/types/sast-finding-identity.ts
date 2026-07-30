import {
  SAST_FINDING_FINGERPRINT_FIELDS,
  SAST_FINDING_FINGERPRINT_VERSION,
  buildFindingFingerprintPreimage,
  type FindingFingerprintInput
} from './sast-runtime';
import {
  SAST_SECRET_REDACTION_VERSION,
  canonicalizeSastSecretRedactedFindingCandidate,
  isSastSecretRedactedFindingCandidateShapeValid,
  isSastSecretRedactionBatchShapeValid,
  type SastSecretRedactedFindingCandidate,
  type SastSecretRedactionBatch,
  type SastSecretRedactionSummary
} from './sast-secret-redaction';
import {
  hasExactKeys,
  isSha256Digest,
  isRecord
} from './sast-normalization-validation';

export const SAST_FINDING_IDENTITY_VERSION =
  'sast-finding-identity-v1' as const;

/**
 * UNKNOWN locations deliberately contribute an empty path component. The
 * length-prefixed fingerprint contract keeps this distinct from every valid
 * FILE path while excluding provider-availability reason codes from identity.
 */
export const SAST_FINDING_UNKNOWN_NORMALIZED_PATH = '' as const;

export const SAST_FINDING_IDENTITY_LIMITS = Object.freeze({
  maximumFindings: 25_000,
  yieldFindingInterval: 64
});

export const SAST_FINDING_IDENTITY_REJECTION_REASON_CODES = [
  'FINDING_IDENTITY_INPUT_INVALID',
  'FINDING_IDENTITY_RETENTION_INVALID',
  'FINDING_IDENTITY_RETENTION_EXPIRED',
  'FINDING_IDENTITY_FINGERPRINT_COLLISION',
  'FINDING_IDENTITY_OUTPUT_INVALID'
] as const;
export type SastFindingIdentityRejectionReasonCode =
  (typeof SAST_FINDING_IDENTITY_REJECTION_REASON_CODES)[number];

export type SastFindingIdentityCanonicalDigester = (
  canonicalValue: string
) => `sha256:${string}`;

export type SastFindingFingerprintDigester = (
  fingerprintPreimage: string
) => `sha256:${string}`;

type SastFindingFingerprintComponents = Pick<
  FindingFingerprintInput,
  (typeof SAST_FINDING_FINGERPRINT_FIELDS)[number]
>;

export type SastFindingFingerprintDecision = SastFindingFingerprintComponents & {
  version: typeof SAST_FINDING_FINGERPRINT_VERSION;
  stableFingerprint: `sha256:${string}`;
  sourceRedactionDecisionDigest: `sha256:${string}`;
  unstableCoordinatesIncluded: false;
  scannerMatchIdentityAuthoritative: false;
  fingerprintPreimageStored: false;
  decisionDigest: `sha256:${string}`;
  decisionRef: string;
};

const SAST_FINDING_FINGERPRINT_DECISION_KEYS = Object.freeze([
  'version',
  ...SAST_FINDING_FINGERPRINT_FIELDS,
  'stableFingerprint',
  'sourceRedactionDecisionDigest',
  'unstableCoordinatesIncluded',
  'scannerMatchIdentityAuthoritative',
  'fingerprintPreimageStored',
  'decisionDigest',
  'decisionRef'
] as const);

export type SastFindingFingerprintDecisionCore = Omit<
  SastFindingFingerprintDecision,
  'decisionDigest' | 'decisionRef'
>;

type WithSastFindingFingerprint<T> =
  T extends SastSecretRedactedFindingCandidate
    ? Omit<T, 'durablePersistenceAllowed'> & {
        fingerprint: SastFindingFingerprintDecision;
        durablePersistenceAllowed: true;
      }
    : never;

export type SastFingerprintedFinding =
  WithSastFindingFingerprint<SastSecretRedactedFindingCandidate>;

export interface SastFindingIdentitySummary {
  version: typeof SAST_FINDING_IDENTITY_VERSION;
  fingerprintVersion: typeof SAST_FINDING_FINGERPRINT_VERSION;
  findingCount: number;
  distinctFingerprintCount: number;
  repeatedOccurrenceCount: number;
  fingerprintPreimagesStored: false;
  unstableCoordinatesIncluded: false;
  scannerMatchIdentityAuthoritative: false;
  rawSourceCandidatesStored: false;
  secretValuesStored: false;
}

export interface SastFindingIdentityAuthority {
  normalizedFindingPersistenceEligible: true;
  occurrenceAuthority: false;
  lifecycleAuthority: false;
  correlationAuthority: false;
  coverageAuthority: false;
  evidenceAuthority: false;
  policyAuthority: false;
  publicationAuthority: false;
  aiPayloadEligible: false;
}

export interface SastFingerprintedFindingBatch
  extends Omit<
    SastSecretRedactionBatch,
    | 'version'
    | 'outcome'
    | 'findings'
    | 'redaction'
    | 'durablePersistenceAllowed'
    | 'batchDigest'
  > {
  version: typeof SAST_FINDING_IDENTITY_VERSION;
  outcome: 'FINGERPRINTED';
  sourceRedactionVersion: typeof SAST_SECRET_REDACTION_VERSION;
  sourceRedactionBatchDigest: `sha256:${string}`;
  findings: SastFingerprintedFinding[];
  sourceRedaction: SastSecretRedactionSummary;
  identity: SastFindingIdentitySummary;
  authority: SastFindingIdentityAuthority;
  durablePersistenceAllowed: true;
  batchDigest: `sha256:${string}`;
}

export type SastFingerprintedFindingBatchCore = Omit<
  SastFingerprintedFindingBatch,
  'batchDigest'
>;

export interface SastFindingIdentitySuccess {
  outcome: 'FINGERPRINTED';
  batch: SastFingerprintedFindingBatch;
}

export interface SastFindingIdentityRejection {
  version: typeof SAST_FINDING_IDENTITY_VERSION;
  outcome: 'REJECTED';
  reasonCodes: SastFindingIdentityRejectionReasonCode[];
  sourceBatchDigestStored: false;
  fingerprintPreimageStored: false;
  sourceCandidateStored: false;
  secretValueStored: false;
  rejectionDigest: `sha256:${string}`;
}

export type SastFindingIdentityRejectionCore = Omit<
  SastFindingIdentityRejection,
  'rejectionDigest'
>;

export type SastFindingIdentityResult =
  | SastFindingIdentitySuccess
  | SastFindingIdentityRejection;

export type SastFindingIdentityAuditMetadata =
  | {
      version: typeof SAST_FINDING_IDENTITY_VERSION;
      outcome: 'FINGERPRINTED';
      batchDigest: `sha256:${string}`;
      sourceRedactionBatchDigest: `sha256:${string}`;
      artifactDigest: `sha256:${string}`;
      dispositionDecisionDigest: `sha256:${string}`;
      findingCount: number;
      distinctFingerprintCount: number;
      repeatedOccurrenceCount: number;
    }
  | {
      version: typeof SAST_FINDING_IDENTITY_VERSION;
      outcome: 'REJECTED';
      reasonCodes: SastFindingIdentityRejectionReasonCode[];
      rejectionDigest: `sha256:${string}`;
    };

export function orderSastFindingIdentityRejectionReasons(
  reasons: Iterable<SastFindingIdentityRejectionReasonCode>
): SastFindingIdentityRejectionReasonCode[] {
  const present = new Set(reasons);
  return SAST_FINDING_IDENTITY_REJECTION_REASON_CODES.filter(
    (reason) => present.has(reason)
  );
}

export function toSastFindingFingerprintInput(
  finding: Readonly<SastSecretRedactedFindingCandidate>
): FindingFingerprintInput {
  return {
    repositoryBindingId: finding.repositoryBindingId.normalize('NFC'),
    capability: finding.capability,
    ruleSemanticId:
      finding.identityMaterial.ruleSemanticId.normalize('NFC'),
    normalizedPath:
      finding.location.kind === 'FILE'
        ? finding.location.normalizedPath.normalize('NFC')
        : SAST_FINDING_UNKNOWN_NORMALIZED_PATH,
    symbolAnchor:
      finding.identityMaterial.symbolAnchor.normalize('NFC'),
    sinkKind: finding.identityMaterial.sinkKind.normalize('NFC'),
    structuralHash:
      finding.identityMaterial.structuralHash.normalize('NFC')
  };
}

export function stripSastFindingFingerprint(
  finding: Readonly<SastFingerprintedFinding>
): SastSecretRedactedFindingCandidate {
  const {
    fingerprint: _fingerprint,
    durablePersistenceAllowed: _durablePersistenceAllowed,
    ...source
  } = finding;
  void _fingerprint;
  void _durablePersistenceAllowed;
  return {
    ...source,
    durablePersistenceAllowed: false
  } as SastSecretRedactedFindingCandidate;
}

export function canonicalizeSastFindingFingerprintDecision(
  decision: Readonly<SastFindingFingerprintDecisionCore>
): string {
  const fingerprintComponents = Object.fromEntries(
    SAST_FINDING_FINGERPRINT_FIELDS.map((field) => [
      field,
      decision[field]
    ])
  ) as SastFindingFingerprintComponents;

  return JSON.stringify({
    version: decision.version,
    ...fingerprintComponents,
    stableFingerprint: decision.stableFingerprint,
    sourceRedactionDecisionDigest:
      decision.sourceRedactionDecisionDigest,
    unstableCoordinatesIncluded: false,
    scannerMatchIdentityAuthoritative: false,
    fingerprintPreimageStored: false
  });
}

export function canonicalizeSastFingerprintedFinding(
  finding: Readonly<SastFingerprintedFinding>
): string {
  return JSON.stringify({
    sourceRedactedCandidate:
      canonicalizeSastSecretRedactedFindingCandidate(
        stripSastFindingFingerprint(finding)
      ),
    fingerprint: {
      version: finding.fingerprint.version,
      repositoryBindingId:
        finding.fingerprint.repositoryBindingId,
      capability: finding.fingerprint.capability,
      ruleSemanticId: finding.fingerprint.ruleSemanticId,
      normalizedPath: finding.fingerprint.normalizedPath,
      symbolAnchor: finding.fingerprint.symbolAnchor,
      sinkKind: finding.fingerprint.sinkKind,
      structuralHash: finding.fingerprint.structuralHash,
      stableFingerprint: finding.fingerprint.stableFingerprint,
      sourceRedactionDecisionDigest:
        finding.fingerprint.sourceRedactionDecisionDigest,
      unstableCoordinatesIncluded: false,
      scannerMatchIdentityAuthoritative: false,
      fingerprintPreimageStored: false,
      decisionDigest: finding.fingerprint.decisionDigest,
      decisionRef: finding.fingerprint.decisionRef
    },
    durablePersistenceAllowed: true
  });
}

export function canonicalizeSastFingerprintedFindingBatch(
  batch: Readonly<SastFingerprintedFindingBatchCore>
): string {
  return JSON.stringify({
    version: batch.version,
    outcome: batch.outcome,
    sourceRedactionVersion: batch.sourceRedactionVersion,
    sourceAdapterVersion: batch.sourceAdapterVersion,
    artifactSchema: batch.artifactSchema,
    artifactSchemaVersion: batch.artifactSchemaVersion,
    ingestionId: batch.ingestionId,
    scope: {
      tenantId: batch.scope.tenantId,
      repositoryBindingId: batch.scope.repositoryBindingId,
      scanRequestId: batch.scope.scanRequestId,
      attemptId: batch.scope.attemptId,
      scannerRunId: batch.scope.scannerRunId
    },
    scannerRunId: batch.scannerRunId,
    scanner: batch.scanner,
    scannerVersion: batch.scannerVersion,
    scannerImageDigest: batch.scannerImageDigest,
    ruleBundleDigest: batch.ruleBundleDigest,
    ...('vulnerabilityDatabaseDigest' in batch
      ? {
          vulnerabilityDatabaseDigest:
            batch.vulnerabilityDatabaseDigest
        }
      : {}),
    planDigest: batch.planDigest,
    canonicalScanKey: batch.canonicalScanKey,
    preflightAttestationRef: batch.preflightAttestationRef,
    preflightInventoryDigest: batch.preflightInventoryDigest,
    lane: batch.lane,
    commitSha: batch.commitSha,
    envelopeDigest: batch.envelopeDigest,
    artifactDigest: batch.artifactDigest,
    schemaBundleDigest: batch.schemaBundleDigest,
    normalizerBundleDigest: batch.normalizerBundleDigest,
    validationResultDigest: batch.validationResultDigest,
    dispositionDecisionDigest: batch.dispositionDecisionDigest,
    retentionExpiresAt: batch.retentionExpiresAt,
    sourceRedactionBatchDigest:
      batch.sourceRedactionBatchDigest,
    findings: batch.findings.map(
      canonicalizeSastFingerprintedFinding
    ),
    sourceRedaction: canonicalizeSourceRedactionSummary(
      batch.sourceRedaction
    ),
    identity: {
      version: batch.identity.version,
      fingerprintVersion: batch.identity.fingerprintVersion,
      findingCount: batch.identity.findingCount,
      distinctFingerprintCount:
        batch.identity.distinctFingerprintCount,
      repeatedOccurrenceCount:
        batch.identity.repeatedOccurrenceCount,
      fingerprintPreimagesStored: false,
      unstableCoordinatesIncluded: false,
      scannerMatchIdentityAuthoritative: false,
      rawSourceCandidatesStored: false,
      secretValuesStored: false
    },
    authority: {
      normalizedFindingPersistenceEligible: true,
      occurrenceAuthority: false,
      lifecycleAuthority: false,
      correlationAuthority: false,
      coverageAuthority: false,
      evidenceAuthority: false,
      policyAuthority: false,
      publicationAuthority: false,
      aiPayloadEligible: false
    },
    durablePersistenceAllowed: true
  });
}

export function canonicalizeSastFindingIdentityRejection(
  rejection: Readonly<SastFindingIdentityRejectionCore>
): string {
  return JSON.stringify({
    version: rejection.version,
    outcome: rejection.outcome,
    reasonCodes: [...rejection.reasonCodes],
    sourceBatchDigestStored: false,
    fingerprintPreimageStored: false,
    sourceCandidateStored: false,
    secretValueStored: false
  });
}

export function isSastFingerprintedFindingShapeValid(
  value: unknown,
  digestCanonical: SastFindingIdentityCanonicalDigester,
  digestFingerprint: SastFindingFingerprintDigester =
    digestCanonical
): value is SastFingerprintedFinding {
  if (
    !isRecord(value) ||
    value.durablePersistenceAllowed !== true ||
    !isRecord(value.fingerprint)
  ) {
    return false;
  }
  const finding =
    value as unknown as SastFingerprintedFinding;
  const source = stripSastFindingFingerprint(finding);
  if (
    !isSastSecretRedactedFindingCandidateShapeValid(
      source,
      digestCanonical
    )
  ) {
    return false;
  }
  return isSastFindingFingerprintDecisionValid(
    value.fingerprint,
    source,
    digestCanonical,
    digestFingerprint
  );
}

export function isSastFingerprintedFindingBatchShapeValid(
  value: unknown,
  digestCanonical: SastFindingIdentityCanonicalDigester,
  digestFingerprint: SastFindingFingerprintDigester =
    digestCanonical
): value is SastFingerprintedFindingBatch {
  if (!isRecord(value)) return false;
  const isTrivy = value.scanner === 'TRIVY';
  const commonKeys = [
    'version',
    'outcome',
    'sourceRedactionVersion',
    'sourceAdapterVersion',
    'artifactSchema',
    'artifactSchemaVersion',
    'ingestionId',
    'scope',
    'scannerRunId',
    'scanner',
    'scannerVersion',
    'scannerImageDigest',
    'ruleBundleDigest',
    'planDigest',
    'canonicalScanKey',
    'preflightAttestationRef',
    'preflightInventoryDigest',
    'lane',
    'commitSha',
    'envelopeDigest',
    'artifactDigest',
    'schemaBundleDigest',
    'normalizerBundleDigest',
    'validationResultDigest',
    'dispositionDecisionDigest',
    'retentionExpiresAt',
    'sourceRedactionBatchDigest',
    'findings',
    'sourceRedaction',
    'identity',
    'authority',
    'durablePersistenceAllowed',
    'batchDigest'
  ] as const;
  if (
    !hasExactKeys(
      value,
      isTrivy
        ? [...commonKeys, 'vulnerabilityDatabaseDigest']
        : commonKeys
    ) ||
    value.version !== SAST_FINDING_IDENTITY_VERSION ||
    value.outcome !== 'FINGERPRINTED' ||
    value.sourceRedactionVersion !==
      SAST_SECRET_REDACTION_VERSION ||
    !Array.isArray(value.findings) ||
    value.findings.length >
      SAST_FINDING_IDENTITY_LIMITS.maximumFindings ||
    !isSha256Digest(value.sourceRedactionBatchDigest) ||
    !isSha256Digest(value.batchDigest) ||
    value.durablePersistenceAllowed !== true
  ) {
    return false;
  }

  const batch =
    value as unknown as SastFingerprintedFindingBatch;
  if (
    !batch.findings.every((finding) =>
      isSastFingerprintedFindingShapeValid(
        finding,
        digestCanonical,
        digestFingerprint
      )
    )
  ) {
    return false;
  }
  const sourceBatch = reconstructSourceRedactionBatch(batch);
  if (
    !isSastSecretRedactionBatchShapeValid(
      sourceBatch,
      digestCanonical
    )
  ) {
    return false;
  }
  const fingerprints = batch.findings.map(
    (finding) => finding.fingerprint.stableFingerprint
  );
  const distinctFingerprintCount =
    new Set(fingerprints).size;
  if (
    !isSastFindingIdentitySummaryValid(
      batch.identity,
      batch.findings.length,
      distinctFingerprintCount
    ) ||
    !isSastFindingIdentityAuthorityValid(batch.authority) ||
    !hasConsistentFingerprintPreimages(batch.findings)
  ) {
    return false;
  }
  const { batchDigest, ...batchCore } = batch;
  return canonicalDigestMatches(
    digestCanonical,
    canonicalizeSastFingerprintedFindingBatch(batchCore),
    batchDigest
  );
}

export function isSastFindingIdentityRejectionShapeValid(
  value: unknown,
  digestCanonical: SastFindingIdentityCanonicalDigester
): value is SastFindingIdentityRejection {
  if (
    !(
      isRecord(value) &&
      hasExactKeys(value, [
        'version',
        'outcome',
        'reasonCodes',
        'sourceBatchDigestStored',
        'fingerprintPreimageStored',
        'sourceCandidateStored',
        'secretValueStored',
        'rejectionDigest'
      ]) &&
      value.version === SAST_FINDING_IDENTITY_VERSION &&
      value.outcome === 'REJECTED' &&
      isStrictOrderedMembers(
        value.reasonCodes,
        SAST_FINDING_IDENTITY_REJECTION_REASON_CODES
      ) &&
      (value.reasonCodes as readonly unknown[]).length > 0 &&
      value.sourceBatchDigestStored === false &&
      value.fingerprintPreimageStored === false &&
      value.sourceCandidateStored === false &&
      value.secretValueStored === false &&
      isSha256Digest(value.rejectionDigest)
    )
  ) {
    return false;
  }
  const rejection =
    value as unknown as SastFindingIdentityRejection;
  const { rejectionDigest, ...rejectionCore } = rejection;
  return canonicalDigestMatches(
    digestCanonical,
    canonicalizeSastFindingIdentityRejection(rejectionCore),
    rejectionDigest
  );
}

export function toSastFindingIdentityAuditMetadata(
  result: unknown,
  digestCanonical: SastFindingIdentityCanonicalDigester
): SastFindingIdentityAuditMetadata {
  if (
    isSastFindingIdentityRejectionShapeValid(
      result,
      digestCanonical
    )
  ) {
    return {
      version: result.version,
      outcome: result.outcome,
      reasonCodes: [...result.reasonCodes],
      rejectionDigest: result.rejectionDigest
    };
  }
  if (
    !isRecord(result) ||
    !hasExactKeys(result, ['outcome', 'batch']) ||
    result.outcome !== 'FINGERPRINTED' ||
    !isSastFingerprintedFindingBatchShapeValid(
      result.batch,
      digestCanonical
    )
  ) {
    throw new TypeError(
      'SAST finding-identity result is invalid.'
    );
  }
  const batch = result.batch;
  return {
    version: batch.version,
    outcome: result.outcome,
    batchDigest: batch.batchDigest,
    sourceRedactionBatchDigest:
      batch.sourceRedactionBatchDigest,
    artifactDigest: batch.artifactDigest,
    dispositionDecisionDigest:
      batch.dispositionDecisionDigest,
    findingCount: batch.identity.findingCount,
    distinctFingerprintCount:
      batch.identity.distinctFingerprintCount,
    repeatedOccurrenceCount:
      batch.identity.repeatedOccurrenceCount
  };
}

function isSastFindingFingerprintDecisionValid(
  value: Record<string, unknown>,
  source: Readonly<SastSecretRedactedFindingCandidate>,
  digestCanonical: SastFindingIdentityCanonicalDigester,
  digestFingerprint: SastFindingFingerprintDigester
): boolean {
  if (
    !hasExactKeys(
      value,
      SAST_FINDING_FINGERPRINT_DECISION_KEYS
    ) ||
    value.version !== SAST_FINDING_FINGERPRINT_VERSION ||
    !isSha256Digest(value.stableFingerprint) ||
    !isSha256Digest(value.sourceRedactionDecisionDigest) ||
    value.unstableCoordinatesIncluded !== false ||
    value.scannerMatchIdentityAuthoritative !== false ||
    value.fingerprintPreimageStored !== false ||
    !isSha256Digest(value.decisionDigest) ||
    value.decisionRef !==
      `fingerprint://${SAST_FINDING_FINGERPRINT_VERSION}/${
        (value.decisionDigest as string).slice('sha256:'.length)
      }`
  ) {
    return false;
  }
  const expected = toSastFindingFingerprintInput(source);
  if (
    SAST_FINDING_FINGERPRINT_FIELDS.some(
      (field) => value[field] !== expected[field]
    ) ||
    value.sourceRedactionDecisionDigest !==
      source.redaction.decisionDigest ||
    !canonicalDigestMatches(
      digestFingerprint,
      buildFindingFingerprintPreimage(expected),
      value.stableFingerprint as string
    )
  ) {
    return false;
  }
  const decision =
    value as unknown as SastFindingFingerprintDecision;
  const {
    decisionDigest,
    decisionRef: _decisionRef,
    ...decisionCore
  } = decision;
  void _decisionRef;
  return canonicalDigestMatches(
    digestCanonical,
    canonicalizeSastFindingFingerprintDecision(decisionCore),
    decisionDigest
  );
}

function reconstructSourceRedactionBatch(
  batch: Readonly<SastFingerprintedFindingBatch>
): SastSecretRedactionBatch {
  const {
    version: _version,
    outcome: _outcome,
    sourceRedactionVersion,
    sourceRedactionBatchDigest,
    findings,
    sourceRedaction,
    identity: _identity,
    authority: _authority,
    durablePersistenceAllowed: _durablePersistenceAllowed,
    batchDigest: _batchDigest,
    ...sourceFields
  } = batch;
  void _version;
  void _outcome;
  void _identity;
  void _authority;
  void _durablePersistenceAllowed;
  void _batchDigest;
  return {
    ...sourceFields,
    version: sourceRedactionVersion,
    outcome: 'REDACTED',
    findings: findings.map(stripSastFindingFingerprint),
    redaction: sourceRedaction,
    durablePersistenceAllowed: false,
    batchDigest: sourceRedactionBatchDigest
  };
}

function canonicalizeSourceRedactionSummary(
  summary: Readonly<SastSecretRedactionSummary>
): SastSecretRedactionSummary {
  return {
    version: summary.version,
    secretRedactionApplied: true,
    candidateCount: summary.candidateCount,
    batchInspectedFieldCount: summary.batchInspectedFieldCount,
    inspectedFieldCount: summary.inspectedFieldCount,
    redactedCandidateCount: summary.redactedCandidateCount,
    redactedFieldCount: summary.redactedFieldCount,
    replacementCount: summary.replacementCount,
    detectorKinds: [...summary.detectorKinds],
    secretValuesStored: false,
    matchedValueDigestsStored: false,
    rawCandidatesStored: false,
    sourceCandidateDigestStored: false
  };
}

function isSastFindingIdentitySummaryValid(
  value: unknown,
  findingCount: number,
  distinctFingerprintCount: number
): value is SastFindingIdentitySummary {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      'version',
      'fingerprintVersion',
      'findingCount',
      'distinctFingerprintCount',
      'repeatedOccurrenceCount',
      'fingerprintPreimagesStored',
      'unstableCoordinatesIncluded',
      'scannerMatchIdentityAuthoritative',
      'rawSourceCandidatesStored',
      'secretValuesStored'
    ]) &&
    value.version === SAST_FINDING_IDENTITY_VERSION &&
    value.fingerprintVersion ===
      SAST_FINDING_FINGERPRINT_VERSION &&
    value.findingCount === findingCount &&
    value.distinctFingerprintCount ===
      distinctFingerprintCount &&
    value.repeatedOccurrenceCount ===
      findingCount - distinctFingerprintCount &&
    value.fingerprintPreimagesStored === false &&
    value.unstableCoordinatesIncluded === false &&
    value.scannerMatchIdentityAuthoritative === false &&
    value.rawSourceCandidatesStored === false &&
    value.secretValuesStored === false
  );
}

function isSastFindingIdentityAuthorityValid(
  value: unknown
): value is SastFindingIdentityAuthority {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      'normalizedFindingPersistenceEligible',
      'occurrenceAuthority',
      'lifecycleAuthority',
      'correlationAuthority',
      'coverageAuthority',
      'evidenceAuthority',
      'policyAuthority',
      'publicationAuthority',
      'aiPayloadEligible'
    ]) &&
    value.normalizedFindingPersistenceEligible === true &&
    value.occurrenceAuthority === false &&
    value.lifecycleAuthority === false &&
    value.correlationAuthority === false &&
    value.coverageAuthority === false &&
    value.evidenceAuthority === false &&
    value.policyAuthority === false &&
    value.publicationAuthority === false &&
    value.aiPayloadEligible === false
  );
}

function hasConsistentFingerprintPreimages(
  findings: readonly SastFingerprintedFinding[]
): boolean {
  const preimageByFingerprint = new Map<string, string>();
  for (const finding of findings) {
    const fingerprint = finding.fingerprint.stableFingerprint;
    const preimage = buildFindingFingerprintPreimage(
      toSastFindingFingerprintInput(
        stripSastFindingFingerprint(finding)
      )
    );
    const previous = preimageByFingerprint.get(fingerprint);
    if (previous !== undefined && previous !== preimage) {
      return false;
    }
    preimageByFingerprint.set(fingerprint, preimage);
  }
  return true;
}

function isStrictOrderedMembers(
  value: unknown,
  order: readonly string[]
): boolean {
  if (!Array.isArray(value)) return false;
  const indexes = value.map((entry) =>
    typeof entry === 'string' ? order.indexOf(entry) : -1
  );
  return (
    indexes.every((index) => index >= 0) &&
    indexes.every(
      (index, position) =>
        position === 0 ||
        index > (indexes[position - 1] as number)
    )
  );
}

function canonicalDigestMatches(
  digestCanonical: SastFindingIdentityCanonicalDigester,
  canonicalValue: string,
  expectedDigest: string
): boolean {
  try {
    return digestCanonical(canonicalValue) === expectedDigest;
  } catch {
    return false;
  }
}
