import type {
  SastArtifactDispositionScope
} from './sast-artifact-disposition';
import {
  canonicalizeSastNormalizedFindingCandidate,
  compareSastNormalizedFindingCandidates,
  isSastNormalizedFindingCandidateShapeValid,
  OPENGREP_SARIF_NORMALIZER_VERSION,
  type SastNormalizedFindingCandidate
} from './sast-normalization';
import {
  hasExactKeys,
  isAllowedString,
  isBoundedIdentifier,
  isBoundedReference,
  isCommitSha,
  isNormalizationScopeValid,
  isRecord,
  isSha256Digest
} from './sast-normalization-validation';
import {
  TRIVY_JSON_NORMALIZER_VERSION
} from './sast-trivy-normalization';

export const SAST_SECRET_REDACTION_VERSION =
  'sast-secret-redaction-v1' as const;

/**
 * A fixed, non-secret-bearing marker prevents the replacement from exposing
 * secret length, a matched-value digest, or provider-specific secret detail.
 */
export const SAST_SECRET_REDACTION_TOKEN = '[REDACTED]' as const;

export const SAST_SECRET_REDACTION_LIMITS = Object.freeze({
  maximumCandidates: 25_000,
  maximumPlatformSecretValues: 64,
  maximumPlatformSecretValueBytes: 4_096,
  maximumPlatformSecretValueTotalBytes: 65_536
});

export const SAST_SECRET_REDACTION_BATCH_INSPECTED_FIELD_COUNT = 8;

/**
 * Order is part of every redaction decision digest.
 */
export const SAST_SECRET_DETECTOR_KINDS = [
  'PLATFORM_VALUE',
  'PRIVATE_KEY',
  'AUTHORIZATION_CREDENTIAL',
  'URL_CREDENTIAL',
  'AWS_ACCESS_KEY_ID',
  'GITHUB_TOKEN',
  'GITLAB_TOKEN',
  'SLACK_TOKEN',
  'GOOGLE_API_KEY',
  'STRIPE_KEY',
  'SENDGRID_KEY',
  'JWT',
  'SECRET_ASSIGNMENT',
  'HIGH_ENTROPY'
] as const;
export type SastSecretDetectorKind =
  (typeof SAST_SECRET_DETECTOR_KINDS)[number];

export const SAST_SECRET_REDACTABLE_FIELDS = [
  'TITLE',
  'DESCRIPTION',
  'LOCATION_SYMBOL'
] as const;
export type SastSecretRedactableField =
  (typeof SAST_SECRET_REDACTABLE_FIELDS)[number];

/**
 * Rejections are intentionally coarse. A field name, matched value, match
 * length, or matched-value digest would become a secret side channel.
 */
export const SAST_SECRET_REDACTION_REJECTION_REASON_CODES = [
  'SECRET_REDACTION_INPUT_INVALID',
  'SECRET_REDACTION_SOURCE_DIGEST_MISMATCH',
  'SECRET_REDACTION_DISPOSITION_INVALID',
  'SECRET_REDACTION_RETENTION_EXPIRED',
  'SECRET_REDACTION_PLATFORM_VALUES_INVALID',
  'SECRET_REDACTION_RESERVED_TOKEN_PRESENT',
  'SECRET_REDACTION_IDENTITY_FIELD_BLOCKED',
  'SECRET_REDACTION_OUTPUT_INVALID'
] as const;
export type SastSecretRedactionRejectionReasonCode =
  (typeof SAST_SECRET_REDACTION_REJECTION_REASON_CODES)[number];

export type SastSecretRedactionSourceAdapterVersion =
  | typeof OPENGREP_SARIF_NORMALIZER_VERSION
  | typeof TRIVY_JSON_NORMALIZER_VERSION;

export interface SastFindingSecretRedaction {
  version: typeof SAST_SECRET_REDACTION_VERSION;
  secretRedactionApplied: true;
  replacementToken: typeof SAST_SECRET_REDACTION_TOKEN;
  inspectedFieldCount: number;
  redactedFields: SastSecretRedactableField[];
  replacementCount: number;
  detectorKinds: SastSecretDetectorKind[];
  secretValueStored: false;
  matchedValueDigestStored: false;
  rawCandidateStored: false;
  decisionDigest: `sha256:${string}`;
  decisionRef: string;
}

type WithSecretRedaction<T> =
  T extends SastNormalizedFindingCandidate
    ? Omit<T, 'durablePersistenceAllowed'> & {
        redaction: SastFindingSecretRedaction;
        durablePersistenceAllowed: false;
      }
    : never;

export type SastSecretRedactedFindingCandidate =
  WithSecretRedaction<SastNormalizedFindingCandidate>;

export type SastSecretRedactedFindingCandidateCore =
  Omit<SastSecretRedactedFindingCandidate, 'redaction'> & {
    redaction: Omit<
      SastFindingSecretRedaction,
      'decisionDigest' | 'decisionRef'
    >;
  };

export interface SastSecretRedactionSummary {
  version: typeof SAST_SECRET_REDACTION_VERSION;
  secretRedactionApplied: true;
  candidateCount: number;
  batchInspectedFieldCount: number;
  inspectedFieldCount: number;
  redactedCandidateCount: number;
  redactedFieldCount: number;
  replacementCount: number;
  detectorKinds: SastSecretDetectorKind[];
  secretValuesStored: false;
  matchedValueDigestsStored: false;
  rawCandidatesStored: false;
  sourceCandidateDigestStored: false;
}

export interface SastSecretRedactionBatch {
  version: typeof SAST_SECRET_REDACTION_VERSION;
  outcome: 'REDACTED';
  sourceAdapterVersion: SastSecretRedactionSourceAdapterVersion;
  artifactSchema: 'OPENGREP_SARIF' | 'TRIVY_JSON';
  artifactSchemaVersion: '2.1.0' | '2';
  ingestionId: string;
  scope: Readonly<SastArtifactDispositionScope>;
  scannerRunId: string;
  scanner: 'OPENGREP' | 'TRIVY';
  scannerVersion: string;
  scannerImageDigest: `sha256:${string}`;
  ruleBundleDigest: `sha256:${string}`;
  vulnerabilityDatabaseDigest?: `sha256:${string}`;
  planDigest: `sha256:${string}`;
  canonicalScanKey: `sha256:${string}`;
  preflightAttestationRef: string;
  preflightInventoryDigest: `sha256:${string}`;
  lane: 'FAST' | 'DEEP';
  commitSha: string;
  envelopeDigest: `sha256:${string}`;
  artifactDigest: `sha256:${string}`;
  schemaBundleDigest: `sha256:${string}`;
  normalizerBundleDigest: `sha256:${string}`;
  validationResultDigest: `sha256:${string}`;
  dispositionDecisionDigest: `sha256:${string}`;
  retentionExpiresAt: string;
  findings: SastSecretRedactedFindingCandidate[];
  redaction: SastSecretRedactionSummary;
  durablePersistenceAllowed: false;
  batchDigest: `sha256:${string}`;
}

export type SastSecretRedactionBatchCore = Omit<
  SastSecretRedactionBatch,
  'batchDigest'
>;

export interface SastSecretRedactionSuccess {
  outcome: 'REDACTED';
  batch: SastSecretRedactionBatch;
}

export interface SastSecretRedactionRejection {
  version: typeof SAST_SECRET_REDACTION_VERSION;
  outcome: 'REJECTED';
  reasonCodes: SastSecretRedactionRejectionReasonCode[];
  secretValuesStored: false;
  matchedValueDigestsStored: false;
  sourceCandidateDigestStored: false;
  rejectionDigest: `sha256:${string}`;
}

export type SastSecretRedactionRejectionCore = Omit<
  SastSecretRedactionRejection,
  'rejectionDigest'
>;

export type SastSecretRedactionResult =
  | SastSecretRedactionSuccess
  | SastSecretRedactionRejection;

export type SastSecretRedactionAuditMetadata =
  | {
      version: typeof SAST_SECRET_REDACTION_VERSION;
      outcome: 'REDACTED';
      batchDigest: `sha256:${string}`;
      artifactDigest: `sha256:${string}`;
      dispositionDecisionDigest: `sha256:${string}`;
      candidateCount: number;
      redactedCandidateCount: number;
      replacementCount: number;
      detectorKinds: SastSecretDetectorKind[];
    }
  | {
      version: typeof SAST_SECRET_REDACTION_VERSION;
      outcome: 'REJECTED';
      reasonCodes: SastSecretRedactionRejectionReasonCode[];
      rejectionDigest: `sha256:${string}`;
    };

export function orderSastSecretDetectorKinds(
  kinds: Iterable<SastSecretDetectorKind>
): SastSecretDetectorKind[] {
  const present = new Set(kinds);
  return SAST_SECRET_DETECTOR_KINDS.filter((kind) =>
    present.has(kind)
  );
}

export function orderSastSecretRedactableFields(
  fields: Iterable<SastSecretRedactableField>
): SastSecretRedactableField[] {
  const present = new Set(fields);
  return SAST_SECRET_REDACTABLE_FIELDS.filter((field) =>
    present.has(field)
  );
}

export function orderSastSecretRedactionRejectionReasons(
  reasons: Iterable<SastSecretRedactionRejectionReasonCode>
): SastSecretRedactionRejectionReasonCode[] {
  const present = new Set(reasons);
  return SAST_SECRET_REDACTION_REJECTION_REASON_CODES.filter(
    (reason) => present.has(reason)
  );
}

export function canonicalizeSastSecretRedactedFindingCandidate(
  finding: Readonly<SastSecretRedactedFindingCandidate>
): string {
  const base = stripSastSecretRedaction(finding);
  return JSON.stringify({
    candidate: canonicalizeSastNormalizedFindingCandidate(base),
    redaction: {
      version: finding.redaction.version,
      secretRedactionApplied: true,
      replacementToken: finding.redaction.replacementToken,
      inspectedFieldCount: finding.redaction.inspectedFieldCount,
      redactedFields: [...finding.redaction.redactedFields],
      replacementCount: finding.redaction.replacementCount,
      detectorKinds: [...finding.redaction.detectorKinds],
      secretValueStored: false,
      matchedValueDigestStored: false,
      rawCandidateStored: false,
      decisionDigest: finding.redaction.decisionDigest,
      decisionRef: finding.redaction.decisionRef
    }
  });
}

export function canonicalizeSastSecretRedactionDecision(
  finding: Readonly<SastSecretRedactedFindingCandidateCore>
): string {
  const base = stripSastSecretRedaction(finding);
  return JSON.stringify({
    candidate: canonicalizeSastNormalizedFindingCandidate(base),
    redaction: {
      version: finding.redaction.version,
      secretRedactionApplied: true,
      replacementToken: finding.redaction.replacementToken,
      inspectedFieldCount: finding.redaction.inspectedFieldCount,
      redactedFields: [...finding.redaction.redactedFields],
      replacementCount: finding.redaction.replacementCount,
      detectorKinds: [...finding.redaction.detectorKinds],
      secretValueStored: false,
      matchedValueDigestStored: false,
      rawCandidateStored: false
    }
  });
}

export function canonicalizeSastSecretRedactionBatch(
  batch: Readonly<SastSecretRedactionBatchCore>
): string {
  return JSON.stringify({
    version: batch.version,
    outcome: batch.outcome,
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
    ...(batch.vulnerabilityDatabaseDigest
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
    findings: batch.findings.map(
      canonicalizeSastSecretRedactedFindingCandidate
    ),
    redaction: {
      version: batch.redaction.version,
      secretRedactionApplied: true,
      candidateCount: batch.redaction.candidateCount,
      batchInspectedFieldCount:
        batch.redaction.batchInspectedFieldCount,
      inspectedFieldCount: batch.redaction.inspectedFieldCount,
      redactedCandidateCount:
        batch.redaction.redactedCandidateCount,
      redactedFieldCount: batch.redaction.redactedFieldCount,
      replacementCount: batch.redaction.replacementCount,
      detectorKinds: [...batch.redaction.detectorKinds],
      secretValuesStored: false,
      matchedValueDigestsStored: false,
      rawCandidatesStored: false,
      sourceCandidateDigestStored: false
    },
    durablePersistenceAllowed: false
  });
}

export function canonicalizeSastSecretRedactionRejection(
  rejection: Readonly<SastSecretRedactionRejectionCore>
): string {
  return JSON.stringify({
    version: rejection.version,
    outcome: rejection.outcome,
    reasonCodes: [...rejection.reasonCodes],
    secretValuesStored: false,
    matchedValueDigestsStored: false,
    sourceCandidateDigestStored: false
  });
}

export function isSastSecretRedactionBatchShapeValid(
  value: unknown
): value is SastSecretRedactionBatch {
  if (!isRecord(value)) return false;
  const isTrivy = value.scanner === 'TRIVY';
  const commonKeys = [
    'version',
    'outcome',
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
    'findings',
    'redaction',
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
    value.version !== SAST_SECRET_REDACTION_VERSION ||
    value.outcome !== 'REDACTED' ||
    !isBoundedReference(value.ingestionId) ||
    !isNormalizationScopeValid(value.scope) ||
    !isBoundedReference(value.scannerRunId) ||
    !isBoundedIdentifier(value.scannerVersion, 255, false) ||
    !isAllowedString(value.lane, ['FAST', 'DEEP']) ||
    !isBoundedReference(value.preflightAttestationRef) ||
    !isCommitSha(value.commitSha) ||
    !isIsoTimestamp(value.retentionExpiresAt) ||
    ![
      value.scannerImageDigest,
      value.ruleBundleDigest,
      value.planDigest,
      value.canonicalScanKey,
      value.preflightInventoryDigest,
      value.envelopeDigest,
      value.artifactDigest,
      value.schemaBundleDigest,
      value.normalizerBundleDigest,
      value.validationResultDigest,
      value.dispositionDecisionDigest,
      value.batchDigest
    ].every(isSha256Digest) ||
    !Array.isArray(value.findings) ||
    value.findings.length >
      SAST_SECRET_REDACTION_LIMITS.maximumCandidates ||
    !isSastSecretRedactionSummaryValid(value.redaction) ||
    value.durablePersistenceAllowed !== false
  ) {
    return false;
  }
  if (
    isTrivy
      ? value.sourceAdapterVersion !==
          TRIVY_JSON_NORMALIZER_VERSION ||
        value.artifactSchema !== 'TRIVY_JSON' ||
        value.artifactSchemaVersion !== '2' ||
        !isSha256Digest(value.vulnerabilityDatabaseDigest)
      : value.scanner !== 'OPENGREP' ||
        value.sourceAdapterVersion !==
          OPENGREP_SARIF_NORMALIZER_VERSION ||
        value.artifactSchema !== 'OPENGREP_SARIF' ||
        value.artifactSchemaVersion !== '2.1.0' ||
        'vulnerabilityDatabaseDigest' in value
  ) {
    return false;
  }

  const scope = value.scope as SastArtifactDispositionScope;
  if (value.scannerRunId !== scope.scannerRunId) return false;
  const findings =
    value.findings as readonly SastSecretRedactedFindingCandidate[];
  if (
    !findings.every(
      (finding) =>
        isSastSecretRedactedFindingCandidateShapeValid(finding) &&
        finding.tenantId === scope.tenantId &&
        finding.repositoryBindingId === scope.repositoryBindingId &&
        finding.scanRequestId === scope.scanRequestId &&
        finding.attemptId === scope.attemptId &&
        finding.scannerRunId === value.scannerRunId &&
        finding.planDigest === value.planDigest &&
        finding.canonicalScanKey === value.canonicalScanKey &&
        finding.preflightAttestationRef ===
          value.preflightAttestationRef &&
        finding.preflightInventoryDigest ===
          value.preflightInventoryDigest &&
        finding.commitSha === value.commitSha &&
        finding.lane === value.lane &&
        finding.provenance.scanner === value.scanner &&
        finding.provenance.scannerVersion ===
          value.scannerVersion &&
        finding.provenance.scannerImageDigest ===
          value.scannerImageDigest &&
        finding.provenance.ruleBundleDigest ===
          value.ruleBundleDigest &&
        finding.provenance.artifactDigest ===
          value.artifactDigest &&
        (isTrivy
          ? finding.provenance.scanner === 'TRIVY' &&
            finding.provenance.vulnerabilityDatabaseDigest ===
              value.vulnerabilityDatabaseDigest
          : finding.provenance.scanner === 'OPENGREP')
    )
  ) {
    return false;
  }
  if (
    !findings.every(
      (finding, index) =>
        index === 0 ||
        compareSastNormalizedFindingCandidates(
          stripSastSecretRedaction(
            findings[index - 1] as SastSecretRedactedFindingCandidate
          ),
          stripSastSecretRedaction(finding)
        ) < 0
    )
  ) {
    return false;
  }

  const summary = value.redaction as SastSecretRedactionSummary;
  const inspectedFieldCount = findings.reduce(
    (sum, finding) =>
      sum + finding.redaction.inspectedFieldCount,
    0
  );
  const redactedCandidateCount = findings.filter(
    (finding) => finding.redaction.replacementCount > 0
  ).length;
  const redactedFieldCount = findings.reduce(
    (sum, finding) =>
      sum + finding.redaction.redactedFields.length,
    0
  );
  const replacementCount = findings.reduce(
    (sum, finding) => sum + finding.redaction.replacementCount,
    0
  );
  const detectorKinds = orderSastSecretDetectorKinds(
    findings.flatMap((finding) => finding.redaction.detectorKinds)
  );
  return (
    summary.candidateCount === findings.length &&
    summary.batchInspectedFieldCount ===
      SAST_SECRET_REDACTION_BATCH_INSPECTED_FIELD_COUNT &&
    summary.inspectedFieldCount ===
      inspectedFieldCount +
        SAST_SECRET_REDACTION_BATCH_INSPECTED_FIELD_COUNT &&
    summary.redactedCandidateCount === redactedCandidateCount &&
    summary.redactedFieldCount === redactedFieldCount &&
    summary.replacementCount === replacementCount &&
    arraysEqual(summary.detectorKinds, detectorKinds)
  );
}

export function isSastSecretRedactedFindingCandidateShapeValid(
  value: unknown
): value is SastSecretRedactedFindingCandidate {
  if (
    !isRecord(value) ||
    !isRecord(value.redaction) ||
    !isSastFindingSecretRedactionValid(value.redaction)
  ) {
    return false;
  }
  const base = stripSastSecretRedaction(
    value as SastSecretRedactedFindingCandidate
  );
  if (!isSastNormalizedFindingCandidateShapeValid(base)) {
    return false;
  }
  const displayValues: Record<SastSecretRedactableField, string> = {
    TITLE: base.title,
    DESCRIPTION: base.description,
    LOCATION_SYMBOL:
      base.location.symbol === undefined
        ? ''
        : base.location.symbol
  };
  const actualFields = orderSastSecretRedactableFields(
    SAST_SECRET_REDACTABLE_FIELDS.filter((field) =>
      displayValues[field].includes(SAST_SECRET_REDACTION_TOKEN)
    )
  );
  const replacementCount = Object.values(displayValues).reduce(
    (sum, text) =>
      sum + countOccurrences(text, SAST_SECRET_REDACTION_TOKEN),
    0
  );
  const redaction =
    value.redaction as unknown as SastFindingSecretRedaction;
  return (
    arraysEqual(redaction.redactedFields, actualFields) &&
    redaction.replacementCount === replacementCount &&
    (replacementCount === 0
      ? redaction.detectorKinds.length === 0 &&
        redaction.redactedFields.length === 0
      : redaction.detectorKinds.length > 0 &&
        redaction.redactedFields.length > 0)
  );
}

export function isSastSecretRedactionRejectionShapeValid(
  value: unknown
): value is SastSecretRedactionRejection {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      'version',
      'outcome',
      'reasonCodes',
      'secretValuesStored',
      'matchedValueDigestsStored',
      'sourceCandidateDigestStored',
      'rejectionDigest'
    ]) &&
    value.version === SAST_SECRET_REDACTION_VERSION &&
    value.outcome === 'REJECTED' &&
    isStrictOrderedMembers(
      value.reasonCodes,
      SAST_SECRET_REDACTION_REJECTION_REASON_CODES
    ) &&
    (value.reasonCodes as readonly unknown[]).length > 0 &&
    value.secretValuesStored === false &&
    value.matchedValueDigestsStored === false &&
    value.sourceCandidateDigestStored === false &&
    isSha256Digest(value.rejectionDigest)
  );
}

export function toSastSecretRedactionAuditMetadata(
  result: unknown
): SastSecretRedactionAuditMetadata {
  if (isSastSecretRedactionRejectionShapeValid(result)) {
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
    result.outcome !== 'REDACTED' ||
    !isSastSecretRedactionBatchShapeValid(result.batch)
  ) {
    throw new TypeError(
      'SAST secret-redaction result is invalid.'
    );
  }
  const batch = result.batch;
  return {
    version: batch.version,
    outcome: result.outcome,
    batchDigest: batch.batchDigest,
    artifactDigest: batch.artifactDigest,
    dispositionDecisionDigest:
      batch.dispositionDecisionDigest,
    candidateCount: batch.redaction.candidateCount,
    redactedCandidateCount:
      batch.redaction.redactedCandidateCount,
    replacementCount: batch.redaction.replacementCount,
    detectorKinds: [...batch.redaction.detectorKinds]
  };
}

export function stripSastSecretRedaction(
  finding:
    | Readonly<SastSecretRedactedFindingCandidate>
    | Readonly<SastSecretRedactedFindingCandidateCore>
): SastNormalizedFindingCandidate {
  const { redaction, ...base } = finding;
  void redaction;
  return base as SastNormalizedFindingCandidate;
}

function isSastFindingSecretRedactionValid(
  value: Record<string, unknown>
): boolean {
  return (
    hasExactKeys(value, [
      'version',
      'secretRedactionApplied',
      'replacementToken',
      'inspectedFieldCount',
      'redactedFields',
      'replacementCount',
      'detectorKinds',
      'secretValueStored',
      'matchedValueDigestStored',
      'rawCandidateStored',
      'decisionDigest',
      'decisionRef'
    ]) &&
    value.version === SAST_SECRET_REDACTION_VERSION &&
    value.secretRedactionApplied === true &&
    value.replacementToken === SAST_SECRET_REDACTION_TOKEN &&
    isPositiveSafeInteger(value.inspectedFieldCount) &&
    isStrictOrderedMembers(
      value.redactedFields,
      SAST_SECRET_REDACTABLE_FIELDS
    ) &&
    isNonNegativeSafeInteger(value.replacementCount) &&
    isStrictOrderedMembers(
      value.detectorKinds,
      SAST_SECRET_DETECTOR_KINDS
    ) &&
    value.secretValueStored === false &&
    value.matchedValueDigestStored === false &&
    value.rawCandidateStored === false &&
    isSha256Digest(value.decisionDigest) &&
    value.decisionRef ===
      `redaction://${SAST_SECRET_REDACTION_VERSION}/${
        (value.decisionDigest as string).slice('sha256:'.length)
      }`
  );
}

function isSastSecretRedactionSummaryValid(
  value: unknown
): value is SastSecretRedactionSummary {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      'version',
      'secretRedactionApplied',
      'candidateCount',
      'batchInspectedFieldCount',
      'inspectedFieldCount',
      'redactedCandidateCount',
      'redactedFieldCount',
      'replacementCount',
      'detectorKinds',
      'secretValuesStored',
      'matchedValueDigestsStored',
      'rawCandidatesStored',
      'sourceCandidateDigestStored'
    ]) &&
    value.version === SAST_SECRET_REDACTION_VERSION &&
    value.secretRedactionApplied === true &&
    isNonNegativeSafeInteger(value.candidateCount) &&
    value.batchInspectedFieldCount ===
      SAST_SECRET_REDACTION_BATCH_INSPECTED_FIELD_COUNT &&
    isNonNegativeSafeInteger(value.inspectedFieldCount) &&
    value.inspectedFieldCount >= value.batchInspectedFieldCount &&
    isNonNegativeSafeInteger(value.redactedCandidateCount) &&
    isNonNegativeSafeInteger(value.redactedFieldCount) &&
    isNonNegativeSafeInteger(value.replacementCount) &&
    value.redactedCandidateCount <= value.candidateCount &&
    value.redactedFieldCount <=
      value.candidateCount *
        SAST_SECRET_REDACTABLE_FIELDS.length &&
    isStrictOrderedMembers(
      value.detectorKinds,
      SAST_SECRET_DETECTOR_KINDS
    ) &&
    value.secretValuesStored === false &&
    value.matchedValueDigestsStored === false &&
    value.rawCandidatesStored === false &&
    value.sourceCandidateDigestStored === false
  );
}

function isStrictOrderedMembers(
  value: unknown,
  allowed: readonly string[]
): boolean {
  if (!Array.isArray(value)) return false;
  let previous = -1;
  for (const member of value) {
    if (typeof member !== 'string') return false;
    const index = allowed.indexOf(member);
    if (index <= previous) return false;
    previous = index;
  }
  return true;
}

function isNonNegativeSafeInteger(value: unknown): value is number {
  return (
    typeof value === 'number' &&
    Number.isSafeInteger(value) &&
    value >= 0
  );
}

function isPositiveSafeInteger(value: unknown): value is number {
  return isNonNegativeSafeInteger(value) && value > 0;
}

function isIsoTimestamp(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    Number.isFinite(Date.parse(value)) &&
    new Date(value).toISOString() === value
  );
}

function countOccurrences(text: string, token: string): number {
  let count = 0;
  let offset = 0;
  while (offset <= text.length - token.length) {
    const index = text.indexOf(token, offset);
    if (index < 0) break;
    count += 1;
    offset = index + token.length;
  }
  return count;
}

function arraysEqual(
  left: readonly unknown[],
  right: readonly unknown[]
): boolean {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}
