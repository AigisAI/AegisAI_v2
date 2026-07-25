import type {
  SastArtifactDispositionScope
} from './sast-artifact-disposition';
import {
  canonicalizeSastNormalizedFindingCandidate,
  compareSastNormalizedFindingCandidates,
  isSastNormalizedFindingCandidateShapeValid,
  orderSastNormalizationRejectionReasons,
  type SastNormalizationRejectionReasonCode,
  type TrivyNormalizedFindingCandidate
} from './sast-normalization';
import type { SastScanLane } from './sast-runtime';

export const TRIVY_JSON_NORMALIZER_VERSION =
  'trivy-json-normalizer-v1' as const;

export interface TrivyJsonNormalizationBatch {
  version: typeof TRIVY_JSON_NORMALIZER_VERSION;
  adapterVersion: typeof TRIVY_JSON_NORMALIZER_VERSION;
  artifactSchema: 'TRIVY_JSON';
  artifactSchemaVersion: '2';
  ingestionId: string;
  scope: Readonly<SastArtifactDispositionScope>;
  scannerRunId: string;
  scanner: 'TRIVY';
  scannerVersion: string;
  scannerImageDigest: `sha256:${string}`;
  ruleBundleDigest: `sha256:${string}`;
  vulnerabilityDatabaseDigest: `sha256:${string}`;
  planDigest: `sha256:${string}`;
  canonicalScanKey: `sha256:${string}`;
  preflightAttestationRef: string;
  preflightInventoryDigest: `sha256:${string}`;
  lane: SastScanLane;
  commitSha: string;
  envelopeDigest: `sha256:${string}`;
  artifactDigest: `sha256:${string}`;
  schemaBundleDigest: `sha256:${string}`;
  normalizerBundleDigest: `sha256:${string}`;
  validationResultDigest: `sha256:${string}`;
  dispositionDecisionDigest: `sha256:${string}`;
  findings: TrivyNormalizedFindingCandidate[];
  durablePersistenceAllowed: false;
  batchDigest: `sha256:${string}`;
}

export type TrivyJsonNormalizationBatchCore = Omit<
  TrivyJsonNormalizationBatch,
  'batchDigest'
>;

export interface TrivyJsonNormalizationSuccess {
  outcome: 'NORMALIZED';
  batch: TrivyJsonNormalizationBatch;
}

export interface TrivyJsonNormalizationRejection {
  version: typeof TRIVY_JSON_NORMALIZER_VERSION;
  adapterVersion: typeof TRIVY_JSON_NORMALIZER_VERSION;
  outcome: 'REJECTED';
  ingestionId: string;
  reasonCodes: SastNormalizationRejectionReasonCode[];
  rejectionDigest: `sha256:${string}`;
}

export type TrivyJsonNormalizationRejectionCore = Omit<
  TrivyJsonNormalizationRejection,
  'rejectionDigest'
>;

export type TrivyJsonNormalizationResult =
  | TrivyJsonNormalizationSuccess
  | TrivyJsonNormalizationRejection;

export function canonicalizeTrivyJsonNormalizationBatch(
  batch: Readonly<TrivyJsonNormalizationBatchCore>
): string {
  return JSON.stringify({
    version: batch.version,
    adapterVersion: batch.adapterVersion,
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
    vulnerabilityDatabaseDigest: batch.vulnerabilityDatabaseDigest,
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
    findings: batch.findings.map(
      canonicalizeSastNormalizedFindingCandidate
    ),
    durablePersistenceAllowed: false
  });
}

export function canonicalizeTrivyJsonNormalizationRejection(
  rejection: Readonly<TrivyJsonNormalizationRejectionCore>
): string {
  return JSON.stringify({
    version: rejection.version,
    adapterVersion: rejection.adapterVersion,
    outcome: rejection.outcome,
    ingestionId: rejection.ingestionId,
    reasonCodes: [...rejection.reasonCodes]
  });
}

export function isTrivyJsonNormalizationBatchShapeValid(
  value: unknown
): value is TrivyJsonNormalizationBatch {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'version',
      'adapterVersion',
      'artifactSchema',
      'artifactSchemaVersion',
      'ingestionId',
      'scope',
      'scannerRunId',
      'scanner',
      'scannerVersion',
      'scannerImageDigest',
      'ruleBundleDigest',
      'vulnerabilityDatabaseDigest',
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
      'findings',
      'durablePersistenceAllowed',
      'batchDigest'
    ]) ||
    value.version !== TRIVY_JSON_NORMALIZER_VERSION ||
    value.adapterVersion !== TRIVY_JSON_NORMALIZER_VERSION ||
    value.artifactSchema !== 'TRIVY_JSON' ||
    value.artifactSchemaVersion !== '2' ||
    !isBoundedReference(value.ingestionId) ||
    !isNormalizationScopeValid(value.scope) ||
    !isBoundedReference(value.scannerRunId) ||
    value.scanner !== 'TRIVY' ||
    !isBoundedIdentifier(value.scannerVersion, 255, false) ||
    !isAllowedString(value.lane, ['FAST', 'DEEP']) ||
    !isBoundedReference(value.preflightAttestationRef) ||
    !isCommitSha(value.commitSha) ||
    ![
      value.envelopeDigest,
      value.artifactDigest,
      value.scannerImageDigest,
      value.ruleBundleDigest,
      value.vulnerabilityDatabaseDigest,
      value.planDigest,
      value.canonicalScanKey,
      value.preflightInventoryDigest,
      value.schemaBundleDigest,
      value.normalizerBundleDigest,
      value.validationResultDigest,
      value.dispositionDecisionDigest,
      value.batchDigest
    ].every(isSha256Digest) ||
    !Array.isArray(value.findings) ||
    value.durablePersistenceAllowed !== false
  ) {
    return false;
  }

  const scope = value.scope as SastArtifactDispositionScope;
  if (value.scannerRunId !== scope.scannerRunId) return false;
  const findingsValid = value.findings.every(
    (finding) =>
      isSastNormalizedFindingCandidateShapeValid(finding) &&
      finding.provenance.scanner === 'TRIVY' &&
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
      finding.provenance.scannerVersion === value.scannerVersion &&
      finding.provenance.scannerImageDigest ===
        value.scannerImageDigest &&
      finding.provenance.ruleBundleDigest === value.ruleBundleDigest &&
      finding.provenance.vulnerabilityDatabaseDigest ===
        value.vulnerabilityDatabaseDigest &&
      finding.provenance.artifactDigest === value.artifactDigest
  );
  if (!findingsValid) return false;
  const findings =
    value.findings as readonly TrivyNormalizedFindingCandidate[];
  return findings.every(
    (finding, index) =>
      index === 0 ||
      compareSastNormalizedFindingCandidates(
        findings[index - 1] as TrivyNormalizedFindingCandidate,
        finding
      ) < 0
  );
}

export function isTrivyJsonNormalizationRejectionShapeValid(
  value: unknown
): value is TrivyJsonNormalizationRejection {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'version',
      'adapterVersion',
      'outcome',
      'ingestionId',
      'reasonCodes',
      'rejectionDigest'
    ]) ||
    value.version !== TRIVY_JSON_NORMALIZER_VERSION ||
    value.adapterVersion !== TRIVY_JSON_NORMALIZER_VERSION ||
    value.outcome !== 'REJECTED' ||
    !isBoundedReference(value.ingestionId) ||
    !Array.isArray(value.reasonCodes) ||
    value.reasonCodes.length === 0 ||
    !isSha256Digest(value.rejectionDigest)
  ) {
    return false;
  }
  return arraysEqual(
    value.reasonCodes,
    orderSastNormalizationRejectionReasons(
      value.reasonCodes as SastNormalizationRejectionReasonCode[]
    )
  );
}

function isNormalizationScopeValid(
  value: unknown
): value is SastArtifactDispositionScope {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      'tenantId',
      'repositoryBindingId',
      'scanRequestId',
      'attemptId',
      'scannerRunId'
    ]) &&
    Object.values(value).every(isBoundedReference)
  );
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

function isBoundedReference(value: unknown): value is string {
  return isBoundedIdentifier(value, 2048, false);
}

function isBoundedIdentifier(
  value: unknown,
  maximumBytes: number,
  allowEmpty: boolean
): value is string {
  return (
    typeof value === 'string' &&
    (allowEmpty || value.length > 0) &&
    value === value.normalize('NFC') &&
    value === value.trim() &&
    new TextEncoder().encode(value).byteLength <= maximumBytes &&
    ![...value].some((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return (
        codePoint <= 0x1f ||
        (codePoint >= 0x7f && codePoint <= 0x9f) ||
        (codePoint >= 0xd800 && codePoint <= 0xdfff)
      );
    })
  );
}

function isAllowedString(
  value: unknown,
  allowed: readonly string[]
): value is string {
  return typeof value === 'string' && allowed.includes(value);
}

function isCommitSha(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/u.test(value)
  );
}

function isSha256Digest(value: unknown): value is `sha256:${string}` {
  return (
    typeof value === 'string' &&
    /^sha256:[a-f0-9]{64}$/u.test(value)
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function hasExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[]
): boolean {
  const actual = Object.keys(value);
  return (
    actual.length === expected.length &&
    actual.every((key) => expected.includes(key))
  );
}
