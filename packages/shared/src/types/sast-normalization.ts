import type {
  SastArtifactDispositionScope
} from './sast-artifact-disposition';
import type {
  SastFindingLocation,
  SastFindingProvenance,
  SastScanLane
} from './sast-runtime';

export const OPENGREP_SARIF_NORMALIZER_VERSION =
  'opengrep-sarif-normalizer-v1' as const;

export const SAST_NORMALIZATION_LIMITS = Object.freeze({
  titleBytes: 512,
  descriptionBytes: 4096,
  normalizedPathBytes: 1024,
  symbolBytes: 512,
  ruleIdBytes: 256,
  ruleRevisionBytes: 256,
  scannerIdentityHintBytes: 512,
  vulnerabilityIdentifierBytes: 64,
  vulnerabilityIdBytes: 256,
  packageNameBytes: 512,
  packageVersionBytes: 512,
  packageTypeBytes: 128,
  trivyCategoryBytes: 128,
  maximumRuleTags: 128,
  maximumCweIds: 25,
  maximumCveIds: 25
});

/**
 * Order is part of the rejection digest contract. Adapters must de-duplicate
 * and return reasons in this order, never in discovery order.
 */
export const SAST_NORMALIZATION_REJECTION_REASON_CODES = [
  'NORMALIZATION_ACCEPTANCE_INVALID',
  'NORMALIZATION_RETENTION_EXPIRED',
  'NORMALIZATION_PLAN_BINDING_MISMATCH',
  'NORMALIZATION_VALIDATION_BINDING_MISMATCH',
  'NORMALIZATION_CONTENT_DIGEST_MISMATCH',
  'NORMALIZATION_BYTE_SIZE_MISMATCH',
  'NORMALIZATION_SCHEMA_UNSUPPORTED',
  'NORMALIZATION_ARTIFACT_STREAM_INVALID',
  'NORMALIZATION_OPENGREP_STRUCTURE_INVALID',
  'NORMALIZATION_OPENGREP_DRIVER_INVALID',
  'NORMALIZATION_OPENGREP_INVOCATION_INVALID',
  'NORMALIZATION_OPENGREP_RULE_INVALID',
  'NORMALIZATION_OPENGREP_RESULT_INVALID',
  'NORMALIZATION_OPENGREP_LOCATION_INVALID',
  'NORMALIZATION_TRIVY_STRUCTURE_INVALID',
  'NORMALIZATION_TRIVY_RESULT_INVALID',
  'NORMALIZATION_TRIVY_VULNERABILITY_INVALID',
  'NORMALIZATION_TRIVY_SECRET_INVALID',
  'NORMALIZATION_TRIVY_MISCONFIGURATION_INVALID',
  'NORMALIZATION_TRIVY_RULE_INVALID',
  'NORMALIZATION_TRIVY_LOCATION_INVALID',
  'NORMALIZATION_TRIVY_SUPPRESSION_INVALID',
  'NORMALIZATION_TRIVY_PACKAGE_INVALID',
  'NORMALIZATION_TEXT_INVALID',
  'NORMALIZATION_FIELD_LIMIT_EXCEEDED',
  'NORMALIZATION_IDENTIFIER_INVALID',
  'NORMALIZATION_IDENTIFIER_LIMIT_EXCEEDED'
] as const;
export type SastNormalizationRejectionReasonCode =
  (typeof SAST_NORMALIZATION_REJECTION_REASON_CODES)[number];

export const SAST_NORMALIZATION_NOTE_CODES = [
  'UNKNOWN_SEVERITY',
  'UNKNOWN_CONFIDENCE'
] as const;
export type SastNormalizationNoteCode =
  (typeof SAST_NORMALIZATION_NOTE_CODES)[number];

/**
 * Scanner identity data is an input to T036. It is not an authoritative
 * platform fingerprint and must never be used directly as finding identity.
 */
export interface SastFindingIdentityMaterial {
  ruleSemanticId: string;
  symbolAnchor: string;
  sinkKind: string;
  structuralHash: string;
  scannerMatchBasedId: string;
}

export const TRIVY_SCANNER_DISPOSITION_STATUSES = [
  'active',
  'ignored',
  'unknown',
  'not_affected',
  'affected',
  'fixed',
  'under_investigation'
] as const;
export type TrivyScannerDispositionStatus =
  (typeof TRIVY_SCANNER_DISPOSITION_STATUSES)[number];

/**
 * Trivy can emit externally modified findings when --show-suppressed is
 * enabled. This value is provenance only and can never become a platform
 * waiver, suppression, severity, lifecycle, or policy decision.
 */
export interface TrivyScannerDispositionProvenance {
  source: 'DIRECT' | 'MODIFIED';
  status: TrivyScannerDispositionStatus;
  platformPolicyAuthority: false;
}

export interface TrivyDependencyVulnerabilityDetails {
  kind: 'DEPENDENCY_VULNERABILITY';
  vulnerabilityId: string;
  packageName: string;
  packageType: string;
  installedVersion: string;
  fixedVersion: string;
  advisoryStatus:
    | 'unknown'
    | 'not_affected'
    | 'affected'
    | 'fixed'
    | 'under_investigation'
    | 'will_not_fix'
    | 'fix_deferred'
    | 'end_of_life';
}

export interface TrivySecretDetectionDetails {
  kind: 'SECRET_DETECTION';
  category: string;
  secretValueStored: false;
  secretPayloadDiscarded: true;
}

export interface TrivyIacMisconfigurationDetails {
  kind: 'IAC_MISCONFIGURATION';
  checkType: string;
  avdId: string;
  resultStatus: 'FAIL';
}

export type TrivyFindingDetails =
  | TrivyDependencyVulnerabilityDetails
  | TrivySecretDetectionDetails
  | TrivyIacMisconfigurationDetails;

export interface TrivyFindingProvenance
  extends SastFindingProvenance {
  scanner: 'TRIVY';
  ruleSource: 'CHECK_BUNDLE' | 'VULNERABILITY_DATABASE';
  vulnerabilityDatabaseDigest: `sha256:${string}`;
}

/**
 * T032/T033 adapters return transient candidates. T035 must redact them and
 * T036 must compute the platform fingerprint before durable finding storage.
 */
interface SastNormalizedFindingCandidateBase {
  tenantId: string;
  repositoryBindingId: string;
  scanRequestId: string;
  attemptId: string;
  scannerRunId: string;
  planDigest: `sha256:${string}`;
  canonicalScanKey: `sha256:${string}`;
  preflightAttestationRef: string;
  preflightInventoryDigest: `sha256:${string}`;
  commitSha: string;
  lane: SastScanLane;
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  confidence: 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  cweIds: string[];
  cveIds: string[];
  location: SastFindingLocation;
  identityMaterial: SastFindingIdentityMaterial;
  notes: SastNormalizationNoteCode[];
  durablePersistenceAllowed: false;
}

export interface OpenGrepNormalizedFindingCandidate
  extends SastNormalizedFindingCandidateBase {
  capability: 'SAST';
  provenance: SastFindingProvenance & { scanner: 'OPENGREP' };
}

interface TrivyNormalizedFindingCandidateBase
  extends SastNormalizedFindingCandidateBase {
  scannerDisposition: TrivyScannerDispositionProvenance;
}

export type TrivyNormalizedFindingCandidate =
  | (TrivyNormalizedFindingCandidateBase & {
      capability: 'DEPENDENCY_VULNERABILITY';
      provenance: TrivyFindingProvenance & {
        ruleSource: 'VULNERABILITY_DATABASE';
      };
      trivy: TrivyDependencyVulnerabilityDetails;
    })
  | (TrivyNormalizedFindingCandidateBase & {
      capability: 'SECRET_DETECTION';
      provenance: TrivyFindingProvenance & {
        ruleSource: 'CHECK_BUNDLE';
      };
      trivy: TrivySecretDetectionDetails;
    })
  | (TrivyNormalizedFindingCandidateBase & {
      capability: 'IAC_MISCONFIGURATION';
      provenance: TrivyFindingProvenance & {
        ruleSource: 'CHECK_BUNDLE';
      };
      trivy: TrivyIacMisconfigurationDetails;
    });

export type SastNormalizedFindingCandidate =
  | OpenGrepNormalizedFindingCandidate
  | TrivyNormalizedFindingCandidate;

export interface OpenGrepSarifNormalizationBatch {
  version: typeof OPENGREP_SARIF_NORMALIZER_VERSION;
  adapterVersion: typeof OPENGREP_SARIF_NORMALIZER_VERSION;
  artifactSchema: 'OPENGREP_SARIF';
  artifactSchemaVersion: '2.1.0';
  ingestionId: string;
  scope: Readonly<SastArtifactDispositionScope>;
  scannerRunId: string;
  scanner: 'OPENGREP';
  scannerVersion: string;
  scannerImageDigest: `sha256:${string}`;
  ruleBundleDigest: `sha256:${string}`;
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
  findings: OpenGrepNormalizedFindingCandidate[];
  durablePersistenceAllowed: false;
  batchDigest: `sha256:${string}`;
}

export type OpenGrepSarifNormalizationBatchCore = Omit<
  OpenGrepSarifNormalizationBatch,
  'batchDigest'
>;

export interface OpenGrepSarifNormalizationSuccess {
  outcome: 'NORMALIZED';
  batch: OpenGrepSarifNormalizationBatch;
}

export interface OpenGrepSarifNormalizationRejection {
  version: typeof OPENGREP_SARIF_NORMALIZER_VERSION;
  adapterVersion: typeof OPENGREP_SARIF_NORMALIZER_VERSION;
  outcome: 'REJECTED';
  ingestionId: string;
  reasonCodes: SastNormalizationRejectionReasonCode[];
  rejectionDigest: `sha256:${string}`;
}

export type OpenGrepSarifNormalizationRejectionCore = Omit<
  OpenGrepSarifNormalizationRejection,
  'rejectionDigest'
>;

export type OpenGrepSarifNormalizationResult =
  | OpenGrepSarifNormalizationSuccess
  | OpenGrepSarifNormalizationRejection;

export function orderSastNormalizationRejectionReasons(
  reasons: Iterable<SastNormalizationRejectionReasonCode>
): SastNormalizationRejectionReasonCode[] {
  const present = new Set(reasons);
  return SAST_NORMALIZATION_REJECTION_REASON_CODES.filter((reason) =>
    present.has(reason)
  );
}

export function orderSastNormalizationNotes(
  notes: Iterable<SastNormalizationNoteCode>
): SastNormalizationNoteCode[] {
  const present = new Set(notes);
  return SAST_NORMALIZATION_NOTE_CODES.filter((note) =>
    present.has(note)
  );
}

export function compareSastNormalizationIdentifiers(
  left: string,
  right: string
): number {
  const leftParts = left.match(/\d+|\D+/gu) ?? [left];
  const rightParts = right.match(/\d+|\D+/gu) ?? [right];
  const length = Math.min(leftParts.length, rightParts.length);
  for (let index = 0; index < length; index += 1) {
    const leftPart = leftParts[index] as string;
    const rightPart = rightParts[index] as string;
    const leftNumeric = /^\d+$/u.test(leftPart);
    const rightNumeric = /^\d+$/u.test(rightPart);
    if (leftNumeric && rightNumeric) {
      const leftCanonical = leftPart.replace(/^0+(?=\d)/u, '');
      const rightCanonical = rightPart.replace(/^0+(?=\d)/u, '');
      if (leftCanonical.length !== rightCanonical.length) {
        return leftCanonical.length - rightCanonical.length;
      }
      const numericOrder = compareCodeUnitStrings(
        leftCanonical,
        rightCanonical
      );
      if (numericOrder !== 0) return numericOrder;
      if (leftPart.length !== rightPart.length) {
        return leftPart.length - rightPart.length;
      }
      continue;
    }
    const partOrder = compareCodeUnitStrings(leftPart, rightPart);
    if (partOrder !== 0) return partOrder;
  }
  if (leftParts.length !== rightParts.length) {
    return leftParts.length - rightParts.length;
  }
  return compareCodeUnitStrings(left, right);
}

export function compareSastNormalizedFindingCandidates(
  left: Readonly<SastNormalizedFindingCandidate>,
  right: Readonly<SastNormalizedFindingCandidate>
): number {
  const leftPath =
    left.location.kind === 'FILE'
      ? left.location.normalizedPath
      : '';
  const rightPath =
    right.location.kind === 'FILE'
      ? right.location.normalizedPath
      : '';
  const leftLine =
    left.location.kind === 'FILE' ? left.location.lineStart : 0;
  const rightLine =
    right.location.kind === 'FILE' ? right.location.lineStart : 0;
  const leftColumn =
    left.location.kind === 'FILE'
      ? left.location.columnStart ?? 0
      : 0;
  const rightColumn =
    right.location.kind === 'FILE'
      ? right.location.columnStart ?? 0
      : 0;
  const scalarComparisons = [
    compareCodeUnitStrings(
      left.provenance.ruleId,
      right.provenance.ruleId
    ),
    compareCodeUnitStrings(leftPath, rightPath),
    leftLine - rightLine,
    leftColumn - rightColumn,
    compareCodeUnitStrings(
      left.identityMaterial.scannerMatchBasedId,
      right.identityMaterial.scannerMatchBasedId
    ),
    compareCodeUnitStrings(left.description, right.description)
  ];
  return scalarComparisons.find((comparison) => comparison !== 0) ?? 0;
}

export function canonicalizeOpenGrepSarifNormalizationBatch(
  batch: Readonly<OpenGrepSarifNormalizationBatchCore>
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

export function canonicalizeOpenGrepSarifNormalizationRejection(
  rejection: Readonly<OpenGrepSarifNormalizationRejectionCore>
): string {
  return JSON.stringify({
    version: rejection.version,
    adapterVersion: rejection.adapterVersion,
    outcome: rejection.outcome,
    ingestionId: rejection.ingestionId,
    reasonCodes: [...rejection.reasonCodes]
  });
}

export function isOpenGrepSarifNormalizationBatchShapeValid(
  value: unknown
): value is OpenGrepSarifNormalizationBatch {
  if (!isRecord(value)) return false;
  if (
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
    value.version !== OPENGREP_SARIF_NORMALIZER_VERSION ||
    value.adapterVersion !== OPENGREP_SARIF_NORMALIZER_VERSION ||
    value.artifactSchema !== 'OPENGREP_SARIF' ||
    value.artifactSchemaVersion !== '2.1.0' ||
    !isBoundedReference(value.ingestionId) ||
    !isNormalizationScopeValid(value.scope) ||
    !isBoundedReference(value.scannerRunId) ||
    value.scanner !== 'OPENGREP' ||
    !isBoundedIdentifier(value.scannerVersion, 255, false) ||
    !isAllowedString(value.lane, ['FAST', 'DEEP']) ||
    !isBoundedReference(value.preflightAttestationRef) ||
    !isCommitSha(value.commitSha) ||
    ![
      value.envelopeDigest,
      value.artifactDigest,
      value.scannerImageDigest,
      value.ruleBundleDigest,
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
      finding.provenance.scannerVersion === value.scannerVersion &&
      finding.provenance.scannerImageDigest ===
        value.scannerImageDigest &&
      finding.provenance.ruleBundleDigest === value.ruleBundleDigest &&
      finding.provenance.artifactDigest === value.artifactDigest
  );
  if (!findingsValid) return false;
  const findings =
    value.findings as readonly OpenGrepNormalizedFindingCandidate[];
  return findings.every(
    (finding, index) =>
      index === 0 ||
      compareSastNormalizedFindingCandidates(
        findings[index - 1] as OpenGrepNormalizedFindingCandidate,
        finding
      ) < 0
  );
}

export function isOpenGrepSarifNormalizationRejectionShapeValid(
  value: unknown
): value is OpenGrepSarifNormalizationRejection {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      'version',
      'adapterVersion',
      'outcome',
      'ingestionId',
      'reasonCodes',
      'rejectionDigest'
    ]) &&
    value.version === OPENGREP_SARIF_NORMALIZER_VERSION &&
    value.adapterVersion === OPENGREP_SARIF_NORMALIZER_VERSION &&
    value.outcome === 'REJECTED' &&
    isBoundedReference(value.ingestionId) &&
    isStrictOrderedMembers(
      value.reasonCodes,
      SAST_NORMALIZATION_REJECTION_REASON_CODES
    ) &&
    (value.reasonCodes as readonly string[]).length > 0 &&
    isSha256Digest(value.rejectionDigest)
  );
}

export function canonicalizeSastNormalizedFindingCandidate(
  finding: Readonly<SastNormalizedFindingCandidate>
) {
  const common = {
    tenantId: finding.tenantId,
    repositoryBindingId: finding.repositoryBindingId,
    scanRequestId: finding.scanRequestId,
    attemptId: finding.attemptId,
    scannerRunId: finding.scannerRunId,
    planDigest: finding.planDigest,
    canonicalScanKey: finding.canonicalScanKey,
    preflightAttestationRef: finding.preflightAttestationRef,
    preflightInventoryDigest: finding.preflightInventoryDigest,
    commitSha: finding.commitSha,
    lane: finding.lane,
    capability: finding.capability,
    title: finding.title,
    description: finding.description,
    severity: finding.severity,
    confidence: finding.confidence,
    cweIds: [...finding.cweIds],
    cveIds: [...finding.cveIds],
    location:
      finding.location.kind === 'FILE'
        ? {
            kind: finding.location.kind,
            normalizedPath: finding.location.normalizedPath,
            lineStart: finding.location.lineStart,
            ...(finding.location.lineEnd === undefined
              ? {}
              : { lineEnd: finding.location.lineEnd }),
            ...(finding.location.columnStart === undefined
              ? {}
              : { columnStart: finding.location.columnStart }),
            ...(finding.location.columnEnd === undefined
              ? {}
              : { columnEnd: finding.location.columnEnd }),
            ...(finding.location.symbol === undefined
              ? {}
              : { symbol: finding.location.symbol })
          }
        : {
            kind: finding.location.kind,
            reasonCode: finding.location.reasonCode,
            ...(finding.location.symbol === undefined
              ? {}
              : { symbol: finding.location.symbol })
          },
    identityMaterial: {
      ruleSemanticId: finding.identityMaterial.ruleSemanticId,
      symbolAnchor: finding.identityMaterial.symbolAnchor,
      sinkKind: finding.identityMaterial.sinkKind,
      structuralHash: finding.identityMaterial.structuralHash,
      scannerMatchBasedId:
        finding.identityMaterial.scannerMatchBasedId
    },
    provenance: {
      scanner: finding.provenance.scanner,
      scannerVersion: finding.provenance.scannerVersion,
      scannerImageDigest: finding.provenance.scannerImageDigest,
      ruleId: finding.provenance.ruleId,
      ruleRevision: finding.provenance.ruleRevision,
      ruleBundleDigest: finding.provenance.ruleBundleDigest,
      artifactDigest: finding.provenance.artifactDigest,
      ...(finding.provenance.scanner === 'TRIVY'
        ? {
            ruleSource: finding.provenance.ruleSource,
            vulnerabilityDatabaseDigest:
              finding.provenance.vulnerabilityDatabaseDigest
          }
        : {})
    },
    notes: [...finding.notes],
    durablePersistenceAllowed: false
  };
  if (
    !('scannerDisposition' in finding) ||
    !('trivy' in finding)
  ) {
    return common;
  }
  return {
    ...common,
    scannerDisposition: {
      source: finding.scannerDisposition.source,
      status: finding.scannerDisposition.status,
      platformPolicyAuthority: false
    },
    trivy:
      finding.trivy.kind === 'DEPENDENCY_VULNERABILITY'
        ? {
            kind: finding.trivy.kind,
            vulnerabilityId: finding.trivy.vulnerabilityId,
            packageName: finding.trivy.packageName,
            packageType: finding.trivy.packageType,
            installedVersion: finding.trivy.installedVersion,
            fixedVersion: finding.trivy.fixedVersion,
            advisoryStatus: finding.trivy.advisoryStatus
          }
        : finding.trivy.kind === 'SECRET_DETECTION'
          ? {
              kind: finding.trivy.kind,
              category: finding.trivy.category,
              secretValueStored: false,
              secretPayloadDiscarded: true
            }
          : {
              kind: finding.trivy.kind,
              checkType: finding.trivy.checkType,
              avdId: finding.trivy.avdId,
              resultStatus: finding.trivy.resultStatus
            }
  };
}

export function isSastNormalizedFindingCandidateShapeValid(
  value: unknown
): value is SastNormalizedFindingCandidate {
  if (!isRecord(value) || !isRecord(value.provenance)) return false;
  const isTrivy = value.provenance.scanner === 'TRIVY';
  const commonKeys = [
    'tenantId',
    'repositoryBindingId',
    'scanRequestId',
    'attemptId',
    'scannerRunId',
    'planDigest',
    'canonicalScanKey',
    'preflightAttestationRef',
    'preflightInventoryDigest',
    'commitSha',
    'lane',
    'capability',
    'title',
    'description',
    'severity',
    'confidence',
    'cweIds',
    'cveIds',
    'location',
    'identityMaterial',
    'provenance',
    'notes',
    'durablePersistenceAllowed'
  ] as const;
  if (
    !hasExactKeys(
      value,
      isTrivy
        ? [...commonKeys, 'scannerDisposition', 'trivy']
        : commonKeys
    ) ||
    ![
      value.tenantId,
      value.repositoryBindingId,
      value.scanRequestId,
      value.attemptId,
      value.scannerRunId
    ].every(isBoundedReference) ||
    !isSha256Digest(value.planDigest) ||
    !isSha256Digest(value.canonicalScanKey) ||
    !isBoundedReference(value.preflightAttestationRef) ||
    !isSha256Digest(value.preflightInventoryDigest) ||
    !isCommitSha(value.commitSha) ||
    !isAllowedString(value.lane, ['FAST', 'DEEP']) ||
    !isAllowedString(
      value.capability,
      isTrivy
        ? [
            'DEPENDENCY_VULNERABILITY',
            'SECRET_DETECTION',
            'IAC_MISCONFIGURATION'
          ]
        : ['SAST']
    ) ||
    !isBoundedPlainText(value.title, SAST_NORMALIZATION_LIMITS.titleBytes, false) ||
    !isBoundedPlainText(
      value.description,
      SAST_NORMALIZATION_LIMITS.descriptionBytes,
      true
    ) ||
    !isAllowedString(value.severity, [
      'CRITICAL',
      'HIGH',
      'MEDIUM',
      'LOW',
      'INFO'
    ]) ||
    !isAllowedString(value.confidence, [
      'HIGH',
      'MEDIUM',
      'LOW',
      'UNKNOWN'
    ]) ||
    !isOrderedIdentifierArray(
      value.cweIds,
      /^CWE-[1-9][0-9]{0,9}$/u,
      SAST_NORMALIZATION_LIMITS.maximumCweIds
    ) ||
    !isOrderedIdentifierArray(
      value.cveIds,
      /^CVE-[0-9]{4}-[0-9]{4,}$/u,
      SAST_NORMALIZATION_LIMITS.maximumCveIds
    ) ||
    !isNormalizationLocationShapeValid(value.location) ||
    !isIdentityMaterialValid(value.identityMaterial) ||
    !(isTrivy
      ? isTrivyProvenanceValid(value.provenance)
      : isOpenGrepProvenanceValid(value.provenance)) ||
    (isTrivy &&
      (!isTrivyScannerDispositionValid(value.scannerDisposition) ||
        !isTrivyFindingDetailsValid(
          value.trivy,
          value.capability
        ) ||
        !isTrivyCandidateSemanticsValid(value))) ||
    !isStrictOrderedMembers(value.notes, SAST_NORMALIZATION_NOTE_CODES) ||
    value.durablePersistenceAllowed !== false
  ) {
    return false;
  }
  return true;
}

function isNormalizationLocationShapeValid(
  value: unknown
): value is SastFindingLocation {
  if (!isRecord(value)) return false;
  if (value.kind === 'UNKNOWN') {
    return (
      hasOnlyKeys(value, ['kind', 'reasonCode', 'symbol']) &&
      isAllowedString(value.reasonCode, [
        'SCANNER_LOCATION_OMITTED',
        'LOCATION_NOT_MAPPABLE'
      ]) &&
      isOptionalBoundedText(
        value.symbol,
        SAST_NORMALIZATION_LIMITS.symbolBytes,
        false
      ) &&
      !('normalizedPath' in value) &&
      !('lineStart' in value) &&
      !('lineEnd' in value) &&
      !('columnStart' in value) &&
      !('columnEnd' in value)
    );
  }
  if (
    value.kind !== 'FILE' ||
    !hasOnlyKeys(value, [
      'kind',
      'normalizedPath',
      'lineStart',
      'lineEnd',
      'columnStart',
      'columnEnd',
      'symbol'
    ]) ||
    !isSafeNormalizedPath(value.normalizedPath) ||
    !isPositiveCoordinate(value.lineStart) ||
    !isOptionalPositiveCoordinate(value.lineEnd) ||
    !isOptionalPositiveCoordinate(value.columnStart) ||
    !isOptionalPositiveCoordinate(value.columnEnd) ||
    !isOptionalBoundedText(
      value.symbol,
      SAST_NORMALIZATION_LIMITS.symbolBytes,
      false
    )
  ) {
    return false;
  }
  const lineEnd =
    typeof value.lineEnd === 'number'
      ? value.lineEnd
      : value.lineStart;
  return (
    lineEnd >= (value.lineStart as number) &&
    (value.columnEnd === undefined ||
      (value.columnStart !== undefined &&
        (lineEnd !== value.lineStart ||
          (value.columnEnd as number) >=
            (value.columnStart as number))))
  );
}

function isIdentityMaterialValid(value: unknown): boolean {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      'ruleSemanticId',
      'symbolAnchor',
      'sinkKind',
      'structuralHash',
      'scannerMatchBasedId'
    ]) &&
    isBoundedIdentifier(
      value.ruleSemanticId,
      SAST_NORMALIZATION_LIMITS.ruleIdBytes,
      false
    ) &&
    isBoundedIdentifier(
      value.symbolAnchor,
      SAST_NORMALIZATION_LIMITS.symbolBytes,
      true
    ) &&
    isBoundedIdentifier(
      value.sinkKind,
      SAST_NORMALIZATION_LIMITS.symbolBytes,
      true
    ) &&
    isBoundedIdentifier(
      value.structuralHash,
      SAST_NORMALIZATION_LIMITS.scannerIdentityHintBytes,
      false
    ) &&
    isBoundedIdentifier(
      value.scannerMatchBasedId,
      SAST_NORMALIZATION_LIMITS.scannerIdentityHintBytes,
      false
    )
  );
}

function isOpenGrepProvenanceValid(value: unknown): boolean {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      'scanner',
      'scannerVersion',
      'scannerImageDigest',
      'ruleId',
      'ruleRevision',
      'ruleBundleDigest',
      'artifactDigest'
    ]) &&
    value.scanner === 'OPENGREP' &&
    isBoundedIdentifier(value.scannerVersion, 255, false) &&
    isSha256Digest(value.scannerImageDigest) &&
    isBoundedIdentifier(
      value.ruleId,
      SAST_NORMALIZATION_LIMITS.ruleIdBytes,
      false
    ) &&
    isBoundedIdentifier(
      value.ruleRevision,
      SAST_NORMALIZATION_LIMITS.ruleRevisionBytes,
      false
    ) &&
    isSha256Digest(value.ruleBundleDigest) &&
    isSha256Digest(value.artifactDigest)
  );
}

function isTrivyProvenanceValid(value: unknown): boolean {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      'scanner',
      'scannerVersion',
      'scannerImageDigest',
      'ruleId',
      'ruleRevision',
      'ruleBundleDigest',
      'artifactDigest',
      'ruleSource',
      'vulnerabilityDatabaseDigest'
    ]) &&
    value.scanner === 'TRIVY' &&
    isBoundedIdentifier(value.scannerVersion, 255, false) &&
    isSha256Digest(value.scannerImageDigest) &&
    isBoundedIdentifier(
      value.ruleId,
      SAST_NORMALIZATION_LIMITS.ruleIdBytes,
      false
    ) &&
    isBoundedIdentifier(
      value.ruleRevision,
      SAST_NORMALIZATION_LIMITS.ruleRevisionBytes,
      false
    ) &&
    isSha256Digest(value.ruleBundleDigest) &&
    isSha256Digest(value.artifactDigest) &&
    isAllowedString(value.ruleSource, [
      'CHECK_BUNDLE',
      'VULNERABILITY_DATABASE'
    ]) &&
    isSha256Digest(value.vulnerabilityDatabaseDigest)
  );
}

function isTrivyScannerDispositionValid(value: unknown): boolean {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      'source',
      'status',
      'platformPolicyAuthority'
    ]) &&
    isAllowedString(value.source, ['DIRECT', 'MODIFIED']) &&
    isAllowedString(value.status, TRIVY_SCANNER_DISPOSITION_STATUSES) &&
    value.platformPolicyAuthority === false &&
    (value.source === 'MODIFIED' || value.status === 'active')
  );
}

function isTrivyCandidateSemanticsValid(
  value: Record<string, unknown>
): boolean {
  if (
    !isRecord(value.provenance) ||
    !isRecord(value.identityMaterial) ||
    !isRecord(value.location) ||
    !isRecord(value.trivy) ||
    value.confidence !== 'UNKNOWN' ||
    !Array.isArray(value.notes) ||
    !value.notes.includes('UNKNOWN_CONFIDENCE') ||
    (value.severity === 'INFO') !==
      value.notes.includes('UNKNOWN_SEVERITY') ||
    !isSha256Digest(value.identityMaterial.structuralHash) ||
    !isSha256Digest(value.identityMaterial.scannerMatchBasedId)
  ) {
    return false;
  }

  if (value.capability === 'DEPENDENCY_VULNERABILITY') {
    const vulnerabilityId = value.trivy.vulnerabilityId;
    return (
      value.provenance.ruleSource === 'VULNERABILITY_DATABASE' &&
      typeof vulnerabilityId === 'string' &&
      value.provenance.ruleId === vulnerabilityId &&
      value.identityMaterial.ruleSemanticId ===
        `trivy-advisory:${vulnerabilityId}` &&
      value.identityMaterial.symbolAnchor ===
        value.trivy.packageName &&
      value.identityMaterial.sinkKind === value.trivy.packageType &&
      value.location.kind === 'UNKNOWN' &&
      value.location.reasonCode === 'SCANNER_LOCATION_OMITTED' &&
      (!/^CVE-/u.test(vulnerabilityId) ||
        (Array.isArray(value.cveIds) &&
          value.cveIds.includes(vulnerabilityId)))
    );
  }

  if (
    value.provenance.ruleSource !== 'CHECK_BUNDLE' ||
    value.identityMaterial.symbolAnchor !== ''
  ) {
    return false;
  }
  return value.capability === 'SECRET_DETECTION'
    ? value.identityMaterial.sinkKind === value.trivy.category
    : value.capability === 'IAC_MISCONFIGURATION' &&
        value.identityMaterial.sinkKind === value.trivy.checkType;
}

function isTrivyFindingDetailsValid(
  value: unknown,
  capability: unknown
): boolean {
  if (!isRecord(value) || value.kind !== capability) return false;
  if (value.kind === 'DEPENDENCY_VULNERABILITY') {
    return (
      hasExactKeys(value, [
        'kind',
        'vulnerabilityId',
        'packageName',
        'packageType',
        'installedVersion',
        'fixedVersion',
        'advisoryStatus'
      ]) &&
      isBoundedIdentifier(
        value.vulnerabilityId,
        SAST_NORMALIZATION_LIMITS.vulnerabilityIdBytes,
        false
      ) &&
      /^[A-Z0-9][A-Z0-9._:+-]*$/u.test(
        value.vulnerabilityId as string
      ) &&
      isBoundedIdentifier(
        value.packageName,
        SAST_NORMALIZATION_LIMITS.packageNameBytes,
        false
      ) &&
      isBoundedIdentifier(
        value.packageType,
        SAST_NORMALIZATION_LIMITS.packageTypeBytes,
        false
      ) &&
      isBoundedIdentifier(
        value.installedVersion,
        SAST_NORMALIZATION_LIMITS.packageVersionBytes,
        false
      ) &&
      isBoundedIdentifier(
        value.fixedVersion,
        SAST_NORMALIZATION_LIMITS.packageVersionBytes,
        true
      ) &&
      isAllowedString(value.advisoryStatus, [
        'unknown',
        'not_affected',
        'affected',
        'fixed',
        'under_investigation',
        'will_not_fix',
        'fix_deferred',
        'end_of_life'
      ])
    );
  }
  if (value.kind === 'SECRET_DETECTION') {
    return (
      hasExactKeys(value, [
        'kind',
        'category',
        'secretValueStored',
        'secretPayloadDiscarded'
      ]) &&
      isBoundedIdentifier(
        value.category,
        SAST_NORMALIZATION_LIMITS.trivyCategoryBytes,
        false
      ) &&
      value.secretValueStored === false &&
      value.secretPayloadDiscarded === true
    );
  }
  return (
    value.kind === 'IAC_MISCONFIGURATION' &&
    hasExactKeys(value, [
      'kind',
      'checkType',
      'avdId',
      'resultStatus'
    ]) &&
    isBoundedIdentifier(
      value.checkType,
      SAST_NORMALIZATION_LIMITS.ruleIdBytes,
      false
    ) &&
    isBoundedIdentifier(
      value.avdId,
      SAST_NORMALIZATION_LIMITS.ruleIdBytes,
      true
    ) &&
    value.resultStatus === 'FAIL'
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

function isOrderedIdentifierArray(
  value: unknown,
  pattern: RegExp,
  maximum: number
): value is string[] {
  return (
    Array.isArray(value) &&
    value.length <= maximum &&
    value.every(
      (item, index) =>
        typeof item === 'string' &&
        pattern.test(item) &&
        utf8Length(item) <=
          SAST_NORMALIZATION_LIMITS.vulnerabilityIdentifierBytes &&
        (index === 0 ||
          compareSastNormalizationIdentifiers(
            value[index - 1] as string,
            item
          ) < 0)
    )
  );
}

function isStrictOrderedMembers(
  value: unknown,
  allowed: readonly string[]
): value is string[] {
  return (
    Array.isArray(value) &&
    value.every(
      (item, index) =>
        typeof item === 'string' &&
        allowed.includes(item) &&
        (index === 0 ||
          allowed.indexOf(value[index - 1] as string) <
            allowed.indexOf(item))
    )
  );
}

function isSafeNormalizedPath(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value === value.normalize('NFC') &&
    utf8Length(value) <=
      SAST_NORMALIZATION_LIMITS.normalizedPathBytes &&
    !value.includes('\\') &&
    !value.startsWith('/') &&
    !/^[A-Za-z]:/u.test(value) &&
    !/^[A-Za-z][A-Za-z0-9+.-]*:/u.test(value) &&
    !value.split('/').some(
      (segment) =>
        segment.length === 0 || segment === '.' || segment === '..'
    ) &&
    !hasUnsafeControl(value, false)
  );
}

function isBoundedReference(value: unknown): value is string {
  return isBoundedIdentifier(value, 2048, false);
}

function isAllowedString(
  value: unknown,
  allowed: readonly string[]
): value is string {
  return typeof value === 'string' && allowed.includes(value);
}

function isOptionalBoundedText(
  value: unknown,
  maximumBytes: number,
  allowNewlines: boolean
): boolean {
  return (
    value === undefined ||
    isBoundedPlainText(value, maximumBytes, allowNewlines)
  );
}

function isBoundedPlainText(
  value: unknown,
  maximumBytes: number,
  allowNewlines: boolean
): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value === value.normalize('NFC') &&
    value === value.trim() &&
    utf8Length(value) <= maximumBytes &&
    !hasUnsafeControl(value, allowNewlines)
  );
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
    utf8Length(value) <= maximumBytes &&
    !hasUnsafeControl(value, false)
  );
}

function hasUnsafeControl(
  value: string,
  allowNewlines: boolean
): boolean {
  return [...value].some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    if (allowNewlines && [0x09, 0x0a].includes(codePoint)) {
      return false;
    }
    return (
      codePoint <= 0x1f ||
      (codePoint >= 0x7f && codePoint <= 0x9f) ||
      (codePoint >= 0xd800 && codePoint <= 0xdfff)
    );
  });
}

function isOptionalPositiveCoordinate(value: unknown): boolean {
  return value === undefined || isPositiveCoordinate(value);
}

function isPositiveCoordinate(value: unknown): value is number {
  return (
    typeof value === 'number' &&
    Number.isSafeInteger(value) &&
    value > 0 &&
    value <= 2147483647
  );
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

function utf8Length(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function compareCodeUnitStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
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

function hasOnlyKeys(
  value: Record<string, unknown>,
  allowed: readonly string[]
): boolean {
  return Object.keys(value).every((key) => allowed.includes(key));
}
