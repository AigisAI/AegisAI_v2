import {
  SAST_CAPABILITIES,
  SAST_FINDING_FINGERPRINT_VERSION,
  SAST_PROFILE_IDS,
  SAST_SCAN_LANES,
  SAST_SCANNER_KINDS,
  type SastCapability,
  type SastProfileId,
  type SastScanLane,
  type SastScannerKind
} from './sast-runtime';
import {
  hasExactKeys,
  isRecord,
  isSha256Digest
} from './sast-normalization-validation';

export const SAST_FINDING_CORRELATION_VERSION =
  'sast-finding-correlation-v1' as const;
export const SAST_FINDING_CORRELATION_SOURCE_VERSION =
  'sast-finding-correlation-source-v1' as const;
export const SAST_FINDING_CORRELATION_BASIS_VERSION =
  'sast-finding-correlation-basis-v1' as const;
export const SAST_FINDING_CORRELATION_PROVENANCE_VERSION =
  'sast-finding-correlation-provenance-v1' as const;

export const SAST_FINDING_CORRELATION_LIMITS = Object.freeze({
  maximumObservationBatches: 16,
  maximumOccurrences: 25_000,
  maximumEdges: 100_000,
  maximumBasisDigestsPerEdge: 256,
  maximumReferenceUtf8Bytes: 4_096,
  yieldOccurrenceInterval: 64
});

export const SAST_FINDING_CORRELATION_KINDS = [
  'EXACT_FINGERPRINT',
  'SAME_DEPENDENCY_CVE',
  'SUPPORTING_EVIDENCE',
  'POSSIBLE_OVERLAP'
] as const;
export type SastFindingCorrelationKind =
  (typeof SAST_FINDING_CORRELATION_KINDS)[number];

export const SAST_FINDING_CORRELATION_AUTHORITY_LEVELS = [
  'AUTHORITATIVE',
  'SUPPORTING_ONLY'
] as const;
export type SastFindingCorrelationAuthorityLevel =
  (typeof SAST_FINDING_CORRELATION_AUTHORITY_LEVELS)[number];

export const SAST_FINDING_CORRELATION_PROVENANCE_SIDES = [
  'SOURCE',
  'TARGET'
] as const;
export type SastFindingCorrelationProvenanceSide =
  (typeof SAST_FINDING_CORRELATION_PROVENANCE_SIDES)[number];

export const SAST_FINDING_CORRELATION_REJECTION_REASON_CODES = [
  'FINDING_CORRELATION_INPUT_INVALID',
  'FINDING_CORRELATION_SOURCE_SET_INCOMPLETE',
  'FINDING_CORRELATION_DURABLE_SCOPE_INVALID',
  'FINDING_CORRELATION_AUTHORITY_INVALID',
  'FINDING_CORRELATION_OCCURRENCE_INVALID',
  'FINDING_CORRELATION_EDGE_LIMIT_EXCEEDED',
  'FINDING_CORRELATION_REPLAY_CONFLICT',
  'FINDING_CORRELATION_PERSISTENCE_FAILED'
] as const;
export type SastFindingCorrelationRejectionReasonCode =
  (typeof SAST_FINDING_CORRELATION_REJECTION_REASON_CODES)[number];

export type SastFindingCorrelationCanonicalDigester = (
  canonicalValue: string
) => `sha256:${string}`;

type FindingCapability = Exclude<SastCapability, 'SBOM'>;

export interface SastFindingCorrelationScope {
  tenantId: string;
  repositoryBindingId: string;
  scanRequestId: string;
  attemptId: string;
  lifecycleContextKey: `sha256:${string}`;
  targetRef: string;
  commitSha: string;
  lane: SastScanLane;
  canonicalScanKey: `sha256:${string}`;
  planDigest: `sha256:${string}`;
  profileId: SastProfileId;
  profileDigest: `sha256:${string}`;
}

export interface SastFindingCorrelationSourceBinding {
  version: typeof SAST_FINDING_CORRELATION_SOURCE_VERSION;
  observationBatchId: string;
  sourceIdentityBatchDigest: `sha256:${string}`;
  scannerRunId: string;
  scanner: Exclude<SastScannerKind, 'SYFT'>;
  capabilities: FindingCapability[];
  lifecycleContextKey: `sha256:${string}`;
  findingCount: number;
  occurrenceCount: number;
  observedAt: string;
  sourceBindingDigest: `sha256:${string}`;
}

export type SastFindingCorrelationSourceBindingCore = Omit<
  SastFindingCorrelationSourceBinding,
  'sourceBindingDigest'
>;

export interface SastFindingCorrelationProvenance {
  version: typeof SAST_FINDING_CORRELATION_PROVENANCE_VERSION;
  side: SastFindingCorrelationProvenanceSide;
  occurrenceId: string;
  observationBatchId: string;
  lineageId: string;
  normalizedFindingId: string;
  scannerRunId: string;
  scanner: Exclude<SastScannerKind, 'SYFT'>;
  capability: FindingCapability;
  authorityLevel: SastFindingCorrelationAuthorityLevel;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  fingerprintVersion: typeof SAST_FINDING_FINGERPRINT_VERSION;
  stableFingerprint: `sha256:${string}`;
  fingerprintDecisionDigest: `sha256:${string}`;
  sourceFindingDigest: `sha256:${string}`;
  scannerVersion: string;
  scannerImageDigest: `sha256:${string}`;
  ruleId: string;
  ruleRevision: string;
  ruleBundleDigest: `sha256:${string}`;
  artifactDigest: `sha256:${string}`;
  vulnerabilityDatabaseDigest?: `sha256:${string}`;
  provenanceDigest: `sha256:${string}`;
}

export type SastFindingCorrelationProvenanceCore = Omit<
  SastFindingCorrelationProvenance,
  'provenanceDigest'
>;

export interface SastFindingCorrelationSafetyFlags {
  findingMergeAllowed: false;
  severityInheritanceAllowed: false;
  lifecycleInheritanceAllowed: false;
  policyInheritanceAllowed: false;
  coverageInheritanceAllowed: false;
  occurrenceProvenancePreserved: true;
}

export interface SastFindingCorrelationEdgeDecision {
  version: typeof SAST_FINDING_CORRELATION_VERSION;
  correlationBatchId: string;
  kind: SastFindingCorrelationKind;
  sourceOccurrenceId: string;
  targetOccurrenceId: string;
  basisDigests: `sha256:${string}`[];
  confidenceBasisPoints: number;
  sourceProvenanceDigest: `sha256:${string}`;
  targetProvenanceDigest: `sha256:${string}`;
  safety: SastFindingCorrelationSafetyFlags;
  decidedAt: string;
  edgeDigest: `sha256:${string}`;
}

export type SastFindingCorrelationEdgeDecisionCore = Omit<
  SastFindingCorrelationEdgeDecision,
  'edgeDigest'
>;

export interface SastFindingCorrelationAuthority {
  correlationAuthority: true;
  provenancePreservationAuthority: true;
  findingMergeAuthority: false;
  severityAuthority: false;
  lifecycleAuthority: false;
  coverageCalculationAuthority: false;
  evidenceAuthority: false;
  policyAuthority: false;
  publicationAuthority: false;
  aiPayloadEligible: false;
}

export interface SastFindingCorrelationResult {
  version: typeof SAST_FINDING_CORRELATION_VERSION;
  outcome: 'CORRELATED';
  correlationBatchId: string;
  sourceSetDigest: `sha256:${string}`;
  lifecycleContextKey: `sha256:${string}`;
  sourceBatchCount: number;
  occurrenceCount: number;
  edgeCount: number;
  exactFingerprintCount: number;
  sameDependencyCveCount: number;
  supportingEvidenceCount: number;
  possibleOverlapCount: number;
  replayed: boolean;
  correlatedAt: string;
  authority: SastFindingCorrelationAuthority;
  resultDigest: `sha256:${string}`;
}

export type SastFindingCorrelationResultCore = Omit<
  SastFindingCorrelationResult,
  'resultDigest'
>;

export interface SastFindingCorrelationRejection {
  version: typeof SAST_FINDING_CORRELATION_VERSION;
  outcome: 'REJECTED';
  reasonCodes: SastFindingCorrelationRejectionReasonCode[];
  observationBatchIdsStored: false;
  sourceResultDigestsStored: false;
  sourceFindingStored: false;
  correlationBasisStored: false;
  secretValueStored: false;
  rejectionDigest: `sha256:${string}`;
}

export type SastFindingCorrelationRejectionCore = Omit<
  SastFindingCorrelationRejection,
  'rejectionDigest'
>;

export type SastFindingCorrelationOutcome =
  | SastFindingCorrelationResult
  | SastFindingCorrelationRejection;

export type SastFindingCorrelationAuditMetadata =
  | {
      version: typeof SAST_FINDING_CORRELATION_VERSION;
      outcome: 'CORRELATED';
      correlationBatchId: string;
      resultDigest: `sha256:${string}`;
      sourceBatchCount: number;
      occurrenceCount: number;
      edgeCount: number;
      exactFingerprintCount: number;
      sameDependencyCveCount: number;
      supportingEvidenceCount: number;
      possibleOverlapCount: number;
      replayed: boolean;
    }
  | {
      version: typeof SAST_FINDING_CORRELATION_VERSION;
      outcome: 'REJECTED';
      reasonCodes: SastFindingCorrelationRejectionReasonCode[];
      rejectionDigest: `sha256:${string}`;
    };

const FINDING_CAPABILITIES = SAST_CAPABILITIES.filter(
  (capability): capability is FindingCapability =>
    capability !== 'SBOM'
);
const FINDING_SCANNERS = SAST_SCANNER_KINDS.filter(
  (scanner): scanner is Exclude<SastScannerKind, 'SYFT'> =>
    scanner !== 'SYFT'
);
const SEVERITIES = [
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
  'INFO'
] as const;
const UTF8_ENCODER = new TextEncoder();

const SAFETY: Readonly<SastFindingCorrelationSafetyFlags> =
  Object.freeze({
    findingMergeAllowed: false,
    severityInheritanceAllowed: false,
    lifecycleInheritanceAllowed: false,
    policyInheritanceAllowed: false,
    coverageInheritanceAllowed: false,
    occurrenceProvenancePreserved: true
  });

const AUTHORITY: Readonly<SastFindingCorrelationAuthority> =
  Object.freeze({
    correlationAuthority: true,
    provenancePreservationAuthority: true,
    findingMergeAuthority: false,
    severityAuthority: false,
    lifecycleAuthority: false,
    coverageCalculationAuthority: false,
    evidenceAuthority: false,
    policyAuthority: false,
    publicationAuthority: false,
    aiPayloadEligible: false
  });

export function canonicalizeSastFindingCorrelationSourceBinding(
  source: Readonly<SastFindingCorrelationSourceBindingCore>
): string {
  return JSON.stringify({
    version: source.version,
    observationBatchId: source.observationBatchId,
    sourceIdentityBatchDigest:
      source.sourceIdentityBatchDigest,
    scannerRunId: source.scannerRunId,
    scanner: source.scanner,
    capabilities: [...source.capabilities],
    lifecycleContextKey: source.lifecycleContextKey,
    findingCount: source.findingCount,
    occurrenceCount: source.occurrenceCount,
    observedAt: source.observedAt
  });
}

export function buildSastFindingCorrelationSourceSetPreimage(
  sources: readonly Readonly<SastFindingCorrelationSourceBinding>[]
): string {
  return `${SAST_FINDING_CORRELATION_VERSION}\0${sources
    .map((source) => source.sourceBindingDigest)
    .map(encodeCanonicalField)
    .join('')}`;
}

export function buildSastFindingCorrelationBatchKeyPreimage(input: {
  scope: Readonly<SastFindingCorrelationScope>;
  sourceSetDigest: `sha256:${string}`;
}): string {
  return `${SAST_FINDING_CORRELATION_VERSION}\0${[
    input.scope.tenantId,
    input.scope.repositoryBindingId,
    input.scope.scanRequestId,
    input.scope.attemptId,
    input.scope.lifecycleContextKey,
    input.scope.targetRef,
    input.scope.commitSha,
    input.scope.lane,
    input.scope.canonicalScanKey,
    input.scope.planDigest,
    input.scope.profileId,
    input.scope.profileDigest,
    input.sourceSetDigest
  ]
    .map(encodeCanonicalField)
    .join('')}`;
}

export function buildSastFindingCorrelationBasisPreimage(input: {
  kind: SastFindingCorrelationKind;
  components: readonly string[];
}): string {
  return `${SAST_FINDING_CORRELATION_BASIS_VERSION}\0${[
    input.kind,
    ...input.components.map((component) =>
      component.normalize('NFC')
    )
  ]
    .map(encodeCanonicalField)
    .join('')}`;
}

export function canonicalizeSastFindingCorrelationProvenance(
  provenance: Readonly<SastFindingCorrelationProvenanceCore>
): string {
  return JSON.stringify({
    version: provenance.version,
    side: provenance.side,
    occurrenceId: provenance.occurrenceId,
    observationBatchId: provenance.observationBatchId,
    lineageId: provenance.lineageId,
    normalizedFindingId: provenance.normalizedFindingId,
    scannerRunId: provenance.scannerRunId,
    scanner: provenance.scanner,
    capability: provenance.capability,
    authorityLevel: provenance.authorityLevel,
    severity: provenance.severity,
    fingerprintVersion: provenance.fingerprintVersion,
    stableFingerprint: provenance.stableFingerprint,
    fingerprintDecisionDigest:
      provenance.fingerprintDecisionDigest,
    sourceFindingDigest: provenance.sourceFindingDigest,
    scannerVersion: provenance.scannerVersion,
    scannerImageDigest: provenance.scannerImageDigest,
    ruleId: provenance.ruleId,
    ruleRevision: provenance.ruleRevision,
    ruleBundleDigest: provenance.ruleBundleDigest,
    artifactDigest: provenance.artifactDigest,
    ...(provenance.vulnerabilityDatabaseDigest
      ? {
          vulnerabilityDatabaseDigest:
            provenance.vulnerabilityDatabaseDigest
        }
      : {})
  });
}

export function canonicalizeSastFindingCorrelationEdge(
  edge: Readonly<SastFindingCorrelationEdgeDecisionCore>
): string {
  return JSON.stringify({
    version: edge.version,
    correlationBatchId: edge.correlationBatchId,
    kind: edge.kind,
    sourceOccurrenceId: edge.sourceOccurrenceId,
    targetOccurrenceId: edge.targetOccurrenceId,
    basisDigests: [...edge.basisDigests],
    confidenceBasisPoints: edge.confidenceBasisPoints,
    sourceProvenanceDigest: edge.sourceProvenanceDigest,
    targetProvenanceDigest: edge.targetProvenanceDigest,
    safety: canonicalSafety(),
    decidedAt: edge.decidedAt
  });
}

export function canonicalizeSastFindingCorrelationResult(
  result: Readonly<SastFindingCorrelationResultCore>
): string {
  return JSON.stringify({
    version: result.version,
    outcome: 'CORRELATED',
    correlationBatchId: result.correlationBatchId,
    sourceSetDigest: result.sourceSetDigest,
    lifecycleContextKey: result.lifecycleContextKey,
    sourceBatchCount: result.sourceBatchCount,
    occurrenceCount: result.occurrenceCount,
    edgeCount: result.edgeCount,
    exactFingerprintCount: result.exactFingerprintCount,
    sameDependencyCveCount: result.sameDependencyCveCount,
    supportingEvidenceCount: result.supportingEvidenceCount,
    possibleOverlapCount: result.possibleOverlapCount,
    replayed: result.replayed,
    correlatedAt: result.correlatedAt,
    authority: canonicalAuthority()
  });
}

export function canonicalizeSastFindingCorrelationRejection(
  rejection: Readonly<SastFindingCorrelationRejectionCore>
): string {
  return JSON.stringify({
    version: rejection.version,
    outcome: 'REJECTED',
    reasonCodes: [...rejection.reasonCodes],
    observationBatchIdsStored: false,
    sourceResultDigestsStored: false,
    sourceFindingStored: false,
    correlationBasisStored: false,
    secretValueStored: false
  });
}

export function orderSastFindingCorrelationRejectionReasons(
  reasons: Iterable<SastFindingCorrelationRejectionReasonCode>
): SastFindingCorrelationRejectionReasonCode[] {
  const found = new Set(reasons);
  return SAST_FINDING_CORRELATION_REJECTION_REASON_CODES.filter(
    (reason) => found.has(reason)
  );
}

export function isSastFindingCorrelationScopeValid(
  value: unknown
): value is SastFindingCorrelationScope {
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
      'canonicalScanKey',
      'planDigest',
      'profileId',
      'profileDigest'
    ]) &&
    isBoundedReference(value.tenantId) &&
    isBoundedReference(value.repositoryBindingId) &&
    isBoundedReference(value.scanRequestId) &&
    isBoundedReference(value.attemptId) &&
    isSha256Digest(value.lifecycleContextKey) &&
    isBoundedReference(value.targetRef) &&
    isCommitSha(value.commitSha) &&
    SAST_SCAN_LANES.includes(value.lane as SastScanLane) &&
    isSha256Digest(value.canonicalScanKey) &&
    isSha256Digest(value.planDigest) &&
    SAST_PROFILE_IDS.includes(value.profileId as SastProfileId) &&
    isSha256Digest(value.profileDigest)
  );
}

export function isSastFindingCorrelationSourceBindingShapeValid(
  value: unknown,
  digestCanonical: SastFindingCorrelationCanonicalDigester
): value is SastFindingCorrelationSourceBinding {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'version',
      'observationBatchId',
      'sourceIdentityBatchDigest',
      'scannerRunId',
      'scanner',
      'capabilities',
      'lifecycleContextKey',
      'findingCount',
      'occurrenceCount',
      'observedAt',
      'sourceBindingDigest'
    ]) ||
    value.version !== SAST_FINDING_CORRELATION_SOURCE_VERSION ||
    !isCorrelationId(value.observationBatchId, 'finding-observation') ||
    !isSha256Digest(value.sourceIdentityBatchDigest) ||
    !isBoundedReference(value.scannerRunId) ||
    !FINDING_SCANNERS.includes(
      value.scanner as Exclude<SastScannerKind, 'SYFT'>
    ) ||
    !Array.isArray(value.capabilities) ||
    !isCanonicalCapabilityList(value.capabilities) ||
    !isSha256Digest(value.lifecycleContextKey) ||
    !isBoundedCount(
      value.findingCount,
      SAST_FINDING_CORRELATION_LIMITS.maximumOccurrences
    ) ||
    value.occurrenceCount !== value.findingCount ||
    !isCanonicalIsoTimestamp(value.observedAt) ||
    !isSha256Digest(value.sourceBindingDigest)
  ) {
    return false;
  }
  const source = value as unknown as SastFindingCorrelationSourceBinding;
  const { sourceBindingDigest, ...core } = source;
  return (
    digestCanonical(
      canonicalizeSastFindingCorrelationSourceBinding(core)
    ) === sourceBindingDigest
  );
}

export function isSastFindingCorrelationProvenanceShapeValid(
  value: unknown,
  digestCanonical: SastFindingCorrelationCanonicalDigester
): value is SastFindingCorrelationProvenance {
  if (!isRecord(value)) return false;
  const keys = [
    'version',
    'side',
    'occurrenceId',
    'observationBatchId',
    'lineageId',
    'normalizedFindingId',
    'scannerRunId',
    'scanner',
    'capability',
    'authorityLevel',
    'severity',
    'fingerprintVersion',
    'stableFingerprint',
    'fingerprintDecisionDigest',
    'sourceFindingDigest',
    'scannerVersion',
    'scannerImageDigest',
    'ruleId',
    'ruleRevision',
    'ruleBundleDigest',
    'artifactDigest',
    ...(value.vulnerabilityDatabaseDigest === undefined
      ? []
      : ['vulnerabilityDatabaseDigest']),
    'provenanceDigest'
  ];
  if (
    !hasExactKeys(value, keys) ||
    value.version !== SAST_FINDING_CORRELATION_PROVENANCE_VERSION ||
    !SAST_FINDING_CORRELATION_PROVENANCE_SIDES.includes(
      value.side as SastFindingCorrelationProvenanceSide
    ) ||
    !isCorrelationId(value.occurrenceId, 'finding-occurrence') ||
    !isCorrelationId(value.observationBatchId, 'finding-observation') ||
    !isCorrelationId(value.lineageId, 'finding-lineage') ||
    !isCorrelationId(value.normalizedFindingId, 'normalized-finding') ||
    !isBoundedReference(value.scannerRunId) ||
    !FINDING_SCANNERS.includes(
      value.scanner as Exclude<SastScannerKind, 'SYFT'>
    ) ||
    !FINDING_CAPABILITIES.includes(
      value.capability as FindingCapability
    ) ||
    !SAST_FINDING_CORRELATION_AUTHORITY_LEVELS.includes(
      value.authorityLevel as SastFindingCorrelationAuthorityLevel
    ) ||
    !SEVERITIES.includes(value.severity as (typeof SEVERITIES)[number]) ||
    value.fingerprintVersion !== SAST_FINDING_FINGERPRINT_VERSION ||
    !isSha256Digest(value.stableFingerprint) ||
    !isSha256Digest(value.fingerprintDecisionDigest) ||
    !isSha256Digest(value.sourceFindingDigest) ||
    !isBoundedReference(value.scannerVersion) ||
    !isSha256Digest(value.scannerImageDigest) ||
    !isBoundedReference(value.ruleId) ||
    !isBoundedReference(value.ruleRevision) ||
    !isSha256Digest(value.ruleBundleDigest) ||
    !isSha256Digest(value.artifactDigest) ||
    (value.vulnerabilityDatabaseDigest !== undefined &&
      !isSha256Digest(value.vulnerabilityDatabaseDigest)) ||
    (value.scanner === 'TRIVY') !==
      (value.vulnerabilityDatabaseDigest !== undefined) ||
    !isSha256Digest(value.provenanceDigest)
  ) {
    return false;
  }
  const provenance =
    value as unknown as SastFindingCorrelationProvenance;
  const { provenanceDigest, ...core } = provenance;
  return (
    digestCanonical(
      canonicalizeSastFindingCorrelationProvenance(core)
    ) === provenanceDigest
  );
}

export function isSastFindingCorrelationEdgeShapeValid(
  value: unknown,
  digestCanonical: SastFindingCorrelationCanonicalDigester
): value is SastFindingCorrelationEdgeDecision {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'version',
      'correlationBatchId',
      'kind',
      'sourceOccurrenceId',
      'targetOccurrenceId',
      'basisDigests',
      'confidenceBasisPoints',
      'sourceProvenanceDigest',
      'targetProvenanceDigest',
      'safety',
      'decidedAt',
      'edgeDigest'
    ]) ||
    value.version !== SAST_FINDING_CORRELATION_VERSION ||
    !isCorrelationId(value.correlationBatchId, 'finding-correlation') ||
    !SAST_FINDING_CORRELATION_KINDS.includes(
      value.kind as SastFindingCorrelationKind
    ) ||
    !isCorrelationId(value.sourceOccurrenceId, 'finding-occurrence') ||
    !isCorrelationId(value.targetOccurrenceId, 'finding-occurrence') ||
    value.sourceOccurrenceId >= value.targetOccurrenceId ||
    !Array.isArray(value.basisDigests) ||
    value.basisDigests.length === 0 ||
    value.basisDigests.length >
      SAST_FINDING_CORRELATION_LIMITS.maximumBasisDigestsPerEdge ||
    !isSortedUniqueDigestArray(value.basisDigests) ||
    value.confidenceBasisPoints !==
      confidenceForKind(value.kind as SastFindingCorrelationKind) ||
    !isSha256Digest(value.sourceProvenanceDigest) ||
    !isSha256Digest(value.targetProvenanceDigest) ||
    !isSafetyValid(value.safety) ||
    !isCanonicalIsoTimestamp(value.decidedAt) ||
    !isSha256Digest(value.edgeDigest)
  ) {
    return false;
  }
  const edge = value as unknown as SastFindingCorrelationEdgeDecision;
  const { edgeDigest, ...core } = edge;
  return (
    digestCanonical(canonicalizeSastFindingCorrelationEdge(core)) ===
    edgeDigest
  );
}

export function isSastFindingCorrelationResultShapeValid(
  value: unknown,
  digestCanonical: SastFindingCorrelationCanonicalDigester
): value is SastFindingCorrelationResult {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'version',
      'outcome',
      'correlationBatchId',
      'sourceSetDigest',
      'lifecycleContextKey',
      'sourceBatchCount',
      'occurrenceCount',
      'edgeCount',
      'exactFingerprintCount',
      'sameDependencyCveCount',
      'supportingEvidenceCount',
      'possibleOverlapCount',
      'replayed',
      'correlatedAt',
      'authority',
      'resultDigest'
    ]) ||
    value.version !== SAST_FINDING_CORRELATION_VERSION ||
    value.outcome !== 'CORRELATED' ||
    !isCorrelationId(value.correlationBatchId, 'finding-correlation') ||
    !isSha256Digest(value.sourceSetDigest) ||
    !isSha256Digest(value.lifecycleContextKey) ||
    !isBoundedCount(
      value.sourceBatchCount,
      SAST_FINDING_CORRELATION_LIMITS.maximumObservationBatches
    ) ||
    (value.sourceBatchCount as number) < 1 ||
    !isBoundedCount(
      value.occurrenceCount,
      SAST_FINDING_CORRELATION_LIMITS.maximumOccurrences
    ) ||
    !isBoundedCount(
      value.edgeCount,
      SAST_FINDING_CORRELATION_LIMITS.maximumEdges
    ) ||
    !isBoundedCount(
      value.exactFingerprintCount,
      value.edgeCount as number
    ) ||
    !isBoundedCount(
      value.sameDependencyCveCount,
      value.edgeCount as number
    ) ||
    !isBoundedCount(
      value.supportingEvidenceCount,
      value.edgeCount as number
    ) ||
    !isBoundedCount(
      value.possibleOverlapCount,
      value.edgeCount as number
    ) ||
    (value.exactFingerprintCount as number) +
        (value.sameDependencyCveCount as number) +
        (value.supportingEvidenceCount as number) +
        (value.possibleOverlapCount as number) !==
      (value.edgeCount as number) ||
    typeof value.replayed !== 'boolean' ||
    !isCanonicalIsoTimestamp(value.correlatedAt) ||
    !isAuthorityValid(value.authority) ||
    !isSha256Digest(value.resultDigest)
  ) {
    return false;
  }
  const result = value as unknown as SastFindingCorrelationResult;
  const { resultDigest, ...core } = result;
  return (
    digestCanonical(canonicalizeSastFindingCorrelationResult(core)) ===
    resultDigest
  );
}

export function isSastFindingCorrelationRejectionShapeValid(
  value: unknown,
  digestCanonical: SastFindingCorrelationCanonicalDigester
): value is SastFindingCorrelationRejection {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'version',
      'outcome',
      'reasonCodes',
      'observationBatchIdsStored',
      'sourceResultDigestsStored',
      'sourceFindingStored',
      'correlationBasisStored',
      'secretValueStored',
      'rejectionDigest'
    ]) ||
    value.version !== SAST_FINDING_CORRELATION_VERSION ||
    value.outcome !== 'REJECTED' ||
    !Array.isArray(value.reasonCodes) ||
    value.reasonCodes.length === 0 ||
    value.observationBatchIdsStored !== false ||
    value.sourceResultDigestsStored !== false ||
    value.sourceFindingStored !== false ||
    value.correlationBasisStored !== false ||
    value.secretValueStored !== false ||
    !isSha256Digest(value.rejectionDigest)
  ) {
    return false;
  }
  const reasons =
    value.reasonCodes as SastFindingCorrelationRejectionReasonCode[];
  const ordered = orderSastFindingCorrelationRejectionReasons(reasons);
  if (
    reasons.length !== ordered.length ||
    reasons.some((reason, index) => reason !== ordered[index])
  ) {
    return false;
  }
  const rejection =
    value as unknown as SastFindingCorrelationRejection;
  const { rejectionDigest, ...core } = rejection;
  return (
    digestCanonical(
      canonicalizeSastFindingCorrelationRejection(core)
    ) === rejectionDigest
  );
}

export function sastFindingCorrelationSafety(): SastFindingCorrelationSafetyFlags {
  return { ...SAFETY };
}

export function sastFindingCorrelationAuthority(): SastFindingCorrelationAuthority {
  return { ...AUTHORITY };
}

export function toSastFindingCorrelationAuditMetadata(
  result: Readonly<SastFindingCorrelationOutcome>,
  digestCanonical: SastFindingCorrelationCanonicalDigester
): SastFindingCorrelationAuditMetadata {
  if (
    result.outcome === 'REJECTED' &&
    isSastFindingCorrelationRejectionShapeValid(
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
    result.outcome === 'CORRELATED' &&
    isSastFindingCorrelationResultShapeValid(
      result,
      digestCanonical
    )
  ) {
    return {
      version: result.version,
      outcome: result.outcome,
      correlationBatchId: result.correlationBatchId,
      resultDigest: result.resultDigest,
      sourceBatchCount: result.sourceBatchCount,
      occurrenceCount: result.occurrenceCount,
      edgeCount: result.edgeCount,
      exactFingerprintCount: result.exactFingerprintCount,
      sameDependencyCveCount: result.sameDependencyCveCount,
      supportingEvidenceCount: result.supportingEvidenceCount,
      possibleOverlapCount: result.possibleOverlapCount,
      replayed: result.replayed
    };
  }
  throw new TypeError('SAST finding-correlation result is invalid.');
}

export function confidenceForSastFindingCorrelationKind(
  kind: SastFindingCorrelationKind
): number {
  return confidenceForKind(kind);
}

function confidenceForKind(kind: SastFindingCorrelationKind): number {
  switch (kind) {
    case 'EXACT_FINGERPRINT':
    case 'SAME_DEPENDENCY_CVE':
      return 10_000;
    case 'SUPPORTING_EVIDENCE':
      return 8_000;
    case 'POSSIBLE_OVERLAP':
      return 5_000;
  }
}

function canonicalSafety(): SastFindingCorrelationSafetyFlags {
  return { ...SAFETY };
}

function canonicalAuthority(): SastFindingCorrelationAuthority {
  return { ...AUTHORITY };
}

function isSafetyValid(value: unknown): boolean {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      'findingMergeAllowed',
      'severityInheritanceAllowed',
      'lifecycleInheritanceAllowed',
      'policyInheritanceAllowed',
      'coverageInheritanceAllowed',
      'occurrenceProvenancePreserved'
    ]) &&
    value.findingMergeAllowed === false &&
    value.severityInheritanceAllowed === false &&
    value.lifecycleInheritanceAllowed === false &&
    value.policyInheritanceAllowed === false &&
    value.coverageInheritanceAllowed === false &&
    value.occurrenceProvenancePreserved === true
  );
}

function isAuthorityValid(value: unknown): boolean {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      'correlationAuthority',
      'provenancePreservationAuthority',
      'findingMergeAuthority',
      'severityAuthority',
      'lifecycleAuthority',
      'coverageCalculationAuthority',
      'evidenceAuthority',
      'policyAuthority',
      'publicationAuthority',
      'aiPayloadEligible'
    ]) &&
    value.correlationAuthority === true &&
    value.provenancePreservationAuthority === true &&
    value.findingMergeAuthority === false &&
    value.severityAuthority === false &&
    value.lifecycleAuthority === false &&
    value.coverageCalculationAuthority === false &&
    value.evidenceAuthority === false &&
    value.policyAuthority === false &&
    value.publicationAuthority === false &&
    value.aiPayloadEligible === false
  );
}

function isCanonicalCapabilityList(value: unknown[]): boolean {
  const capabilities = value as string[];
  return capabilities.every(
    (capability, index) =>
      FINDING_CAPABILITIES.includes(
        capability as FindingCapability
      ) &&
      (index === 0 ||
        FINDING_CAPABILITIES.indexOf(
          capabilities[index - 1] as FindingCapability
        ) <
          FINDING_CAPABILITIES.indexOf(
            capability as FindingCapability
          ))
  );
}

function isSortedUniqueDigestArray(value: unknown[]): boolean {
  return value.every(
    (candidate, index) =>
      isSha256Digest(candidate) &&
      (index === 0 ||
        (value[index - 1] as string) < candidate)
  );
}

const CORRELATION_ID_PATTERNS = Object.freeze({
  'finding-observation': /^finding-observation:\/\/[a-f0-9]{64}$/u,
  'finding-occurrence': /^finding-occurrence:\/\/[a-f0-9]{64}$/u,
  'finding-lineage': /^finding-lineage:\/\/[a-f0-9]{64}$/u,
  'normalized-finding': /^normalized-finding:\/\/[a-f0-9]{64}$/u,
  'finding-correlation': /^finding-correlation:\/\/[a-f0-9]{64}$/u
});

function isCorrelationId(
  value: unknown,
  prefix: keyof typeof CORRELATION_ID_PATTERNS
): value is string {
  return (
    typeof value === 'string' &&
    CORRELATION_ID_PATTERNS[prefix].test(value)
  );
}

function isBoundedReference(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value === value.normalize('NFC') &&
    ![...value].some((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return codePoint <= 0x1f || codePoint === 0x7f;
    }) &&
    UTF8_ENCODER.encode(value).length <=
      SAST_FINDING_CORRELATION_LIMITS.maximumReferenceUtf8Bytes
  );
}

function isCommitSha(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    (/^[a-f0-9]{40}$/u.test(value) ||
      /^[a-f0-9]{64}$/u.test(value))
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

function isBoundedCount(value: unknown, maximum: number): boolean {
  return (
    Number.isInteger(value) &&
    (value as number) >= 0 &&
    (value as number) <= maximum
  );
}

function encodeCanonicalField(value: string): string {
  const normalized = value.normalize('NFC');
  return `${UTF8_ENCODER.encode(normalized).length}:${normalized}`;
}
