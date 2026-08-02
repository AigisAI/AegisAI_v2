import type {
  SastExternalPublicationDecision,
  SastFindingLifecycleCoverageDecision,
  SastScanCoverageDecision,
  SastScanCoverageScope,
  SastScannerCoverageExecutionStatus,
  SastScannerCoverageRecord,
  SastScannerKind
} from '@aegisai/shared';

export interface SastScanCoverageCorrelationContext {
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
  correlatedAt: string;
  sourceSetValid: boolean;
}

export interface SastScannerCoverageDurableEvidence {
  scanner: SastScannerKind;
  executionStatus: Exclude<
    SastScannerCoverageExecutionStatus,
    'NOT_STARTED'
  >;
  requiredBinding: boolean | null;
  scannerRunId: string;
  scannerVersion: string | null;
  scannerImageDigest: `sha256:${string}` | null;
  wrapperDigest: `sha256:${string}` | null;
  ruleBundleDigest: `sha256:${string}` | null;
  vulnerabilityDatabaseDigest: `sha256:${string}` | null;
  schemaBundleDigest: `sha256:${string}` | null;
  normalizerBundleDigest: `sha256:${string}` | null;
  provenanceValid: boolean;
  artifactIngestionId: string | null;
  artifactEnvelopeDigest: `sha256:${string}` | null;
  artifactDigest: `sha256:${string}` | null;
  dispositionDecisionId: string | null;
  dispositionDecisionDigest: `sha256:${string}` | null;
  artifactAccepted: boolean;
  normalizationEligible: boolean;
  artifactBindingValid: boolean;
  correlationSourceId: string | null;
  observationBatchId: string | null;
  correlationSourceBindingDigest: `sha256:${string}` | null;
  correlationSourceValid: boolean;
}

export interface SastScanCoverageContext {
  scope: SastScanCoverageScope;
  correlation: SastScanCoverageCorrelationContext;
  scanners: readonly Readonly<SastScannerCoverageDurableEvidence>[];
  existingDecision?: {
    coverageDecisionId: string;
    decisionDigest: `sha256:${string}`;
    publicationDecisionId: string;
    publicationDecisionDigest: `sha256:${string}`;
    decidedAt: string;
  };
}

export interface PersistSastScanCoverageInput {
  context: Readonly<SastScanCoverageContext>;
  records: readonly Readonly<SastScannerCoverageRecord>[];
  decision: Readonly<SastScanCoverageDecision>;
  publication: Readonly<SastExternalPublicationDecision>;
}

export interface PersistedSastScanCoverage {
  coverageDecisionId: string;
  decisionDigest: `sha256:${string}`;
  publicationDecisionId: string;
  publicationDecisionDigest: `sha256:${string}`;
  decidedAt: string;
  replayed: boolean;
}

export type SastScanCoverageLifecycleSourceVerification =
  | 'MATCHED'
  | 'REJECTED';

export class SastScanCoverageDurableScopeError extends Error {
  constructor() {
    super('The durable SAST scan-coverage scope is invalid.');
    this.name = 'SastScanCoverageDurableScopeError';
  }
}

export class SastScanCoverageScannerSetError extends Error {
  constructor() {
    super('The durable SAST scanner set is invalid.');
    this.name = 'SastScanCoverageScannerSetError';
  }
}

export class SastScanCoverageSourceSetError extends Error {
  constructor() {
    super('The durable SAST correlation source set is incomplete.');
    this.name = 'SastScanCoverageSourceSetError';
  }
}

export class SastScanCoverageReplayConflictError extends Error {
  constructor() {
    super('The SAST scan-coverage replay conflicts with durable state.');
    this.name = 'SastScanCoverageReplayConflictError';
  }
}

export abstract class SastScanCoverageStore {
  abstract loadContext(
    correlationBatchId: string
  ): Promise<SastScanCoverageContext | null>;

  abstract persist(
    input: Readonly<PersistSastScanCoverageInput>
  ): Promise<PersistedSastScanCoverage>;

  abstract verifyLifecycleSource(
    decision: Readonly<SastFindingLifecycleCoverageDecision>
  ): Promise<SastScanCoverageLifecycleSourceVerification>;
}
