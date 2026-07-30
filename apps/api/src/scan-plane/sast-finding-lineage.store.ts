import type {
  SastFindingLifecycleCoverageDecision,
  SastFindingRenameAttestation,
  SastFindingLineageObservationResult,
  SastFindingLifecycleReconciliationResult,
  SastFingerprintedFinding,
  SastFingerprintedFindingBatch,
  SastFindingRenameCandidate,
  SastProfileId,
  SastScanLane,
  SastScannerKind
} from '@aegisai/shared';

export interface SastFindingLineageObservationScope {
  tenantId: string;
  repositoryBindingId: string;
  scanRequestId: string;
  attemptId: string;
  scannerRunId: string;
}

export interface SastFindingLineageScanContext {
  scope: SastFindingLineageObservationScope;
  targetRef: string;
  lane: SastScanLane;
  commitSha: string;
  canonicalScanKey: `sha256:${string}`;
  planDigest: `sha256:${string}`;
  profileId: SastProfileId;
  profileDigest: `sha256:${string}`;
  scanner: SastScannerKind;
  source: {
    ingestionId: string;
    scannerVersion: string;
    scannerImageDigest: `sha256:${string}`;
    ruleBundleDigest?: `sha256:${string}`;
    vulnerabilityDatabaseDigest?: `sha256:${string}`;
    schemaBundleDigest: `sha256:${string}`;
    normalizerBundleDigest: `sha256:${string}`;
    preflightAttestationRef: string;
    preflightInventoryDigest: `sha256:${string}`;
    artifactSchema: string;
    artifactSchemaVersion: string;
    envelopeDigest: `sha256:${string}`;
    artifactDigest: `sha256:${string}`;
    validationResultDigest: `sha256:${string}`;
    dispositionDecisionDigest: `sha256:${string}`;
    retentionExpiresAt: string;
  };
}

export interface SastFindingReconciliationScanContext {
  tenantId: string;
  repositoryBindingId: string;
  scanRequestId: string;
  attemptId: string;
  targetRef: string;
  lane: SastScanLane;
  commitSha: string;
  canonicalScanKey: `sha256:${string}`;
  planDigest: `sha256:${string}`;
  profileId: SastProfileId;
  profileDigest: `sha256:${string}`;
}

export interface PersistSastFindingObservationInput {
  observationBatchId: string;
  lifecycleContextKey: `sha256:${string}`;
  observedAt: string;
  batch: Readonly<SastFingerprintedFindingBatch>;
  context: Readonly<SastFindingLineageScanContext>;
  renameAttestationDigest?: `sha256:${string}`;
  renameAttestation?: Readonly<SastFindingRenameAttestation>;
  renameCandidates: readonly Readonly<SastFindingRenameCandidate>[];
}

export interface PersistedSastFindingObservation {
  observationBatchId: string;
  sourceIdentityBatchDigest: `sha256:${string}`;
  lifecycleContextKey: `sha256:${string}`;
  findingCount: number;
  occurrenceCount: number;
  distinctFingerprintCount: number;
  createdLineageCount: number;
  exactMatchCount: number;
  renamedMatchCount: number;
  replayed: boolean;
  observedAt: string;
}

export interface PersistSastFindingReconciliationInput {
  reconciliationId: string;
  reconciledAt: string;
  decision: Readonly<SastFindingLifecycleCoverageDecision>;
  context: Readonly<SastFindingReconciliationScanContext>;
}

export interface PersistedSastFindingReconciliation {
  reconciliationId: string;
  coverageDecisionDigest: `sha256:${string}`;
  lifecycleContextKey: `sha256:${string}`;
  sequence: number;
  eligibleLineageCount: number;
  observedLineageCount: number;
  fixedCount: number;
  reopenedCount: number;
  unchangedOpenCount: number;
  unchangedFixedCount: number;
  replayed: boolean;
  reconciledAt: string;
}

export class SastFindingLineageReplayConflictError extends Error {
  constructor() {
    super('The finding-lineage operation conflicts with persisted state.');
    this.name = 'SastFindingLineageReplayConflictError';
  }
}

export class SastFindingLineageRenameAmbiguousError extends Error {
  constructor() {
    super('The rename would bind more than one finding lineage.');
    this.name = 'SastFindingLineageRenameAmbiguousError';
  }
}

export class SastFindingLineageDurableScopeError extends Error {
  constructor() {
    super('The finding-lineage durable scope is not valid.');
    this.name = 'SastFindingLineageDurableScopeError';
  }
}

export class SastFindingLineageReconciliationOrderError extends Error {
  constructor() {
    super('The finding lifecycle reconciliation is out of order.');
    this.name = 'SastFindingLineageReconciliationOrderError';
  }
}

export class SastFindingLineageObservationIncompleteError extends Error {
  constructor() {
    super('The finding lifecycle observation set is incomplete.');
    this.name = 'SastFindingLineageObservationIncompleteError';
  }
}

export abstract class SastFindingLineageStore {
  abstract loadObservationContext(
    scope: Readonly<SastFindingLineageObservationScope>
  ): Promise<SastFindingLineageScanContext | null>;

  abstract loadReconciliationContext(input: {
    tenantId: string;
    repositoryBindingId: string;
    scanRequestId: string;
    attemptId: string;
  }): Promise<SastFindingReconciliationScanContext | null>;

  abstract observe(
    input: Readonly<PersistSastFindingObservationInput>
  ): Promise<PersistedSastFindingObservation>;

  abstract reconcile(
    input: Readonly<PersistSastFindingReconciliationInput>
  ): Promise<PersistedSastFindingReconciliation>;
}

export type DurableSastFingerprintedFinding =
  SastFingerprintedFinding;
export type DurableSastFindingObservationResult =
  SastFindingLineageObservationResult;
export type DurableSastFindingReconciliationResult =
  SastFindingLifecycleReconciliationResult;
