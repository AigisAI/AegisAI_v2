import type {
  SastFindingCorrelationEdgeDecision,
  SastFindingCorrelationProvenance,
  SastFindingCorrelationScope,
  SastFindingCorrelationSourceBinding,
  SastFindingCorrelationSourceBindingCore,
  SastFingerprintedFinding
} from '@aegisai/shared';

export interface SastFindingCorrelationOccurrence {
  id: string;
  observationBatchId: string;
  lineageId: string;
  normalizedFindingId: string;
  scannerRunId: string;
  ordinal: number;
  sourceFinding: SastFingerprintedFinding;
}

export interface SastFindingCorrelationContext {
  scope: SastFindingCorrelationScope;
  requiredCapabilities: ReadonlyArray<
    SastFingerprintedFinding['capability']
  >;
  sources: readonly Readonly<SastFindingCorrelationSourceBindingCore>[];
  occurrences: readonly Readonly<SastFindingCorrelationOccurrence>[];
  existingCorrelation?: {
    correlationBatchId: string;
    sourceSetDigest: `sha256:${string}`;
    correlatedAt: string;
  };
}

export interface PersistSastFindingCorrelationEdge {
  decision: Readonly<SastFindingCorrelationEdgeDecision>;
  sourceProvenance: Readonly<SastFindingCorrelationProvenance>;
  targetProvenance: Readonly<SastFindingCorrelationProvenance>;
}

export interface PersistSastFindingCorrelationInput {
  correlationBatchId: string;
  sourceSetDigest: `sha256:${string}`;
  correlatedAt: string;
  context: Readonly<SastFindingCorrelationContext>;
  sources: readonly Readonly<SastFindingCorrelationSourceBinding>[];
  edges: readonly Readonly<PersistSastFindingCorrelationEdge>[];
}

export interface PersistedSastFindingCorrelation {
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
}

export class SastFindingCorrelationSourceSetIncompleteError extends Error {
  constructor() {
    super('The durable finding-correlation source set is incomplete.');
    this.name = 'SastFindingCorrelationSourceSetIncompleteError';
  }
}

export class SastFindingCorrelationDurableScopeError extends Error {
  constructor() {
    super('The finding-correlation durable scope is not valid.');
    this.name = 'SastFindingCorrelationDurableScopeError';
  }
}

export class SastFindingCorrelationAuthorityError extends Error {
  constructor() {
    super('The finding-correlation authority matrix is not valid.');
    this.name = 'SastFindingCorrelationAuthorityError';
  }
}

export class SastFindingCorrelationOccurrenceError extends Error {
  constructor() {
    super('A durable finding occurrence is not valid for correlation.');
    this.name = 'SastFindingCorrelationOccurrenceError';
  }
}

export class SastFindingCorrelationReplayConflictError extends Error {
  constructor() {
    super('The finding-correlation replay conflicts with persisted state.');
    this.name = 'SastFindingCorrelationReplayConflictError';
  }
}

export abstract class SastFindingCorrelationStore {
  abstract loadContext(
    observationBatchIds: readonly string[]
  ): Promise<SastFindingCorrelationContext | null>;

  abstract correlate(
    input: Readonly<PersistSastFindingCorrelationInput>
  ): Promise<PersistedSastFindingCorrelation>;
}
