import type {
  SastFindingLifecycleCoverageDecision,
  SastLatestTargetObservation,
  SastScanComparisonSource,
  SastScanFreshnessDecision,
  SastScanFreshnessScope,
  SastScanRetryDecision,
  SastScanRetryEvaluation,
  SastScannerWrapperExecutionRequest
} from '@aegisai/shared';

export interface SastScanFreshnessContext {
  coverageComplete: boolean;
  coverageCompletedAt: string | null;
  scope: SastScanFreshnessScope;
  comparison: SastScanComparisonSource | null;
  latestObservation: {
    observationId: string;
    sequence: number;
    observedAt: string;
  } | null;
  existingDecision: SastScanFreshnessDecision | null;
}

export interface PersistedSastScanFreshness {
  freshnessDecisionId: string;
  decisionDigest: `sha256:${string}`;
  replayed: boolean;
}

export interface SastScanRetryDurableContext {
  evaluation: Omit<
    SastScanRetryEvaluation,
    | 'currentScannerSetDigest'
    | 'scannerSetAvailable'
    | 'killSwitchStatus'
    | 'killSwitchSnapshotDigest'
  >;
  existingDecision: SastScanRetryDecision | null;
}

export class SastScanFreshnessPersistenceError extends Error {
  constructor(readonly reason: 'CONTEXT_DRIFT' | 'REPLAY_CONFLICT') {
    super('The SAST freshness or retry ledger conflicts with durable state.');
    this.name = 'SastScanFreshnessPersistenceError';
  }
}

export abstract class SastScanFreshnessStore {
  abstract loadContext(
    coverageDecisionId: string
  ): Promise<SastScanFreshnessContext | null>;

  abstract persistFreshness(input: {
    context: Readonly<SastScanFreshnessContext>;
    observation: Readonly<SastLatestTargetObservation> | null;
    decision: Readonly<SastScanFreshnessDecision>;
  }): Promise<PersistedSastScanFreshness>;

  abstract verifyLifecycleSource(
    decision: Readonly<SastFindingLifecycleCoverageDecision>
  ): Promise<'MATCHED' | 'REJECTED'>;

  abstract loadRetryContext(
    request: Readonly<SastScannerWrapperExecutionRequest>
  ): Promise<SastScanRetryDurableContext | null>;

  abstract persistRetryDecision(input: {
    context: Readonly<SastScanRetryDurableContext>;
    decision: Readonly<SastScanRetryDecision>;
  }): Promise<{
    retryDecisionId: string;
    decisionDigest: `sha256:${string}`;
    retryAllowed: boolean;
    replayed: boolean;
  }>;
}
