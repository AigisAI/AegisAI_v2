import type {
  SastRuleBundleCanaryAssignmentReceipt,
  SastRuleBundleCanaryEligibilityDecision,
  SastRuleBundleCanaryMembership,
  SastRuleBundleCanaryObservationReceipt,
  SastRuleBundleCanaryRollout,
  SastRuleBundleCanaryScanObservation,
  SastRuleBundleCanaryStep,
  SastRuleBundleCanaryStepDecision
} from '@aegisai/shared';

export interface PersistedSastRuleBundleCanaryRollout {
  rollout: SastRuleBundleCanaryRollout;
  replayed: boolean;
}

export interface PersistedSastRuleBundleCanaryEligibilityDecision {
  decision: SastRuleBundleCanaryEligibilityDecision;
  replayed: boolean;
}

export interface PersistedSastRuleBundleCanaryAssignment {
  membership: SastRuleBundleCanaryMembership;
  assignment: SastRuleBundleCanaryAssignmentReceipt;
  replayed: boolean;
}

export interface PersistedSastRuleBundleCanaryObservation {
  observation: SastRuleBundleCanaryScanObservation;
  replayed: boolean;
}

export interface PersistedSastRuleBundleCanaryStepDecision {
  decision: SastRuleBundleCanaryStepDecision;
  receipt: SastRuleBundleCanaryObservationReceipt | null;
  replayed: boolean;
}

export interface SastRuleBundleCanaryRolloutSnapshot {
  rollout: SastRuleBundleCanaryRollout;
  latestDecision: SastRuleBundleCanaryStepDecision | null;
  passedDecisions: SastRuleBundleCanaryStepDecision[];
  observationReceipt: SastRuleBundleCanaryObservationReceipt | null;
}

export interface PendingSastRuleBundleCanaryAssignment {
  membership: SastRuleBundleCanaryMembership;
  assignment: SastRuleBundleCanaryAssignmentReceipt;
}

export class SastRuleBundleCanaryPersistenceError extends Error {
  constructor(
    readonly reason:
      | 'INPUT_INVALID'
      | 'ROLLOUT_NOT_FOUND'
      | 'ELIGIBILITY_NOT_FOUND'
      | 'ASSIGNMENT_NOT_FOUND'
      | 'OBSERVATION_NOT_FOUND'
      | 'STEP_STALE'
      | 'ROLLOUT_PAUSED'
      | 'REPLAY_CONFLICT'
      | 'LEDGER_CORRUPT'
  ) {
    super('The immutable SAST rule-bundle canary ledger rejected the operation.');
    this.name = 'SastRuleBundleCanaryPersistenceError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export abstract class SastRuleBundleCanaryStore {
  abstract registerRollout(
    rollout: Readonly<SastRuleBundleCanaryRollout>
  ): Promise<PersistedSastRuleBundleCanaryRollout>;

  abstract findRolloutForCandidate(
    manifestId: string,
    profileId: string
  ): Promise<SastRuleBundleCanaryRolloutSnapshot | null>;

  abstract findRollout(
    rolloutId: string
  ): Promise<SastRuleBundleCanaryRolloutSnapshot | null>;

  abstract registerEligibilityDecision(
    decision: Readonly<SastRuleBundleCanaryEligibilityDecision>
  ): Promise<PersistedSastRuleBundleCanaryEligibilityDecision>;

  abstract findEligibilityDecision(input: {
    rolloutId: string;
    tenantId: string;
    repositoryBindingId: string;
    profileId: string;
  }): Promise<SastRuleBundleCanaryEligibilityDecision | null>;

  abstract recordAssignments(
    assignments: readonly Readonly<PendingSastRuleBundleCanaryAssignment>[]
  ): Promise<PersistedSastRuleBundleCanaryAssignment[]>;

  abstract registerObservation(
    observation: Readonly<SastRuleBundleCanaryScanObservation>
  ): Promise<PersistedSastRuleBundleCanaryObservation>;

  abstract findObservations(input: {
    rolloutId: string;
    step: SastRuleBundleCanaryStep;
    windowStartedAt: string;
    windowEndedAt: string;
  }): Promise<SastRuleBundleCanaryScanObservation[]>;

  abstract appendStepDecision(input: {
    decision: Readonly<SastRuleBundleCanaryStepDecision>;
    finalReceipt: Readonly<SastRuleBundleCanaryObservationReceipt> | null;
  }): Promise<PersistedSastRuleBundleCanaryStepDecision>;

  abstract findObservationReceiptForAuthority(input: {
    manifestId: string;
    manifestDigest: string;
    bundleId: string;
    bundleDigest: string;
    promotionEvidenceId: string;
    promotionEvidenceDigest: string;
  }): Promise<SastRuleBundleCanaryObservationReceipt | null>;
}
