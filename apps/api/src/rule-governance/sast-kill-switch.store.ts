import type {
  SastKillSwitchControlDecision,
  SastKillSwitchEmergencySuspensionReceipt,
  SastKillSwitchEvaluationContext,
  SastKillSwitchEvaluationResult,
  SastKillSwitchGate,
  SastKillSwitchVerification,
  SastScanPlan
} from '@aegisai/shared';

import type {
  SastRuleBundleLifecycleAuthorityInput
} from './sast-rule-bundle-lifecycle.authority';

export interface PersistedSastKillSwitchDecision {
  decision: SastKillSwitchControlDecision;
  verification: SastKillSwitchVerification;
  replayed: boolean;
}

export interface SastKillSwitchPersistedPlanScope {
  tenantId: string;
  repositoryBindingId: string;
  scanRequestId: string;
}

export class SastKillSwitchPersistenceError extends Error {
  constructor(
    readonly reason:
      | 'INPUT_INVALID'
      | 'AUTHORITY_UNAVAILABLE'
      | 'LEDGER_CORRUPT'
      | 'PLAN_NOT_FOUND'
      | 'PLAN_SCOPE_MISMATCH'
      | 'STALE_DECISION'
      | 'DEACTIVATION_WITHOUT_ACTIVE_HEAD'
      | 'ACTIVE_DECISION_EXPIRED'
      | 'REPLAY_CONFLICT'
      | 'LIFECYCLE_NOT_FOUND'
      | 'LIFECYCLE_SCOPE_MISMATCH'
      | 'NO_ACTIVE_SUSPENSION_DECISION'
  ) {
    super('The immutable SAST kill-switch ledger rejected the operation.');
    this.name = 'SastKillSwitchPersistenceError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export abstract class SastKillSwitchStore {
  abstract appendDecision(
    decision: Readonly<SastKillSwitchControlDecision>,
    verification: Readonly<SastKillSwitchVerification>
  ): Promise<PersistedSastKillSwitchDecision>;

  abstract evaluate(
    context: Readonly<SastKillSwitchEvaluationContext>,
    gate: SastKillSwitchGate,
    evaluatedAt: string
  ): Promise<SastKillSwitchEvaluationResult>;

  abstract loadPersistedPlan(
    scope: Readonly<SastKillSwitchPersistedPlanScope>
  ): Promise<SastScanPlan | null>;

  abstract authorizeEmergencySuspension(
    input: Readonly<SastRuleBundleLifecycleAuthorityInput>,
    verifiedAt: string
  ): Promise<SastKillSwitchEmergencySuspensionReceipt>;
}
