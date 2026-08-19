import type {
  SastKillSwitchEvaluationContext,
  SastKillSwitchEvaluationResult,
  SastKillSwitchGate as SastKillSwitchGateName,
  SastScanPlan,
  SastScannerKind
} from '@aegisai/shared';

export type SastKillSwitchGateFailureReason =
  | 'CONTEXT_INVALID'
  | 'AUTHORITY_UNAVAILABLE'
  | 'STATE_STALE'
  | 'STORE_UNAVAILABLE';

export class SastKillSwitchGateError extends Error {
  constructor(readonly reason: SastKillSwitchGateFailureReason) {
    super('The SAST kill-switch authority failed closed.');
    this.name = 'SastKillSwitchGateError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export interface SastKillSwitchContextEvaluationInput {
  gate: SastKillSwitchGateName;
  context: Readonly<SastKillSwitchEvaluationContext>;
  evaluatedAt: string;
}

export interface SastKillSwitchPlanEvaluationInput {
  gate: SastKillSwitchGateName;
  plan: Readonly<SastScanPlan>;
  evaluatedAt: string;
  scanner?: SastScannerKind;
}

export interface SastKillSwitchPersistedScanEvaluationInput {
  gate: SastKillSwitchGateName;
  tenantId: string;
  repositoryBindingId: string;
  scanRequestId: string;
  evaluatedAt: string;
  scanner?: SastScannerKind;
}

export abstract class SastKillSwitchGate {
  abstract evaluateContext(
    input: Readonly<SastKillSwitchContextEvaluationInput>
  ): Promise<SastKillSwitchEvaluationResult>;

  abstract evaluatePlan(
    input: Readonly<SastKillSwitchPlanEvaluationInput>
  ): Promise<SastKillSwitchEvaluationResult>;

  abstract evaluatePersistedScan(
    input: Readonly<SastKillSwitchPersistedScanEvaluationInput>
  ): Promise<SastKillSwitchEvaluationResult>;
}

export class UnavailableSastKillSwitchGate extends SastKillSwitchGate {
  evaluateContext(): Promise<never> {
    return Promise.reject(
      new SastKillSwitchGateError('AUTHORITY_UNAVAILABLE')
    );
  }

  evaluatePlan(): Promise<never> {
    return this.evaluateContext();
  }

  evaluatePersistedScan(): Promise<never> {
    return this.evaluateContext();
  }
}
