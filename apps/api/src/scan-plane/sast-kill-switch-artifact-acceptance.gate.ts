import { Injectable } from '@nestjs/common';

import {
  SastKillSwitchGate,
  SastKillSwitchGateError
} from '../rule-governance/sast-kill-switch.gate';
import {
  SastArtifactAcceptanceAuthority,
  SastArtifactAcceptanceGate,
  SastArtifactAcceptanceGateUnavailableError,
  type SastArtifactAcceptanceGateDecision,
  type SastArtifactAcceptanceGateInput
} from './sast-artifact-acceptance-gate';

@Injectable()
export class SastKillSwitchArtifactAcceptanceGate extends SastArtifactAcceptanceGate {
  constructor(
    private readonly killSwitch: SastKillSwitchGate,
    private readonly acceptanceAuthority: SastArtifactAcceptanceAuthority
  ) {
    super();
  }

  async evaluate(
    input: Readonly<SastArtifactAcceptanceGateInput>
  ): Promise<SastArtifactAcceptanceGateDecision> {
    try {
      const result = await this.killSwitch.evaluatePlan({
        gate: 'ARTIFACT_ACCEPTANCE',
        plan: input.plan,
        scanner: input.scanner,
        evaluatedAt: input.evaluatedAt
      });
      if (result.receipt.outcome === 'ACTIVE') {
        return {
          outcome: 'DENY',
          controlRef: result.receipt.evaluationId,
          evaluatedAt: result.receipt.evaluatedAt,
          reasonCode: 'SAST_KILL_SWITCH_ACTIVE'
        };
      }
      return this.acceptanceAuthority.evaluate(input);
    } catch (error) {
      if (error instanceof SastKillSwitchGateError) {
        throw new SastArtifactAcceptanceGateUnavailableError();
      }
      throw new SastArtifactAcceptanceGateUnavailableError();
    }
  }
}
