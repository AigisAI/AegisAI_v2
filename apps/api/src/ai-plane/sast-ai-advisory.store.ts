import type {
  AiAdvisoryResult,
  SastAiAdvisoryHandoff,
  SastAiAdvisoryNormalizedFinding,
  SastEvidenceAccessDecision
} from '@aegisai/shared';

export interface PersistedSastAiAdvisoryHandoff {
  handoff: SastAiAdvisoryHandoff;
  replayed: boolean;
}

export class SastAiAdvisoryPersistenceError extends Error {
  constructor(
    readonly reason:
      | 'CONTEXT_DRIFT'
      | 'OUTPUT_INVALID'
      | 'REPLAY_CONFLICT'
  ) {
    super('The SAST AI advisory handoff conflicts with durable state.');
    this.name = 'SastAiAdvisoryPersistenceError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export abstract class SastAiAdvisoryStore {
  abstract loadNormalizedFinding(
    decision: Readonly<SastEvidenceAccessDecision>
  ): Promise<SastAiAdvisoryNormalizedFinding | null>;

  abstract persistHandoff(
    handoff: Readonly<SastAiAdvisoryHandoff>
  ): Promise<PersistedSastAiAdvisoryHandoff>;

  abstract loadAdvisory(input: {
    tenantId: string;
    advisoryId: string;
  }): Promise<AiAdvisoryResult | null>;

  abstract persistAdvisory(input: {
    handoff: Readonly<SastAiAdvisoryHandoff>;
    advisory: Readonly<AiAdvisoryResult>;
  }): Promise<AiAdvisoryResult>;
}
