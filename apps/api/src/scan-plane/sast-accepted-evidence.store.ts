import type {
  SastAcceptedEvidenceBuildResult,
  SastAcceptedEvidenceScope,
  SastEvidenceBuildDecision
} from '@aegisai/shared';

export interface SastAcceptedEvidenceContext {
  scope: SastAcceptedEvidenceScope;
  freshnessDecidedAt: string;
}

export interface PersistedSastAcceptedEvidence {
  buildDecisionId: string;
  decisionDigest: string;
  outcome: SastEvidenceBuildDecision['outcome'];
  evidencePackId: string | null;
  replayed: boolean;
}

export class SastAcceptedEvidencePersistenceError extends Error {
  constructor(
    readonly reason:
      | 'CONTEXT_DRIFT'
      | 'REPLAY_CONFLICT'
      | 'OUTPUT_INVALID'
  ) {
    super('The accepted-finding evidence ledger conflicts with durable state.');
    this.name = 'SastAcceptedEvidencePersistenceError';
  }
}

export abstract class SastAcceptedEvidenceStore {
  abstract loadContext(
    freshnessDecisionId: string,
    occurrenceId: string
  ): Promise<SastAcceptedEvidenceContext | null>;

  abstract persist(input: {
    context: Readonly<SastAcceptedEvidenceContext>;
    result: Readonly<SastAcceptedEvidenceBuildResult>;
  }): Promise<PersistedSastAcceptedEvidence>;
}
