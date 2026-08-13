import type {
  SastAiAdvisoryAuthorityProof,
  SastAiAdvisoryPolicyReference
} from '@aegisai/shared';

export interface PersistedSastAiAdvisoryAuthorityProof {
  proof: SastAiAdvisoryAuthorityProof;
  replayed: boolean;
}

export class SastAiAdvisoryAuthorityPersistenceError extends Error {
  constructor(
    readonly reason:
      | 'CONTEXT_DRIFT'
      | 'OUTPUT_INVALID'
      | 'REPLAY_CONFLICT'
      | 'STATE_DRIFT'
      | 'STATE_TOO_BROAD'
  ) {
    super('The SAST AI advisory authority proof conflicts with durable state.');
    this.name = 'SastAiAdvisoryAuthorityPersistenceError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export abstract class SastAiAdvisoryAuthorityStore {
  abstract createProof(input: {
    tenantId: string;
    advisoryId: string;
    verifiedAt: string;
  }): Promise<PersistedSastAiAdvisoryAuthorityProof>;

  abstract verifyPolicyReference(input: {
    tenantId: string;
    normalizedFindingId: string;
    reference: Readonly<SastAiAdvisoryPolicyReference>;
  }): Promise<boolean>;
}
