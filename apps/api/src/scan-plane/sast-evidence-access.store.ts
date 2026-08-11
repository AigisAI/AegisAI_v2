import type {
  SastAcceptedEvidenceBuildResult,
  SastEvidenceAccessDecision,
  SastEvidenceAccessScope,
  SastEvidenceAccessPurpose,
  SastEvidenceDeletionProof,
  SastEvidenceDeletionReceipt,
  SastEvidenceDeletionSchedule
} from '@aegisai/shared';

export type SastEvidenceDeletionState =
  | 'ACTIVE'
  | 'DELETION_PENDING'
  | 'DELETED';

export interface SastEvidenceAccessContext {
  result: SastAcceptedEvidenceBuildResult | null;
  schedule: SastEvidenceDeletionSchedule;
  deletionState: SastEvidenceDeletionState;
  deletionProof: SastEvidenceDeletionProof | null;
  tenantAiAdvisoryOptIn: boolean;
  repositoryAiAdvisoryOptIn: boolean;
  freshnessEligible: boolean;
  coverageComplete: boolean;
}

export interface PersistedSastEvidenceAccessDecision {
  decision: SastEvidenceAccessDecision;
  replayed: boolean;
}

export interface SastEvidenceDeletionCandidate {
  schedule: SastEvidenceDeletionSchedule;
  leaseOwner: string;
  leaseToken: string;
  leaseExpiresAt: string;
}

export class SastEvidenceAccessPersistenceError extends Error {
  constructor(
    readonly reason:
      | 'CONTEXT_DRIFT'
      | 'OUTPUT_INVALID'
      | 'REPLAY_CONFLICT'
      | 'LEASE_LOST'
  ) {
    super('The evidence access/deletion ledger conflicts with durable state.');
    this.name = 'SastEvidenceAccessPersistenceError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export abstract class SastEvidenceAccessStore {
  abstract load(input: {
    tenantId: string;
    repositoryBindingId: string;
    evidencePackId: string;
    referenceTime: string;
  }): Promise<SastEvidenceAccessContext | null>;

  abstract persistDecision(input: {
    context: Readonly<SastEvidenceAccessContext>;
    decision: Readonly<SastEvidenceAccessDecision>;
  }): Promise<PersistedSastEvidenceAccessDecision>;

  abstract confirmAccess(input: {
    tenantId: string;
    repositoryBindingId: string;
    evidencePackId: string;
    accessDecisionId: string;
    purpose: SastEvidenceAccessPurpose;
    secretRegistryVersion: string;
    redactedProjectionDigest: `sha256:${string}`;
    referenceTime: string;
  }): Promise<SastEvidenceAccessContext | null>;

  abstract backfillDeletionSchedules(input: {
    referenceTime: string;
    limit: number;
  }): Promise<number>;

  abstract claimDeletion(input: {
    referenceTime: string;
    leaseOwner: string;
    leaseExpiresAt: string;
  }): Promise<SastEvidenceDeletionCandidate | null>;

  abstract finalizeDeletion(input: {
    candidate: Readonly<SastEvidenceDeletionCandidate>;
    receipt: Readonly<SastEvidenceDeletionReceipt>;
    proof: Readonly<SastEvidenceDeletionProof>;
  }): Promise<{ proof: SastEvidenceDeletionProof; replayed: boolean }>;

  abstract releaseDeletion(input: {
    candidate: Readonly<SastEvidenceDeletionCandidate>;
    retryAt: string;
  }): Promise<void>;
}

export function sastEvidenceAccessScopeFromResult(
  result: Readonly<SastAcceptedEvidenceBuildResult>
): SastEvidenceAccessScope {
  const pack = result.pack;
  if (!pack) {
    throw new SastEvidenceAccessPersistenceError('OUTPUT_INVALID');
  }
  return {
    tenantId: pack.scope.tenantId,
    repositoryBindingId: pack.scope.repositoryBindingId,
    scanRequestId: pack.scope.scanRequestId,
    attemptId: pack.scope.attemptId,
    occurrenceId: pack.scope.occurrenceId,
    buildDecisionId: result.decision.buildDecisionId,
    evidencePackId: pack.evidencePackId,
    findingFingerprint:
      pack.scope.findingFingerprint as `sha256:${string}`,
    profileId: pack.scope.profileId,
    profileDigest: pack.scope.profileDigest as `sha256:${string}`,
    freshnessDecisionId: pack.scope.freshnessDecisionId,
    freshnessDecisionDigest:
      pack.scope.freshnessDecisionDigest as `sha256:${string}`,
    coverageDecisionId: pack.scope.coverageDecisionId,
    coverageDecisionDigest:
      pack.scope.coverageDecisionDigest as `sha256:${string}`,
    sourcePackDigest: pack.packDigest as `sha256:${string}`
  };
}
