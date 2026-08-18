import type {
  SastRuleBundleLifecycleSelectionReceipt,
  SastRuleBundleLifecycleTransition,
  SastRuleBundlePromotionApproval,
  SastRuleBundlePromotionEvidence
} from '@aegisai/shared';

export interface PersistedSastRuleBundlePromotionEvidence {
  evidence: SastRuleBundlePromotionEvidence;
  replayed: boolean;
}

export interface PersistedSastRuleBundlePromotionApproval {
  approval: SastRuleBundlePromotionApproval;
  replayed: boolean;
}

export interface PersistedSastRuleBundleLifecycleTransition {
  transition: SastRuleBundleLifecycleTransition;
  replayed: boolean;
}

export interface PersistedSastRuleBundleLifecycleSelection {
  receipt: SastRuleBundleLifecycleSelectionReceipt;
  replayed: boolean;
}

export interface SastRuleBundleLifecycleLedgerSnapshot {
  transition: SastRuleBundleLifecycleTransition;
  evidence: SastRuleBundlePromotionEvidence;
  approvals: SastRuleBundlePromotionApproval[];
}

export class SastRuleBundleLifecyclePersistenceError extends Error {
  constructor(
    readonly reason:
      | 'INPUT_INVALID'
      | 'LEDGER_CORRUPT'
      | 'MANIFEST_NOT_FOUND'
      | 'EVIDENCE_NOT_FOUND'
      | 'APPROVAL_NOT_FOUND'
      | 'TRANSITION_NOT_FOUND'
      | 'REFERENCE_INVALID'
      | 'STALE_TRANSITION'
      | 'REPLAY_CONFLICT'
  ) {
    super('The immutable SAST rule-bundle lifecycle ledger rejected the operation.');
    this.name = 'SastRuleBundleLifecyclePersistenceError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export abstract class SastRuleBundleLifecycleStore {
  abstract registerPromotionEvidence(
    evidence: Readonly<SastRuleBundlePromotionEvidence>
  ): Promise<PersistedSastRuleBundlePromotionEvidence>;

  abstract findPromotionEvidence(
    evidenceId: string
  ): Promise<PersistedSastRuleBundlePromotionEvidence | null>;

  abstract registerPromotionApproval(
    approval: Readonly<SastRuleBundlePromotionApproval>
  ): Promise<PersistedSastRuleBundlePromotionApproval>;

  abstract findPromotionApprovals(
    approvalIds: readonly string[]
  ): Promise<SastRuleBundlePromotionApproval[]>;

  abstract appendLifecycleTransition(
    transition: Readonly<SastRuleBundleLifecycleTransition>
  ): Promise<PersistedSastRuleBundleLifecycleTransition>;

  abstract findLatestLifecycleSnapshot(
    manifestId: string
  ): Promise<SastRuleBundleLifecycleLedgerSnapshot | null>;

  abstract recordLifecycleSelections(
    receipts: readonly Readonly<SastRuleBundleLifecycleSelectionReceipt>[]
  ): Promise<PersistedSastRuleBundleLifecycleSelection[]>;
}
