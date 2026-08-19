import type {
  SastRuleBundleRollbackApproval,
  SastRuleBundleRollbackCommand,
  SastRuleBundleRollbackReceipt,
  SastRuleBundleRollbackVerification
} from '@aegisai/shared';

export interface PersistedSastRuleBundleRollbackCommand {
  command: SastRuleBundleRollbackCommand;
  verification: SastRuleBundleRollbackVerification;
  replayed: boolean;
}

export interface PersistedSastRuleBundleRollbackApproval {
  approval: SastRuleBundleRollbackApproval;
  replayed: boolean;
}

export interface PersistedSastRuleBundleRollbackReceipt {
  receipt: SastRuleBundleRollbackReceipt;
  replayed: boolean;
}

export interface SastRuleBundleRollbackCommandSnapshot {
  command: SastRuleBundleRollbackCommand;
  verification: SastRuleBundleRollbackVerification;
  approvals: SastRuleBundleRollbackApproval[];
  receipt: SastRuleBundleRollbackReceipt | null;
}

export class SastRuleBundleRollbackPersistenceError extends Error {
  constructor(
    readonly reason:
      | 'INPUT_INVALID'
      | 'COMMAND_NOT_FOUND'
      | 'VERIFICATION_NOT_FOUND'
      | 'APPROVAL_NOT_FOUND'
      | 'STATE_STALE'
      | 'REPLAY_CONFLICT'
      | 'LEDGER_CORRUPT'
  ) {
    super('The immutable SAST rule-bundle rollback ledger rejected the operation.');
    this.name = 'SastRuleBundleRollbackPersistenceError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export abstract class SastRuleBundleRollbackStore {
  abstract registerCommand(input: {
    command: Readonly<SastRuleBundleRollbackCommand>;
    verification: Readonly<SastRuleBundleRollbackVerification>;
  }): Promise<PersistedSastRuleBundleRollbackCommand>;

  abstract findCommandForCandidate(
    manifestId: string
  ): Promise<SastRuleBundleRollbackCommandSnapshot | null>;

  abstract findCommand(
    commandId: string
  ): Promise<SastRuleBundleRollbackCommandSnapshot | null>;

  abstract registerApproval(
    approval: Readonly<SastRuleBundleRollbackApproval>
  ): Promise<PersistedSastRuleBundleRollbackApproval>;

  abstract registerReceipt(
    receipt: Readonly<SastRuleBundleRollbackReceipt>
  ): Promise<PersistedSastRuleBundleRollbackReceipt>;
}
