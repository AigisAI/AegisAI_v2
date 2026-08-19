import {
  SAST_RULE_BUNDLE_ROLLBACK_LIMITS,
  buildSastRuleBundleRollbackApproval,
  buildSastRuleBundleRollbackCommand,
  buildSastRuleBundleRollbackReceipt,
  buildSastRuleBundleRollbackVerification,
  isSastRuleBundlePromotionApprovalShapeValid,
  isSastRuleBundlePromotionEvidenceShapeValid,
  isSastRuleBundleRollbackApprovalValid,
  isSastRuleBundleRollbackCommandValid,
  isSastRuleBundleRollbackReceiptValid,
  isSastRuleBundleRollbackRequestValid,
  isSastRuleBundleRollbackVerificationValid,
  isSastRuleBundleLifecycleTransitionShapeValid,
  type SastRuleBundleRollbackApprovalInput,
  type SastRuleBundleRollbackCommand,
  type SastRuleBundleRollbackReceipt,
  type SastRuleBundleRollbackRequest
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';

import { digestSastRuleBundleCanonical } from './sast-rule-bundle-canonical';
import type {
  SastRuleBundleLifecycleAuthorityInput,
  SastRuleBundleLifecycleAuthorityReceipt
} from './sast-rule-bundle-lifecycle.authority';
import {
  SastRuleBundleLifecyclePersistenceError,
  SastRuleBundleLifecycleStore,
  type SastRuleBundleLifecycleLedgerSnapshot
} from './sast-rule-bundle-lifecycle.store';
import {
  SastRuleBundleManifestPersistenceError,
  SastRuleBundleManifestStore,
  type PersistedVerifiedSastRuleBundle
} from './sast-rule-bundle-manifest.store';
import { SastRuleBundleRollbackClock } from './sast-rule-bundle-rollback.clock';
import {
  SastRuleBundleRollbackSignatureAuthority,
  SastRuleBundleRollbackSignatureAuthorityError
} from './sast-rule-bundle-rollback-signature.authority';
import {
  SastRuleBundleRollbackPersistenceError,
  SastRuleBundleRollbackStore,
  type PersistedSastRuleBundleRollbackApproval,
  type PersistedSastRuleBundleRollbackCommand,
  type SastRuleBundleRollbackCommandSnapshot
} from './sast-rule-bundle-rollback.store';

const MAXIMUM_AUTHORITY_CLOCK_SKEW_MILLISECONDS = 60_000;

export class SastRuleBundleRollbackServiceError extends Error {
  constructor(
    readonly reason:
      | 'INPUT_INVALID'
      | 'SIGNATURE_UNAVAILABLE'
      | 'SIGNATURE_REJECTED'
      | 'COMMAND_INVALID'
      | 'APPROVAL_INVALID'
      | 'STATE_STALE'
      | 'AUTHORITY_UNAVAILABLE'
      | 'STORE_UNAVAILABLE'
  ) {
    super('The SAST rule-bundle rollback operation failed closed.');
    this.name = 'SastRuleBundleRollbackServiceError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

@Injectable()
export class SastRuleBundleRollbackService {
  constructor(
    private readonly store: SastRuleBundleRollbackStore,
    private readonly manifestStore: SastRuleBundleManifestStore,
    private readonly lifecycleStore: SastRuleBundleLifecycleStore,
    private readonly signatureAuthority: SastRuleBundleRollbackSignatureAuthority,
    private readonly clock: SastRuleBundleRollbackClock
  ) {}

  async registerCommand(
    request: Readonly<SastRuleBundleRollbackRequest>
  ): Promise<PersistedSastRuleBundleRollbackCommand> {
    if (!isSastRuleBundleRollbackRequestValid(request)) {
      throw new SastRuleBundleRollbackServiceError('INPUT_INVALID');
    }
    const trustedNow = this.readTrustedNow();
    if (!isFreshAt(request.commandedAt, trustedNow)) {
      throw new SastRuleBundleRollbackServiceError('INPUT_INVALID');
    }

    try {
      const [candidate, candidateLifecycle] = await Promise.all([
        this.manifestStore.findVerified(request.candidateManifestId),
        this.lifecycleStore.findLatestLifecycleSnapshot(
          request.candidateManifestId
        )
      ]);
      if (
        !candidate ||
        !candidateLifecycle ||
        !candidateSuspensionMatchesRequest(
          candidate,
          candidateLifecycle,
          request
        )
      ) {
        throw new SastRuleBundleRollbackServiceError('STATE_STALE');
      }

      const evidence = candidateLifecycle.evidence;
      const [baseline, baselineLifecycle] = await Promise.all([
        this.manifestStore.findVerified(evidence.baselineManifestId),
        this.lifecycleStore.findLatestLifecycleSnapshot(
          evidence.baselineManifestId
        )
      ]);
      if (
        !baseline ||
        !baselineLifecycle ||
        !rollbackBaselineIsCurrent(
          candidate,
          candidateLifecycle,
          baseline,
          baselineLifecycle
        )
      ) {
        throw new SastRuleBundleRollbackServiceError('STATE_STALE');
      }

      const transition = candidateLifecycle.transition;
      const baselineTransition = baselineLifecycle.transition;
      const command = buildSastRuleBundleRollbackCommand(
        {
          candidateManifestId: candidate.manifest.manifestId,
          candidateManifestDigest: candidate.manifest.manifestDigest,
          candidateVerificationId: candidate.attestation.verificationId,
          candidateVerificationDigest: candidate.attestation.attestationDigest,
          candidateBundleId: candidate.manifest.bundleId,
          candidateBundleDigest: candidate.manifest.bundleDigest,
          suspendedTransitionId: transition.transitionId,
          suspendedTransitionDigest: transition.transitionDigest,
          suspendedSequence: transition.sequence,
          suspendedTransitionedAt: transition.transitionedAt,
          suspensionAuthorityReceiptRef:
            transition.externalAuthorityReceiptRef as string,
          suspensionAuthorityReceiptDigest:
            transition.externalAuthorityReceiptDigest as `sha256:${string}`,
          promotionEvidenceId: evidence.evidenceId,
          promotionEvidenceDigest: evidence.evidenceDigest,
          profileId: evidence.profileId,
          baselineManifestId: baseline.manifest.manifestId,
          baselineManifestDigest: baseline.manifest.manifestDigest,
          baselineVerificationId: baseline.attestation.verificationId,
          baselineVerificationDigest: baseline.attestation.attestationDigest,
          baselineBundleId: baseline.manifest.bundleId,
          baselineBundleDigest: baseline.manifest.bundleDigest,
          baselineTransitionId: baselineTransition.transitionId,
          baselineTransitionDigest: baselineTransition.transitionDigest,
          baselineSequence: baselineTransition.sequence,
          baselineTransitionedAt: baselineTransition.transitionedAt,
          incidentRef: request.incidentRef,
          actorRef: request.actorRef,
          actorRole: request.actorRole,
          reasonRef: request.reasonRef,
          auditRef: request.auditRef,
          signatureRef: request.signatureRef,
          provenanceRef: request.provenanceRef,
          commandedAt: request.commandedAt
        },
        digestSastRuleBundleCanonical
      );
      if (!command) {
        throw new SastRuleBundleRollbackServiceError('COMMAND_INVALID');
      }

      const facts = await this.signatureAuthority.verify(command);
      if (
        facts.signatureRef !== command.signatureRef ||
        facts.provenanceRef !== command.provenanceRef ||
        facts.signatureVerified !== true ||
        facts.provenanceVerified !== true ||
        facts.trustedSigner !== true ||
        facts.signatureBytesStored !== false ||
        facts.provenancePayloadStored !== false
      ) {
        throw new SastRuleBundleRollbackServiceError('SIGNATURE_REJECTED');
      }
      const verification = buildSastRuleBundleRollbackVerification(
        {
          commandId: command.commandId,
          commandDigest: command.commandDigest,
          signerIdentity: facts.signerIdentity,
          signatureRef: facts.signatureRef,
          provenanceRef: facts.provenanceRef,
          verifiedAt: trustedNow
        },
        digestSastRuleBundleCanonical
      );
      if (!verification) {
        throw new SastRuleBundleRollbackServiceError('SIGNATURE_REJECTED');
      }
      return await this.store.registerCommand({ command, verification });
    } catch (error) {
      if (error instanceof SastRuleBundleRollbackServiceError) throw error;
      if (error instanceof SastRuleBundleRollbackSignatureAuthorityError) {
        throw new SastRuleBundleRollbackServiceError(
          error.reason === 'UNAVAILABLE'
            ? 'SIGNATURE_UNAVAILABLE'
            : 'SIGNATURE_REJECTED'
        );
      }
      if (
        error instanceof SastRuleBundleManifestPersistenceError ||
        error instanceof SastRuleBundleLifecyclePersistenceError
      ) {
        throw new SastRuleBundleRollbackServiceError('STATE_STALE');
      }
      if (error instanceof SastRuleBundleRollbackPersistenceError) {
        throw new SastRuleBundleRollbackServiceError(
          rollbackServiceReasonForPersistence(error.reason)
        );
      }
      throw new SastRuleBundleRollbackServiceError('STORE_UNAVAILABLE');
    }
  }

  async registerApproval(
    input: Readonly<SastRuleBundleRollbackApprovalInput>
  ): Promise<PersistedSastRuleBundleRollbackApproval> {
    const approval = buildSastRuleBundleRollbackApproval(
      input,
      digestSastRuleBundleCanonical
    );
    if (!approval) {
      throw new SastRuleBundleRollbackServiceError('INPUT_INVALID');
    }
    const trustedNow = this.readTrustedNow();
    try {
      const snapshot = await this.findCommandById(approval.commandId);
      const replay = snapshot?.approvals.find(
        (current) => current.approvalId === approval.approvalId
      );
      if (
        !snapshot ||
        !commandSnapshotIsValid(snapshot) ||
        approval.commandDigest !== snapshot.command.commandDigest ||
        (replay
          ? replay.approvalDigest !== approval.approvalDigest
          : snapshot.receipt !== null ||
            approval.approverRef === snapshot.command.actorRef ||
            Date.parse(approval.approvedAt) <
              Date.parse(snapshot.command.commandedAt) ||
            Date.parse(approval.approvedAt) > Date.parse(trustedNow) ||
            !isFreshAt(snapshot.command.commandedAt, approval.approvedAt) ||
            !approvalSetCanAccept(
              snapshot,
              approval.role,
              approval.approverRef
            ))
      ) {
        throw new SastRuleBundleRollbackServiceError('APPROVAL_INVALID');
      }
      return await this.store.registerApproval(approval);
    } catch (error) {
      if (error instanceof SastRuleBundleRollbackServiceError) throw error;
      if (error instanceof SastRuleBundleRollbackPersistenceError) {
        throw new SastRuleBundleRollbackServiceError(
          rollbackServiceReasonForPersistence(error.reason)
        );
      }
      throw new SastRuleBundleRollbackServiceError('STORE_UNAVAILABLE');
    }
  }

  async authorizeLifecycleTransition(
    input: Readonly<SastRuleBundleLifecycleAuthorityInput>
  ): Promise<SastRuleBundleLifecycleAuthorityReceipt> {
    if (
      input.authority !== 'ROLLBACK' ||
      input.fromState !== 'SUSPENDED' ||
      input.toState !== 'ROLLED_BACK'
    ) {
      throw new SastRuleBundleRollbackServiceError('INPUT_INVALID');
    }
    const trustedNow = this.readTrustedNow();
    if (
      Date.parse(input.requestedAt) > Date.parse(trustedNow) ||
      Date.parse(trustedNow) - Date.parse(input.requestedAt) >
        MAXIMUM_AUTHORITY_CLOCK_SKEW_MILLISECONDS
    ) {
      throw new SastRuleBundleRollbackServiceError('AUTHORITY_UNAVAILABLE');
    }

    try {
      const snapshot = await this.store.findCommandForCandidate(
        input.manifestId
      );
      if (
        !snapshot ||
        !commandSnapshotIsValid(snapshot) ||
        !commandMatchesAuthorityInput(snapshot.command, input) ||
        !isFreshAt(snapshot.command.commandedAt, input.requestedAt)
      ) {
        throw new SastRuleBundleRollbackServiceError('COMMAND_INVALID');
      }

      const [candidate, candidateLifecycle, baseline, baselineLifecycle] =
        await Promise.all([
          this.manifestStore.findVerified(snapshot.command.candidateManifestId),
          this.lifecycleStore.findLatestLifecycleSnapshot(
            snapshot.command.candidateManifestId
          ),
          this.manifestStore.findVerified(snapshot.command.baselineManifestId),
          this.lifecycleStore.findLatestLifecycleSnapshot(
            snapshot.command.baselineManifestId
          )
        ]);
      if (
        !candidate ||
        !candidateLifecycle ||
        !baseline ||
        !baselineLifecycle ||
        !commandMatchesCurrentState(
          snapshot.command,
          candidate,
          candidateLifecycle,
          baseline,
          baselineLifecycle
        )
      ) {
        throw new SastRuleBundleRollbackServiceError('STATE_STALE');
      }

      const receipt = buildSastRuleBundleRollbackReceipt(
        {
          command: snapshot.command,
          verification: snapshot.verification,
          approvals: snapshot.approvals,
          requestedAt: input.requestedAt,
          issuedAt: input.requestedAt
        },
        digestSastRuleBundleCanonical
      );
      if (!receipt) {
        throw new SastRuleBundleRollbackServiceError('APPROVAL_INVALID');
      }
      const persisted = await this.store.registerReceipt(receipt);
      if (
        !isSastRuleBundleRollbackReceiptValid(
          persisted.receipt,
          digestSastRuleBundleCanonical
        ) ||
        persisted.receipt.receiptRef !== receipt.receiptRef ||
        persisted.receipt.receiptDigest !== receipt.receiptDigest
      ) {
        throw new SastRuleBundleRollbackServiceError('STORE_UNAVAILABLE');
      }
      return toLifecycleAuthorityReceipt(persisted.receipt);
    } catch (error) {
      if (error instanceof SastRuleBundleRollbackServiceError) throw error;
      if (
        error instanceof SastRuleBundleManifestPersistenceError ||
        error instanceof SastRuleBundleLifecyclePersistenceError
      ) {
        throw new SastRuleBundleRollbackServiceError('STATE_STALE');
      }
      if (error instanceof SastRuleBundleRollbackPersistenceError) {
        throw new SastRuleBundleRollbackServiceError(
          rollbackServiceReasonForPersistence(error.reason)
        );
      }
      throw new SastRuleBundleRollbackServiceError('STORE_UNAVAILABLE');
    }
  }

  private async findCommandById(
    commandId: string
  ): Promise<SastRuleBundleRollbackCommandSnapshot | null> {
    if (!/^sast-rule-bundle-rollback-command:\/\/[a-f0-9]{64}$/u.test(commandId)) {
      return null;
    }
    return this.store.findCommand(commandId);
  }

  private readTrustedNow(): string {
    try {
      const milliseconds = Date.prototype.getTime.call(this.clock.now());
      if (!Number.isFinite(milliseconds)) throw new Error('invalid clock');
      return new Date(milliseconds).toISOString();
    } catch {
      throw new SastRuleBundleRollbackServiceError('STORE_UNAVAILABLE');
    }
  }
}

function candidateSuspensionMatchesRequest(
  candidate: Readonly<PersistedVerifiedSastRuleBundle>,
  snapshot: Readonly<SastRuleBundleLifecycleLedgerSnapshot>,
  request: Readonly<SastRuleBundleRollbackRequest>
): boolean {
  const transition = snapshot.transition;
  return (
    lifecycleSnapshotIsValid(snapshot) &&
    transition.manifestId === candidate.manifest.manifestId &&
    transition.manifestDigest === candidate.manifest.manifestDigest &&
    transition.bundleId === candidate.manifest.bundleId &&
    transition.bundleDigest === candidate.manifest.bundleDigest &&
    transition.transitionId === request.suspendedTransitionId &&
    transition.transitionDigest === request.suspendedTransitionDigest &&
    transition.toState === 'SUSPENDED' &&
    (transition.fromState === 'CANARY' || transition.fromState === 'ACTIVE') &&
    transition.externalAuthority === 'EMERGENCY_SUSPENSION' &&
    typeof transition.externalAuthorityReceiptRef === 'string' &&
    typeof transition.externalAuthorityReceiptDigest === 'string' &&
    snapshot.evidence.manifestId === candidate.manifest.manifestId &&
    snapshot.evidence.manifestDigest === candidate.manifest.manifestDigest &&
    snapshot.evidence.verificationId === candidate.attestation.verificationId &&
    snapshot.evidence.verificationDigest ===
      candidate.attestation.attestationDigest
  );
}

function rollbackBaselineIsCurrent(
  candidate: Readonly<PersistedVerifiedSastRuleBundle>,
  candidateLifecycle: Readonly<SastRuleBundleLifecycleLedgerSnapshot>,
  baseline: Readonly<PersistedVerifiedSastRuleBundle>,
  baselineLifecycle: Readonly<SastRuleBundleLifecycleLedgerSnapshot>
): boolean {
  const evidence = candidateLifecycle.evidence;
  const head = baselineLifecycle.transition;
  return (
    lifecycleSnapshotIsValid(baselineLifecycle) &&
    evidence.baselineManifestId === baseline.manifest.manifestId &&
    evidence.baselineManifestDigest === baseline.manifest.manifestDigest &&
    evidence.baselineBundleDigest === baseline.manifest.bundleDigest &&
    evidence.rollbackTargetDigest === candidate.manifest.rollbackTargetDigest &&
    evidence.rollbackTargetDigest === baseline.manifest.bundleDigest &&
    candidate.manifest.manifestId !== baseline.manifest.manifestId &&
    candidate.manifest.bundleId === baseline.manifest.bundleId &&
    candidate.manifest.scanner === baseline.manifest.scanner &&
    candidate.manifest.compatibility.profileIds.includes(evidence.profileId) &&
    baseline.manifest.compatibility.profileIds.includes(evidence.profileId) &&
    baseline.attestation.manifestId === baseline.manifest.manifestId &&
    baseline.attestation.manifestDigest === baseline.manifest.manifestDigest &&
    baseline.attestation.bundleDigest === baseline.manifest.bundleDigest &&
    head.manifestId === baseline.manifest.manifestId &&
    head.manifestDigest === baseline.manifest.manifestDigest &&
    head.bundleId === baseline.manifest.bundleId &&
    head.bundleDigest === baseline.manifest.bundleDigest &&
    head.toState === 'ACTIVE'
  );
}

function lifecycleSnapshotIsValid(
  snapshot: Readonly<SastRuleBundleLifecycleLedgerSnapshot>
): boolean {
  const transition = snapshot.transition;
  const evidence = snapshot.evidence;
  return (
    isSastRuleBundleLifecycleTransitionShapeValid(
      transition,
      digestSastRuleBundleCanonical
    ) &&
    isSastRuleBundlePromotionEvidenceShapeValid(
      evidence,
      digestSastRuleBundleCanonical
    ) &&
    evidence.evidenceId === transition.promotionEvidenceId &&
    evidence.evidenceDigest === transition.promotionEvidenceDigest &&
    evidence.manifestId === transition.manifestId &&
    evidence.manifestDigest === transition.manifestDigest &&
    evidence.bundleDigest === transition.bundleDigest &&
    snapshot.approvals.length === transition.approvals.length &&
    snapshot.approvals.every(
      (approval) =>
        isSastRuleBundlePromotionApprovalShapeValid(
          approval,
          digestSastRuleBundleCanonical
        ) &&
        transition.approvals.some(
          (binding) =>
            binding.approvalId === approval.approvalId &&
            binding.approvalDigest === approval.approvalDigest &&
            binding.role === approval.role &&
            binding.approverRef === approval.approverRef &&
            binding.approvedAt === approval.approvedAt
        )
    )
  );
}

function commandSnapshotIsValid(
  snapshot: Readonly<SastRuleBundleRollbackCommandSnapshot>
): boolean {
  return (
    isSastRuleBundleRollbackCommandValid(
      snapshot.command,
      digestSastRuleBundleCanonical
    ) &&
    isSastRuleBundleRollbackVerificationValid(
      snapshot.verification,
      digestSastRuleBundleCanonical
    ) &&
    snapshot.verification.commandId === snapshot.command.commandId &&
    snapshot.verification.commandDigest === snapshot.command.commandDigest &&
    snapshot.verification.signatureRef === snapshot.command.signatureRef &&
    snapshot.verification.provenanceRef === snapshot.command.provenanceRef &&
    snapshot.approvals.every(
      (approval) =>
        isSastRuleBundleRollbackApprovalValid(
          approval,
          digestSastRuleBundleCanonical
        ) &&
        approval.commandId === snapshot.command.commandId &&
        approval.commandDigest === snapshot.command.commandDigest
    ) &&
    (snapshot.receipt === null ||
      isSastRuleBundleRollbackReceiptValid(
        snapshot.receipt,
        digestSastRuleBundleCanonical
      ))
  );
}

function commandMatchesAuthorityInput(
  command: Readonly<SastRuleBundleRollbackCommand>,
  input: Readonly<SastRuleBundleLifecycleAuthorityInput>
): boolean {
  return (
    command.candidateManifestId === input.manifestId &&
    command.candidateManifestDigest === input.manifestDigest &&
    command.candidateBundleId === input.bundleId &&
    command.candidateBundleDigest === input.bundleDigest &&
    command.promotionEvidenceId === input.promotionEvidenceId &&
    command.promotionEvidenceDigest === input.promotionEvidenceDigest &&
    command.actorRef === input.actorRef &&
    command.reasonRef === input.reasonRef &&
    command.auditRef === input.auditRef
  );
}

function commandMatchesCurrentState(
  command: Readonly<SastRuleBundleRollbackCommand>,
  candidate: Readonly<PersistedVerifiedSastRuleBundle>,
  candidateLifecycle: Readonly<SastRuleBundleLifecycleLedgerSnapshot>,
  baseline: Readonly<PersistedVerifiedSastRuleBundle>,
  baselineLifecycle: Readonly<SastRuleBundleLifecycleLedgerSnapshot>
): boolean {
  const candidateHead = candidateLifecycle.transition;
  const baselineHead = baselineLifecycle.transition;
  return (
    lifecycleSnapshotIsValid(candidateLifecycle) &&
    rollbackBaselineIsCurrent(
      candidate,
      candidateLifecycle,
      baseline,
      baselineLifecycle
    ) &&
    command.candidateManifestDigest === candidate.manifest.manifestDigest &&
    command.candidateVerificationId === candidate.attestation.verificationId &&
    command.candidateVerificationDigest ===
      candidate.attestation.attestationDigest &&
    command.candidateBundleId === candidate.manifest.bundleId &&
    command.candidateBundleDigest === candidate.manifest.bundleDigest &&
    command.suspendedTransitionId === candidateHead.transitionId &&
    command.suspendedTransitionDigest === candidateHead.transitionDigest &&
    command.suspendedSequence === candidateHead.sequence &&
    command.suspendedTransitionedAt === candidateHead.transitionedAt &&
    command.suspensionAuthorityReceiptRef ===
      candidateHead.externalAuthorityReceiptRef &&
    command.suspensionAuthorityReceiptDigest ===
      candidateHead.externalAuthorityReceiptDigest &&
    candidateHead.toState === 'SUSPENDED' &&
    candidateHead.externalAuthority === 'EMERGENCY_SUSPENSION' &&
    command.promotionEvidenceId === candidateLifecycle.evidence.evidenceId &&
    command.promotionEvidenceDigest ===
      candidateLifecycle.evidence.evidenceDigest &&
    command.baselineManifestId === baseline.manifest.manifestId &&
    command.baselineManifestDigest === baseline.manifest.manifestDigest &&
    command.baselineVerificationId === baseline.attestation.verificationId &&
    command.baselineVerificationDigest ===
      baseline.attestation.attestationDigest &&
    command.baselineBundleId === baseline.manifest.bundleId &&
    command.baselineBundleDigest === baseline.manifest.bundleDigest &&
    command.baselineTransitionId === baselineHead.transitionId &&
    command.baselineTransitionDigest === baselineHead.transitionDigest &&
    command.baselineSequence === baselineHead.sequence &&
    command.baselineTransitionedAt === baselineHead.transitionedAt &&
    baselineHead.toState === 'ACTIVE'
  );
}

function approvalSetCanAccept(
  snapshot: Readonly<SastRuleBundleRollbackCommandSnapshot>,
  role: SastRuleBundleRollbackApprovalInput['role'],
  approverRef: string
): boolean {
  const roles = new Set(snapshot.approvals.map((approval) => approval.role));
  const approvers = new Set(
    snapshot.approvals.map((approval) => approval.approverRef)
  );
  if (roles.has(role) || approvers.has(approverRef)) return false;
  if (snapshot.approvals.length >= 2) return false;
  if (role === 'SECURITY_ENGINEERING') return true;
  return !roles.has('SCAN_PLATFORM') && !roles.has('SECURITY_OPERATIONS');
}

function isFreshAt(commandedAt: string, evaluatedAt: string): boolean {
  const commandMilliseconds = Date.parse(commandedAt);
  const evaluatedMilliseconds = Date.parse(evaluatedAt);
  return (
    Number.isFinite(commandMilliseconds) &&
    Number.isFinite(evaluatedMilliseconds) &&
    evaluatedMilliseconds >= commandMilliseconds &&
    evaluatedMilliseconds - commandMilliseconds <=
      SAST_RULE_BUNDLE_ROLLBACK_LIMITS.maximumCommandAgeMilliseconds
  );
}

function toLifecycleAuthorityReceipt(
  receipt: Readonly<SastRuleBundleRollbackReceipt>
): SastRuleBundleLifecycleAuthorityReceipt {
  return {
    authority: 'ROLLBACK',
    manifestId: receipt.candidateManifestId,
    manifestDigest: receipt.candidateManifestDigest,
    bundleId: receipt.candidateBundleId,
    bundleDigest: receipt.candidateBundleDigest,
    fromState: 'SUSPENDED',
    toState: 'ROLLED_BACK',
    promotionEvidenceId: receipt.promotionEvidenceId,
    promotionEvidenceDigest: receipt.promotionEvidenceDigest,
    requestedAt: receipt.requestedAt,
    receiptRef: receipt.receiptRef,
    receiptDigest: receipt.receiptDigest,
    verifiedAt: receipt.issuedAt
  };
}

function rollbackServiceReasonForPersistence(
  reason: SastRuleBundleRollbackPersistenceError['reason']
): SastRuleBundleRollbackServiceError['reason'] {
  switch (reason) {
    case 'INPUT_INVALID':
      return 'INPUT_INVALID';
    case 'COMMAND_NOT_FOUND':
    case 'VERIFICATION_NOT_FOUND':
    case 'APPROVAL_NOT_FOUND':
      return 'APPROVAL_INVALID';
    case 'STATE_STALE':
    case 'REPLAY_CONFLICT':
      return 'STATE_STALE';
    case 'LEDGER_CORRUPT':
      return 'STORE_UNAVAILABLE';
  }
}
