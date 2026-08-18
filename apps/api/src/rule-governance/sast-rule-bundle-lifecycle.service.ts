import {
  buildSastRuleBundleLifecycleSelectionReceipt,
  buildSastRuleBundleLifecycleTransition,
  buildSastRuleBundlePromotionApproval,
  buildSastRuleBundlePromotionEvidence,
  isSastRuleBundleLifecycleSelectionReceiptShapeValid,
  isSastRuleBundleLifecycleTransitionShapeValid,
  isSastRuleBundleLifecycleTransitionAllowed,
  isSastRuleBundlePromotionApprovalShapeValid,
  isSastRuleBundlePromotionEvidenceShapeValid,
  isVerifiedScannerSetDescriptorValid,
  toVerifiedSastRuleBundleLifecycleDescriptor,
  type PromotionVerifiedRuleBundleDescriptor,
  type PromotionVerifiedScannerSetDescriptor,
  type RuleBundleState,
  type SastRuleBundleLifecycleExternalAuthority,
  type SastRuleBundleLifecycleSelectionReceipt,
  type SastRuleBundlePromotionApproval,
  type SastRuleBundlePromotionApprovalInput,
  type SastRuleBundlePromotionEvidence,
  type SastRuleBundlePromotionEvidenceInput,
  type VerifiedRuleBundleDescriptor
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';

import { digestSastRuleBundleCanonical } from './sast-rule-bundle-canonical';
import {
  SastRuleBundleLifecycleAuthority,
  SastRuleBundleLifecycleAuthorityError,
  type SastRuleBundleLifecycleAuthorityReceipt
} from './sast-rule-bundle-lifecycle.authority';
import { SastRuleBundleLifecycleClock } from './sast-rule-bundle-lifecycle.clock';
import {
  SastRuleBundleLifecycleGate,
  SastRuleBundleLifecycleGateError,
  type SastRuleBundleLifecycleGateInput
} from './sast-rule-bundle-lifecycle.gate';
import {
  SastRuleBundleLifecyclePersistenceError,
  SastRuleBundleLifecycleStore,
  type PersistedSastRuleBundleLifecycleTransition,
  type PersistedSastRuleBundlePromotionApproval,
  type PersistedSastRuleBundlePromotionEvidence,
  type SastRuleBundleLifecycleLedgerSnapshot
} from './sast-rule-bundle-lifecycle.store';
import {
  SastRuleBundleManifestPersistenceError,
  SastRuleBundleManifestStore,
  type PersistedVerifiedSastRuleBundle
} from './sast-rule-bundle-manifest.store';

export interface SastRuleBundleLifecycleTransitionRequest {
  manifestId: string;
  promotionEvidenceId: string;
  approvalIds: string[];
  toState: RuleBundleState;
  actorRef: string;
  reasonRef: string;
  auditRef: string;
  transitionedAt: string;
}

export class SastRuleBundleLifecycleServiceError extends Error {
  constructor(
    readonly reason:
      | 'INPUT_INVALID'
      | 'MANIFEST_UNVERIFIED'
      | 'EVIDENCE_UNVERIFIED'
      | 'APPROVAL_INVALID'
      | 'TRANSITION_INVALID'
      | 'AUTHORITY_UNAVAILABLE'
      | 'STORE_UNAVAILABLE'
  ) {
    super('The SAST rule-bundle lifecycle operation failed closed.');
    this.name = 'SastRuleBundleLifecycleServiceError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

@Injectable()
export class SastRuleBundleLifecycleService extends SastRuleBundleLifecycleGate {
  constructor(
    private readonly store: SastRuleBundleLifecycleStore,
    private readonly manifestStore: SastRuleBundleManifestStore,
    private readonly authority: SastRuleBundleLifecycleAuthority,
    private readonly clock: SastRuleBundleLifecycleClock
  ) {
    super();
  }

  async registerPromotionEvidence(
    input: Readonly<SastRuleBundlePromotionEvidenceInput>
  ): Promise<PersistedSastRuleBundlePromotionEvidence> {
    const evidence = buildSastRuleBundlePromotionEvidence(
      input,
      digestSastRuleBundleCanonical
    );
    if (!evidence || !this.isAtOrBeforeTrustedNow(evidence.measuredAt)) {
      throw new SastRuleBundleLifecycleServiceError('INPUT_INVALID');
    }

    try {
      const [candidate, baseline] = await Promise.all([
        this.manifestStore.findVerified(evidence.manifestId),
        this.manifestStore.findVerified(evidence.baselineManifestId)
      ]);
      if (!candidate || !baseline) {
        throw new SastRuleBundleLifecycleServiceError('MANIFEST_UNVERIFIED');
      }
      if (!evidenceMatchesVerifiedManifests(evidence, candidate, baseline)) {
        throw new SastRuleBundleLifecycleServiceError('EVIDENCE_UNVERIFIED');
      }
      return await this.store.registerPromotionEvidence(evidence);
    } catch (error) {
      if (error instanceof SastRuleBundleLifecycleServiceError) throw error;
      if (error instanceof SastRuleBundleManifestPersistenceError) {
        throw new SastRuleBundleLifecycleServiceError('MANIFEST_UNVERIFIED');
      }
      if (error instanceof SastRuleBundleLifecyclePersistenceError) {
        throw new SastRuleBundleLifecycleServiceError(
          error.reason === 'MANIFEST_NOT_FOUND'
            ? 'MANIFEST_UNVERIFIED'
            : 'EVIDENCE_UNVERIFIED'
        );
      }
      throw new SastRuleBundleLifecycleServiceError('STORE_UNAVAILABLE');
    }
  }

  async registerPromotionApproval(
    input: Readonly<SastRuleBundlePromotionApprovalInput>
  ): Promise<PersistedSastRuleBundlePromotionApproval> {
    const approval = buildSastRuleBundlePromotionApproval(
      input,
      digestSastRuleBundleCanonical
    );
    if (!approval || !this.isAtOrBeforeTrustedNow(approval.approvedAt)) {
      throw new SastRuleBundleLifecycleServiceError('INPUT_INVALID');
    }

    try {
      const persistedEvidence = await this.store.findPromotionEvidence(
        approval.evidenceId
      );
      if (
        !persistedEvidence ||
        !approvalMatchesEvidence(approval, persistedEvidence.evidence) ||
        Date.parse(approval.approvedAt) <
          Date.parse(persistedEvidence.evidence.measuredAt)
      ) {
        throw new SastRuleBundleLifecycleServiceError('APPROVAL_INVALID');
      }
      return await this.store.registerPromotionApproval(approval);
    } catch (error) {
      if (error instanceof SastRuleBundleLifecycleServiceError) throw error;
      if (error instanceof SastRuleBundleLifecyclePersistenceError) {
        throw new SastRuleBundleLifecycleServiceError('APPROVAL_INVALID');
      }
      throw new SastRuleBundleLifecycleServiceError('STORE_UNAVAILABLE');
    }
  }

  async transition(
    request: Readonly<SastRuleBundleLifecycleTransitionRequest>
  ): Promise<PersistedSastRuleBundleLifecycleTransition> {
    if (!isTransitionRequestShapeValid(request)) {
      throw new SastRuleBundleLifecycleServiceError('INPUT_INVALID');
    }
    const trustedNow = this.readTrustedNow();
    if (Date.parse(request.transitionedAt) > Date.parse(trustedNow)) {
      throw new SastRuleBundleLifecycleServiceError('INPUT_INVALID');
    }

    try {
      const verified = await this.manifestStore.findVerified(request.manifestId);
      if (!verified) {
        throw new SastRuleBundleLifecycleServiceError('MANIFEST_UNVERIFIED');
      }
      const [latest, persistedEvidence, approvals] = await Promise.all([
        this.store.findLatestLifecycleSnapshot(request.manifestId),
        this.store.findPromotionEvidence(request.promotionEvidenceId),
        this.store.findPromotionApprovals(request.approvalIds)
      ]);
      if (latest && lifecycleSnapshotReason(latest) !== null) {
        throw new SastRuleBundleLifecycleServiceError('TRANSITION_INVALID');
      }
      if (
        !persistedEvidence ||
        !evidenceMatchesCandidate(persistedEvidence.evidence, verified)
      ) {
        throw new SastRuleBundleLifecycleServiceError('EVIDENCE_UNVERIFIED');
      }
      if (
        !approvalsMatchRequestAndEvidence(
          approvals,
          request.approvalIds,
          persistedEvidence.evidence,
          request.transitionedAt
        )
      ) {
        throw new SastRuleBundleLifecycleServiceError('APPROVAL_INVALID');
      }
      if (!approvalsMeetTransitionRequirement(approvals, request.toState)) {
        throw new SastRuleBundleLifecycleServiceError('APPROVAL_INVALID');
      }

      const fromState = latest?.transition.toState ?? 'DRAFT';
      if (
        !isSastRuleBundleLifecycleTransitionAllowed(
          fromState,
          request.toState
        ) ||
        (latest !== null &&
          Date.parse(request.transitionedAt) <
            Date.parse(latest.transition.transitionedAt))
      ) {
        throw new SastRuleBundleLifecycleServiceError('TRANSITION_INVALID');
      }
      const externalAuthority = requiredExternalAuthority(
        fromState,
        request.toState
      );
      const externalReceipt =
        externalAuthority === 'NONE'
          ? null
          : await this.authorizeTransition({
              authority: externalAuthority,
              verified,
              evidence: persistedEvidence.evidence,
              fromState,
              toState: request.toState,
              requestedAt: request.transitionedAt
            });
      if (
        externalReceipt &&
        externalAuthority !== 'NONE' &&
        !authorityReceiptMatches(
          externalReceipt,
          externalAuthority,
          verified,
          persistedEvidence.evidence,
          fromState,
          request.toState,
          request.transitionedAt
        )
      ) {
        throw new SastRuleBundleLifecycleServiceError('AUTHORITY_UNAVAILABLE');
      }

      const orderedApprovals = [...approvals].sort(compareApprovalsByRole);
      const transition = buildSastRuleBundleLifecycleTransition(
        {
          manifestId: verified.manifest.manifestId,
          manifestDigest: verified.manifest.manifestDigest,
          bundleId: verified.manifest.bundleId,
          bundleDigest: verified.manifest.bundleDigest,
          sequence: (latest?.transition.sequence ?? 0) + 1,
          fromState,
          toState: request.toState,
          previousTransitionId: latest?.transition.transitionId ?? null,
          previousTransitionDigest:
            latest?.transition.transitionDigest ?? null,
          promotionEvidenceId: persistedEvidence.evidence.evidenceId,
          promotionEvidenceDigest: persistedEvidence.evidence.evidenceDigest,
          candidateAuthorRef: persistedEvidence.evidence.candidateAuthorRef,
          approvals: orderedApprovals.map(toApprovalBinding),
          externalAuthority,
          externalAuthorityReceiptRef: externalReceipt?.receiptRef ?? null,
          externalAuthorityReceiptDigest:
            externalReceipt?.receiptDigest ?? null,
          actorRef: request.actorRef,
          reasonRef: request.reasonRef,
          auditRef: request.auditRef,
          transitionedAt: request.transitionedAt
        },
        digestSastRuleBundleCanonical
      );
      if (!transition) {
        throw new SastRuleBundleLifecycleServiceError('TRANSITION_INVALID');
      }
      return await this.store.appendLifecycleTransition(transition);
    } catch (error) {
      if (error instanceof SastRuleBundleLifecycleServiceError) throw error;
      if (error instanceof SastRuleBundleLifecycleAuthorityError) {
        throw new SastRuleBundleLifecycleServiceError(
          'AUTHORITY_UNAVAILABLE'
        );
      }
      if (error instanceof SastRuleBundleManifestPersistenceError) {
        throw new SastRuleBundleLifecycleServiceError('MANIFEST_UNVERIFIED');
      }
      if (error instanceof SastRuleBundleLifecyclePersistenceError) {
        throw new SastRuleBundleLifecycleServiceError(
          lifecycleServiceReasonForPersistence(error.reason)
        );
      }
      throw new SastRuleBundleLifecycleServiceError('STORE_UNAVAILABLE');
    }
  }

  async verifyScannerSet(
    input: Readonly<SastRuleBundleLifecycleGateInput>
  ): Promise<PromotionVerifiedScannerSetDescriptor> {
    if (
      !isVerifiedScannerSetDescriptorValid(input.scannerSet) ||
      !isExactIsoInstant(input.evaluatedAt)
    ) {
      throw new SastRuleBundleLifecycleGateError(
        'LIFECYCLE_STATE_NOT_SELECTABLE'
      );
    }

    try {
      if (!this.isAtOrBeforeTrustedNow(input.evaluatedAt)) {
        throw new SastRuleBundleLifecycleGateError('LIFECYCLE_STATE_STALE');
      }
      const pendingSelections: Array<{
        bundle: VerifiedRuleBundleDescriptor;
        receipt: SastRuleBundleLifecycleSelectionReceipt;
      }> = [];
      for (const bundle of input.scannerSet.ruleBundles) {
        const snapshot = await this.store.findLatestLifecycleSnapshot(
          bundle.manifestId
        );
        if (!snapshot) {
          throw new SastRuleBundleLifecycleGateError(
            'PROMOTION_EVIDENCE_UNVERIFIED'
          );
        }
        const snapshotReason = lifecycleSnapshotReason(snapshot);
        if (snapshotReason) {
          throw new SastRuleBundleLifecycleGateError(snapshotReason);
        }
        if (!snapshotMatchesBundle(snapshot, bundle)) {
          throw new SastRuleBundleLifecycleGateError(
            'LIFECYCLE_STATE_NOT_SELECTABLE'
          );
        }
        if (
          Date.parse(input.evaluatedAt) <
          Date.parse(snapshot.transition.transitionedAt)
        ) {
          throw new SastRuleBundleLifecycleGateError('LIFECYCLE_STATE_STALE');
        }
        if (
          snapshot.transition.toState !== 'CANARY' &&
          snapshot.transition.toState !== 'ACTIVE'
        ) {
          throw new SastRuleBundleLifecycleGateError(
            'LIFECYCLE_STATE_NOT_SELECTABLE'
          );
        }

        const receipt = buildSastRuleBundleLifecycleSelectionReceipt(
          {
            manifestId: snapshot.transition.manifestId,
            manifestDigest: snapshot.transition.manifestDigest,
            bundleId: snapshot.transition.bundleId,
            bundleDigest: snapshot.transition.bundleDigest,
            lifecycleState: snapshot.transition.toState,
            lifecycleSequence: snapshot.transition.sequence,
            transitionId: snapshot.transition.transitionId,
            transitionDigest: snapshot.transition.transitionDigest,
            promotionEvidenceId:
              snapshot.transition.promotionEvidenceId,
            promotionEvidenceDigest:
              snapshot.transition.promotionEvidenceDigest,
            approvalSetDigest: snapshot.transition.approvalSetDigest,
            evaluatedAt: input.evaluatedAt
          },
          digestSastRuleBundleCanonical
        );
        if (!receipt) {
          throw new SastRuleBundleLifecycleGateError(
            'LIFECYCLE_STATE_NOT_SELECTABLE'
          );
        }
        pendingSelections.push({ bundle: cloneVerifiedBundle(bundle), receipt });
      }

      const persistedSelections = await this.store.recordLifecycleSelections(
        pendingSelections.map(({ receipt }) => receipt)
      );
      if (persistedSelections.length !== pendingSelections.length) {
        throw new SastRuleBundleLifecycleGateError(
          'LIFECYCLE_STORE_UNAVAILABLE'
        );
      }
      const bundles: PromotionVerifiedRuleBundleDescriptor[] = [];
      for (const [index, pending] of pendingSelections.entries()) {
        const persisted = persistedSelections[index];
        if (
          !persisted ||
          !isSastRuleBundleLifecycleSelectionReceiptShapeValid(
            persisted.receipt,
            digestSastRuleBundleCanonical
          ) ||
          persisted.receipt.receiptId !== pending.receipt.receiptId ||
          persisted.receipt.receiptDigest !== pending.receipt.receiptDigest
        ) {
          throw new SastRuleBundleLifecycleGateError(
            'LIFECYCLE_STORE_UNAVAILABLE'
          );
        }
        bundles.push({
          ...pending.bundle,
          lifecycle: toVerifiedSastRuleBundleLifecycleDescriptor(
            persisted.receipt
          )
        });
      }

      return {
        ...input.scannerSet,
        scanners: structuredClone(input.scannerSet.scanners),
        ruleBundles: bundles,
        vulnerabilityDatabase: {
          ...input.scannerSet.vulnerabilityDatabase
        },
        schemaBundle: { ...input.scannerSet.schemaBundle },
        normalizerBundle: { ...input.scannerSet.normalizerBundle }
      };
    } catch (error) {
      if (error instanceof SastRuleBundleLifecycleGateError) throw error;
      if (error instanceof SastRuleBundleLifecyclePersistenceError) {
        throw new SastRuleBundleLifecycleGateError(
          lifecycleGateReasonForPersistence(error.reason)
        );
      }
      throw new SastRuleBundleLifecycleGateError(
        'LIFECYCLE_STORE_UNAVAILABLE'
      );
    }
  }

  private async authorizeTransition(input: {
    authority: Exclude<SastRuleBundleLifecycleExternalAuthority, 'NONE'>;
    verified: Readonly<PersistedVerifiedSastRuleBundle>;
    evidence: Readonly<SastRuleBundlePromotionEvidence>;
    fromState: RuleBundleState;
    toState: RuleBundleState;
    requestedAt: string;
  }): Promise<SastRuleBundleLifecycleAuthorityReceipt> {
    return this.authority.authorize({
      authority: input.authority,
      manifestId: input.verified.manifest.manifestId,
      manifestDigest: input.verified.manifest.manifestDigest,
      bundleId: input.verified.manifest.bundleId,
      bundleDigest: input.verified.manifest.bundleDigest,
      fromState: input.fromState,
      toState: input.toState,
      promotionEvidenceId: input.evidence.evidenceId,
      promotionEvidenceDigest: input.evidence.evidenceDigest,
      requestedAt: input.requestedAt
    });
  }

  private isAtOrBeforeTrustedNow(value: string): boolean {
    return isExactIsoInstant(value) && Date.parse(value) <= Date.parse(this.readTrustedNow());
  }

  private readTrustedNow(): string {
    try {
      const value = this.clock.now();
      const milliseconds = Date.prototype.getTime.call(value);
      if (!Number.isFinite(milliseconds)) {
        throw new SastRuleBundleLifecycleServiceError('STORE_UNAVAILABLE');
      }
      return new Date(milliseconds).toISOString();
    } catch (error) {
      if (error instanceof SastRuleBundleLifecycleServiceError) throw error;
      throw new SastRuleBundleLifecycleServiceError('STORE_UNAVAILABLE');
    }
  }
}

function evidenceMatchesVerifiedManifests(
  evidence: Readonly<SastRuleBundlePromotionEvidence>,
  candidate: Readonly<PersistedVerifiedSastRuleBundle>,
  baseline: Readonly<PersistedVerifiedSastRuleBundle>
): boolean {
  return (
    evidenceMatchesCandidate(evidence, candidate) &&
    evidence.baselineManifestId === baseline.manifest.manifestId &&
    evidence.baselineManifestDigest === baseline.manifest.manifestDigest &&
    evidence.baselineBundleDigest === baseline.manifest.bundleDigest &&
    evidence.rollbackTargetDigest === candidate.manifest.rollbackTargetDigest &&
    evidence.rollbackTargetDigest === baseline.manifest.bundleDigest &&
    candidate.manifest.bundleId === baseline.manifest.bundleId &&
    candidate.manifest.scanner === baseline.manifest.scanner &&
    candidate.manifest.compatibility.profileIds.includes(evidence.profileId) &&
    Date.parse(evidence.measuredAt) >= Date.parse(candidate.manifest.builtAt) &&
    Date.parse(evidence.measuredAt) >= Date.parse(candidate.attestation.verifiedAt) &&
    Date.parse(evidence.measuredAt) >= Date.parse(baseline.manifest.builtAt) &&
    Date.parse(evidence.measuredAt) >= Date.parse(baseline.attestation.verifiedAt)
  );
}

function evidenceMatchesCandidate(
  evidence: Readonly<SastRuleBundlePromotionEvidence>,
  candidate: Readonly<PersistedVerifiedSastRuleBundle>
): boolean {
  return (
    isSastRuleBundlePromotionEvidenceShapeValid(
      evidence,
      digestSastRuleBundleCanonical
    ) &&
    evidence.manifestId === candidate.manifest.manifestId &&
    evidence.manifestDigest === candidate.manifest.manifestDigest &&
    evidence.verificationId === candidate.attestation.verificationId &&
    evidence.verificationDigest === candidate.attestation.attestationDigest &&
    evidence.bundleId === candidate.manifest.bundleId &&
    evidence.bundleDigest === candidate.manifest.bundleDigest
  );
}

function approvalMatchesEvidence(
  approval: Readonly<SastRuleBundlePromotionApproval>,
  evidence: Readonly<SastRuleBundlePromotionEvidence>
): boolean {
  return (
    isSastRuleBundlePromotionApprovalShapeValid(
      approval,
      digestSastRuleBundleCanonical
    ) &&
    approval.evidenceId === evidence.evidenceId &&
    approval.evidenceDigest === evidence.evidenceDigest &&
    approval.manifestId === evidence.manifestId &&
    approval.manifestDigest === evidence.manifestDigest &&
    approval.bundleDigest === evidence.bundleDigest &&
    approval.candidateAuthorRef === evidence.candidateAuthorRef &&
    approval.approverRef !== evidence.candidateAuthorRef &&
    Date.parse(approval.approvedAt) >= Date.parse(evidence.measuredAt)
  );
}

function approvalsMatchRequestAndEvidence(
  approvals: readonly SastRuleBundlePromotionApproval[],
  approvalIds: readonly string[],
  evidence: Readonly<SastRuleBundlePromotionEvidence>,
  transitionedAt: string
): boolean {
  const requested = new Set(approvalIds);
  return (
    requested.size === approvalIds.length &&
    approvals.length === approvalIds.length &&
    approvals.every(
      (approval) =>
        requested.has(approval.approvalId) &&
        approvalMatchesEvidence(approval, evidence) &&
        Date.parse(approval.approvedAt) <= Date.parse(transitionedAt)
    ) &&
    new Set(approvals.map((approval) => approval.approverRef)).size ===
      approvals.length &&
    new Set(approvals.map((approval) => approval.role)).size === approvals.length
  );
}

function approvalsMeetTransitionRequirement(
  approvals: readonly SastRuleBundlePromotionApproval[],
  toState: RuleBundleState
): boolean {
  const roles = new Set(approvals.map((approval) => approval.role));
  if (!roles.has('SECURITY_ENGINEERING')) return false;
  return toState !== 'ACTIVE' && toState !== 'RETIRED'
    ? true
    : roles.has('SCAN_PLATFORM') || roles.has('SECURITY_OPERATIONS');
}

function lifecycleSnapshotReason(
  snapshot: Readonly<SastRuleBundleLifecycleLedgerSnapshot>
): SastRuleBundleLifecycleGateError['reason'] | null {
  const transition = snapshot.transition;
  if (
    !isSastRuleBundleLifecycleTransitionShapeValid(
      transition,
      digestSastRuleBundleCanonical
    ) ||
    !isSastRuleBundlePromotionEvidenceShapeValid(
      snapshot.evidence,
      digestSastRuleBundleCanonical
    ) ||
    snapshot.evidence.evidenceId !== transition.promotionEvidenceId ||
    snapshot.evidence.evidenceDigest !== transition.promotionEvidenceDigest ||
    snapshot.evidence.manifestId !== transition.manifestId ||
    snapshot.evidence.manifestDigest !== transition.manifestDigest ||
    snapshot.evidence.bundleDigest !== transition.bundleDigest ||
    Date.parse(snapshot.evidence.measuredAt) >
      Date.parse(transition.transitionedAt)
  ) {
    return 'PROMOTION_EVIDENCE_UNVERIFIED';
  }
  if (
    snapshot.approvals.length !== transition.approvals.length ||
    !snapshot.approvals.every((approval) =>
      approvalMatchesEvidence(approval, snapshot.evidence)
    ) ||
    !transition.approvals.every((binding) =>
      snapshot.approvals.some(
        (approval) =>
          approval.approvalId === binding.approvalId &&
          approval.approvalDigest === binding.approvalDigest &&
          approval.role === binding.role &&
          approval.approverRef === binding.approverRef &&
          approval.approvedAt === binding.approvedAt
      )
    )
  ) {
    return 'PROMOTION_APPROVAL_INVALID';
  }
  return null;
}

function snapshotMatchesBundle(
  snapshot: Readonly<SastRuleBundleLifecycleLedgerSnapshot>,
  bundle: Readonly<VerifiedRuleBundleDescriptor>
): boolean {
  return (
    snapshot.transition.manifestId === bundle.manifestId &&
    snapshot.transition.manifestDigest === bundle.manifestDigest &&
    snapshot.transition.bundleId === bundle.bundleId &&
    snapshot.transition.bundleDigest === bundle.digest &&
    snapshot.evidence.verificationId === bundle.verificationId &&
    snapshot.evidence.verificationDigest === bundle.verificationDigest
  );
}

function requiredExternalAuthority(
  fromState: RuleBundleState,
  toState: RuleBundleState
): SastRuleBundleLifecycleExternalAuthority {
  if (fromState === 'CANARY' && toState === 'ACTIVE') {
    return 'CANARY_OBSERVATION';
  }
  if (toState === 'SUSPENDED') return 'EMERGENCY_SUSPENSION';
  if (fromState === 'SUSPENDED' && toState === 'ROLLED_BACK') {
    return 'ROLLBACK';
  }
  return 'NONE';
}

function authorityReceiptMatches(
  receipt: Readonly<SastRuleBundleLifecycleAuthorityReceipt>,
  authority: Exclude<SastRuleBundleLifecycleExternalAuthority, 'NONE'>,
  verified: Readonly<PersistedVerifiedSastRuleBundle>,
  evidence: Readonly<SastRuleBundlePromotionEvidence>,
  fromState: RuleBundleState,
  toState: RuleBundleState,
  transitionedAt: string
): boolean {
  return (
    receipt.authority === authority &&
    receipt.manifestId === verified.manifest.manifestId &&
    receipt.manifestDigest === verified.manifest.manifestDigest &&
    receipt.bundleId === verified.manifest.bundleId &&
    receipt.bundleDigest === verified.manifest.bundleDigest &&
    receipt.fromState === fromState &&
    receipt.toState === toState &&
    receipt.promotionEvidenceId === evidence.evidenceId &&
    receipt.promotionEvidenceDigest === evidence.evidenceDigest &&
    receipt.requestedAt === transitionedAt &&
    isDigestBoundReference(receipt.receiptRef) &&
    isDigest(receipt.receiptDigest) &&
    receipt.receiptRef.endsWith(receipt.receiptDigest) &&
    isExactIsoInstant(receipt.verifiedAt) &&
    Date.parse(receipt.verifiedAt) >= Date.parse(evidence.measuredAt) &&
    Date.parse(receipt.verifiedAt) <= Date.parse(transitionedAt)
  );
}

function toApprovalBinding(
  approval: Readonly<SastRuleBundlePromotionApproval>
) {
  return {
    approvalId: approval.approvalId,
    approvalDigest: approval.approvalDigest,
    role: approval.role,
    approverRef: approval.approverRef,
    approvedAt: approval.approvedAt
  };
}

function compareApprovalsByRole(
  left: Readonly<SastRuleBundlePromotionApproval>,
  right: Readonly<SastRuleBundlePromotionApproval>
): number {
  const order = {
    SECURITY_ENGINEERING: 0,
    SCAN_PLATFORM: 1,
    SECURITY_OPERATIONS: 2
  } as const;
  return order[left.role] - order[right.role];
}

function cloneVerifiedBundle(
  bundle: Readonly<VerifiedRuleBundleDescriptor>
): VerifiedRuleBundleDescriptor {
  return {
    ...bundle,
    rules: bundle.rules.map((rule) => ({ ...rule }))
  };
}

function isTransitionRequestShapeValid(
  request: Readonly<SastRuleBundleLifecycleTransitionRequest>
): boolean {
  return (
    /^sast-rule-bundle-manifest:\/\/[a-f0-9]{64}$/u.test(request.manifestId) &&
    /^sast-rule-bundle-promotion-evidence:\/\/[a-f0-9]{64}$/u.test(
      request.promotionEvidenceId
    ) &&
    Array.isArray(request.approvalIds) &&
    request.approvalIds.length >= 1 &&
    request.approvalIds.length <= 3 &&
    request.approvalIds.every((id) =>
      /^sast-rule-bundle-promotion-approval:\/\/[a-f0-9]{64}$/u.test(id)
    ) &&
    new Set(request.approvalIds).size === request.approvalIds.length &&
    [
      'DRAFT',
      'VALIDATED',
      'CANARY',
      'ACTIVE',
      'SUSPENDED',
      'ROLLED_BACK',
      'RETIRED'
    ].includes(request.toState) &&
    isActorReference(request.actorRef) &&
    isDigestBoundReference(request.reasonRef) &&
    isDigestBoundReference(request.auditRef) &&
    isExactIsoInstant(request.transitionedAt)
  );
}

function lifecycleServiceReasonForPersistence(
  reason: SastRuleBundleLifecyclePersistenceError['reason']
): SastRuleBundleLifecycleServiceError['reason'] {
  switch (reason) {
    case 'MANIFEST_NOT_FOUND':
      return 'MANIFEST_UNVERIFIED';
    case 'EVIDENCE_NOT_FOUND':
      return 'EVIDENCE_UNVERIFIED';
    case 'APPROVAL_NOT_FOUND':
      return 'APPROVAL_INVALID';
    case 'INPUT_INVALID':
    case 'LEDGER_CORRUPT':
    case 'TRANSITION_NOT_FOUND':
    case 'REFERENCE_INVALID':
    case 'STALE_TRANSITION':
    case 'REPLAY_CONFLICT':
      return 'TRANSITION_INVALID';
  }
}

function lifecycleGateReasonForPersistence(
  reason: SastRuleBundleLifecyclePersistenceError['reason']
): SastRuleBundleLifecycleGateError['reason'] {
  switch (reason) {
    case 'EVIDENCE_NOT_FOUND':
      return 'PROMOTION_EVIDENCE_UNVERIFIED';
    case 'APPROVAL_NOT_FOUND':
      return 'PROMOTION_APPROVAL_INVALID';
    case 'STALE_TRANSITION':
      return 'LIFECYCLE_STATE_STALE';
    case 'MANIFEST_NOT_FOUND':
    case 'TRANSITION_NOT_FOUND':
    case 'REFERENCE_INVALID':
    case 'REPLAY_CONFLICT':
      return 'LIFECYCLE_STATE_NOT_SELECTABLE';
    case 'INPUT_INVALID':
    case 'LEDGER_CORRUPT':
      return 'LIFECYCLE_STORE_UNAVAILABLE';
  }
}

function isDigest(value: unknown): value is `sha256:${string}` {
  return typeof value === 'string' && /^sha256:[a-f0-9]{64}$/u.test(value);
}

function isDigestBoundReference(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length <= 2_048 &&
    /^[a-z][a-z0-9+.-]*:\/\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+\/sha256:[a-f0-9]{64}$/u.test(
      value
    ) &&
    !/^https?:/u.test(value)
  );
}

function isActorReference(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length <= 512 &&
    /^(?:spiffe|sast-actor|sast-approver):\/\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+$/u.test(
      value
    )
  );
}

function isExactIsoInstant(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) &&
    Number.isFinite(Date.parse(value)) &&
    new Date(value).toISOString() === value
  );
}
