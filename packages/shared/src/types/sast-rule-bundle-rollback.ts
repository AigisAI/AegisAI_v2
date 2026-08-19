import {
  SAST_RULE_BUNDLE_PROMOTION_APPROVAL_ROLES,
  type SastRuleBundlePromotionApprovalRole,
  type SastRuleBundlePromotionCanonicalDigester
} from './sast-rule-promotion-lifecycle';
import type { SastProfileId } from './sast-runtime';

export const SAST_RULE_BUNDLE_ROLLBACK_REQUEST_VERSION =
  'sast-rule-bundle-rollback-request-v1' as const;
export const SAST_RULE_BUNDLE_ROLLBACK_COMMAND_VERSION =
  'sast-rule-bundle-rollback-command-v1' as const;
export const SAST_RULE_BUNDLE_ROLLBACK_VERIFICATION_VERSION =
  'sast-rule-bundle-rollback-verification-v1' as const;
export const SAST_RULE_BUNDLE_ROLLBACK_APPROVAL_VERSION =
  'sast-rule-bundle-rollback-approval-v1' as const;
export const SAST_RULE_BUNDLE_ROLLBACK_RECEIPT_VERSION =
  'sast-rule-bundle-rollback-receipt-v1' as const;

export const SAST_RULE_BUNDLE_ROLLBACK_ACTOR_ROLES = [
  'SECURITY_ON_CALL',
  'PLATFORM_ON_CALL'
] as const;
export type SastRuleBundleRollbackActorRole =
  (typeof SAST_RULE_BUNDLE_ROLLBACK_ACTOR_ROLES)[number];

export const SAST_RULE_BUNDLE_ROLLBACK_LIMITS = Object.freeze({
  identifierBytes: 512,
  referenceBytes: 2_048,
  maximumLifecycleSequence: 1_000_000,
  maximumCommandAgeMilliseconds: 15 * 60 * 1_000,
  requiredApprovalCount: 2
});

type Sha256Digest = `sha256:${string}`;

export interface SastRuleBundleRollbackRequest {
  version: typeof SAST_RULE_BUNDLE_ROLLBACK_REQUEST_VERSION;
  candidateManifestId: string;
  suspendedTransitionId: string;
  suspendedTransitionDigest: Sha256Digest;
  incidentRef: string;
  actorRef: string;
  actorRole: SastRuleBundleRollbackActorRole;
  reasonRef: string;
  auditRef: string;
  signatureRef: string;
  provenanceRef: string;
  commandedAt: string;
}

export interface SastRuleBundleRollbackCommandInput
  extends Omit<SastRuleBundleRollbackRequest, 'version'> {
  candidateManifestDigest: Sha256Digest;
  candidateVerificationId: string;
  candidateVerificationDigest: Sha256Digest;
  candidateBundleId: string;
  candidateBundleDigest: Sha256Digest;
  suspendedSequence: number;
  suspendedTransitionedAt: string;
  suspensionAuthorityReceiptRef: string;
  suspensionAuthorityReceiptDigest: Sha256Digest;
  promotionEvidenceId: string;
  promotionEvidenceDigest: Sha256Digest;
  profileId: SastProfileId;
  baselineManifestId: string;
  baselineManifestDigest: Sha256Digest;
  baselineVerificationId: string;
  baselineVerificationDigest: Sha256Digest;
  baselineBundleId: string;
  baselineBundleDigest: Sha256Digest;
  baselineTransitionId: string;
  baselineTransitionDigest: Sha256Digest;
  baselineSequence: number;
  baselineTransitionedAt: string;
}

export interface SastRuleBundleRollbackCommand
  extends SastRuleBundleRollbackCommandInput {
  version: typeof SAST_RULE_BUNDLE_ROLLBACK_COMMAND_VERSION;
  commandId: string;
  baselineState: 'ACTIVE';
  rollbackTargetDerived: true;
  customerTargetAccepted: false;
  source: 'PLATFORM_RULE_GOVERNANCE';
  immutable: true;
  repositoryContentStored: false;
  findingContentStored: false;
  secretValueStored: false;
  arbitraryPayloadStored: false;
  commandDigest: Sha256Digest;
}

export interface SastRuleBundleRollbackVerificationInput {
  commandId: string;
  commandDigest: Sha256Digest;
  signerIdentity: string;
  signatureRef: string;
  provenanceRef: string;
  verifiedAt: string;
}

export interface SastRuleBundleRollbackVerification
  extends SastRuleBundleRollbackVerificationInput {
  version: typeof SAST_RULE_BUNDLE_ROLLBACK_VERIFICATION_VERSION;
  verificationId: string;
  signatureVerified: true;
  provenanceVerified: true;
  trustedSigner: true;
  signatureBytesStored: false;
  provenancePayloadStored: false;
  repositoryContentStored: false;
  secretValueStored: false;
  verificationDigest: Sha256Digest;
}

export interface SastRuleBundleRollbackApprovalInput {
  commandId: string;
  commandDigest: Sha256Digest;
  role: SastRuleBundlePromotionApprovalRole;
  approverRef: string;
  approvalRef: string;
  approvedAt: string;
}

export interface SastRuleBundleRollbackApproval
  extends SastRuleBundleRollbackApprovalInput {
  version: typeof SAST_RULE_BUNDLE_ROLLBACK_APPROVAL_VERSION;
  approvalId: string;
  approved: true;
  humanApproval: true;
  automatedApproval: false;
  customerInputAccepted: false;
  approvalDigest: Sha256Digest;
}

export interface SastRuleBundleRollbackApprovalBinding {
  approvalId: string;
  approvalDigest: Sha256Digest;
  role: SastRuleBundlePromotionApprovalRole;
  approverRef: string;
  approvedAt: string;
}

export interface SastRuleBundleRollbackReceiptInput {
  command: SastRuleBundleRollbackCommand;
  verification: SastRuleBundleRollbackVerification;
  approvals: readonly SastRuleBundleRollbackApproval[];
  requestedAt: string;
  issuedAt: string;
}

export interface SastRuleBundleRollbackReceipt {
  version: typeof SAST_RULE_BUNDLE_ROLLBACK_RECEIPT_VERSION;
  receiptRef: string;
  receiptDigest: Sha256Digest;
  commandId: string;
  commandDigest: Sha256Digest;
  commandVerificationId: string;
  commandVerificationDigest: Sha256Digest;
  candidateManifestId: string;
  candidateManifestDigest: Sha256Digest;
  candidateBundleId: string;
  candidateBundleDigest: Sha256Digest;
  suspendedTransitionId: string;
  suspendedTransitionDigest: Sha256Digest;
  suspendedSequence: number;
  suspendedTransitionedAt: string;
  suspensionAuthorityReceiptRef: string;
  suspensionAuthorityReceiptDigest: Sha256Digest;
  promotionEvidenceId: string;
  promotionEvidenceDigest: Sha256Digest;
  profileId: SastProfileId;
  baselineManifestId: string;
  baselineManifestDigest: Sha256Digest;
  baselineVerificationId: string;
  baselineVerificationDigest: Sha256Digest;
  baselineBundleId: string;
  baselineBundleDigest: Sha256Digest;
  baselineTransitionId: string;
  baselineTransitionDigest: Sha256Digest;
  baselineSequence: number;
  baselineTransitionedAt: string;
  baselineState: 'ACTIVE';
  approvalCount: 2;
  approvals: SastRuleBundleRollbackApprovalBinding[];
  approvalSetDigest: Sha256Digest;
  actorRef: string;
  reasonRef: string;
  auditRef: string;
  commandedAt: string;
  requestedAt: string;
  issuedAt: string;
  fromState: 'SUSPENDED';
  toState: 'ROLLED_BACK';
  rollbackTargetDerived: true;
  baselineMutationAuthorized: false;
  historicalMutationAuthorized: false;
  scannerSetMutationAuthorized: false;
  findingAuthority: false;
  policyAuthority: false;
  publicationAuthority: false;
  scmWriteAuthority: false;
  customerInputAccepted: false;
  repositoryContentStored: false;
  findingContentStored: false;
  secretValueStored: false;
  arbitraryPayloadStored: false;
}

export function buildSastRuleBundleRollbackCommand(
  input: Readonly<SastRuleBundleRollbackCommandInput>,
  digestCanonical: SastRuleBundlePromotionCanonicalDigester
): SastRuleBundleRollbackCommand | null {
  if (!isRollbackCommandInputValid(input)) return null;
  const core = {
    version: SAST_RULE_BUNDLE_ROLLBACK_COMMAND_VERSION,
    ...input,
    baselineState: 'ACTIVE' as const,
    rollbackTargetDerived: true as const,
    customerTargetAccepted: false as const,
    source: 'PLATFORM_RULE_GOVERNANCE' as const,
    immutable: true as const,
    repositoryContentStored: false as const,
    findingContentStored: false as const,
    secretValueStored: false as const,
    arbitraryPayloadStored: false as const
  };
  const commandDigest = digestCanonical(stableJson(core));
  if (!isDigest(commandDigest)) return null;
  return {
    ...core,
    commandId: `sast-rule-bundle-rollback-command://${commandDigest.slice(7)}`,
    commandDigest
  };
}

export function buildSastRuleBundleRollbackVerification(
  input: Readonly<SastRuleBundleRollbackVerificationInput>,
  digestCanonical: SastRuleBundlePromotionCanonicalDigester
): SastRuleBundleRollbackVerification | null {
  if (!isRollbackVerificationInputValid(input)) return null;
  const core = {
    version: SAST_RULE_BUNDLE_ROLLBACK_VERIFICATION_VERSION,
    ...input,
    signatureVerified: true as const,
    provenanceVerified: true as const,
    trustedSigner: true as const,
    signatureBytesStored: false as const,
    provenancePayloadStored: false as const,
    repositoryContentStored: false as const,
    secretValueStored: false as const
  };
  const verificationDigest = digestCanonical(stableJson(core));
  if (!isDigest(verificationDigest)) return null;
  return {
    ...core,
    verificationId:
      `sast-rule-bundle-rollback-verification://${verificationDigest.slice(7)}`,
    verificationDigest
  };
}

export function buildSastRuleBundleRollbackApproval(
  input: Readonly<SastRuleBundleRollbackApprovalInput>,
  digestCanonical: SastRuleBundlePromotionCanonicalDigester
): SastRuleBundleRollbackApproval | null {
  if (!isRollbackApprovalInputValid(input)) return null;
  const core = {
    version: SAST_RULE_BUNDLE_ROLLBACK_APPROVAL_VERSION,
    ...input,
    approved: true as const,
    humanApproval: true as const,
    automatedApproval: false as const,
    customerInputAccepted: false as const
  };
  const approvalDigest = digestCanonical(stableJson(core));
  if (!isDigest(approvalDigest)) return null;
  return {
    ...core,
    approvalId: `sast-rule-bundle-rollback-approval://${approvalDigest.slice(7)}`,
    approvalDigest
  };
}

export function buildSastRuleBundleRollbackReceipt(
  input: Readonly<SastRuleBundleRollbackReceiptInput>,
  digestCanonical: SastRuleBundlePromotionCanonicalDigester
): SastRuleBundleRollbackReceipt | null {
  if (
    !isSastRuleBundleRollbackCommandValid(input.command, digestCanonical) ||
    !isSastRuleBundleRollbackVerificationValid(
      input.verification,
      digestCanonical
    ) ||
    !verificationMatchesCommand(input.verification, input.command) ||
    !isIsoInstant(input.requestedAt) ||
    !isIsoInstant(input.issuedAt) ||
    Date.parse(input.requestedAt) < Date.parse(input.command.commandedAt) ||
    Date.parse(input.requestedAt) - Date.parse(input.command.commandedAt) >
      SAST_RULE_BUNDLE_ROLLBACK_LIMITS.maximumCommandAgeMilliseconds ||
    input.issuedAt !== input.requestedAt
  ) {
    return null;
  }
  const approvals = canonicalRollbackApprovals(
    input.approvals,
    input.command,
    input.requestedAt,
    digestCanonical
  );
  if (!approvals) return null;
  const approvalSetDigest = digestCanonical(stableJson(approvals));
  if (!isDigest(approvalSetDigest)) return null;
  const core = {
    version: SAST_RULE_BUNDLE_ROLLBACK_RECEIPT_VERSION,
    commandId: input.command.commandId,
    commandDigest: input.command.commandDigest,
    commandVerificationId: input.verification.verificationId,
    commandVerificationDigest: input.verification.verificationDigest,
    candidateManifestId: input.command.candidateManifestId,
    candidateManifestDigest: input.command.candidateManifestDigest,
    candidateBundleId: input.command.candidateBundleId,
    candidateBundleDigest: input.command.candidateBundleDigest,
    suspendedTransitionId: input.command.suspendedTransitionId,
    suspendedTransitionDigest: input.command.suspendedTransitionDigest,
    suspendedSequence: input.command.suspendedSequence,
    suspendedTransitionedAt: input.command.suspendedTransitionedAt,
    suspensionAuthorityReceiptRef:
      input.command.suspensionAuthorityReceiptRef,
    suspensionAuthorityReceiptDigest:
      input.command.suspensionAuthorityReceiptDigest,
    promotionEvidenceId: input.command.promotionEvidenceId,
    promotionEvidenceDigest: input.command.promotionEvidenceDigest,
    profileId: input.command.profileId,
    baselineManifestId: input.command.baselineManifestId,
    baselineManifestDigest: input.command.baselineManifestDigest,
    baselineVerificationId: input.command.baselineVerificationId,
    baselineVerificationDigest: input.command.baselineVerificationDigest,
    baselineBundleId: input.command.baselineBundleId,
    baselineBundleDigest: input.command.baselineBundleDigest,
    baselineTransitionId: input.command.baselineTransitionId,
    baselineTransitionDigest: input.command.baselineTransitionDigest,
    baselineSequence: input.command.baselineSequence,
    baselineTransitionedAt: input.command.baselineTransitionedAt,
    baselineState: 'ACTIVE' as const,
    approvalCount: 2 as const,
    approvals,
    approvalSetDigest,
    actorRef: input.command.actorRef,
    reasonRef: input.command.reasonRef,
    auditRef: input.command.auditRef,
    commandedAt: input.command.commandedAt,
    requestedAt: input.requestedAt,
    issuedAt: input.issuedAt,
    fromState: 'SUSPENDED' as const,
    toState: 'ROLLED_BACK' as const,
    rollbackTargetDerived: true as const,
    baselineMutationAuthorized: false as const,
    historicalMutationAuthorized: false as const,
    scannerSetMutationAuthorized: false as const,
    findingAuthority: false as const,
    policyAuthority: false as const,
    publicationAuthority: false as const,
    scmWriteAuthority: false as const,
    customerInputAccepted: false as const,
    repositoryContentStored: false as const,
    findingContentStored: false as const,
    secretValueStored: false as const,
    arbitraryPayloadStored: false as const
  };
  const receiptDigest = digestCanonical(stableJson(core));
  if (!isDigest(receiptDigest)) return null;
  return {
    ...core,
    receiptRef:
      `sast-rule-bundle-rollback-receipt://authority/${receiptDigest}`,
    receiptDigest
  };
}

export function isSastRuleBundleRollbackRequestValid(
  value: unknown
): value is SastRuleBundleRollbackRequest {
  if (!hasExactKeys(value, ROLLBACK_REQUEST_KEYS)) return false;
  const request = value as SastRuleBundleRollbackRequest;
  return (
    request.version === SAST_RULE_BUNDLE_ROLLBACK_REQUEST_VERSION &&
    isManifestId(request.candidateManifestId) &&
    isTransitionId(request.suspendedTransitionId) &&
    isDigest(request.suspendedTransitionDigest) &&
    isDigestBoundReference(request.incidentRef) &&
    isActorReference(request.actorRef) &&
    SAST_RULE_BUNDLE_ROLLBACK_ACTOR_ROLES.includes(request.actorRole) &&
    isDigestBoundReference(request.reasonRef) &&
    isDigestBoundReference(request.auditRef) &&
    isDigestBoundReference(request.signatureRef) &&
    isDigestBoundReference(request.provenanceRef) &&
    isIsoInstant(request.commandedAt)
  );
}

export function isSastRuleBundleRollbackCommandValid(
  value: unknown,
  digestCanonical: SastRuleBundlePromotionCanonicalDigester
): value is SastRuleBundleRollbackCommand {
  if (!hasExactKeys(value, ROLLBACK_COMMAND_KEYS)) return false;
  const command = value as SastRuleBundleRollbackCommand;
  const rebuilt = buildSastRuleBundleRollbackCommand(
    projectExactKeys<SastRuleBundleRollbackCommandInput>(
      command,
      ROLLBACK_COMMAND_INPUT_KEYS
    ),
    digestCanonical
  );
  return (
    rebuilt !== null &&
    command.version === SAST_RULE_BUNDLE_ROLLBACK_COMMAND_VERSION &&
    command.commandId === rebuilt.commandId &&
    command.commandDigest === rebuilt.commandDigest &&
    command.baselineState === 'ACTIVE' &&
    command.rollbackTargetDerived === true &&
    command.customerTargetAccepted === false &&
    command.source === 'PLATFORM_RULE_GOVERNANCE' &&
    command.immutable === true &&
    command.repositoryContentStored === false &&
    command.findingContentStored === false &&
    command.secretValueStored === false &&
    command.arbitraryPayloadStored === false
  );
}

export function isSastRuleBundleRollbackVerificationValid(
  value: unknown,
  digestCanonical: SastRuleBundlePromotionCanonicalDigester
): value is SastRuleBundleRollbackVerification {
  if (!hasExactKeys(value, ROLLBACK_VERIFICATION_KEYS)) return false;
  const verification = value as SastRuleBundleRollbackVerification;
  const rebuilt = buildSastRuleBundleRollbackVerification(
    projectExactKeys<SastRuleBundleRollbackVerificationInput>(
      verification,
      ROLLBACK_VERIFICATION_INPUT_KEYS
    ),
    digestCanonical
  );
  return (
    rebuilt !== null &&
    verification.version === SAST_RULE_BUNDLE_ROLLBACK_VERIFICATION_VERSION &&
    verification.verificationId === rebuilt.verificationId &&
    verification.verificationDigest === rebuilt.verificationDigest &&
    verification.signatureVerified === true &&
    verification.provenanceVerified === true &&
    verification.trustedSigner === true &&
    verification.signatureBytesStored === false &&
    verification.provenancePayloadStored === false &&
    verification.repositoryContentStored === false &&
    verification.secretValueStored === false
  );
}

export function isSastRuleBundleRollbackApprovalValid(
  value: unknown,
  digestCanonical: SastRuleBundlePromotionCanonicalDigester
): value is SastRuleBundleRollbackApproval {
  if (!hasExactKeys(value, ROLLBACK_APPROVAL_KEYS)) return false;
  const approval = value as SastRuleBundleRollbackApproval;
  const rebuilt = buildSastRuleBundleRollbackApproval(
    projectExactKeys<SastRuleBundleRollbackApprovalInput>(
      approval,
      ROLLBACK_APPROVAL_INPUT_KEYS
    ),
    digestCanonical
  );
  return (
    rebuilt !== null &&
    approval.version === SAST_RULE_BUNDLE_ROLLBACK_APPROVAL_VERSION &&
    approval.approvalId === rebuilt.approvalId &&
    approval.approvalDigest === rebuilt.approvalDigest &&
    approval.approved === true &&
    approval.humanApproval === true &&
    approval.automatedApproval === false &&
    approval.customerInputAccepted === false
  );
}

export function isSastRuleBundleRollbackReceiptValid(
  value: unknown,
  digestCanonical: SastRuleBundlePromotionCanonicalDigester
): value is SastRuleBundleRollbackReceipt {
  if (!hasExactKeys(value, ROLLBACK_RECEIPT_KEYS)) return false;
  const receipt = value as SastRuleBundleRollbackReceipt;
  if (
    receipt.version !== SAST_RULE_BUNDLE_ROLLBACK_RECEIPT_VERSION ||
    !isDigest(receipt.receiptDigest) ||
    receipt.receiptRef !==
      `sast-rule-bundle-rollback-receipt://authority/${receipt.receiptDigest}` ||
    !isCommandId(receipt.commandId) ||
    !isDigest(receipt.commandDigest) ||
    !isVerificationId(receipt.commandVerificationId) ||
    !isDigest(receipt.commandVerificationDigest) ||
    !isManifestId(receipt.candidateManifestId) ||
    !isDigest(receipt.candidateManifestDigest) ||
    !isSafeIdentifier(receipt.candidateBundleId) ||
    !isDigest(receipt.candidateBundleDigest) ||
    !isTransitionId(receipt.suspendedTransitionId) ||
    !isDigest(receipt.suspendedTransitionDigest) ||
    !isSequence(receipt.suspendedSequence) ||
    !isIsoInstant(receipt.suspendedTransitionedAt) ||
    !isDigestBoundReference(receipt.suspensionAuthorityReceiptRef) ||
    !isDigest(receipt.suspensionAuthorityReceiptDigest) ||
    !isEvidenceId(receipt.promotionEvidenceId) ||
    !isDigest(receipt.promotionEvidenceDigest) ||
    !PROFILE_IDS.includes(receipt.profileId) ||
    !isManifestId(receipt.baselineManifestId) ||
    !isDigest(receipt.baselineManifestDigest) ||
    !isSupplyChainVerificationId(receipt.baselineVerificationId) ||
    !isDigest(receipt.baselineVerificationDigest) ||
    !isSafeIdentifier(receipt.baselineBundleId) ||
    !isDigest(receipt.baselineBundleDigest) ||
    !isTransitionId(receipt.baselineTransitionId) ||
    !isDigest(receipt.baselineTransitionDigest) ||
    !isSequence(receipt.baselineSequence) ||
    !isIsoInstant(receipt.baselineTransitionedAt) ||
    receipt.baselineState !== 'ACTIVE' ||
    receipt.approvalCount !== 2 ||
    !isActorReference(receipt.actorRef) ||
    !isIsoInstant(receipt.commandedAt) ||
    Date.parse(receipt.commandedAt) <
      Date.parse(receipt.suspendedTransitionedAt) ||
    Date.parse(receipt.commandedAt) <
      Date.parse(receipt.baselineTransitionedAt) ||
    !isIsoInstant(receipt.requestedAt) ||
    Date.parse(receipt.requestedAt) < Date.parse(receipt.commandedAt) ||
    Date.parse(receipt.requestedAt) - Date.parse(receipt.commandedAt) >
      SAST_RULE_BUNDLE_ROLLBACK_LIMITS.maximumCommandAgeMilliseconds ||
    !isCanonicalApprovalBindings(
      receipt.approvals,
      receipt.actorRef,
      receipt.commandedAt,
      receipt.requestedAt
    ) ||
    receipt.approvalSetDigest !== digestCanonical(stableJson(receipt.approvals)) ||
    !isDigestBoundReference(receipt.reasonRef) ||
    !isDigestBoundReference(receipt.auditRef) ||
    !isIsoInstant(receipt.issuedAt) ||
    receipt.issuedAt !== receipt.requestedAt ||
    receipt.fromState !== 'SUSPENDED' ||
    receipt.toState !== 'ROLLED_BACK' ||
    receipt.rollbackTargetDerived !== true ||
    receipt.baselineMutationAuthorized !== false ||
    receipt.historicalMutationAuthorized !== false ||
    receipt.scannerSetMutationAuthorized !== false ||
    receipt.findingAuthority !== false ||
    receipt.policyAuthority !== false ||
    receipt.publicationAuthority !== false ||
    receipt.scmWriteAuthority !== false ||
    receipt.customerInputAccepted !== false ||
    receipt.repositoryContentStored !== false ||
    receipt.findingContentStored !== false ||
    receipt.secretValueStored !== false ||
    receipt.arbitraryPayloadStored !== false
  ) {
    return false;
  }
  const core = Object.fromEntries(
    Object.entries(receipt).filter(
      ([key]) => key !== 'receiptRef' && key !== 'receiptDigest'
    )
  );
  return digestCanonical(stableJson(core)) === receipt.receiptDigest;
}

function isRollbackCommandInputValid(
  input: Readonly<SastRuleBundleRollbackCommandInput>
): boolean {
  return (
    hasExactKeys(input, ROLLBACK_COMMAND_INPUT_KEYS) &&
    isManifestId(input.candidateManifestId) &&
    isDigest(input.candidateManifestDigest) &&
    isSupplyChainVerificationId(input.candidateVerificationId) &&
    isDigest(input.candidateVerificationDigest) &&
    isSafeIdentifier(input.candidateBundleId) &&
    isDigest(input.candidateBundleDigest) &&
    isTransitionId(input.suspendedTransitionId) &&
    isDigest(input.suspendedTransitionDigest) &&
    isSequence(input.suspendedSequence) &&
    isIsoInstant(input.suspendedTransitionedAt) &&
    isDigestBoundReference(input.suspensionAuthorityReceiptRef) &&
    isDigest(input.suspensionAuthorityReceiptDigest) &&
    isEvidenceId(input.promotionEvidenceId) &&
    isDigest(input.promotionEvidenceDigest) &&
    PROFILE_IDS.includes(input.profileId) &&
    isManifestId(input.baselineManifestId) &&
    input.baselineManifestId !== input.candidateManifestId &&
    isDigest(input.baselineManifestDigest) &&
    isSupplyChainVerificationId(input.baselineVerificationId) &&
    isDigest(input.baselineVerificationDigest) &&
    isSafeIdentifier(input.baselineBundleId) &&
    input.baselineBundleId === input.candidateBundleId &&
    isDigest(input.baselineBundleDigest) &&
    input.baselineBundleDigest !== input.candidateBundleDigest &&
    isTransitionId(input.baselineTransitionId) &&
    isDigest(input.baselineTransitionDigest) &&
    isSequence(input.baselineSequence) &&
    isIsoInstant(input.baselineTransitionedAt) &&
    isDigestBoundReference(input.incidentRef) &&
    isActorReference(input.actorRef) &&
    SAST_RULE_BUNDLE_ROLLBACK_ACTOR_ROLES.includes(input.actorRole) &&
    isDigestBoundReference(input.reasonRef) &&
    isDigestBoundReference(input.auditRef) &&
    isDigestBoundReference(input.signatureRef) &&
    isDigestBoundReference(input.provenanceRef) &&
    isIsoInstant(input.commandedAt) &&
    Date.parse(input.commandedAt) >=
      Date.parse(input.suspendedTransitionedAt) &&
    Date.parse(input.commandedAt) >= Date.parse(input.baselineTransitionedAt)
  );
}

function isRollbackVerificationInputValid(
  input: Readonly<SastRuleBundleRollbackVerificationInput>
): boolean {
  return (
    hasExactKeys(input, ROLLBACK_VERIFICATION_INPUT_KEYS) &&
    isCommandId(input.commandId) &&
    isDigest(input.commandDigest) &&
    isActorReference(input.signerIdentity) &&
    isDigestBoundReference(input.signatureRef) &&
    isDigestBoundReference(input.provenanceRef) &&
    isIsoInstant(input.verifiedAt)
  );
}

function isRollbackApprovalInputValid(
  input: Readonly<SastRuleBundleRollbackApprovalInput>
): boolean {
  return (
    hasExactKeys(input, ROLLBACK_APPROVAL_INPUT_KEYS) &&
    isCommandId(input.commandId) &&
    isDigest(input.commandDigest) &&
    SAST_RULE_BUNDLE_PROMOTION_APPROVAL_ROLES.includes(input.role) &&
    isActorReference(input.approverRef) &&
    isDigestBoundReference(input.approvalRef) &&
    isIsoInstant(input.approvedAt)
  );
}

function verificationMatchesCommand(
  verification: Readonly<SastRuleBundleRollbackVerification>,
  command: Readonly<SastRuleBundleRollbackCommand>
): boolean {
  return (
    verification.commandId === command.commandId &&
    verification.commandDigest === command.commandDigest &&
    verification.signatureRef === command.signatureRef &&
    verification.provenanceRef === command.provenanceRef &&
    Date.parse(verification.verifiedAt) >= Date.parse(command.commandedAt)
  );
}

function canonicalRollbackApprovals(
  approvals: readonly Readonly<SastRuleBundleRollbackApproval>[],
  command: Readonly<SastRuleBundleRollbackCommand>,
  requestedAt: string,
  digestCanonical: SastRuleBundlePromotionCanonicalDigester
): SastRuleBundleRollbackApprovalBinding[] | null {
  if (approvals.length !== SAST_RULE_BUNDLE_ROLLBACK_LIMITS.requiredApprovalCount) {
    return null;
  }
  if (
    approvals.some(
      (approval) =>
        !isSastRuleBundleRollbackApprovalValid(approval, digestCanonical) ||
        approval.commandId !== command.commandId ||
        approval.commandDigest !== command.commandDigest ||
        approval.approverRef === command.actorRef ||
        Date.parse(approval.approvedAt) < Date.parse(command.commandedAt) ||
        Date.parse(approval.approvedAt) > Date.parse(requestedAt)
    )
  ) {
    return null;
  }
  const roles = new Set(approvals.map((approval) => approval.role));
  const approvers = new Set(approvals.map((approval) => approval.approverRef));
  if (
    roles.size !== approvals.length ||
    approvers.size !== approvals.length ||
    !roles.has('SECURITY_ENGINEERING') ||
    (roles.has('SCAN_PLATFORM') === roles.has('SECURITY_OPERATIONS'))
  ) {
    return null;
  }
  return [...approvals]
    .sort((left, right) => roleOrder(left.role) - roleOrder(right.role))
    .map((approval) => ({
      approvalId: approval.approvalId,
      approvalDigest: approval.approvalDigest,
      role: approval.role,
      approverRef: approval.approverRef,
      approvedAt: approval.approvedAt
    }));
}

function isCanonicalApprovalBindings(
  value: unknown,
  actorRef: string,
  commandedAt: string,
  requestedAt: string
): boolean {
  if (!Array.isArray(value) || value.length !== 2) return false;
  if (
    value.some(
      (entry) =>
        !hasExactKeys(entry, ROLLBACK_APPROVAL_BINDING_KEYS) ||
        !isApprovalId(entry.approvalId) ||
        !isDigest(entry.approvalDigest) ||
        !isPromotionApprovalRole(entry.role) ||
        !isActorReference(entry.approverRef) ||
        entry.approverRef === actorRef ||
        !isIsoInstant(entry.approvedAt) ||
        Date.parse(entry.approvedAt) < Date.parse(commandedAt) ||
        Date.parse(entry.approvedAt) > Date.parse(requestedAt)
    )
  ) {
    return false;
  }
  const bindings = value as SastRuleBundleRollbackApprovalBinding[];
  const roles = new Set(bindings.map((entry) => entry.role));
  return (
    new Set(bindings.map((entry) => entry.approvalId)).size === bindings.length &&
    new Set(bindings.map((entry) => entry.approverRef)).size === bindings.length &&
    roles.has('SECURITY_ENGINEERING') &&
    (roles.has('SCAN_PLATFORM') !== roles.has('SECURITY_OPERATIONS')) &&
    bindings.every(
      (entry, index) =>
        index === 0 ||
        roleOrder(bindings[index - 1].role) < roleOrder(entry.role)
    )
  );
}

function projectExactKeys<T>(
  value: Readonly<object>,
  keys: readonly string[]
): T {
  const record = value as Readonly<Record<string, unknown>>;
  return Object.fromEntries(keys.map((key) => [key, record[key]])) as T;
}

function roleOrder(role: SastRuleBundlePromotionApprovalRole): number {
  return APPROVAL_ROLE_ORDER.get(role) ?? Number.MAX_SAFE_INTEGER;
}

function isPromotionApprovalRole(
  value: unknown
): value is SastRuleBundlePromotionApprovalRole {
  return (
    typeof value === 'string' &&
    SAST_RULE_BUNDLE_PROMOTION_APPROVAL_ROLES.some((role) => role === value)
  );
}

function hasExactKeys<T extends readonly string[]>(
  value: unknown,
  keys: T
): value is Record<T[number], unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return (
    actual.length === expected.length &&
    actual.every((key, index) => key === expected[index])
  );
}

function isDigest(value: unknown): value is Sha256Digest {
  return typeof value === 'string' && /^sha256:[a-f0-9]{64}$/u.test(value);
}

function isManifestId(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^sast-rule-bundle-manifest:\/\/[a-f0-9]{64}$/u.test(value)
  );
}

function isSupplyChainVerificationId(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^sast-rule-bundle-verification:\/\/[a-f0-9]{64}$/u.test(value)
  );
}

function isTransitionId(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^sast-rule-bundle-lifecycle-transition:\/\/[a-f0-9]{64}$/u.test(value)
  );
}

function isEvidenceId(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^sast-rule-bundle-promotion-evidence:\/\/[a-f0-9]{64}$/u.test(value)
  );
}

function isCommandId(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^sast-rule-bundle-rollback-command:\/\/[a-f0-9]{64}$/u.test(value)
  );
}

function isVerificationId(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^sast-rule-bundle-rollback-verification:\/\/[a-f0-9]{64}$/u.test(value)
  );
}

function isApprovalId(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^sast-rule-bundle-rollback-approval:\/\/[a-f0-9]{64}$/u.test(value)
  );
}

function isSequence(value: unknown): value is number {
  return (
    typeof value === 'number' &&
    Number.isSafeInteger(value) &&
    value >= 1 &&
    value <= SAST_RULE_BUNDLE_ROLLBACK_LIMITS.maximumLifecycleSequence
  );
}

function isSafeIdentifier(value: unknown): value is string {
  return isBoundedText(value, SAST_RULE_BUNDLE_ROLLBACK_LIMITS.identifierBytes);
}

function isActorReference(value: unknown): value is string {
  return (
    isBoundedText(value, SAST_RULE_BUNDLE_ROLLBACK_LIMITS.referenceBytes) &&
    /^[a-z][a-z0-9+.-]*:\/\/[^\s]+$/u.test(value) &&
    !/^https?:\/\//u.test(value)
  );
}

function isDigestBoundReference(value: unknown): value is string {
  return (
    isActorReference(value) &&
    /sha256:[a-f0-9]{64}$/u.test(value)
  );
}

function isBoundedText(value: unknown, maximumBytes: number): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value === value.trim() &&
    value === value.normalize('NFC') &&
    ![...value].some((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return codePoint <= 31 || codePoint === 127;
    }) &&
    new TextEncoder().encode(value).byteLength <= maximumBytes
  );
}

function isIsoInstant(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) &&
    Number.isFinite(Date.parse(value))
  );
}

function stableJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((entry) => stableJson(entry)).join(',')}]`;
  }
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .filter((key) => record[key] !== undefined)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`)
    .join(',')}}`;
}

const PROFILE_IDS = [
  'JAVA_FAST_V1',
  'JAVA_DEEP_V1',
  'COMMON_DEEP_V1'
] as const satisfies readonly SastProfileId[];
const APPROVAL_ROLE_ORDER = new Map(
  SAST_RULE_BUNDLE_PROMOTION_APPROVAL_ROLES.map((role, index) => [role, index])
);

const ROLLBACK_REQUEST_KEYS = [
  'version',
  'candidateManifestId',
  'suspendedTransitionId',
  'suspendedTransitionDigest',
  'incidentRef',
  'actorRef',
  'actorRole',
  'reasonRef',
  'auditRef',
  'signatureRef',
  'provenanceRef',
  'commandedAt'
] as const;
const ROLLBACK_COMMAND_INPUT_KEYS = [
  ...ROLLBACK_REQUEST_KEYS.filter((key) => key !== 'version'),
  'candidateManifestDigest',
  'candidateVerificationId',
  'candidateVerificationDigest',
  'candidateBundleId',
  'candidateBundleDigest',
  'suspendedSequence',
  'suspendedTransitionedAt',
  'suspensionAuthorityReceiptRef',
  'suspensionAuthorityReceiptDigest',
  'promotionEvidenceId',
  'promotionEvidenceDigest',
  'profileId',
  'baselineManifestId',
  'baselineManifestDigest',
  'baselineVerificationId',
  'baselineVerificationDigest',
  'baselineBundleId',
  'baselineBundleDigest',
  'baselineTransitionId',
  'baselineTransitionDigest',
  'baselineSequence',
  'baselineTransitionedAt'
] as const;
const ROLLBACK_COMMAND_KEYS = [
  ...ROLLBACK_COMMAND_INPUT_KEYS,
  'version',
  'commandId',
  'baselineState',
  'rollbackTargetDerived',
  'customerTargetAccepted',
  'source',
  'immutable',
  'repositoryContentStored',
  'findingContentStored',
  'secretValueStored',
  'arbitraryPayloadStored',
  'commandDigest'
] as const;
const ROLLBACK_VERIFICATION_INPUT_KEYS = [
  'commandId',
  'commandDigest',
  'signerIdentity',
  'signatureRef',
  'provenanceRef',
  'verifiedAt'
] as const;
const ROLLBACK_VERIFICATION_KEYS = [
  ...ROLLBACK_VERIFICATION_INPUT_KEYS,
  'version',
  'verificationId',
  'signatureVerified',
  'provenanceVerified',
  'trustedSigner',
  'signatureBytesStored',
  'provenancePayloadStored',
  'repositoryContentStored',
  'secretValueStored',
  'verificationDigest'
] as const;
const ROLLBACK_APPROVAL_INPUT_KEYS = [
  'commandId',
  'commandDigest',
  'role',
  'approverRef',
  'approvalRef',
  'approvedAt'
] as const;
const ROLLBACK_APPROVAL_KEYS = [
  ...ROLLBACK_APPROVAL_INPUT_KEYS,
  'version',
  'approvalId',
  'approved',
  'humanApproval',
  'automatedApproval',
  'customerInputAccepted',
  'approvalDigest'
] as const;
const ROLLBACK_APPROVAL_BINDING_KEYS = [
  'approvalId',
  'approvalDigest',
  'role',
  'approverRef',
  'approvedAt'
] as const;
const ROLLBACK_RECEIPT_KEYS = [
  'version',
  'receiptRef',
  'receiptDigest',
  'commandId',
  'commandDigest',
  'commandVerificationId',
  'commandVerificationDigest',
  'candidateManifestId',
  'candidateManifestDigest',
  'candidateBundleId',
  'candidateBundleDigest',
  'suspendedTransitionId',
  'suspendedTransitionDigest',
  'suspendedSequence',
  'suspendedTransitionedAt',
  'suspensionAuthorityReceiptRef',
  'suspensionAuthorityReceiptDigest',
  'promotionEvidenceId',
  'promotionEvidenceDigest',
  'profileId',
  'baselineManifestId',
  'baselineManifestDigest',
  'baselineVerificationId',
  'baselineVerificationDigest',
  'baselineBundleId',
  'baselineBundleDigest',
  'baselineTransitionId',
  'baselineTransitionDigest',
  'baselineSequence',
  'baselineTransitionedAt',
  'baselineState',
  'approvalCount',
  'approvals',
  'approvalSetDigest',
  'actorRef',
  'reasonRef',
  'auditRef',
  'commandedAt',
  'requestedAt',
  'issuedAt',
  'fromState',
  'toState',
  'rollbackTargetDerived',
  'baselineMutationAuthorized',
  'historicalMutationAuthorized',
  'scannerSetMutationAuthorized',
  'findingAuthority',
  'policyAuthority',
  'publicationAuthority',
  'scmWriteAuthority',
  'customerInputAccepted',
  'repositoryContentStored',
  'findingContentStored',
  'secretValueStored',
  'arbitraryPayloadStored'
] as const;
