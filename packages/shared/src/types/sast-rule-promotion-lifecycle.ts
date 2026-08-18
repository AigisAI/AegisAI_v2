import type {
  RuleBundleState,
  SastProfileId
} from './sast-runtime';

export const SAST_RULE_BUNDLE_PROMOTION_EVIDENCE_VERSION =
  'sast-rule-bundle-promotion-evidence-v1' as const;
export const SAST_RULE_BUNDLE_PROMOTION_APPROVAL_VERSION =
  'sast-rule-bundle-promotion-approval-v1' as const;
export const SAST_RULE_BUNDLE_LIFECYCLE_TRANSITION_VERSION =
  'sast-rule-bundle-lifecycle-transition-v1' as const;
export const SAST_RULE_BUNDLE_LIFECYCLE_SELECTION_VERSION =
  'sast-rule-bundle-lifecycle-selection-v1' as const;

export const SAST_RULE_BUNDLE_PROMOTION_LIMITS = Object.freeze({
  identifierBytes: 512,
  referenceBytes: 2_048,
  maximumCount: 1_000_000_000,
  maximumApprovals: 3,
  minimumPositiveCases: 200,
  minimumNegativeCases: 200,
  minimumPerformanceRuns: 30,
  minimumMustDetectRecallBasisPoints: 9_500,
  minimumCriticalHighPrecisionBasisPoints: 9_000,
  maximumFalsePositiveIncreaseBasisPoints: 200,
  maximumScannerFailureRateBasisPoints: 200,
  maximumP95LatencyIncreaseBasisPoints: 2_000,
  maximumLifecycleSequence: 1_000_000
});

export const SAST_RULE_BUNDLE_PROMOTION_APPROVAL_ROLES = [
  'SECURITY_ENGINEERING',
  'SCAN_PLATFORM',
  'SECURITY_OPERATIONS'
] as const;
export type SastRuleBundlePromotionApprovalRole =
  (typeof SAST_RULE_BUNDLE_PROMOTION_APPROVAL_ROLES)[number];

export const SAST_RULE_BUNDLE_LIFECYCLE_EXTERNAL_AUTHORITIES = [
  'NONE',
  'CANARY_OBSERVATION',
  'EMERGENCY_SUSPENSION',
  'ROLLBACK'
] as const;
export type SastRuleBundleLifecycleExternalAuthority =
  (typeof SAST_RULE_BUNDLE_LIFECYCLE_EXTERNAL_AUTHORITIES)[number];

export const SAST_RULE_BUNDLE_PROMOTION_EVIDENCE_REASON_CODES = [
  'INPUT_INVALID',
  'SAMPLE_INSUFFICIENT',
  'CORPUS_GATE_FAILED',
  'RECALL_GATE_FAILED',
  'PRECISION_GATE_FAILED',
  'FALSE_POSITIVE_GATE_FAILED',
  'FAILURE_RATE_GATE_FAILED',
  'LATENCY_GATE_FAILED',
  'SECURITY_EVENT_RECORDED'
] as const;
export type SastRuleBundlePromotionEvidenceReasonCode =
  (typeof SAST_RULE_BUNDLE_PROMOTION_EVIDENCE_REASON_CODES)[number];

type Sha256Digest = `sha256:${string}`;
export type SastRuleBundlePromotionCanonicalDigester = (
  canonicalValue: string
) => Sha256Digest;

export interface SastRuleBundlePromotionCorpusReferences {
  goldenCorpusRef: string;
  priorMustDetectCorpusRef: string;
  maliciousCorpusRef: string;
  parserCorpusRef: string;
  fingerprintCorpusRef: string;
  coverageCorpusRef: string;
  performanceCorpusRef: string;
}

export interface SastRuleBundlePromotionMeasurements {
  positiveCases: number;
  negativeCases: number;
  performanceRuns: number;
  goldenPassedCases: number;
  goldenTotalCases: number;
  priorMustDetectPassedCases: number;
  priorMustDetectTotalCases: number;
  mustDetectTruePositiveCases: number;
  mustDetectExpectedCases: number;
  criticalHighTruePositiveCases: number;
  criticalHighReportedCases: number;
  maliciousPassedCases: number;
  maliciousTotalCases: number;
  parserRejectedCases: number;
  parserExpectedRejectCases: number;
  fingerprintPassedCases: number;
  fingerprintTotalCases: number;
  coveragePassedCases: number;
  coverageTotalCases: number;
  falsePositiveIncreaseBasisPoints: number;
  scannerFailureRateBasisPoints: number;
  p95LatencyIncreaseBasisPoints: number;
  crossTenantEvents: number;
  secretLeakEvents: number;
  sandboxEscapeEvents: number;
  stalePublicationEvents: number;
}

export interface SastRuleBundlePromotionEvidenceInput {
  manifestId: string;
  manifestDigest: Sha256Digest;
  verificationId: string;
  verificationDigest: Sha256Digest;
  bundleId: string;
  bundleDigest: Sha256Digest;
  profileId: SastProfileId;
  candidateAuthorRef: string;
  baselineManifestId: string;
  baselineManifestDigest: Sha256Digest;
  baselineBundleDigest: Sha256Digest;
  rollbackTargetDigest: Sha256Digest;
  environmentRef: string;
  corpusReferences: SastRuleBundlePromotionCorpusReferences;
  measurements: SastRuleBundlePromotionMeasurements;
  measuredAt: string;
}

export interface SastRuleBundlePromotionEvidence
  extends SastRuleBundlePromotionEvidenceInput {
  version: typeof SAST_RULE_BUNDLE_PROMOTION_EVIDENCE_VERSION;
  evidenceId: string;
  corpusSetDigest: Sha256Digest;
  measurementDigest: Sha256Digest;
  gatesPassed: true;
  automatedEvidenceOnly: true;
  approvalGranted: false;
  customerInputAccepted: false;
  executableRuleContentStored: false;
  repositoryContentStored: false;
  secretValueStored: false;
  evidenceDigest: Sha256Digest;
}

export interface SastRuleBundlePromotionApprovalInput {
  evidenceId: string;
  evidenceDigest: Sha256Digest;
  manifestId: string;
  manifestDigest: Sha256Digest;
  bundleDigest: Sha256Digest;
  candidateAuthorRef: string;
  role: SastRuleBundlePromotionApprovalRole;
  approverRef: string;
  approvalRef: string;
  approvedAt: string;
}

export interface SastRuleBundlePromotionApproval
  extends SastRuleBundlePromotionApprovalInput {
  version: typeof SAST_RULE_BUNDLE_PROMOTION_APPROVAL_VERSION;
  approvalId: string;
  approved: true;
  humanApproval: true;
  automatedApproval: false;
  customerInputAccepted: false;
  approvalDigest: Sha256Digest;
}

export interface SastRuleBundlePromotionApprovalBinding {
  approvalId: string;
  approvalDigest: Sha256Digest;
  role: SastRuleBundlePromotionApprovalRole;
  approverRef: string;
  approvedAt: string;
}

export interface SastRuleBundleLifecycleTransitionInput {
  manifestId: string;
  manifestDigest: Sha256Digest;
  bundleId: string;
  bundleDigest: Sha256Digest;
  sequence: number;
  fromState: RuleBundleState;
  toState: RuleBundleState;
  previousTransitionId: string | null;
  previousTransitionDigest: Sha256Digest | null;
  promotionEvidenceId: string;
  promotionEvidenceDigest: Sha256Digest;
  candidateAuthorRef: string;
  approvals: SastRuleBundlePromotionApprovalBinding[];
  externalAuthority: SastRuleBundleLifecycleExternalAuthority;
  externalAuthorityReceiptRef: string | null;
  externalAuthorityReceiptDigest: Sha256Digest | null;
  actorRef: string;
  reasonRef: string;
  auditRef: string;
  transitionedAt: string;
}

export interface SastRuleBundleLifecycleTransition
  extends SastRuleBundleLifecycleTransitionInput {
  version: typeof SAST_RULE_BUNDLE_LIFECYCLE_TRANSITION_VERSION;
  transitionId: string;
  approvalSetDigest: Sha256Digest;
  source: 'PLATFORM_RULE_GOVERNANCE';
  immutable: true;
  customerInputAccepted: false;
  executableRuleContentStored: false;
  repositoryContentStored: false;
  secretValueStored: false;
  transitionDigest: Sha256Digest;
}

export interface SastRuleBundleLifecycleSelectionReceiptInput {
  manifestId: string;
  manifestDigest: Sha256Digest;
  bundleId: string;
  bundleDigest: Sha256Digest;
  lifecycleState: 'CANARY' | 'ACTIVE';
  lifecycleSequence: number;
  transitionId: string;
  transitionDigest: Sha256Digest;
  promotionEvidenceId: string;
  promotionEvidenceDigest: Sha256Digest;
  approvalSetDigest: Sha256Digest;
  evaluatedAt: string;
}

export interface SastRuleBundleLifecycleSelectionReceipt
  extends SastRuleBundleLifecycleSelectionReceiptInput {
  version: typeof SAST_RULE_BUNDLE_LIFECYCLE_SELECTION_VERSION;
  receiptId: string;
  selectable: true;
  latestTransitionVerified: true;
  approvalSeparationVerified: true;
  customerInputAccepted: false;
  executableRuleContentStored: false;
  receiptDigest: Sha256Digest;
}

export interface VerifiedSastRuleBundleLifecycleDescriptor {
  lifecycleState: 'CANARY' | 'ACTIVE';
  lifecycleSequence: number;
  lifecycleTransitionId: string;
  lifecycleTransitionDigest: Sha256Digest;
  promotionEvidenceId: string;
  promotionEvidenceDigest: Sha256Digest;
  approvalSetDigest: Sha256Digest;
  selectionReceiptId: string;
  selectionReceiptDigest: Sha256Digest;
}

const PROFILE_IDS = [
  'JAVA_FAST_V1',
  'JAVA_DEEP_V1',
  'COMMON_DEEP_V1'
] as const satisfies readonly SastProfileId[];
const RULE_BUNDLE_STATES = [
  'DRAFT',
  'VALIDATED',
  'CANARY',
  'ACTIVE',
  'SUSPENDED',
  'ROLLED_BACK',
  'RETIRED'
] as const satisfies readonly RuleBundleState[];
const APPROVAL_ROLE_ORDER = new Map(
  SAST_RULE_BUNDLE_PROMOTION_APPROVAL_ROLES.map((role, index) => [role, index])
);
const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const MANIFEST_ID_PATTERN =
  /^sast-rule-bundle-manifest:\/\/[a-f0-9]{64}$/u;
const VERIFICATION_ID_PATTERN =
  /^sast-rule-bundle-verification:\/\/[a-f0-9]{64}$/u;
const EVIDENCE_ID_PATTERN =
  /^sast-rule-bundle-promotion-evidence:\/\/[a-f0-9]{64}$/u;
const APPROVAL_ID_PATTERN =
  /^sast-rule-bundle-promotion-approval:\/\/[a-f0-9]{64}$/u;
const TRANSITION_ID_PATTERN =
  /^sast-rule-bundle-lifecycle-transition:\/\/[a-f0-9]{64}$/u;
const SELECTION_ID_PATTERN =
  /^sast-rule-bundle-lifecycle-selection:\/\/[a-f0-9]{64}$/u;
const BUNDLE_ID_PATTERN =
  /^sast-rule-bundle:\/\/(?:opengrep|trivy)\/[a-z0-9][a-z0-9._-]{0,127}$/u;
const DIGEST_BOUND_REFERENCE_PATTERN =
  /^[a-z][a-z0-9+.-]*:\/\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+\/sha256:[a-f0-9]{64}$/u;
const ACTOR_REFERENCE_PATTERN =
  /^(?:spiffe|sast-actor|sast-approver):\/\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+$/u;
const ISO_INSTANT_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const UTF8_ENCODER = new TextEncoder();

export function findSastRuleBundlePromotionEvidenceReasonCodes(
  input: Readonly<SastRuleBundlePromotionEvidenceInput>
): SastRuleBundlePromotionEvidenceReasonCode[] {
  if (!isPromotionEvidenceInputStructurallyValid(input)) {
    return ['INPUT_INVALID'];
  }
  const measurements = input.measurements;
  const reasons: SastRuleBundlePromotionEvidenceReasonCode[] = [];
  if (
    measurements.positiveCases <
      SAST_RULE_BUNDLE_PROMOTION_LIMITS.minimumPositiveCases ||
    measurements.negativeCases <
      SAST_RULE_BUNDLE_PROMOTION_LIMITS.minimumNegativeCases ||
    measurements.performanceRuns <
      SAST_RULE_BUNDLE_PROMOTION_LIMITS.minimumPerformanceRuns
  ) {
    reasons.push('SAMPLE_INSUFFICIENT');
  }
  if (
    !isPerfectRatio(
      measurements.goldenPassedCases,
      measurements.goldenTotalCases
    ) ||
    !isPerfectRatio(
      measurements.priorMustDetectPassedCases,
      measurements.priorMustDetectTotalCases
    ) ||
    !isPerfectRatio(
      measurements.maliciousPassedCases,
      measurements.maliciousTotalCases
    ) ||
    !isPerfectRatio(
      measurements.parserRejectedCases,
      measurements.parserExpectedRejectCases
    ) ||
    !isPerfectRatio(
      measurements.fingerprintPassedCases,
      measurements.fingerprintTotalCases
    ) ||
    !isPerfectRatio(
      measurements.coveragePassedCases,
      measurements.coverageTotalCases
    )
  ) {
    reasons.push('CORPUS_GATE_FAILED');
  }
  if (
    !ratioAtLeast(
      measurements.mustDetectTruePositiveCases,
      measurements.mustDetectExpectedCases,
      SAST_RULE_BUNDLE_PROMOTION_LIMITS.minimumMustDetectRecallBasisPoints
    )
  ) {
    reasons.push('RECALL_GATE_FAILED');
  }
  if (
    !ratioAtLeast(
      measurements.criticalHighTruePositiveCases,
      measurements.criticalHighReportedCases,
      SAST_RULE_BUNDLE_PROMOTION_LIMITS.minimumCriticalHighPrecisionBasisPoints
    )
  ) {
    reasons.push('PRECISION_GATE_FAILED');
  }
  if (
    measurements.falsePositiveIncreaseBasisPoints >
    SAST_RULE_BUNDLE_PROMOTION_LIMITS.maximumFalsePositiveIncreaseBasisPoints
  ) {
    reasons.push('FALSE_POSITIVE_GATE_FAILED');
  }
  if (
    measurements.scannerFailureRateBasisPoints >
    SAST_RULE_BUNDLE_PROMOTION_LIMITS.maximumScannerFailureRateBasisPoints
  ) {
    reasons.push('FAILURE_RATE_GATE_FAILED');
  }
  if (
    measurements.p95LatencyIncreaseBasisPoints >
    SAST_RULE_BUNDLE_PROMOTION_LIMITS.maximumP95LatencyIncreaseBasisPoints
  ) {
    reasons.push('LATENCY_GATE_FAILED');
  }
  if (
    measurements.crossTenantEvents !== 0 ||
    measurements.secretLeakEvents !== 0 ||
    measurements.sandboxEscapeEvents !== 0 ||
    measurements.stalePublicationEvents !== 0
  ) {
    reasons.push('SECURITY_EVENT_RECORDED');
  }
  return reasons;
}

export function buildSastRuleBundlePromotionEvidence(
  input: Readonly<SastRuleBundlePromotionEvidenceInput>,
  digestCanonical: SastRuleBundlePromotionCanonicalDigester
): SastRuleBundlePromotionEvidence | null {
  if (findSastRuleBundlePromotionEvidenceReasonCodes(input).length > 0) {
    return null;
  }
  const corpusReferences = { ...input.corpusReferences };
  const measurements = { ...input.measurements };
  const core = {
    version: SAST_RULE_BUNDLE_PROMOTION_EVIDENCE_VERSION,
    manifestId: input.manifestId,
    manifestDigest: input.manifestDigest,
    verificationId: input.verificationId,
    verificationDigest: input.verificationDigest,
    bundleId: input.bundleId,
    bundleDigest: input.bundleDigest,
    profileId: input.profileId,
    candidateAuthorRef: input.candidateAuthorRef,
    baselineManifestId: input.baselineManifestId,
    baselineManifestDigest: input.baselineManifestDigest,
    baselineBundleDigest: input.baselineBundleDigest,
    rollbackTargetDigest: input.rollbackTargetDigest,
    environmentRef: input.environmentRef,
    corpusReferences,
    corpusSetDigest: digestCanonical(stableJson(corpusReferences)),
    measurements,
    measurementDigest: digestCanonical(stableJson(measurements)),
    measuredAt: input.measuredAt,
    gatesPassed: true as const,
    automatedEvidenceOnly: true as const,
    approvalGranted: false as const,
    customerInputAccepted: false as const,
    executableRuleContentStored: false as const,
    repositoryContentStored: false as const,
    secretValueStored: false as const
  };
  const evidenceDigest = digestCanonical(stableJson(core));
  const suffix = digestSuffix(evidenceDigest);
  if (!suffix) return null;
  const evidence: SastRuleBundlePromotionEvidence = {
    ...core,
    evidenceId: `sast-rule-bundle-promotion-evidence://${suffix}`,
    evidenceDigest
  };
  return isSastRuleBundlePromotionEvidenceShapeValid(
    evidence,
    digestCanonical
  )
    ? evidence
    : null;
}

export function isSastRuleBundlePromotionEvidenceShapeValid(
  value: unknown,
  digestCanonical: SastRuleBundlePromotionCanonicalDigester
): value is SastRuleBundlePromotionEvidence {
  if (!hasExactKeys(value, PROMOTION_EVIDENCE_KEYS)) return false;
  const evidence = value as unknown as SastRuleBundlePromotionEvidence;
  if (
    evidence.version !== SAST_RULE_BUNDLE_PROMOTION_EVIDENCE_VERSION ||
    !EVIDENCE_ID_PATTERN.test(evidence.evidenceId) ||
    !isDigest(evidence.evidenceDigest) ||
    !isPromotionEvidenceInputStructurallyValid(
      selectContractFields<SastRuleBundlePromotionEvidenceInput>(
        evidence,
        PROMOTION_EVIDENCE_INPUT_KEYS
      )
    ) ||
    findSastRuleBundlePromotionEvidenceReasonCodes(
      selectContractFields<SastRuleBundlePromotionEvidenceInput>(
        evidence,
        PROMOTION_EVIDENCE_INPUT_KEYS
      )
    ).length > 0 ||
    !isDigest(evidence.corpusSetDigest) ||
    !isDigest(evidence.measurementDigest) ||
    evidence.gatesPassed !== true ||
    evidence.automatedEvidenceOnly !== true ||
    evidence.approvalGranted !== false ||
    evidence.customerInputAccepted !== false ||
    evidence.executableRuleContentStored !== false ||
    evidence.repositoryContentStored !== false ||
    evidence.secretValueStored !== false
  ) {
    return false;
  }
  const core = promotionEvidenceCore(evidence);
  return (
    evidence.corpusSetDigest ===
      digestCanonical(stableJson(evidence.corpusReferences)) &&
    evidence.measurementDigest ===
      digestCanonical(stableJson(evidence.measurements)) &&
    evidence.evidenceDigest === digestCanonical(stableJson(core)) &&
    evidence.evidenceId ===
      `sast-rule-bundle-promotion-evidence://${digestSuffix(evidence.evidenceDigest)}`
  );
}

export function buildSastRuleBundlePromotionApproval(
  input: Readonly<SastRuleBundlePromotionApprovalInput>,
  digestCanonical: SastRuleBundlePromotionCanonicalDigester
): SastRuleBundlePromotionApproval | null {
  if (!isPromotionApprovalInputValid(input)) return null;
  const core = {
    version: SAST_RULE_BUNDLE_PROMOTION_APPROVAL_VERSION,
    ...input,
    approved: true as const,
    humanApproval: true as const,
    automatedApproval: false as const,
    customerInputAccepted: false as const
  };
  const approvalDigest = digestCanonical(stableJson(core));
  const suffix = digestSuffix(approvalDigest);
  if (!suffix) return null;
  const approval: SastRuleBundlePromotionApproval = {
    ...core,
    approvalId: `sast-rule-bundle-promotion-approval://${suffix}`,
    approvalDigest
  };
  return isSastRuleBundlePromotionApprovalShapeValid(
    approval,
    digestCanonical
  )
    ? approval
    : null;
}

export function isSastRuleBundlePromotionApprovalShapeValid(
  value: unknown,
  digestCanonical: SastRuleBundlePromotionCanonicalDigester
): value is SastRuleBundlePromotionApproval {
  if (!hasExactKeys(value, PROMOTION_APPROVAL_KEYS)) return false;
  const approval = value as unknown as SastRuleBundlePromotionApproval;
  if (
    approval.version !== SAST_RULE_BUNDLE_PROMOTION_APPROVAL_VERSION ||
    !APPROVAL_ID_PATTERN.test(approval.approvalId) ||
    !isDigest(approval.approvalDigest) ||
    !isPromotionApprovalInputValid(
      selectContractFields<SastRuleBundlePromotionApprovalInput>(
        approval,
        PROMOTION_APPROVAL_INPUT_KEYS
      )
    ) ||
    approval.approved !== true ||
    approval.humanApproval !== true ||
    approval.automatedApproval !== false ||
    approval.customerInputAccepted !== false
  ) {
    return false;
  }
  const core = promotionApprovalCore(approval);
  return (
    approval.approvalDigest === digestCanonical(stableJson(core)) &&
    approval.approvalId ===
      `sast-rule-bundle-promotion-approval://${digestSuffix(approval.approvalDigest)}`
  );
}

export function buildSastRuleBundleLifecycleTransition(
  input: Readonly<SastRuleBundleLifecycleTransitionInput>,
  digestCanonical: SastRuleBundlePromotionCanonicalDigester
): SastRuleBundleLifecycleTransition | null {
  if (!isLifecycleTransitionInputValid(input)) return null;
  const approvals = input.approvals.map((approval) => ({ ...approval }));
  const approvalSetDigest = digestCanonical(stableJson(approvals));
  const core = {
    version: SAST_RULE_BUNDLE_LIFECYCLE_TRANSITION_VERSION,
    ...input,
    approvals,
    approvalSetDigest,
    source: 'PLATFORM_RULE_GOVERNANCE' as const,
    immutable: true as const,
    customerInputAccepted: false as const,
    executableRuleContentStored: false as const,
    repositoryContentStored: false as const,
    secretValueStored: false as const
  };
  const transitionDigest = digestCanonical(stableJson(core));
  const suffix = digestSuffix(transitionDigest);
  if (!suffix) return null;
  const transition: SastRuleBundleLifecycleTransition = {
    ...core,
    transitionId: `sast-rule-bundle-lifecycle-transition://${suffix}`,
    transitionDigest
  };
  return isSastRuleBundleLifecycleTransitionShapeValid(
    transition,
    digestCanonical
  )
    ? transition
    : null;
}

export function isSastRuleBundleLifecycleTransitionShapeValid(
  value: unknown,
  digestCanonical: SastRuleBundlePromotionCanonicalDigester
): value is SastRuleBundleLifecycleTransition {
  if (!hasExactKeys(value, LIFECYCLE_TRANSITION_KEYS)) return false;
  const transition = value as unknown as SastRuleBundleLifecycleTransition;
  if (
    transition.version !== SAST_RULE_BUNDLE_LIFECYCLE_TRANSITION_VERSION ||
    !TRANSITION_ID_PATTERN.test(transition.transitionId) ||
    !isDigest(transition.transitionDigest) ||
    !isDigest(transition.approvalSetDigest) ||
    !isLifecycleTransitionInputValid(
      selectContractFields<SastRuleBundleLifecycleTransitionInput>(
        transition,
        LIFECYCLE_TRANSITION_INPUT_KEYS
      )
    ) ||
    transition.source !== 'PLATFORM_RULE_GOVERNANCE' ||
    transition.immutable !== true ||
    transition.customerInputAccepted !== false ||
    transition.executableRuleContentStored !== false ||
    transition.repositoryContentStored !== false ||
    transition.secretValueStored !== false
  ) {
    return false;
  }
  const core = lifecycleTransitionCore(transition);
  return (
    transition.approvalSetDigest ===
      digestCanonical(stableJson(transition.approvals)) &&
    transition.transitionDigest === digestCanonical(stableJson(core)) &&
    transition.transitionId ===
      `sast-rule-bundle-lifecycle-transition://${digestSuffix(transition.transitionDigest)}`
  );
}

export function buildSastRuleBundleLifecycleSelectionReceipt(
  input: Readonly<SastRuleBundleLifecycleSelectionReceiptInput>,
  digestCanonical: SastRuleBundlePromotionCanonicalDigester
): SastRuleBundleLifecycleSelectionReceipt | null {
  if (!isLifecycleSelectionInputValid(input)) return null;
  const core = {
    version: SAST_RULE_BUNDLE_LIFECYCLE_SELECTION_VERSION,
    ...input,
    selectable: true as const,
    latestTransitionVerified: true as const,
    approvalSeparationVerified: true as const,
    customerInputAccepted: false as const,
    executableRuleContentStored: false as const
  };
  const receiptDigest = digestCanonical(stableJson(core));
  const suffix = digestSuffix(receiptDigest);
  if (!suffix) return null;
  const receipt: SastRuleBundleLifecycleSelectionReceipt = {
    ...core,
    receiptId: `sast-rule-bundle-lifecycle-selection://${suffix}`,
    receiptDigest
  };
  return isSastRuleBundleLifecycleSelectionReceiptShapeValid(
    receipt,
    digestCanonical
  )
    ? receipt
    : null;
}

export function isSastRuleBundleLifecycleSelectionReceiptShapeValid(
  value: unknown,
  digestCanonical: SastRuleBundlePromotionCanonicalDigester
): value is SastRuleBundleLifecycleSelectionReceipt {
  if (!hasExactKeys(value, LIFECYCLE_SELECTION_KEYS)) return false;
  const receipt =
    value as unknown as SastRuleBundleLifecycleSelectionReceipt;
  if (
    receipt.version !== SAST_RULE_BUNDLE_LIFECYCLE_SELECTION_VERSION ||
    !SELECTION_ID_PATTERN.test(receipt.receiptId) ||
    !isDigest(receipt.receiptDigest) ||
    !isLifecycleSelectionInputValid(
      selectContractFields<SastRuleBundleLifecycleSelectionReceiptInput>(
        receipt,
        LIFECYCLE_SELECTION_INPUT_KEYS
      )
    ) ||
    receipt.selectable !== true ||
    receipt.latestTransitionVerified !== true ||
    receipt.approvalSeparationVerified !== true ||
    receipt.customerInputAccepted !== false ||
    receipt.executableRuleContentStored !== false
  ) {
    return false;
  }
  const core = lifecycleSelectionCore(receipt);
  return (
    receipt.receiptDigest === digestCanonical(stableJson(core)) &&
    receipt.receiptId ===
      `sast-rule-bundle-lifecycle-selection://${digestSuffix(receipt.receiptDigest)}`
  );
}

export function toVerifiedSastRuleBundleLifecycleDescriptor(
  receipt: Readonly<SastRuleBundleLifecycleSelectionReceipt>
): VerifiedSastRuleBundleLifecycleDescriptor {
  return {
    lifecycleState: receipt.lifecycleState,
    lifecycleSequence: receipt.lifecycleSequence,
    lifecycleTransitionId: receipt.transitionId,
    lifecycleTransitionDigest: receipt.transitionDigest,
    promotionEvidenceId: receipt.promotionEvidenceId,
    promotionEvidenceDigest: receipt.promotionEvidenceDigest,
    approvalSetDigest: receipt.approvalSetDigest,
    selectionReceiptId: receipt.receiptId,
    selectionReceiptDigest: receipt.receiptDigest
  };
}

export function isVerifiedSastRuleBundleLifecycleDescriptorValid(
  value: unknown
): value is VerifiedSastRuleBundleLifecycleDescriptor {
  return (
    hasExactKeys(value, [
      'lifecycleState',
      'lifecycleSequence',
      'lifecycleTransitionId',
      'lifecycleTransitionDigest',
      'promotionEvidenceId',
      'promotionEvidenceDigest',
      'approvalSetDigest',
      'selectionReceiptId',
      'selectionReceiptDigest'
    ]) &&
    (value.lifecycleState === 'CANARY' || value.lifecycleState === 'ACTIVE') &&
    isLifecycleSequence(value.lifecycleSequence) &&
    TRANSITION_ID_PATTERN.test(value.lifecycleTransitionId as string) &&
    isDigest(value.lifecycleTransitionDigest) &&
    EVIDENCE_ID_PATTERN.test(value.promotionEvidenceId as string) &&
    isDigest(value.promotionEvidenceDigest) &&
    isDigest(value.approvalSetDigest) &&
    SELECTION_ID_PATTERN.test(value.selectionReceiptId as string) &&
    isDigest(value.selectionReceiptDigest)
  );
}

export function isSastRuleBundleLifecycleTransitionAllowed(
  fromState: RuleBundleState,
  toState: RuleBundleState
): boolean {
  return (
    (fromState === 'DRAFT' && toState === 'VALIDATED') ||
    (fromState === 'VALIDATED' && toState === 'CANARY') ||
    (fromState === 'CANARY' && toState === 'ACTIVE') ||
    (fromState === 'ACTIVE' && toState === 'RETIRED') ||
    ((fromState === 'CANARY' || fromState === 'ACTIVE') &&
      toState === 'SUSPENDED') ||
    (fromState === 'SUSPENDED' && toState === 'ROLLED_BACK')
  );
}

function isPromotionEvidenceInputStructurallyValid(
  value: unknown
): value is SastRuleBundlePromotionEvidenceInput {
  if (!hasExactKeys(value, PROMOTION_EVIDENCE_INPUT_KEYS)) return false;
  const input = value as unknown as SastRuleBundlePromotionEvidenceInput;
  return (
    MANIFEST_ID_PATTERN.test(input.manifestId) &&
    isDigest(input.manifestDigest) &&
    VERIFICATION_ID_PATTERN.test(input.verificationId) &&
    isDigest(input.verificationDigest) &&
    BUNDLE_ID_PATTERN.test(input.bundleId) &&
    isDigest(input.bundleDigest) &&
    PROFILE_IDS.includes(input.profileId) &&
    isActorReference(input.candidateAuthorRef) &&
    MANIFEST_ID_PATTERN.test(input.baselineManifestId) &&
    isDigest(input.baselineManifestDigest) &&
    isDigest(input.baselineBundleDigest) &&
    input.baselineManifestId !== input.manifestId &&
    input.baselineManifestDigest !== input.manifestDigest &&
    input.baselineBundleDigest !== input.bundleDigest &&
    isDigest(input.rollbackTargetDigest) &&
    input.rollbackTargetDigest === input.baselineBundleDigest &&
    isDigestBoundReference(input.environmentRef) &&
    isPromotionCorpusReferencesValid(input.corpusReferences) &&
    isPromotionMeasurementsStructurallyValid(input.measurements) &&
    isIsoInstant(input.measuredAt)
  );
}

function isPromotionCorpusReferencesValid(
  value: unknown
): value is SastRuleBundlePromotionCorpusReferences {
  return (
    hasExactKeys(value, [
      'goldenCorpusRef',
      'priorMustDetectCorpusRef',
      'maliciousCorpusRef',
      'parserCorpusRef',
      'fingerprintCorpusRef',
      'coverageCorpusRef',
      'performanceCorpusRef'
    ]) &&
    Object.values(value as Record<string, unknown>).every(
      isDigestBoundReference
    )
  );
}

function isPromotionMeasurementsStructurallyValid(
  value: unknown
): value is SastRuleBundlePromotionMeasurements {
  if (!hasExactKeys(value, PROMOTION_MEASUREMENT_KEYS)) return false;
  const measurements =
    value as unknown as SastRuleBundlePromotionMeasurements;
  const counts = PROMOTION_MEASUREMENT_KEYS.filter(
    (key) => !key.endsWith('BasisPoints')
  );
  if (
    !counts.every((key) => isBoundedNonNegativeInteger(measurements[key])) ||
    !isBoundedBasisPointDelta(
      measurements.falsePositiveIncreaseBasisPoints
    ) ||
    !isRateBasisPoints(measurements.scannerFailureRateBasisPoints) ||
    !isBoundedBasisPointDelta(
      measurements.p95LatencyIncreaseBasisPoints,
      100_000
    )
  ) {
    return false;
  }
  return (
    measurements.goldenPassedCases <= measurements.goldenTotalCases &&
    measurements.priorMustDetectPassedCases <=
      measurements.priorMustDetectTotalCases &&
    measurements.mustDetectTruePositiveCases <=
      measurements.mustDetectExpectedCases &&
    measurements.criticalHighTruePositiveCases <=
      measurements.criticalHighReportedCases &&
    measurements.maliciousPassedCases <=
      measurements.maliciousTotalCases &&
    measurements.parserRejectedCases <=
      measurements.parserExpectedRejectCases &&
    measurements.fingerprintPassedCases <=
      measurements.fingerprintTotalCases &&
    measurements.coveragePassedCases <= measurements.coverageTotalCases
  );
}

function isPromotionApprovalInputValid(
  value: unknown
): value is SastRuleBundlePromotionApprovalInput {
  if (!hasExactKeys(value, PROMOTION_APPROVAL_INPUT_KEYS)) return false;
  const approval =
    value as unknown as SastRuleBundlePromotionApprovalInput;
  return (
    EVIDENCE_ID_PATTERN.test(approval.evidenceId) &&
    isDigest(approval.evidenceDigest) &&
    MANIFEST_ID_PATTERN.test(approval.manifestId) &&
    isDigest(approval.manifestDigest) &&
    isDigest(approval.bundleDigest) &&
    SAST_RULE_BUNDLE_PROMOTION_APPROVAL_ROLES.includes(approval.role) &&
    isActorReference(approval.candidateAuthorRef) &&
    isActorReference(approval.approverRef) &&
    approval.approverRef !== approval.candidateAuthorRef &&
    isDigestBoundReference(approval.approvalRef) &&
    isIsoInstant(approval.approvedAt)
  );
}

function isLifecycleTransitionInputValid(
  value: unknown
): value is SastRuleBundleLifecycleTransitionInput {
  if (!hasExactKeys(value, LIFECYCLE_TRANSITION_INPUT_KEYS)) return false;
  const input =
    value as unknown as SastRuleBundleLifecycleTransitionInput;
  if (
    !MANIFEST_ID_PATTERN.test(input.manifestId) ||
    !isDigest(input.manifestDigest) ||
    !BUNDLE_ID_PATTERN.test(input.bundleId) ||
    !isDigest(input.bundleDigest) ||
    !isLifecycleSequence(input.sequence) ||
    !RULE_BUNDLE_STATES.includes(input.fromState) ||
    !RULE_BUNDLE_STATES.includes(input.toState) ||
    !isSastRuleBundleLifecycleTransitionAllowed(
      input.fromState,
      input.toState
    ) ||
    !EVIDENCE_ID_PATTERN.test(input.promotionEvidenceId) ||
    !isDigest(input.promotionEvidenceDigest) ||
    !isActorReference(input.candidateAuthorRef) ||
    !isCanonicalApprovalBindings(input.approvals) ||
    !SAST_RULE_BUNDLE_LIFECYCLE_EXTERNAL_AUTHORITIES.includes(
      input.externalAuthority
    ) ||
    !isExternalAuthorityBindingValid(input) ||
    !isActorReference(input.actorRef) ||
    !isDigestBoundReference(input.reasonRef) ||
    !isDigestBoundReference(input.auditRef) ||
    !isIsoInstant(input.transitionedAt) ||
    input.approvals.some(
      (approval) =>
        Date.parse(approval.approvedAt) > Date.parse(input.transitionedAt)
    ) ||
    !hasRequiredApprovals(input)
  ) {
    return false;
  }
  return input.sequence === 1
    ? input.fromState === 'DRAFT' &&
        input.previousTransitionId === null &&
        input.previousTransitionDigest === null
    : TRANSITION_ID_PATTERN.test(input.previousTransitionId ?? '') &&
        isDigest(input.previousTransitionDigest);
}

function isCanonicalApprovalBindings(
  value: unknown
): value is SastRuleBundlePromotionApprovalBinding[] {
  if (
    !Array.isArray(value) ||
    value.length < 1 ||
    value.length > SAST_RULE_BUNDLE_PROMOTION_LIMITS.maximumApprovals
  ) {
    return false;
  }
  const approvers = new Set<string>();
  const roles = new Set<SastRuleBundlePromotionApprovalRole>();
  return value.every((binding, index) => {
    if (
      !hasExactKeys(binding, [
        'approvalId',
        'approvalDigest',
        'role',
        'approverRef',
        'approvedAt'
      ])
    ) {
      return false;
    }
    const candidate =
      binding as unknown as SastRuleBundlePromotionApprovalBinding;
    const role = candidate.role;
    const previous = value[index - 1] as
      | SastRuleBundlePromotionApprovalBinding
      | undefined;
    const valid =
      APPROVAL_ID_PATTERN.test(candidate.approvalId) &&
      isDigest(candidate.approvalDigest) &&
      SAST_RULE_BUNDLE_PROMOTION_APPROVAL_ROLES.includes(role) &&
      isActorReference(candidate.approverRef) &&
      isIsoInstant(candidate.approvedAt) &&
      !approvers.has(candidate.approverRef) &&
      !roles.has(role) &&
      (index === 0 ||
        (APPROVAL_ROLE_ORDER.get(previous!.role) ?? -1) <
          (APPROVAL_ROLE_ORDER.get(role) ?? -1));
    approvers.add(candidate.approverRef);
    roles.add(role);
    return valid;
  });
}

function hasRequiredApprovals(
  input: Readonly<SastRuleBundleLifecycleTransitionInput>
): boolean {
  const securityApproval = input.approvals.find(
    (approval) => approval.role === 'SECURITY_ENGINEERING'
  );
  if (!securityApproval) return false;
  if (input.toState === 'ACTIVE' || input.toState === 'RETIRED') {
    return input.approvals.some(
      (approval) =>
        approval.role === 'SCAN_PLATFORM' ||
        approval.role === 'SECURITY_OPERATIONS'
    );
  }
  return true;
}

function isExternalAuthorityBindingValid(
  input: Readonly<SastRuleBundleLifecycleTransitionInput>
): boolean {
  const expected =
    input.fromState === 'CANARY' && input.toState === 'ACTIVE'
      ? 'CANARY_OBSERVATION'
      : input.toState === 'SUSPENDED'
        ? 'EMERGENCY_SUSPENSION'
        : input.fromState === 'SUSPENDED' &&
            input.toState === 'ROLLED_BACK'
          ? 'ROLLBACK'
          : 'NONE';
  if (input.externalAuthority !== expected) return false;
  return expected === 'NONE'
    ? input.externalAuthorityReceiptRef === null &&
        input.externalAuthorityReceiptDigest === null
    : isDigestBoundReference(input.externalAuthorityReceiptRef) &&
        isDigest(input.externalAuthorityReceiptDigest) &&
        digestSuffix(input.externalAuthorityReceiptDigest) !== null &&
        input.externalAuthorityReceiptRef.endsWith(
          input.externalAuthorityReceiptDigest
        );
}

function isLifecycleSelectionInputValid(
  value: unknown
): value is SastRuleBundleLifecycleSelectionReceiptInput {
  if (!hasExactKeys(value, LIFECYCLE_SELECTION_INPUT_KEYS)) return false;
  const input =
    value as unknown as SastRuleBundleLifecycleSelectionReceiptInput;
  return (
    MANIFEST_ID_PATTERN.test(input.manifestId) &&
    isDigest(input.manifestDigest) &&
    BUNDLE_ID_PATTERN.test(input.bundleId) &&
    isDigest(input.bundleDigest) &&
    (input.lifecycleState === 'CANARY' ||
      input.lifecycleState === 'ACTIVE') &&
    isLifecycleSequence(input.lifecycleSequence) &&
    TRANSITION_ID_PATTERN.test(input.transitionId) &&
    isDigest(input.transitionDigest) &&
    EVIDENCE_ID_PATTERN.test(input.promotionEvidenceId) &&
    isDigest(input.promotionEvidenceDigest) &&
    isDigest(input.approvalSetDigest) &&
    isIsoInstant(input.evaluatedAt)
  );
}

function promotionEvidenceCore(
  evidence: Readonly<SastRuleBundlePromotionEvidence>
): Omit<SastRuleBundlePromotionEvidence, 'evidenceId' | 'evidenceDigest'> {
  const mutable = { ...evidence } as Partial<SastRuleBundlePromotionEvidence>;
  delete mutable.evidenceId;
  delete mutable.evidenceDigest;
  const core = mutable as Omit<
    SastRuleBundlePromotionEvidence,
    'evidenceId' | 'evidenceDigest'
  >;
  return {
    ...core,
    corpusReferences: { ...core.corpusReferences },
    measurements: { ...core.measurements }
  };
}

function promotionApprovalCore(
  approval: Readonly<SastRuleBundlePromotionApproval>
): Omit<SastRuleBundlePromotionApproval, 'approvalId' | 'approvalDigest'> {
  const mutable = { ...approval } as Partial<SastRuleBundlePromotionApproval>;
  delete mutable.approvalId;
  delete mutable.approvalDigest;
  return mutable as Omit<
    SastRuleBundlePromotionApproval,
    'approvalId' | 'approvalDigest'
  >;
}

function lifecycleTransitionCore(
  transition: Readonly<SastRuleBundleLifecycleTransition>
): Omit<
  SastRuleBundleLifecycleTransition,
  'transitionId' | 'transitionDigest'
> {
  const mutable = {
    ...transition
  } as Partial<SastRuleBundleLifecycleTransition>;
  delete mutable.transitionId;
  delete mutable.transitionDigest;
  const core = mutable as Omit<
    SastRuleBundleLifecycleTransition,
    'transitionId' | 'transitionDigest'
  >;
  return {
    ...core,
    approvals: core.approvals.map((approval) => ({ ...approval }))
  };
}

function lifecycleSelectionCore(
  receipt: Readonly<SastRuleBundleLifecycleSelectionReceipt>
): Omit<SastRuleBundleLifecycleSelectionReceipt, 'receiptId' | 'receiptDigest'> {
  const mutable = {
    ...receipt
  } as Partial<SastRuleBundleLifecycleSelectionReceipt>;
  delete mutable.receiptId;
  delete mutable.receiptDigest;
  return mutable as Omit<
    SastRuleBundleLifecycleSelectionReceipt,
    'receiptId' | 'receiptDigest'
  >;
}

function isPerfectRatio(passed: number, total: number): boolean {
  return total > 0 && passed === total;
}

function ratioAtLeast(
  numerator: number,
  denominator: number,
  minimumBasisPoints: number
): boolean {
  return (
    denominator > 0 &&
    numerator * 10_000 >= denominator * minimumBasisPoints
  );
}

function isBoundedNonNegativeInteger(value: unknown): value is number {
  return (
    Number.isSafeInteger(value) &&
    (value as number) >= 0 &&
    (value as number) <= SAST_RULE_BUNDLE_PROMOTION_LIMITS.maximumCount
  );
}

function isRateBasisPoints(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0 && (value as number) <= 10_000;
}

function isBoundedBasisPointDelta(
  value: unknown,
  maximum = 10_000
): value is number {
  return (
    Number.isSafeInteger(value) &&
    (value as number) >= -10_000 &&
    (value as number) <= maximum
  );
}

function isLifecycleSequence(value: unknown): value is number {
  return (
    Number.isSafeInteger(value) &&
    (value as number) >= 1 &&
    (value as number) <=
      SAST_RULE_BUNDLE_PROMOTION_LIMITS.maximumLifecycleSequence
  );
}

function isActorReference(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    isBoundedText(value, SAST_RULE_BUNDLE_PROMOTION_LIMITS.identifierBytes) &&
    ACTOR_REFERENCE_PATTERN.test(value)
  );
}

function isDigestBoundReference(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    isBoundedText(value, SAST_RULE_BUNDLE_PROMOTION_LIMITS.referenceBytes) &&
    DIGEST_BOUND_REFERENCE_PATTERN.test(value) &&
    !/^https?:/u.test(value)
  );
}

function isBoundedText(value: string, maximumBytes: number): boolean {
  return (
    value.length > 0 &&
    value.normalize('NFC') === value &&
    !Array.from(value).some((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return codePoint <= 31 || codePoint === 127;
    }) &&
    UTF8_ENCODER.encode(value).byteLength <= maximumBytes
  );
}

function isIsoInstant(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    ISO_INSTANT_PATTERN.test(value) &&
    Number.isFinite(Date.parse(value)) &&
    new Date(value).toISOString() === value
  );
}

function isDigest(value: unknown): value is Sha256Digest {
  return typeof value === 'string' && SHA256_PATTERN.test(value);
}

function digestSuffix(value: unknown): string | null {
  return isDigest(value) ? value.slice('sha256:'.length) : null;
}

function hasExactKeys(
  value: unknown,
  expectedKeys: readonly string[]
): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const keys = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  return (
    keys.length === expected.length &&
    keys.every((key, index) => key === expected[index])
  );
}

function selectContractFields<T>(
  value: object,
  keys: readonly string[]
): T {
  const record = value as Record<string, unknown>;
  return Object.fromEntries(keys.map((key) => [key, record[key]])) as T;
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

const PROMOTION_MEASUREMENT_KEYS = [
  'positiveCases',
  'negativeCases',
  'performanceRuns',
  'goldenPassedCases',
  'goldenTotalCases',
  'priorMustDetectPassedCases',
  'priorMustDetectTotalCases',
  'mustDetectTruePositiveCases',
  'mustDetectExpectedCases',
  'criticalHighTruePositiveCases',
  'criticalHighReportedCases',
  'maliciousPassedCases',
  'maliciousTotalCases',
  'parserRejectedCases',
  'parserExpectedRejectCases',
  'fingerprintPassedCases',
  'fingerprintTotalCases',
  'coveragePassedCases',
  'coverageTotalCases',
  'falsePositiveIncreaseBasisPoints',
  'scannerFailureRateBasisPoints',
  'p95LatencyIncreaseBasisPoints',
  'crossTenantEvents',
  'secretLeakEvents',
  'sandboxEscapeEvents',
  'stalePublicationEvents'
] as const satisfies readonly (keyof SastRuleBundlePromotionMeasurements)[];

const PROMOTION_EVIDENCE_INPUT_KEYS = [
  'manifestId',
  'manifestDigest',
  'verificationId',
  'verificationDigest',
  'bundleId',
  'bundleDigest',
  'profileId',
  'candidateAuthorRef',
  'baselineManifestId',
  'baselineManifestDigest',
  'baselineBundleDigest',
  'rollbackTargetDigest',
  'environmentRef',
  'corpusReferences',
  'measurements',
  'measuredAt'
] as const;
const PROMOTION_EVIDENCE_KEYS = [
  ...PROMOTION_EVIDENCE_INPUT_KEYS,
  'version',
  'evidenceId',
  'corpusSetDigest',
  'measurementDigest',
  'gatesPassed',
  'automatedEvidenceOnly',
  'approvalGranted',
  'customerInputAccepted',
  'executableRuleContentStored',
  'repositoryContentStored',
  'secretValueStored',
  'evidenceDigest'
] as const;
const PROMOTION_APPROVAL_INPUT_KEYS = [
  'evidenceId',
  'evidenceDigest',
  'manifestId',
  'manifestDigest',
  'bundleDigest',
  'candidateAuthorRef',
  'role',
  'approverRef',
  'approvalRef',
  'approvedAt'
] as const;
const PROMOTION_APPROVAL_KEYS = [
  ...PROMOTION_APPROVAL_INPUT_KEYS,
  'version',
  'approvalId',
  'approved',
  'humanApproval',
  'automatedApproval',
  'customerInputAccepted',
  'approvalDigest'
] as const;
const LIFECYCLE_TRANSITION_INPUT_KEYS = [
  'manifestId',
  'manifestDigest',
  'bundleId',
  'bundleDigest',
  'sequence',
  'fromState',
  'toState',
  'previousTransitionId',
  'previousTransitionDigest',
  'promotionEvidenceId',
  'promotionEvidenceDigest',
  'candidateAuthorRef',
  'approvals',
  'externalAuthority',
  'externalAuthorityReceiptRef',
  'externalAuthorityReceiptDigest',
  'actorRef',
  'reasonRef',
  'auditRef',
  'transitionedAt'
] as const;
const LIFECYCLE_TRANSITION_KEYS = [
  ...LIFECYCLE_TRANSITION_INPUT_KEYS,
  'version',
  'transitionId',
  'approvalSetDigest',
  'source',
  'immutable',
  'customerInputAccepted',
  'executableRuleContentStored',
  'repositoryContentStored',
  'secretValueStored',
  'transitionDigest'
] as const;
const LIFECYCLE_SELECTION_INPUT_KEYS = [
  'manifestId',
  'manifestDigest',
  'bundleId',
  'bundleDigest',
  'lifecycleState',
  'lifecycleSequence',
  'transitionId',
  'transitionDigest',
  'promotionEvidenceId',
  'promotionEvidenceDigest',
  'approvalSetDigest',
  'evaluatedAt'
] as const;
const LIFECYCLE_SELECTION_KEYS = [
  ...LIFECYCLE_SELECTION_INPUT_KEYS,
  'version',
  'receiptId',
  'selectable',
  'latestTransitionVerified',
  'approvalSeparationVerified',
  'customerInputAccepted',
  'executableRuleContentStored',
  'receiptDigest'
] as const;
