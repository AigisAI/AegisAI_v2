import type { SastProfileId, SastScanLane } from './sast-runtime';

export const SAST_RULE_BUNDLE_CANARY_ROLLOUT_VERSION =
  'sast-rule-bundle-canary-rollout-v1' as const;
export const SAST_RULE_BUNDLE_CANARY_ELIGIBILITY_VERSION =
  'sast-rule-bundle-canary-eligibility-v1' as const;
export const SAST_RULE_BUNDLE_CANARY_MEMBERSHIP_VERSION =
  'sast-rule-bundle-canary-membership-v1' as const;
export const SAST_RULE_BUNDLE_CANARY_ASSIGNMENT_VERSION =
  'sast-rule-bundle-canary-assignment-v1' as const;
export const SAST_RULE_BUNDLE_CANARY_SCAN_OBSERVATION_VERSION =
  'sast-rule-bundle-canary-scan-observation-v1' as const;
export const SAST_RULE_BUNDLE_CANARY_STEP_DECISION_VERSION =
  'sast-rule-bundle-canary-step-decision-v1' as const;
export const SAST_RULE_BUNDLE_CANARY_OBSERVATION_RECEIPT_VERSION =
  'sast-rule-bundle-canary-observation-receipt-v1' as const;

export const SAST_RULE_BUNDLE_CANARY_STEPS = [
  'INTERNAL_CORPUS',
  'INTERNAL_REPOSITORIES',
  'PERCENT_1',
  'PERCENT_5',
  'PERCENT_25',
  'PERCENT_100'
] as const;
export type SastRuleBundleCanaryStep =
  (typeof SAST_RULE_BUNDLE_CANARY_STEPS)[number];

export const SAST_RULE_BUNDLE_CANARY_ELIGIBILITY_CLASSES = [
  'INTERNAL_CORPUS',
  'INTERNAL_REPOSITORY',
  'ELIGIBLE_PRODUCTION'
] as const;
export type SastRuleBundleCanaryEligibilityClass =
  (typeof SAST_RULE_BUNDLE_CANARY_ELIGIBILITY_CLASSES)[number];

export const SAST_RULE_BUNDLE_CANARY_REPOSITORY_SIZE_BUCKETS = [
  'SMALL',
  'MEDIUM',
  'LARGE'
] as const;
export type SastRuleBundleCanaryRepositorySizeBucket =
  (typeof SAST_RULE_BUNDLE_CANARY_REPOSITORY_SIZE_BUCKETS)[number];

export const SAST_RULE_BUNDLE_CANARY_SELECTIONS = [
  'CANDIDATE',
  'BASELINE',
  'EXCLUDED'
] as const;
export type SastRuleBundleCanarySelection =
  (typeof SAST_RULE_BUNDLE_CANARY_SELECTIONS)[number];

export const SAST_RULE_BUNDLE_CANARY_STEP_OUTCOMES = [
  'PENDING',
  'PASSED',
  'PAUSED'
] as const;
export type SastRuleBundleCanaryStepOutcome =
  (typeof SAST_RULE_BUNDLE_CANARY_STEP_OUTCOMES)[number];

export const SAST_RULE_BUNDLE_CANARY_GATE_REASON_CODES = [
  'OBSERVATION_WINDOW_INSUFFICIENT',
  'CANDIDATE_SAMPLE_INSUFFICIENT',
  'BASELINE_SAMPLE_INSUFFICIENT',
  'TELEMETRY_MISSING',
  'COVERAGE_INCOMPLETE',
  'PROFILE_SIZE_COMPARISON_INCOMPLETE',
  'FALSE_POSITIVE_GATE_FAILED',
  'SCANNER_FAILURE_GATE_FAILED',
  'LATENCY_GATE_FAILED',
  'CRITICAL_HIGH_VOLUME_GATE_FAILED',
  'ZERO_TOLERANCE_EVENT_RECORDED'
] as const;
export type SastRuleBundleCanaryGateReasonCode =
  (typeof SAST_RULE_BUNDLE_CANARY_GATE_REASON_CODES)[number];

export const SAST_RULE_BUNDLE_CANARY_LIMITS = Object.freeze({
  identifierBytes: 512,
  referenceBytes: 2_048,
  maximumCount: 1_000_000_000,
  maximumBytes: Number.MAX_SAFE_INTEGER,
  bucketCardinality: 10_000,
  minimumStandardCompletedScansPerArm: 200,
  minimumStandardObservationMilliseconds: 24 * 60 * 60 * 1_000,
  minimumExpandedCompletedScansPerArm: 1_000,
  minimumExpandedObservationMilliseconds: 48 * 60 * 60 * 1_000,
  maximumFalsePositiveIncreaseBasisPoints: 200,
  maximumScannerFailureRateBasisPoints: 200,
  maximumP95LatencyIncreaseBasisPoints: 2_000,
  maximumCriticalHighVolumeIncreaseBasisPoints: 2_000,
  maximumFastP95LatencyMilliseconds: 600_000,
  maximumDeepP95LatencyMilliseconds: 2_700_000,
  maximumDecisionSequence: 1_000_000,
  requiredPassedSteps: 6
});

export const SAST_RULE_BUNDLE_CANARY_STEP_THRESHOLDS = Object.freeze({
  INTERNAL_CORPUS: 0,
  INTERNAL_REPOSITORIES: 0,
  PERCENT_1: 100,
  PERCENT_5: 500,
  PERCENT_25: 2_500,
  PERCENT_100: 10_000
} satisfies Readonly<Record<SastRuleBundleCanaryStep, number>>);

type Sha256Digest = `sha256:${string}`;
export type SastRuleBundleCanaryCanonicalDigester = (
  canonicalValue: string
) => Sha256Digest;

export interface SastRuleBundleCanaryRolloutInput {
  candidateManifestId: string;
  candidateManifestDigest: Sha256Digest;
  candidateBundleId: string;
  candidateBundleDigest: Sha256Digest;
  baselineManifestId: string;
  baselineManifestDigest: Sha256Digest;
  baselineBundleDigest: Sha256Digest;
  profileId: SastProfileId;
  profileDigest: Sha256Digest;
  promotionEvidenceId: string;
  promotionEvidenceDigest: Sha256Digest;
  canaryTransitionId: string;
  canaryTransitionDigest: Sha256Digest;
  cohortKeyRef: string;
  cohortKeyVersion: string;
  eligibilityPolicyRef: string;
  eligibilityPolicyDigest: Sha256Digest;
  observationSourceRef: string;
  observationSourceDigest: Sha256Digest;
  createdAt: string;
}

export interface SastRuleBundleCanaryRollout
  extends SastRuleBundleCanaryRolloutInput {
  version: typeof SAST_RULE_BUNDLE_CANARY_ROLLOUT_VERSION;
  rolloutId: string;
  progression: readonly SastRuleBundleCanaryStep[];
  immutable: true;
  customerInputAccepted: false;
  repositoryContentStored: false;
  findingContentStored: false;
  secretKeyMaterialStored: false;
  rolloutDigest: Sha256Digest;
}

export interface SastRuleBundleCanaryMembershipInput {
  rolloutId: string;
  rolloutDigest: Sha256Digest;
  tenantId: string;
  repositoryBindingId: string;
  profileId: SastProfileId;
  profileDigest: Sha256Digest;
  eligibilityDecisionId: string;
  eligibilityDecisionDigest: Sha256Digest;
  eligibilityClass: SastRuleBundleCanaryEligibilityClass;
  excluded: boolean;
  exclusionRef: string | null;
  eligibilityPolicyRef: string;
  eligibilityPolicyDigest: Sha256Digest;
  cohortKeyRef: string;
  cohortKeyVersion: string;
  assignmentHmacDigest: Sha256Digest;
  evaluatedAt: string;
}

export interface SastRuleBundleCanaryEligibilityDecisionInput {
  rolloutId: string;
  rolloutDigest: Sha256Digest;
  tenantId: string;
  repositoryBindingId: string;
  profileId: SastProfileId;
  profileDigest: Sha256Digest;
  eligibilityClass: SastRuleBundleCanaryEligibilityClass;
  excluded: boolean;
  exclusionRef: string | null;
  eligibilityPolicyRef: string;
  eligibilityPolicyDigest: Sha256Digest;
  actorRef: string;
  auditRef: string;
  evaluatedAt: string;
}

export interface SastRuleBundleCanaryEligibilityDecision
  extends SastRuleBundleCanaryEligibilityDecisionInput {
  version: typeof SAST_RULE_BUNDLE_CANARY_ELIGIBILITY_VERSION;
  eligibilityDecisionId: string;
  platformManaged: true;
  customerOverrideAccepted: false;
  repositoryContentUsed: false;
  findingOrSeverityUsed: false;
  eligibilityDecisionDigest: Sha256Digest;
}

export interface SastRuleBundleCanaryMembership
  extends SastRuleBundleCanaryMembershipInput {
  version: typeof SAST_RULE_BUNDLE_CANARY_MEMBERSHIP_VERSION;
  membershipId: string;
  bucketBasisPoints: number;
  immutableForRollout: true;
  repositoryContentUsed: false;
  findingOrSeverityUsed: false;
  customerAttributeUsed: false;
  secretKeyMaterialStored: false;
  membershipDigest: Sha256Digest;
}

export interface SastRuleBundleCanaryAssignmentInput {
  rolloutId: string;
  rolloutDigest: Sha256Digest;
  membershipId: string;
  membershipDigest: Sha256Digest;
  tenantId: string;
  repositoryBindingId: string;
  profileId: SastProfileId;
  profileDigest: Sha256Digest;
  eligibilityClass: SastRuleBundleCanaryEligibilityClass;
  excluded: boolean;
  bucketBasisPoints: number;
  step: SastRuleBundleCanaryStep;
  stepHeadDecisionId: string | null;
  stepHeadDecisionDigest: Sha256Digest | null;
  candidateManifestId: string;
  candidateManifestDigest: Sha256Digest;
  candidateBundleDigest: Sha256Digest;
  baselineManifestId: string;
  baselineManifestDigest: Sha256Digest;
  baselineBundleDigest: Sha256Digest;
  evaluatedAt: string;
}

export interface SastRuleBundleCanaryAssignmentReceipt
  extends SastRuleBundleCanaryAssignmentInput {
  version: typeof SAST_RULE_BUNDLE_CANARY_ASSIGNMENT_VERSION;
  assignmentReceiptId: string;
  selection: SastRuleBundleCanarySelection;
  selectedManifestId: string | null;
  selectedManifestDigest: Sha256Digest | null;
  selectedBundleDigest: Sha256Digest | null;
  deterministic: true;
  immutable: true;
  customerOverrideAccepted: false;
  repositoryContentUsed: false;
  findingOrSeverityUsed: false;
  assignmentReceiptDigest: Sha256Digest;
}

export interface SastRuleBundleCanaryScanObservationMeasurements {
  findingCount: number;
  criticalHighFindingCount: number;
  falsePositiveCount: number;
  feedbackEligibleFindingCount: number;
  waiverCount: number;
  suppressionCount: number;
  scannerFailureCount: number;
  scannerTimeoutCount: number;
  eligibleScannerAttemptCount: number;
  artifactRejectionCount: number;
  latencyMilliseconds: number;
  cpuMilliseconds: number;
  peakMemoryBytes: number;
  diskBytes: number;
  incompleteCoverageCount: number;
  publicationDenialCount: number;
  egressDenialCount: number;
  cleanupLagMilliseconds: number;
  quarantineCount: number;
  killSwitchSignalCount: number;
  crossTenantEvents: number;
  secretLeakEvents: number;
  sandboxEscapeEvents: number;
  stalePublicationEvents: number;
  unauthorizedEgressEvents: number;
  missingDestructionEvidenceEvents: number;
  evidencePolicyViolationEvents: number;
  unsignedArtifactExecutionEvents: number;
}

export interface SastRuleBundleCanaryScanObservationInput {
  rolloutId: string;
  rolloutDigest: Sha256Digest;
  step: SastRuleBundleCanaryStep;
  cohortRole: 'CANDIDATE' | 'BASELINE';
  tenantId: string;
  repositoryBindingId: string;
  scanRequestId: string;
  attemptId: string;
  assignmentReceiptId: string | null;
  assignmentReceiptDigest: Sha256Digest | null;
  selectedManifestId: string;
  selectedManifestDigest: Sha256Digest;
  selectedBundleDigest: Sha256Digest;
  profileId: SastProfileId;
  profileDigest: Sha256Digest;
  lane: SastScanLane;
  repositorySizeBucket: SastRuleBundleCanaryRepositorySizeBucket;
  coverageDecisionId: string;
  coverageDecisionDigest: Sha256Digest;
  publicationDecisionId: string;
  publicationDecisionDigest: Sha256Digest;
  observationSourceRef: string;
  observationSourceDigest: Sha256Digest;
  telemetrySourceRef: string;
  telemetrySourceDigest: Sha256Digest;
  startedAt: string;
  completedAt: string;
  coverageComplete: boolean;
  telemetryComplete: boolean;
  measurements: SastRuleBundleCanaryScanObservationMeasurements;
}

export interface SastRuleBundleCanaryScanObservation
  extends SastRuleBundleCanaryScanObservationInput {
  version: typeof SAST_RULE_BUNDLE_CANARY_SCAN_OBSERVATION_VERSION;
  observationId: string;
  terminalScanVerified: true;
  immutablePlanVerified: true;
  sourceOrFindingContentStored: false;
  secretValueStored: false;
  observationDigest: Sha256Digest;
}

export interface SastRuleBundleCanaryStepAggregateMeasurements {
  candidateCompletedScans: number;
  baselineCompletedScans: number;
  candidateFindingCount: number;
  baselineFindingCount: number;
  candidateCriticalHighFindingCount: number;
  baselineCriticalHighFindingCount: number;
  candidateFalsePositiveCount: number;
  candidateFeedbackEligibleFindingCount: number;
  baselineFalsePositiveCount: number;
  baselineFeedbackEligibleFindingCount: number;
  candidateWaiverCount: number;
  baselineWaiverCount: number;
  candidateSuppressionCount: number;
  baselineSuppressionCount: number;
  candidateScannerFailureCount: number;
  candidateEligibleScannerAttemptCount: number;
  baselineScannerFailureCount: number;
  baselineEligibleScannerAttemptCount: number;
  candidateScannerTimeoutCount: number;
  baselineScannerTimeoutCount: number;
  candidateP50LatencyMilliseconds: number;
  candidateP95LatencyMilliseconds: number;
  baselineP50LatencyMilliseconds: number;
  baselineP95LatencyMilliseconds: number;
  candidateP95CpuMilliseconds: number;
  baselineP95CpuMilliseconds: number;
  candidateP95PeakMemoryBytes: number;
  baselineP95PeakMemoryBytes: number;
  candidateP95DiskBytes: number;
  baselineP95DiskBytes: number;
  candidateArtifactRejectionCount: number;
  baselineArtifactRejectionCount: number;
  candidateIncompleteCoverageCount: number;
  baselineIncompleteCoverageCount: number;
  candidatePublicationDenialCount: number;
  baselinePublicationDenialCount: number;
  candidateEgressDenialCount: number;
  baselineEgressDenialCount: number;
  candidateP95CleanupLagMilliseconds: number;
  baselineP95CleanupLagMilliseconds: number;
  candidateQuarantineCount: number;
  baselineQuarantineCount: number;
  candidateKillSwitchSignalCount: number;
  baselineKillSwitchSignalCount: number;
  crossTenantEvents: number;
  secretLeakEvents: number;
  sandboxEscapeEvents: number;
  stalePublicationEvents: number;
  unauthorizedEgressEvents: number;
  missingDestructionEvidenceEvents: number;
  evidencePolicyViolationEvents: number;
  unsignedArtifactExecutionEvents: number;
}

export interface SastRuleBundleCanaryObservationBinding {
  observationId: string;
  observationDigest: Sha256Digest;
}

export interface SastRuleBundleCanaryStepDecisionInput {
  rolloutId: string;
  rolloutDigest: Sha256Digest;
  candidateManifestId: string;
  candidateManifestDigest: Sha256Digest;
  candidateBundleDigest: Sha256Digest;
  baselineManifestId: string;
  baselineManifestDigest: Sha256Digest;
  baselineBundleDigest: Sha256Digest;
  profileId: SastProfileId;
  profileDigest: Sha256Digest;
  sequence: number;
  step: SastRuleBundleCanaryStep;
  previousDecisionId: string | null;
  previousDecisionDigest: Sha256Digest | null;
  windowStartedAt: string;
  windowEndedAt: string;
  observations: SastRuleBundleCanaryObservationBinding[];
  measurements: SastRuleBundleCanaryStepAggregateMeasurements;
  telemetryComplete: boolean;
  allProfileSizeBucketsCompared: boolean;
  evaluatorRef: string;
  auditRef: string;
  evaluatedAt: string;
}

export interface SastRuleBundleCanaryStepDecision
  extends SastRuleBundleCanaryStepDecisionInput {
  version: typeof SAST_RULE_BUNDLE_CANARY_STEP_DECISION_VERSION;
  decisionId: string;
  outcome: SastRuleBundleCanaryStepOutcome;
  reasonCodes: SastRuleBundleCanaryGateReasonCode[];
  observationSetDigest: Sha256Digest;
  thresholdsWaived: false;
  customerInputAccepted: false;
  immutable: true;
  decisionDigest: Sha256Digest;
}

export interface SastRuleBundleCanaryPassedStepBinding {
  step: SastRuleBundleCanaryStep;
  decisionId: string;
  decisionDigest: Sha256Digest;
}

export interface SastRuleBundleCanaryObservationReceiptInput {
  rolloutId: string;
  rolloutDigest: Sha256Digest;
  candidateManifestId: string;
  candidateManifestDigest: Sha256Digest;
  candidateBundleId: string;
  candidateBundleDigest: Sha256Digest;
  baselineManifestId: string;
  baselineManifestDigest: Sha256Digest;
  baselineBundleDigest: Sha256Digest;
  profileId: SastProfileId;
  profileDigest: Sha256Digest;
  promotionEvidenceId: string;
  promotionEvidenceDigest: Sha256Digest;
  passedSteps: SastRuleBundleCanaryPassedStepBinding[];
  observedFrom: string;
  observedThrough: string;
  issuedAt: string;
}

export interface SastRuleBundleCanaryObservationReceipt
  extends SastRuleBundleCanaryObservationReceiptInput {
  version: typeof SAST_RULE_BUNDLE_CANARY_OBSERVATION_RECEIPT_VERSION;
  receiptRef: string;
  everyStepPassed: true;
  thresholdsWaived: false;
  immutable: true;
  repositoryContentStored: false;
  findingContentStored: false;
  receiptDigest: Sha256Digest;
}

export interface VerifiedSastRuleBundleCanaryAssignmentDescriptor {
  rolloutId: string;
  rolloutDigest: Sha256Digest;
  membershipId: string;
  membershipDigest: Sha256Digest;
  bucketBasisPoints: number;
  step: SastRuleBundleCanaryStep;
  stepHeadDecisionId: string | null;
  stepHeadDecisionDigest: Sha256Digest | null;
  assignmentReceiptId: string;
  assignmentReceiptDigest: Sha256Digest;
  candidateAssigned: true;
}

export function buildSastRuleBundleCanaryRollout(
  input: Readonly<SastRuleBundleCanaryRolloutInput>,
  digest: SastRuleBundleCanaryCanonicalDigester
): SastRuleBundleCanaryRollout | null {
  if (!isCanaryRolloutInputValid(input)) return null;
  const core = {
    ...input,
    progression: [...SAST_RULE_BUNDLE_CANARY_STEPS]
  };
  const rolloutDigest = digest(canonicalJson(core));
  const rollout: SastRuleBundleCanaryRollout = {
    ...core,
    version: SAST_RULE_BUNDLE_CANARY_ROLLOUT_VERSION,
    rolloutId: `sast-rule-bundle-canary-rollout://${digestSuffix(rolloutDigest)}`,
    immutable: true,
    customerInputAccepted: false,
    repositoryContentStored: false,
    findingContentStored: false,
    secretKeyMaterialStored: false,
    rolloutDigest
  };
  return isSastRuleBundleCanaryRolloutShapeValid(rollout, digest)
    ? rollout
    : null;
}

export function isSastRuleBundleCanaryRolloutShapeValid(
  value: unknown,
  digest: SastRuleBundleCanaryCanonicalDigester
): value is SastRuleBundleCanaryRollout {
  if (!hasExactKeys(value, CANARY_ROLLOUT_KEYS)) return false;
  const rollout = value as unknown as SastRuleBundleCanaryRollout;
  if (
    rollout.version !== SAST_RULE_BUNDLE_CANARY_ROLLOUT_VERSION ||
    !isCanaryRolloutInputValid(pickCanaryRolloutInput(rollout)) ||
    !hasExactArrayValues(rollout.progression, SAST_RULE_BUNDLE_CANARY_STEPS) ||
    rollout.immutable !== true ||
    rollout.customerInputAccepted !== false ||
    rollout.repositoryContentStored !== false ||
    rollout.findingContentStored !== false ||
    rollout.secretKeyMaterialStored !== false ||
    !isDigestDerivedIdentifier(
      rollout.rolloutId,
      'sast-rule-bundle-canary-rollout://',
      rollout.rolloutDigest
    )
  ) {
    return false;
  }
  const core = {
    ...pickCanaryRolloutInput(rollout),
    progression: [...SAST_RULE_BUNDLE_CANARY_STEPS]
  };
  return rollout.rolloutDigest === digest(canonicalJson(core));
}

export function buildSastRuleBundleCanaryEligibilityDecision(
  input: Readonly<SastRuleBundleCanaryEligibilityDecisionInput>,
  digest: SastRuleBundleCanaryCanonicalDigester
): SastRuleBundleCanaryEligibilityDecision | null {
  if (!isCanaryEligibilityDecisionInputValid(input)) return null;
  const core = structuredClone(input);
  const eligibilityDecisionDigest = digest(canonicalJson(core));
  const decision: SastRuleBundleCanaryEligibilityDecision = {
    ...core,
    version: SAST_RULE_BUNDLE_CANARY_ELIGIBILITY_VERSION,
    eligibilityDecisionId: `sast-rule-bundle-canary-eligibility://${digestSuffix(
      eligibilityDecisionDigest
    )}`,
    platformManaged: true,
    customerOverrideAccepted: false,
    repositoryContentUsed: false,
    findingOrSeverityUsed: false,
    eligibilityDecisionDigest
  };
  return isSastRuleBundleCanaryEligibilityDecisionShapeValid(decision, digest)
    ? decision
    : null;
}

export function isSastRuleBundleCanaryEligibilityDecisionShapeValid(
  value: unknown,
  digest: SastRuleBundleCanaryCanonicalDigester
): value is SastRuleBundleCanaryEligibilityDecision {
  if (!hasExactKeys(value, CANARY_ELIGIBILITY_KEYS)) return false;
  const decision = value as unknown as SastRuleBundleCanaryEligibilityDecision;
  const input = pickCanaryEligibilityInput(decision);
  return (
    decision.version === SAST_RULE_BUNDLE_CANARY_ELIGIBILITY_VERSION &&
    isCanaryEligibilityDecisionInputValid(input) &&
    isDigestDerivedIdentifier(
      decision.eligibilityDecisionId,
      'sast-rule-bundle-canary-eligibility://',
      decision.eligibilityDecisionDigest
    ) &&
    decision.platformManaged === true &&
    decision.customerOverrideAccepted === false &&
    decision.repositoryContentUsed === false &&
    decision.findingOrSeverityUsed === false &&
    decision.eligibilityDecisionDigest === digest(canonicalJson(input))
  );
}

export function buildSastRuleBundleCanaryMembership(
  input: Readonly<SastRuleBundleCanaryMembershipInput>,
  digest: SastRuleBundleCanaryCanonicalDigester
): SastRuleBundleCanaryMembership | null {
  if (!isCanaryMembershipInputValid(input)) return null;
  const bucketBasisPoints = deriveSastCanaryBucketFromHmacDigest(
    input.assignmentHmacDigest
  );
  if (bucketBasisPoints === null) return null;
  const core = { ...input, bucketBasisPoints };
  const membershipDigest = digest(canonicalJson(core));
  const membership: SastRuleBundleCanaryMembership = {
    ...core,
    version: SAST_RULE_BUNDLE_CANARY_MEMBERSHIP_VERSION,
    membershipId: `sast-rule-bundle-canary-membership://${digestSuffix(
      membershipDigest
    )}`,
    immutableForRollout: true,
    repositoryContentUsed: false,
    findingOrSeverityUsed: false,
    customerAttributeUsed: false,
    secretKeyMaterialStored: false,
    membershipDigest
  };
  return isSastRuleBundleCanaryMembershipShapeValid(membership, digest)
    ? membership
    : null;
}

export function isSastRuleBundleCanaryMembershipShapeValid(
  value: unknown,
  digest: SastRuleBundleCanaryCanonicalDigester
): value is SastRuleBundleCanaryMembership {
  if (!hasExactKeys(value, CANARY_MEMBERSHIP_KEYS)) return false;
  const membership = value as unknown as SastRuleBundleCanaryMembership;
  const derivedBucket = deriveSastCanaryBucketFromHmacDigest(
    membership.assignmentHmacDigest
  );
  if (
    membership.version !== SAST_RULE_BUNDLE_CANARY_MEMBERSHIP_VERSION ||
    !isCanaryMembershipInputValid(pickCanaryMembershipInput(membership)) ||
    membership.bucketBasisPoints !== derivedBucket ||
    membership.immutableForRollout !== true ||
    membership.repositoryContentUsed !== false ||
    membership.findingOrSeverityUsed !== false ||
    membership.customerAttributeUsed !== false ||
    membership.secretKeyMaterialStored !== false ||
    !isDigestDerivedIdentifier(
      membership.membershipId,
      'sast-rule-bundle-canary-membership://',
      membership.membershipDigest
    )
  ) {
    return false;
  }
  const core = {
    ...pickCanaryMembershipInput(membership),
    bucketBasisPoints: membership.bucketBasisPoints
  };
  return membership.membershipDigest === digest(canonicalJson(core));
}

export function buildSastRuleBundleCanaryAssignmentReceipt(
  input: Readonly<SastRuleBundleCanaryAssignmentInput>,
  digest: SastRuleBundleCanaryCanonicalDigester
): SastRuleBundleCanaryAssignmentReceipt | null {
  if (!isCanaryAssignmentInputValid(input)) return null;
  const selection = expectedCanarySelection(input);
  const selected =
    selection === 'CANDIDATE'
      ? {
          selectedManifestId: input.candidateManifestId,
          selectedManifestDigest: input.candidateManifestDigest,
          selectedBundleDigest: input.candidateBundleDigest
        }
      : selection === 'BASELINE'
        ? {
            selectedManifestId: input.baselineManifestId,
            selectedManifestDigest: input.baselineManifestDigest,
            selectedBundleDigest: input.baselineBundleDigest
          }
        : {
            selectedManifestId: null,
            selectedManifestDigest: null,
            selectedBundleDigest: null
          };
  const core = { ...input, selection, ...selected };
  const assignmentReceiptDigest = digest(canonicalJson(core));
  const receipt: SastRuleBundleCanaryAssignmentReceipt = {
    ...core,
    version: SAST_RULE_BUNDLE_CANARY_ASSIGNMENT_VERSION,
    assignmentReceiptId: `sast-rule-bundle-canary-assignment://${digestSuffix(
      assignmentReceiptDigest
    )}`,
    deterministic: true,
    immutable: true,
    customerOverrideAccepted: false,
    repositoryContentUsed: false,
    findingOrSeverityUsed: false,
    assignmentReceiptDigest
  };
  return isSastRuleBundleCanaryAssignmentReceiptShapeValid(receipt, digest)
    ? receipt
    : null;
}

export function isSastRuleBundleCanaryAssignmentReceiptShapeValid(
  value: unknown,
  digest: SastRuleBundleCanaryCanonicalDigester
): value is SastRuleBundleCanaryAssignmentReceipt {
  if (!hasExactKeys(value, CANARY_ASSIGNMENT_KEYS)) return false;
  const receipt = value as unknown as SastRuleBundleCanaryAssignmentReceipt;
  const expected = expectedCanarySelection(receipt);
  const selectedMatches =
    expected === 'CANDIDATE'
      ? receipt.selectedManifestId === receipt.candidateManifestId &&
        receipt.selectedManifestDigest === receipt.candidateManifestDigest &&
        receipt.selectedBundleDigest === receipt.candidateBundleDigest
      : expected === 'BASELINE'
        ? receipt.selectedManifestId === receipt.baselineManifestId &&
          receipt.selectedManifestDigest === receipt.baselineManifestDigest &&
          receipt.selectedBundleDigest === receipt.baselineBundleDigest
        : receipt.selectedManifestId === null &&
          receipt.selectedManifestDigest === null &&
          receipt.selectedBundleDigest === null;
  if (
    receipt.version !== SAST_RULE_BUNDLE_CANARY_ASSIGNMENT_VERSION ||
    !isCanaryAssignmentInputValid(pickCanaryAssignmentInput(receipt)) ||
    receipt.selection !== expected ||
    !selectedMatches ||
    receipt.deterministic !== true ||
    receipt.immutable !== true ||
    receipt.customerOverrideAccepted !== false ||
    receipt.repositoryContentUsed !== false ||
    receipt.findingOrSeverityUsed !== false ||
    !isDigestDerivedIdentifier(
      receipt.assignmentReceiptId,
      'sast-rule-bundle-canary-assignment://',
      receipt.assignmentReceiptDigest
    )
  ) {
    return false;
  }
  const core = {
    ...pickCanaryAssignmentInput(receipt),
    selection: receipt.selection,
    selectedManifestId: receipt.selectedManifestId,
    selectedManifestDigest: receipt.selectedManifestDigest,
    selectedBundleDigest: receipt.selectedBundleDigest
  };
  return receipt.assignmentReceiptDigest === digest(canonicalJson(core));
}

export function buildSastRuleBundleCanaryScanObservation(
  input: Readonly<SastRuleBundleCanaryScanObservationInput>,
  digest: SastRuleBundleCanaryCanonicalDigester
): SastRuleBundleCanaryScanObservation | null {
  if (!isCanaryScanObservationInputValid(input)) return null;
  const core = structuredClone(input);
  const observationDigest = digest(canonicalJson(core));
  const observation: SastRuleBundleCanaryScanObservation = {
    ...core,
    version: SAST_RULE_BUNDLE_CANARY_SCAN_OBSERVATION_VERSION,
    observationId: `sast-rule-bundle-canary-observation://${digestSuffix(
      observationDigest
    )}`,
    terminalScanVerified: true,
    immutablePlanVerified: true,
    sourceOrFindingContentStored: false,
    secretValueStored: false,
    observationDigest
  };
  return isSastRuleBundleCanaryScanObservationShapeValid(observation, digest)
    ? observation
    : null;
}

export function isSastRuleBundleCanaryScanObservationShapeValid(
  value: unknown,
  digest: SastRuleBundleCanaryCanonicalDigester
): value is SastRuleBundleCanaryScanObservation {
  if (!hasExactKeys(value, CANARY_OBSERVATION_KEYS)) return false;
  const observation = value as unknown as SastRuleBundleCanaryScanObservation;
  if (
    observation.version !== SAST_RULE_BUNDLE_CANARY_SCAN_OBSERVATION_VERSION ||
    !isCanaryScanObservationInputValid(
      pickCanaryObservationInput(observation)
    ) ||
    observation.terminalScanVerified !== true ||
    observation.immutablePlanVerified !== true ||
    typeof observation.coverageComplete !== 'boolean' ||
    typeof observation.telemetryComplete !== 'boolean' ||
    observation.sourceOrFindingContentStored !== false ||
    observation.secretValueStored !== false ||
    !isDigestDerivedIdentifier(
      observation.observationId,
      'sast-rule-bundle-canary-observation://',
      observation.observationDigest
    )
  ) {
    return false;
  }
  return (
    observation.observationDigest ===
    digest(canonicalJson(pickCanaryObservationInput(observation)))
  );
}

export function findSastRuleBundleCanaryGateReasonCodes(
  input: Readonly<SastRuleBundleCanaryStepDecisionInput>
): SastRuleBundleCanaryGateReasonCode[] {
  if (!isCanaryStepDecisionInputValid(input)) {
    return [
      'TELEMETRY_MISSING',
      'PROFILE_SIZE_COMPARISON_INCOMPLETE'
    ];
  }
  const reasons: SastRuleBundleCanaryGateReasonCode[] = [];
  const expanded = input.step === 'PERCENT_25' || input.step === 'PERCENT_100';
  const minimumScans = expanded
    ? SAST_RULE_BUNDLE_CANARY_LIMITS.minimumExpandedCompletedScansPerArm
    : SAST_RULE_BUNDLE_CANARY_LIMITS.minimumStandardCompletedScansPerArm;
  const minimumDuration = expanded
    ? SAST_RULE_BUNDLE_CANARY_LIMITS.minimumExpandedObservationMilliseconds
    : SAST_RULE_BUNDLE_CANARY_LIMITS.minimumStandardObservationMilliseconds;
  const duration = Date.parse(input.windowEndedAt) - Date.parse(input.windowStartedAt);
  const measurements = input.measurements;
  if (duration < minimumDuration) reasons.push('OBSERVATION_WINDOW_INSUFFICIENT');
  if (measurements.candidateCompletedScans < minimumScans) {
    reasons.push('CANDIDATE_SAMPLE_INSUFFICIENT');
  }
  if (measurements.baselineCompletedScans < minimumScans) {
    reasons.push('BASELINE_SAMPLE_INSUFFICIENT');
  }
  if (!input.telemetryComplete) reasons.push('TELEMETRY_MISSING');
  if (
    measurements.candidateIncompleteCoverageCount !== 0 ||
    measurements.baselineIncompleteCoverageCount !== 0
  ) {
    reasons.push('COVERAGE_INCOMPLETE');
  }
  if (!input.allProfileSizeBucketsCompared) {
    reasons.push('PROFILE_SIZE_COMPARISON_INCOMPLETE');
  }
  if (
    !rateIncreaseAtMost(
      measurements.candidateFalsePositiveCount,
      measurements.candidateFeedbackEligibleFindingCount,
      measurements.baselineFalsePositiveCount,
      measurements.baselineFeedbackEligibleFindingCount,
      SAST_RULE_BUNDLE_CANARY_LIMITS.maximumFalsePositiveIncreaseBasisPoints
    )
  ) {
    reasons.push('FALSE_POSITIVE_GATE_FAILED');
  }
  if (
    !ratioAtMost(
      measurements.candidateScannerFailureCount,
      measurements.candidateEligibleScannerAttemptCount,
      SAST_RULE_BUNDLE_CANARY_LIMITS.maximumScannerFailureRateBasisPoints
    )
  ) {
    reasons.push('SCANNER_FAILURE_GATE_FAILED');
  }
  const maximumP95 =
    input.profileId === 'JAVA_FAST_V1'
      ? SAST_RULE_BUNDLE_CANARY_LIMITS.maximumFastP95LatencyMilliseconds
      : SAST_RULE_BUNDLE_CANARY_LIMITS.maximumDeepP95LatencyMilliseconds;
  if (
    measurements.candidateP95LatencyMilliseconds > maximumP95 ||
    !relativeIncreaseAtMost(
      measurements.candidateP95LatencyMilliseconds,
      measurements.baselineP95LatencyMilliseconds,
      SAST_RULE_BUNDLE_CANARY_LIMITS.maximumP95LatencyIncreaseBasisPoints
    )
  ) {
    reasons.push('LATENCY_GATE_FAILED');
  }
  if (
    !relativeRateIncreaseAtMost(
      measurements.candidateCriticalHighFindingCount,
      measurements.candidateCompletedScans,
      measurements.baselineCriticalHighFindingCount,
      measurements.baselineCompletedScans,
      SAST_RULE_BUNDLE_CANARY_LIMITS.maximumCriticalHighVolumeIncreaseBasisPoints
    )
  ) {
    reasons.push('CRITICAL_HIGH_VOLUME_GATE_FAILED');
  }
  if (zeroToleranceEventCount(measurements) !== 0) {
    reasons.push('ZERO_TOLERANCE_EVENT_RECORDED');
  }
  return reasons;
}

export function buildSastRuleBundleCanaryStepDecision(
  input: Readonly<SastRuleBundleCanaryStepDecisionInput>,
  digest: SastRuleBundleCanaryCanonicalDigester
): SastRuleBundleCanaryStepDecision | null {
  if (!isCanaryStepDecisionInputValid(input)) return null;
  const reasonCodes = findSastRuleBundleCanaryGateReasonCodes(input);
  const hardFailure = reasonCodes.some((reason) =>
    CANARY_PAUSE_REASONS.includes(reason)
  );
  const outcome: SastRuleBundleCanaryStepOutcome =
    reasonCodes.length === 0 ? 'PASSED' : hardFailure ? 'PAUSED' : 'PENDING';
  const observationSetDigest = digest(
    canonicalJson(input.observations)
  );
  const core = {
    ...input,
    observations: input.observations.map((binding) => ({ ...binding })),
    measurements: { ...input.measurements },
    outcome,
    reasonCodes,
    observationSetDigest
  };
  const decisionDigest = digest(canonicalJson(core));
  const decision: SastRuleBundleCanaryStepDecision = {
    ...core,
    version: SAST_RULE_BUNDLE_CANARY_STEP_DECISION_VERSION,
    decisionId: `sast-rule-bundle-canary-step-decision://${digestSuffix(
      decisionDigest
    )}`,
    thresholdsWaived: false,
    customerInputAccepted: false,
    immutable: true,
    decisionDigest
  };
  return isSastRuleBundleCanaryStepDecisionShapeValid(decision, digest)
    ? decision
    : null;
}

export function isSastRuleBundleCanaryStepDecisionShapeValid(
  value: unknown,
  digest: SastRuleBundleCanaryCanonicalDigester
): value is SastRuleBundleCanaryStepDecision {
  if (!hasExactKeys(value, CANARY_STEP_DECISION_KEYS)) return false;
  const decision = value as unknown as SastRuleBundleCanaryStepDecision;
  const decisionInput = pickCanaryStepDecisionInput(decision);
  const reasons = findSastRuleBundleCanaryGateReasonCodes(decisionInput);
  const hardFailure = reasons.some((reason) => CANARY_PAUSE_REASONS.includes(reason));
  const expectedOutcome: SastRuleBundleCanaryStepOutcome =
    reasons.length === 0 ? 'PASSED' : hardFailure ? 'PAUSED' : 'PENDING';
  if (
    decision.version !== SAST_RULE_BUNDLE_CANARY_STEP_DECISION_VERSION ||
    !isCanaryStepDecisionInputValid(decisionInput) ||
    decision.outcome !== expectedOutcome ||
    !hasExactArrayValues(decision.reasonCodes, reasons) ||
    decision.observationSetDigest !== digest(canonicalJson(decision.observations)) ||
    decision.thresholdsWaived !== false ||
    decision.customerInputAccepted !== false ||
    decision.immutable !== true ||
    !isDigestDerivedIdentifier(
      decision.decisionId,
      'sast-rule-bundle-canary-step-decision://',
      decision.decisionDigest
    )
  ) {
    return false;
  }
  const core = {
    ...pickCanaryStepDecisionInput(decision),
    outcome: decision.outcome,
    reasonCodes: [...decision.reasonCodes],
    observationSetDigest: decision.observationSetDigest
  };
  return decision.decisionDigest === digest(canonicalJson(core));
}

export function buildSastRuleBundleCanaryObservationReceipt(
  input: Readonly<SastRuleBundleCanaryObservationReceiptInput>,
  digest: SastRuleBundleCanaryCanonicalDigester
): SastRuleBundleCanaryObservationReceipt | null {
  if (!isCanaryObservationReceiptInputValid(input)) return null;
  const core = {
    ...input,
    passedSteps: input.passedSteps.map((binding) => ({ ...binding }))
  };
  const receiptDigest = digest(canonicalJson(core));
  const receipt: SastRuleBundleCanaryObservationReceipt = {
    ...core,
    version: SAST_RULE_BUNDLE_CANARY_OBSERVATION_RECEIPT_VERSION,
    receiptRef: `sast-rule-bundle-canary-observation-receipt://${receiptDigest}`,
    everyStepPassed: true,
    thresholdsWaived: false,
    immutable: true,
    repositoryContentStored: false,
    findingContentStored: false,
    receiptDigest
  };
  return isSastRuleBundleCanaryObservationReceiptShapeValid(receipt, digest)
    ? receipt
    : null;
}

export function isSastRuleBundleCanaryObservationReceiptShapeValid(
  value: unknown,
  digest: SastRuleBundleCanaryCanonicalDigester
): value is SastRuleBundleCanaryObservationReceipt {
  if (!hasExactKeys(value, CANARY_OBSERVATION_RECEIPT_KEYS)) return false;
  const receipt = value as unknown as SastRuleBundleCanaryObservationReceipt;
  if (
    receipt.version !== SAST_RULE_BUNDLE_CANARY_OBSERVATION_RECEIPT_VERSION ||
    !isCanaryObservationReceiptInputValid(
      pickCanaryObservationReceiptInput(receipt)
    ) ||
    receipt.receiptRef !==
      `sast-rule-bundle-canary-observation-receipt://${receipt.receiptDigest}` ||
    receipt.everyStepPassed !== true ||
    receipt.thresholdsWaived !== false ||
    receipt.immutable !== true ||
    receipt.repositoryContentStored !== false ||
    receipt.findingContentStored !== false
  ) {
    return false;
  }
  return (
    receipt.receiptDigest ===
    digest(canonicalJson(pickCanaryObservationReceiptInput(receipt)))
  );
}

export function toVerifiedSastRuleBundleCanaryAssignmentDescriptor(
  membership: Readonly<SastRuleBundleCanaryMembership>,
  assignment: Readonly<SastRuleBundleCanaryAssignmentReceipt>
): VerifiedSastRuleBundleCanaryAssignmentDescriptor | null {
  if (
    assignment.selection !== 'CANDIDATE' ||
    assignment.rolloutId !== membership.rolloutId ||
    assignment.rolloutDigest !== membership.rolloutDigest ||
    assignment.membershipId !== membership.membershipId ||
    assignment.membershipDigest !== membership.membershipDigest ||
    assignment.bucketBasisPoints !== membership.bucketBasisPoints
  ) {
    return null;
  }
  return {
    rolloutId: assignment.rolloutId,
    rolloutDigest: assignment.rolloutDigest,
    membershipId: assignment.membershipId,
    membershipDigest: assignment.membershipDigest,
    bucketBasisPoints: assignment.bucketBasisPoints,
    step: assignment.step,
    stepHeadDecisionId: assignment.stepHeadDecisionId,
    stepHeadDecisionDigest: assignment.stepHeadDecisionDigest,
    assignmentReceiptId: assignment.assignmentReceiptId,
    assignmentReceiptDigest: assignment.assignmentReceiptDigest,
    candidateAssigned: true
  };
}

export function isVerifiedSastRuleBundleCanaryAssignmentDescriptorValid(
  value: unknown
): value is VerifiedSastRuleBundleCanaryAssignmentDescriptor {
  if (!hasExactKeys(value, VERIFIED_CANARY_ASSIGNMENT_DESCRIPTOR_KEYS)) {
    return false;
  }
  const descriptor =
    value as unknown as VerifiedSastRuleBundleCanaryAssignmentDescriptor;
  return (
    isDigestDerivedIdentifier(
      descriptor.rolloutId,
      'sast-rule-bundle-canary-rollout://',
      descriptor.rolloutDigest
    ) &&
    isDigestDerivedIdentifier(
      descriptor.membershipId,
      'sast-rule-bundle-canary-membership://',
      descriptor.membershipDigest
    ) &&
    isCount(descriptor.bucketBasisPoints) &&
    descriptor.bucketBasisPoints <
      SAST_RULE_BUNDLE_CANARY_LIMITS.bucketCardinality &&
    SAST_RULE_BUNDLE_CANARY_STEPS.includes(descriptor.step) &&
    isOptionalDigestPair(
      descriptor.stepHeadDecisionId,
      descriptor.stepHeadDecisionDigest,
      'sast-rule-bundle-canary-step-decision://'
    ) &&
    isDigestDerivedIdentifier(
      descriptor.assignmentReceiptId,
      'sast-rule-bundle-canary-assignment://',
      descriptor.assignmentReceiptDigest
    ) &&
    descriptor.candidateAssigned === true
  );
}

export function buildSastCanaryMembershipHmacPreimage(input: {
  tenantId: string;
  repositoryBindingId: string;
  profileId: SastProfileId;
  rolloutId: string;
}): string | null {
  if (
    !isOpaqueIdentifier(input.tenantId) ||
    !isOpaqueIdentifier(input.repositoryBindingId) ||
    !isProfileId(input.profileId) ||
    !isOpaqueIdentifier(input.rolloutId)
  ) {
    return null;
  }
  return [
    'sast-rule-bundle-canary-membership-hmac-v1',
    frame(input.tenantId),
    frame(input.repositoryBindingId),
    frame(input.profileId),
    frame(input.rolloutId)
  ].join('|');
}

export function deriveSastCanaryBucketFromHmacDigest(
  digest: unknown
): number | null {
  if (!isDigest(digest)) return null;
  const prefix = digest.slice('sha256:'.length, 'sha256:'.length + 16);
  try {
    return Number(BigInt(`0x${prefix}`) % BigInt(SAST_RULE_BUNDLE_CANARY_LIMITS.bucketCardinality));
  } catch {
    return null;
  }
}

export function nextSastRuleBundleCanaryStep(
  step: SastRuleBundleCanaryStep
): SastRuleBundleCanaryStep | null {
  const index = SAST_RULE_BUNDLE_CANARY_STEPS.indexOf(step);
  return index < 0 || index === SAST_RULE_BUNDLE_CANARY_STEPS.length - 1
    ? null
    : (SAST_RULE_BUNDLE_CANARY_STEPS[index + 1] ?? null);
}

function expectedCanarySelection(
  input: Readonly<SastRuleBundleCanaryAssignmentInput>
): SastRuleBundleCanarySelection {
  if (input.excluded) return 'EXCLUDED';
  if (input.eligibilityClass === 'INTERNAL_CORPUS') return 'CANDIDATE';
  if (
    input.eligibilityClass === 'INTERNAL_REPOSITORY' &&
    input.step !== 'INTERNAL_CORPUS'
  ) {
    return 'CANDIDATE';
  }
  if (
    input.eligibilityClass === 'ELIGIBLE_PRODUCTION' &&
    input.step !== 'INTERNAL_CORPUS' &&
    input.step !== 'INTERNAL_REPOSITORIES' &&
    input.bucketBasisPoints < SAST_RULE_BUNDLE_CANARY_STEP_THRESHOLDS[input.step]
  ) {
    return 'CANDIDATE';
  }
  return 'BASELINE';
}

function isCanaryRolloutInputValid(
  value: unknown
): value is SastRuleBundleCanaryRolloutInput {
  if (!hasExactKeys(value, CANARY_ROLLOUT_INPUT_KEYS)) return false;
  const input = value as unknown as SastRuleBundleCanaryRolloutInput;
  return (
    isOpaqueIdentifier(input.candidateManifestId) &&
    isDigest(input.candidateManifestDigest) &&
    isOpaqueIdentifier(input.candidateBundleId) &&
    isDigest(input.candidateBundleDigest) &&
    isOpaqueIdentifier(input.baselineManifestId) &&
    input.baselineManifestId !== input.candidateManifestId &&
    isDigest(input.baselineManifestDigest) &&
    input.baselineManifestDigest !== input.candidateManifestDigest &&
    isDigest(input.baselineBundleDigest) &&
    input.baselineBundleDigest !== input.candidateBundleDigest &&
    isProfileId(input.profileId) &&
    isDigest(input.profileDigest) &&
    isDigestDerivedIdentifier(
      input.promotionEvidenceId,
      'sast-rule-bundle-promotion-evidence://',
      input.promotionEvidenceDigest
    ) &&
    isDigestDerivedIdentifier(
      input.canaryTransitionId,
      'sast-rule-bundle-lifecycle-transition://',
      input.canaryTransitionDigest
    ) &&
    isDigestBoundReference(input.cohortKeyRef) &&
    isOpaqueIdentifier(input.cohortKeyVersion) &&
    isDigestBoundReference(input.eligibilityPolicyRef) &&
    isDigest(input.eligibilityPolicyDigest) &&
    input.eligibilityPolicyRef.endsWith(input.eligibilityPolicyDigest) &&
    isDigestBoundReference(input.observationSourceRef) &&
    isDigest(input.observationSourceDigest) &&
    input.observationSourceRef.endsWith(input.observationSourceDigest) &&
    isIsoInstant(input.createdAt)
  );
}

function isCanaryMembershipInputValid(
  value: unknown
): value is SastRuleBundleCanaryMembershipInput {
  if (!hasExactKeys(value, CANARY_MEMBERSHIP_INPUT_KEYS)) return false;
  const input = value as unknown as SastRuleBundleCanaryMembershipInput;
  return (
    isDigestDerivedIdentifier(
      input.rolloutId,
      'sast-rule-bundle-canary-rollout://',
      input.rolloutDigest
    ) &&
    isOpaqueIdentifier(input.tenantId) &&
    isOpaqueIdentifier(input.repositoryBindingId) &&
    isProfileId(input.profileId) &&
    isDigest(input.profileDigest) &&
    isDigestDerivedIdentifier(
      input.eligibilityDecisionId,
      'sast-rule-bundle-canary-eligibility://',
      input.eligibilityDecisionDigest
    ) &&
    SAST_RULE_BUNDLE_CANARY_ELIGIBILITY_CLASSES.includes(
      input.eligibilityClass
    ) &&
    typeof input.excluded === 'boolean' &&
    (input.excluded
      ? isDigestBoundReference(input.exclusionRef)
      : input.exclusionRef === null) &&
    isDigestBoundReference(input.eligibilityPolicyRef) &&
    isDigest(input.eligibilityPolicyDigest) &&
    input.eligibilityPolicyRef.endsWith(input.eligibilityPolicyDigest) &&
    isDigestBoundReference(input.cohortKeyRef) &&
    isOpaqueIdentifier(input.cohortKeyVersion) &&
    isDigest(input.assignmentHmacDigest) &&
    isIsoInstant(input.evaluatedAt)
  );
}

function isCanaryEligibilityDecisionInputValid(
  value: unknown
): value is SastRuleBundleCanaryEligibilityDecisionInput {
  if (!hasExactKeys(value, CANARY_ELIGIBILITY_INPUT_KEYS)) return false;
  const input =
    value as unknown as SastRuleBundleCanaryEligibilityDecisionInput;
  return (
    isDigestDerivedIdentifier(
      input.rolloutId,
      'sast-rule-bundle-canary-rollout://',
      input.rolloutDigest
    ) &&
    isOpaqueIdentifier(input.tenantId) &&
    isOpaqueIdentifier(input.repositoryBindingId) &&
    isProfileId(input.profileId) &&
    isDigest(input.profileDigest) &&
    SAST_RULE_BUNDLE_CANARY_ELIGIBILITY_CLASSES.includes(
      input.eligibilityClass
    ) &&
    typeof input.excluded === 'boolean' &&
    (input.excluded
      ? isDigestBoundReference(input.exclusionRef)
      : input.exclusionRef === null) &&
    isDigestBoundReference(input.eligibilityPolicyRef) &&
    isDigest(input.eligibilityPolicyDigest) &&
    input.eligibilityPolicyRef.endsWith(input.eligibilityPolicyDigest) &&
    isActorReference(input.actorRef) &&
    isDigestBoundReference(input.auditRef) &&
    isIsoInstant(input.evaluatedAt)
  );
}

function isCanaryAssignmentInputValid(
  value: unknown
): value is SastRuleBundleCanaryAssignmentInput {
  if (!hasExactKeys(value, CANARY_ASSIGNMENT_INPUT_KEYS)) return false;
  const input = value as unknown as SastRuleBundleCanaryAssignmentInput;
  return (
    isDigestDerivedIdentifier(
      input.rolloutId,
      'sast-rule-bundle-canary-rollout://',
      input.rolloutDigest
    ) &&
    isDigestDerivedIdentifier(
      input.membershipId,
      'sast-rule-bundle-canary-membership://',
      input.membershipDigest
    ) &&
    isOpaqueIdentifier(input.tenantId) &&
    isOpaqueIdentifier(input.repositoryBindingId) &&
    isProfileId(input.profileId) &&
    isDigest(input.profileDigest) &&
    SAST_RULE_BUNDLE_CANARY_ELIGIBILITY_CLASSES.includes(
      input.eligibilityClass
    ) &&
    typeof input.excluded === 'boolean' &&
    isCount(input.bucketBasisPoints) &&
    input.bucketBasisPoints < SAST_RULE_BUNDLE_CANARY_LIMITS.bucketCardinality &&
    SAST_RULE_BUNDLE_CANARY_STEPS.includes(input.step) &&
    isOptionalDigestPair(
      input.stepHeadDecisionId,
      input.stepHeadDecisionDigest,
      'sast-rule-bundle-canary-step-decision://'
    ) &&
    isOpaqueIdentifier(input.candidateManifestId) &&
    isDigest(input.candidateManifestDigest) &&
    isDigest(input.candidateBundleDigest) &&
    isOpaqueIdentifier(input.baselineManifestId) &&
    input.baselineManifestId !== input.candidateManifestId &&
    isDigest(input.baselineManifestDigest) &&
    isDigest(input.baselineBundleDigest) &&
    input.baselineBundleDigest !== input.candidateBundleDigest &&
    isIsoInstant(input.evaluatedAt)
  );
}

function isCanaryScanObservationInputValid(
  value: unknown
): value is SastRuleBundleCanaryScanObservationInput {
  if (!hasExactKeys(value, CANARY_OBSERVATION_INPUT_KEYS)) return false;
  const input = value as unknown as SastRuleBundleCanaryScanObservationInput;
  const candidateAssignmentValid =
    input.cohortRole === 'CANDIDATE'
      ? isDigestDerivedIdentifier(
          input.assignmentReceiptId,
          'sast-rule-bundle-canary-assignment://',
          input.assignmentReceiptDigest
        )
      : input.assignmentReceiptId === null &&
        input.assignmentReceiptDigest === null;
  return (
    isDigestDerivedIdentifier(
      input.rolloutId,
      'sast-rule-bundle-canary-rollout://',
      input.rolloutDigest
    ) &&
    SAST_RULE_BUNDLE_CANARY_STEPS.includes(input.step) &&
    (input.cohortRole === 'CANDIDATE' || input.cohortRole === 'BASELINE') &&
    isOpaqueIdentifier(input.tenantId) &&
    isOpaqueIdentifier(input.repositoryBindingId) &&
    isOpaqueIdentifier(input.scanRequestId) &&
    isOpaqueIdentifier(input.attemptId) &&
    candidateAssignmentValid &&
    isOpaqueIdentifier(input.selectedManifestId) &&
    isDigest(input.selectedManifestDigest) &&
    isDigest(input.selectedBundleDigest) &&
    isProfileId(input.profileId) &&
    isDigest(input.profileDigest) &&
    (input.lane === 'FAST' || input.lane === 'DEEP') &&
    SAST_RULE_BUNDLE_CANARY_REPOSITORY_SIZE_BUCKETS.includes(
      input.repositorySizeBucket
    ) &&
    isOpaqueIdentifier(input.coverageDecisionId) &&
    isDigest(input.coverageDecisionDigest) &&
    isOpaqueIdentifier(input.publicationDecisionId) &&
    isDigest(input.publicationDecisionDigest) &&
    isDigestBoundReference(input.observationSourceRef) &&
    isDigest(input.observationSourceDigest) &&
    input.observationSourceRef.endsWith(input.observationSourceDigest) &&
    isDigestBoundReference(input.telemetrySourceRef) &&
    isDigest(input.telemetrySourceDigest) &&
    input.telemetrySourceRef.endsWith(input.telemetrySourceDigest) &&
    isIsoInstant(input.startedAt) &&
    isIsoInstant(input.completedAt) &&
    Date.parse(input.completedAt) >= Date.parse(input.startedAt) &&
    typeof input.coverageComplete === 'boolean' &&
    typeof input.telemetryComplete === 'boolean' &&
    isCanaryObservationMeasurementsValid(input.measurements) &&
    input.measurements.incompleteCoverageCount ===
      (input.coverageComplete ? 0 : 1)
  );
}

function isCanaryStepDecisionInputValid(
  value: unknown
): value is SastRuleBundleCanaryStepDecisionInput {
  if (!hasExactKeys(value, CANARY_STEP_DECISION_INPUT_KEYS)) return false;
  const input = value as unknown as SastRuleBundleCanaryStepDecisionInput;
  return (
    isDigestDerivedIdentifier(
      input.rolloutId,
      'sast-rule-bundle-canary-rollout://',
      input.rolloutDigest
    ) &&
    isOpaqueIdentifier(input.candidateManifestId) &&
    isDigest(input.candidateManifestDigest) &&
    isDigest(input.candidateBundleDigest) &&
    isOpaqueIdentifier(input.baselineManifestId) &&
    isDigest(input.baselineManifestDigest) &&
    isDigest(input.baselineBundleDigest) &&
    isProfileId(input.profileId) &&
    isDigest(input.profileDigest) &&
    Number.isInteger(input.sequence) &&
    input.sequence >= 1 &&
    input.sequence <= SAST_RULE_BUNDLE_CANARY_LIMITS.maximumDecisionSequence &&
    SAST_RULE_BUNDLE_CANARY_STEPS.includes(input.step) &&
    isPreviousDecisionBindingValid(input) &&
    isIsoInstant(input.windowStartedAt) &&
    isIsoInstant(input.windowEndedAt) &&
    Date.parse(input.windowEndedAt) >= Date.parse(input.windowStartedAt) &&
    isCanonicalObservationBindings(input.observations) &&
    isCanaryStepAggregateMeasurementsValid(input.measurements) &&
    typeof input.telemetryComplete === 'boolean' &&
    typeof input.allProfileSizeBucketsCompared === 'boolean' &&
    isActorReference(input.evaluatorRef) &&
    isDigestBoundReference(input.auditRef) &&
    isIsoInstant(input.evaluatedAt) &&
    input.evaluatedAt === input.windowEndedAt
  );
}

function isCanaryObservationReceiptInputValid(
  value: unknown
): value is SastRuleBundleCanaryObservationReceiptInput {
  if (!hasExactKeys(value, CANARY_OBSERVATION_RECEIPT_INPUT_KEYS)) return false;
  const input = value as unknown as SastRuleBundleCanaryObservationReceiptInput;
  return (
    isDigestDerivedIdentifier(
      input.rolloutId,
      'sast-rule-bundle-canary-rollout://',
      input.rolloutDigest
    ) &&
    isOpaqueIdentifier(input.candidateManifestId) &&
    isDigest(input.candidateManifestDigest) &&
    isOpaqueIdentifier(input.candidateBundleId) &&
    isDigest(input.candidateBundleDigest) &&
    isOpaqueIdentifier(input.baselineManifestId) &&
    isDigest(input.baselineManifestDigest) &&
    isDigest(input.baselineBundleDigest) &&
    isProfileId(input.profileId) &&
    isDigest(input.profileDigest) &&
    isDigestDerivedIdentifier(
      input.promotionEvidenceId,
      'sast-rule-bundle-promotion-evidence://',
      input.promotionEvidenceDigest
    ) &&
    isCompletePassedStepBindings(input.passedSteps) &&
    isIsoInstant(input.observedFrom) &&
    isIsoInstant(input.observedThrough) &&
    isIsoInstant(input.issuedAt) &&
    Date.parse(input.observedThrough) >= Date.parse(input.observedFrom) &&
    Date.parse(input.issuedAt) >= Date.parse(input.observedThrough)
  );
}

function isCanaryObservationMeasurementsValid(value: unknown): boolean {
  if (!hasExactKeys(value, CANARY_OBSERVATION_MEASUREMENT_KEYS)) return false;
  const measurements =
    value as unknown as SastRuleBundleCanaryScanObservationMeasurements;
  return Object.values(measurements).every(isBoundedNonNegativeInteger) &&
    measurements.criticalHighFindingCount <= measurements.findingCount &&
    measurements.feedbackEligibleFindingCount <= measurements.findingCount &&
    measurements.falsePositiveCount <= measurements.feedbackEligibleFindingCount &&
    measurements.waiverCount <= measurements.findingCount &&
    measurements.suppressionCount <= measurements.findingCount &&
    measurements.incompleteCoverageCount <= 1 &&
    measurements.publicationDenialCount <= 1 &&
    measurements.scannerFailureCount <= measurements.eligibleScannerAttemptCount &&
    measurements.scannerTimeoutCount <= measurements.scannerFailureCount;
}

function isCanaryStepAggregateMeasurementsValid(value: unknown): boolean {
  if (!hasExactKeys(value, CANARY_STEP_AGGREGATE_MEASUREMENT_KEYS)) return false;
  const measurements =
    value as unknown as SastRuleBundleCanaryStepAggregateMeasurements;
  return (
    Object.values(measurements).every(isBoundedNonNegativeInteger) &&
    measurements.candidateFalsePositiveCount <=
      measurements.candidateFeedbackEligibleFindingCount &&
    measurements.baselineFalsePositiveCount <=
      measurements.baselineFeedbackEligibleFindingCount &&
    measurements.candidateScannerFailureCount <=
      measurements.candidateEligibleScannerAttemptCount &&
    measurements.baselineScannerFailureCount <=
      measurements.baselineEligibleScannerAttemptCount &&
    measurements.candidateScannerTimeoutCount <=
      measurements.candidateScannerFailureCount &&
    measurements.baselineScannerTimeoutCount <=
      measurements.baselineScannerFailureCount
  );
}

function isCanonicalObservationBindings(value: unknown): value is SastRuleBundleCanaryObservationBinding[] {
  if (!Array.isArray(value) || value.length === 0) return false;
  const keys = value.map((binding) => {
    if (
      !hasExactKeys(binding, CANARY_OBSERVATION_BINDING_KEYS) ||
      !isDigestDerivedIdentifier(
        binding.observationId,
        'sast-rule-bundle-canary-observation://',
        binding.observationDigest
      )
    ) {
      return null;
    }
    return `${binding.observationId}:${binding.observationDigest}`;
  });
  return (
    keys.every((key): key is string => key !== null) &&
    new Set(keys).size === keys.length &&
    keys.every((key, index) => index === 0 || (keys[index - 1] as string) < key)
  );
}

function isCompletePassedStepBindings(value: unknown): value is SastRuleBundleCanaryPassedStepBinding[] {
  if (!Array.isArray(value) || value.length !== SAST_RULE_BUNDLE_CANARY_LIMITS.requiredPassedSteps) {
    return false;
  }
  return value.every(
    (binding, index) =>
      hasExactKeys(binding, CANARY_PASSED_STEP_BINDING_KEYS) &&
      binding.step === SAST_RULE_BUNDLE_CANARY_STEPS[index] &&
      isDigestDerivedIdentifier(
        binding.decisionId,
        'sast-rule-bundle-canary-step-decision://',
        binding.decisionDigest
      )
  );
}

function isPreviousDecisionBindingValid(input: {
  sequence: number;
  previousDecisionId: unknown;
  previousDecisionDigest: unknown;
}): boolean {
  return input.sequence === 1
    ? input.previousDecisionId === null && input.previousDecisionDigest === null
    : isDigestDerivedIdentifier(
        input.previousDecisionId,
        'sast-rule-bundle-canary-step-decision://',
        input.previousDecisionDigest
      );
}

function zeroToleranceEventCount(
  measurements: Readonly<SastRuleBundleCanaryStepAggregateMeasurements>
): number {
  return (
    measurements.crossTenantEvents +
    measurements.secretLeakEvents +
    measurements.sandboxEscapeEvents +
    measurements.stalePublicationEvents +
    measurements.unauthorizedEgressEvents +
    measurements.missingDestructionEvidenceEvents +
    measurements.evidencePolicyViolationEvents +
    measurements.unsignedArtifactExecutionEvents
  );
}

function ratioAtMost(
  numerator: number,
  denominator: number,
  maximumBasisPoints: number
): boolean {
  return (
    denominator > 0 &&
    BigInt(numerator) * 10_000n <=
      BigInt(maximumBasisPoints) * BigInt(denominator)
  );
}

function rateIncreaseAtMost(
  candidateNumerator: number,
  candidateDenominator: number,
  baselineNumerator: number,
  baselineDenominator: number,
  maximumIncreaseBasisPoints: number
): boolean {
  if (candidateDenominator <= 0 || baselineDenominator <= 0) return false;
  const candidateRateNumerator =
    BigInt(candidateNumerator) * BigInt(baselineDenominator);
  const baselineRateNumerator =
    BigInt(baselineNumerator) * BigInt(candidateDenominator);
  return (
    (candidateRateNumerator - baselineRateNumerator) * 10_000n <=
    BigInt(maximumIncreaseBasisPoints) *
      BigInt(candidateDenominator) *
      BigInt(baselineDenominator)
  );
}

function relativeRateIncreaseAtMost(
  candidateNumerator: number,
  candidateDenominator: number,
  baselineNumerator: number,
  baselineDenominator: number,
  maximumIncreaseBasisPoints: number
): boolean {
  if (candidateDenominator <= 0 || baselineDenominator <= 0) return false;
  return (
    BigInt(candidateNumerator) * BigInt(baselineDenominator) * 10_000n <=
    BigInt(baselineNumerator) *
      BigInt(candidateDenominator) *
      BigInt(10_000 + maximumIncreaseBasisPoints)
  );
}

function relativeIncreaseAtMost(
  candidate: number,
  baseline: number,
  maximumIncreaseBasisPoints: number
): boolean {
  if (baseline === 0) return candidate === 0;
  return (
    BigInt(candidate) * 10_000n <=
    BigInt(baseline) * BigInt(10_000 + maximumIncreaseBasisPoints)
  );
}

function isOptionalDigestPair(
  id: unknown,
  digest: unknown,
  prefix: string
): boolean {
  return id === null && digest === null
    ? true
    : isDigestDerivedIdentifier(id, prefix, digest);
}

function isDigestDerivedIdentifier(
  id: unknown,
  prefix: string,
  digest: unknown
): boolean {
  return (
    typeof id === 'string' &&
    isDigest(digest) &&
    id === `${prefix}${digestSuffix(digest)}`
  );
}

function isDigest(value: unknown): value is Sha256Digest {
  return typeof value === 'string' && /^sha256:[0-9a-f]{64}$/u.test(value);
}

function digestSuffix(digest: Sha256Digest): string {
  return digest.slice('sha256:'.length);
}

function isDigestBoundReference(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    isBoundedNfc(value, SAST_RULE_BUNDLE_CANARY_LIMITS.referenceBytes) &&
    /^[a-z][a-z0-9+.-]*:\/\/\S*sha256:[0-9a-f]{64}$/u.test(value) &&
    !containsControlCharacter(value) &&
    !/^https?:/u.test(value)
  );
}

function isActorReference(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    isBoundedNfc(value, SAST_RULE_BUNDLE_CANARY_LIMITS.referenceBytes) &&
    /^actor:\/\/[a-zA-Z0-9._~:/@+-]+$/u.test(value)
  );
}

function isOpaqueIdentifier(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    isBoundedNfc(value, SAST_RULE_BUNDLE_CANARY_LIMITS.identifierBytes) &&
    !containsControlCharacter(value)
  );
}

function isBoundedNfc(value: string, maximumBytes: number): boolean {
  return (
    value.length > 0 &&
    value === value.trim() &&
    value.normalize('NFC') === value &&
    utf8ByteLength(value) <= maximumBytes
  );
}

function containsControlCharacter(value: string): boolean {
  return [...value].some((character) => {
    const code = character.codePointAt(0) ?? 0;
    return code <= 31 || code === 127;
  });
}

function isProfileId(value: unknown): value is SastProfileId {
  return (
    value === 'JAVA_FAST_V1' ||
    value === 'JAVA_DEEP_V1' ||
    value === 'COMMON_DEEP_V1'
  );
}

function isIsoInstant(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function isCount(value: unknown): value is number {
  return Number.isInteger(value) && Number(value) >= 0;
}

function isBoundedNonNegativeInteger(value: unknown): value is number {
  return (
    Number.isSafeInteger(value) &&
    Number(value) >= 0 &&
    Number(value) <= SAST_RULE_BUNDLE_CANARY_LIMITS.maximumBytes
  );
}

function frame(value: string): string {
  return `${utf8ByteLength(value)}:${value}`;
}

function utf8ByteLength(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function hasExactKeys<T extends readonly string[]>(
  value: unknown,
  keys: T
): value is Record<T[number], unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const actual = Object.keys(value).sort(compareStrings);
  const expected = [...keys].sort(compareStrings);
  return (
    actual.length === expected.length &&
    actual.every((key, index) => key === expected[index])
  );
}

function hasExactArrayValues<T>(value: unknown, expected: readonly T[]): boolean {
  return (
    Array.isArray(value) &&
    value.length === expected.length &&
    value.every((item, index) => item === expected[index])
  );
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(sortCanonical(value));
}

function sortCanonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortCanonical);
  if (typeof value === 'object' && value !== null) {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => compareStrings(left, right))
        .map(([key, entry]) => [key, sortCanonical(entry)])
    );
  }
  return value;
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function pickCanaryRolloutInput(
  value: Readonly<SastRuleBundleCanaryRollout>
): SastRuleBundleCanaryRolloutInput {
  return Object.fromEntries(
    CANARY_ROLLOUT_INPUT_KEYS.map((key) => [key, value[key]])
  ) as unknown as SastRuleBundleCanaryRolloutInput;
}

function pickCanaryMembershipInput(
  value: Readonly<SastRuleBundleCanaryMembership>
): SastRuleBundleCanaryMembershipInput {
  return Object.fromEntries(
    CANARY_MEMBERSHIP_INPUT_KEYS.map((key) => [key, value[key]])
  ) as unknown as SastRuleBundleCanaryMembershipInput;
}

function pickCanaryEligibilityInput(
  value: Readonly<SastRuleBundleCanaryEligibilityDecision>
): SastRuleBundleCanaryEligibilityDecisionInput {
  return Object.fromEntries(
    CANARY_ELIGIBILITY_INPUT_KEYS.map((key) => [
      key,
      structuredClone(value[key])
    ])
  ) as unknown as SastRuleBundleCanaryEligibilityDecisionInput;
}

function pickCanaryAssignmentInput(
  value: Readonly<SastRuleBundleCanaryAssignmentReceipt>
): SastRuleBundleCanaryAssignmentInput {
  return Object.fromEntries(
    CANARY_ASSIGNMENT_INPUT_KEYS.map((key) => [key, value[key]])
  ) as unknown as SastRuleBundleCanaryAssignmentInput;
}

function pickCanaryObservationInput(
  value: Readonly<SastRuleBundleCanaryScanObservation>
): SastRuleBundleCanaryScanObservationInput {
  return Object.fromEntries(
    CANARY_OBSERVATION_INPUT_KEYS.map((key) => [key, structuredClone(value[key])])
  ) as unknown as SastRuleBundleCanaryScanObservationInput;
}

function pickCanaryStepDecisionInput(
  value: Readonly<SastRuleBundleCanaryStepDecision>
): SastRuleBundleCanaryStepDecisionInput {
  return Object.fromEntries(
    CANARY_STEP_DECISION_INPUT_KEYS.map((key) => [key, structuredClone(value[key])])
  ) as unknown as SastRuleBundleCanaryStepDecisionInput;
}

function pickCanaryObservationReceiptInput(
  value: Readonly<SastRuleBundleCanaryObservationReceipt>
): SastRuleBundleCanaryObservationReceiptInput {
  return Object.fromEntries(
    CANARY_OBSERVATION_RECEIPT_INPUT_KEYS.map((key) => [key, structuredClone(value[key])])
  ) as unknown as SastRuleBundleCanaryObservationReceiptInput;
}

const CANARY_PAUSE_REASONS: readonly SastRuleBundleCanaryGateReasonCode[] = [
  'TELEMETRY_MISSING',
  'COVERAGE_INCOMPLETE',
  'PROFILE_SIZE_COMPARISON_INCOMPLETE',
  'FALSE_POSITIVE_GATE_FAILED',
  'SCANNER_FAILURE_GATE_FAILED',
  'LATENCY_GATE_FAILED',
  'CRITICAL_HIGH_VOLUME_GATE_FAILED',
  'ZERO_TOLERANCE_EVENT_RECORDED'
];

const CANARY_ROLLOUT_INPUT_KEYS = [
  'candidateManifestId',
  'candidateManifestDigest',
  'candidateBundleId',
  'candidateBundleDigest',
  'baselineManifestId',
  'baselineManifestDigest',
  'baselineBundleDigest',
  'profileId',
  'profileDigest',
  'promotionEvidenceId',
  'promotionEvidenceDigest',
  'canaryTransitionId',
  'canaryTransitionDigest',
  'cohortKeyRef',
  'cohortKeyVersion',
  'eligibilityPolicyRef',
  'eligibilityPolicyDigest',
  'observationSourceRef',
  'observationSourceDigest',
  'createdAt'
] as const;
const CANARY_ROLLOUT_KEYS = [
  ...CANARY_ROLLOUT_INPUT_KEYS,
  'version',
  'rolloutId',
  'progression',
  'immutable',
  'customerInputAccepted',
  'repositoryContentStored',
  'findingContentStored',
  'secretKeyMaterialStored',
  'rolloutDigest'
] as const;

const CANARY_ELIGIBILITY_INPUT_KEYS = [
  'rolloutId',
  'rolloutDigest',
  'tenantId',
  'repositoryBindingId',
  'profileId',
  'profileDigest',
  'eligibilityClass',
  'excluded',
  'exclusionRef',
  'eligibilityPolicyRef',
  'eligibilityPolicyDigest',
  'actorRef',
  'auditRef',
  'evaluatedAt'
] as const;
const CANARY_ELIGIBILITY_KEYS = [
  ...CANARY_ELIGIBILITY_INPUT_KEYS,
  'version',
  'eligibilityDecisionId',
  'platformManaged',
  'customerOverrideAccepted',
  'repositoryContentUsed',
  'findingOrSeverityUsed',
  'eligibilityDecisionDigest'
] as const;

const CANARY_MEMBERSHIP_INPUT_KEYS = [
  'rolloutId',
  'rolloutDigest',
  'tenantId',
  'repositoryBindingId',
  'profileId',
  'profileDigest',
  'eligibilityDecisionId',
  'eligibilityDecisionDigest',
  'eligibilityClass',
  'excluded',
  'exclusionRef',
  'eligibilityPolicyRef',
  'eligibilityPolicyDigest',
  'cohortKeyRef',
  'cohortKeyVersion',
  'assignmentHmacDigest',
  'evaluatedAt'
] as const;
const CANARY_MEMBERSHIP_KEYS = [
  ...CANARY_MEMBERSHIP_INPUT_KEYS,
  'version',
  'membershipId',
  'bucketBasisPoints',
  'immutableForRollout',
  'repositoryContentUsed',
  'findingOrSeverityUsed',
  'customerAttributeUsed',
  'secretKeyMaterialStored',
  'membershipDigest'
] as const;

const CANARY_ASSIGNMENT_INPUT_KEYS = [
  'rolloutId',
  'rolloutDigest',
  'membershipId',
  'membershipDigest',
  'tenantId',
  'repositoryBindingId',
  'profileId',
  'profileDigest',
  'eligibilityClass',
  'excluded',
  'bucketBasisPoints',
  'step',
  'stepHeadDecisionId',
  'stepHeadDecisionDigest',
  'candidateManifestId',
  'candidateManifestDigest',
  'candidateBundleDigest',
  'baselineManifestId',
  'baselineManifestDigest',
  'baselineBundleDigest',
  'evaluatedAt'
] as const;
const CANARY_ASSIGNMENT_KEYS = [
  ...CANARY_ASSIGNMENT_INPUT_KEYS,
  'version',
  'assignmentReceiptId',
  'selection',
  'selectedManifestId',
  'selectedManifestDigest',
  'selectedBundleDigest',
  'deterministic',
  'immutable',
  'customerOverrideAccepted',
  'repositoryContentUsed',
  'findingOrSeverityUsed',
  'assignmentReceiptDigest'
] as const;

const CANARY_OBSERVATION_MEASUREMENT_KEYS = [
  'findingCount',
  'criticalHighFindingCount',
  'falsePositiveCount',
  'feedbackEligibleFindingCount',
  'waiverCount',
  'suppressionCount',
  'scannerFailureCount',
  'scannerTimeoutCount',
  'eligibleScannerAttemptCount',
  'artifactRejectionCount',
  'latencyMilliseconds',
  'cpuMilliseconds',
  'peakMemoryBytes',
  'diskBytes',
  'incompleteCoverageCount',
  'publicationDenialCount',
  'egressDenialCount',
  'cleanupLagMilliseconds',
  'quarantineCount',
  'killSwitchSignalCount',
  'crossTenantEvents',
  'secretLeakEvents',
  'sandboxEscapeEvents',
  'stalePublicationEvents',
  'unauthorizedEgressEvents',
  'missingDestructionEvidenceEvents',
  'evidencePolicyViolationEvents',
  'unsignedArtifactExecutionEvents'
] as const;
const CANARY_OBSERVATION_INPUT_KEYS = [
  'rolloutId',
  'rolloutDigest',
  'step',
  'cohortRole',
  'tenantId',
  'repositoryBindingId',
  'scanRequestId',
  'attemptId',
  'assignmentReceiptId',
  'assignmentReceiptDigest',
  'selectedManifestId',
  'selectedManifestDigest',
  'selectedBundleDigest',
  'profileId',
  'profileDigest',
  'lane',
  'repositorySizeBucket',
  'coverageDecisionId',
  'coverageDecisionDigest',
  'publicationDecisionId',
  'publicationDecisionDigest',
  'observationSourceRef',
  'observationSourceDigest',
  'telemetrySourceRef',
  'telemetrySourceDigest',
  'startedAt',
  'completedAt',
  'coverageComplete',
  'telemetryComplete',
  'measurements'
] as const;
const CANARY_OBSERVATION_KEYS = [
  ...CANARY_OBSERVATION_INPUT_KEYS,
  'version',
  'observationId',
  'terminalScanVerified',
  'immutablePlanVerified',
  'sourceOrFindingContentStored',
  'secretValueStored',
  'observationDigest'
] as const;

const CANARY_STEP_AGGREGATE_MEASUREMENT_KEYS = [
  'candidateCompletedScans',
  'baselineCompletedScans',
  'candidateFindingCount',
  'baselineFindingCount',
  'candidateCriticalHighFindingCount',
  'baselineCriticalHighFindingCount',
  'candidateFalsePositiveCount',
  'candidateFeedbackEligibleFindingCount',
  'baselineFalsePositiveCount',
  'baselineFeedbackEligibleFindingCount',
  'candidateWaiverCount',
  'baselineWaiverCount',
  'candidateSuppressionCount',
  'baselineSuppressionCount',
  'candidateScannerFailureCount',
  'candidateEligibleScannerAttemptCount',
  'baselineScannerFailureCount',
  'baselineEligibleScannerAttemptCount',
  'candidateScannerTimeoutCount',
  'baselineScannerTimeoutCount',
  'candidateP50LatencyMilliseconds',
  'candidateP95LatencyMilliseconds',
  'baselineP50LatencyMilliseconds',
  'baselineP95LatencyMilliseconds',
  'candidateP95CpuMilliseconds',
  'baselineP95CpuMilliseconds',
  'candidateP95PeakMemoryBytes',
  'baselineP95PeakMemoryBytes',
  'candidateP95DiskBytes',
  'baselineP95DiskBytes',
  'candidateArtifactRejectionCount',
  'baselineArtifactRejectionCount',
  'candidateIncompleteCoverageCount',
  'baselineIncompleteCoverageCount',
  'candidatePublicationDenialCount',
  'baselinePublicationDenialCount',
  'candidateEgressDenialCount',
  'baselineEgressDenialCount',
  'candidateP95CleanupLagMilliseconds',
  'baselineP95CleanupLagMilliseconds',
  'candidateQuarantineCount',
  'baselineQuarantineCount',
  'candidateKillSwitchSignalCount',
  'baselineKillSwitchSignalCount',
  'crossTenantEvents',
  'secretLeakEvents',
  'sandboxEscapeEvents',
  'stalePublicationEvents',
  'unauthorizedEgressEvents',
  'missingDestructionEvidenceEvents',
  'evidencePolicyViolationEvents',
  'unsignedArtifactExecutionEvents'
] as const;
const CANARY_OBSERVATION_BINDING_KEYS = [
  'observationId',
  'observationDigest'
] as const;
const CANARY_STEP_DECISION_INPUT_KEYS = [
  'rolloutId',
  'rolloutDigest',
  'candidateManifestId',
  'candidateManifestDigest',
  'candidateBundleDigest',
  'baselineManifestId',
  'baselineManifestDigest',
  'baselineBundleDigest',
  'profileId',
  'profileDigest',
  'sequence',
  'step',
  'previousDecisionId',
  'previousDecisionDigest',
  'windowStartedAt',
  'windowEndedAt',
  'observations',
  'measurements',
  'telemetryComplete',
  'allProfileSizeBucketsCompared',
  'evaluatorRef',
  'auditRef',
  'evaluatedAt'
] as const;
const CANARY_STEP_DECISION_KEYS = [
  ...CANARY_STEP_DECISION_INPUT_KEYS,
  'version',
  'decisionId',
  'outcome',
  'reasonCodes',
  'observationSetDigest',
  'thresholdsWaived',
  'customerInputAccepted',
  'immutable',
  'decisionDigest'
] as const;

const CANARY_PASSED_STEP_BINDING_KEYS = [
  'step',
  'decisionId',
  'decisionDigest'
] as const;
const CANARY_OBSERVATION_RECEIPT_INPUT_KEYS = [
  'rolloutId',
  'rolloutDigest',
  'candidateManifestId',
  'candidateManifestDigest',
  'candidateBundleId',
  'candidateBundleDigest',
  'baselineManifestId',
  'baselineManifestDigest',
  'baselineBundleDigest',
  'profileId',
  'profileDigest',
  'promotionEvidenceId',
  'promotionEvidenceDigest',
  'passedSteps',
  'observedFrom',
  'observedThrough',
  'issuedAt'
] as const;
const CANARY_OBSERVATION_RECEIPT_KEYS = [
  ...CANARY_OBSERVATION_RECEIPT_INPUT_KEYS,
  'version',
  'receiptRef',
  'everyStepPassed',
  'thresholdsWaived',
  'immutable',
  'repositoryContentStored',
  'findingContentStored',
  'receiptDigest'
] as const;
const VERIFIED_CANARY_ASSIGNMENT_DESCRIPTOR_KEYS = [
  'rolloutId',
  'rolloutDigest',
  'membershipId',
  'membershipDigest',
  'bucketBasisPoints',
  'step',
  'stepHeadDecisionId',
  'stepHeadDecisionDigest',
  'assignmentReceiptId',
  'assignmentReceiptDigest',
  'candidateAssigned'
] as const;
