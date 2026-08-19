import {
  SAST_ISOLATED_QUALIFICATION_CLEANUP_CONTROLS,
  isSastIsolatedQualificationDependencySetValid,
  isSastIsolatedQualificationManifestValid,
  isSastIsolatedQualificationResultValid,
  type SastIsolatedQualificationDependencySet,
  type SastIsolatedQualificationManifest,
  type SastIsolatedQualificationResult
} from './sast-isolated-integration-qualification';
import {
  isSastMultiClassQualificationSnapshotValid,
  type SastMultiClassQualificationCase,
  type SastMultiClassQualificationSnapshot
} from './sast-multi-class-qualification-corpus';
import {
  isSastQualificationCorpusSnapshotValid,
  isSastQualificationPriorReleaseManifestValid,
  type SastQualificationCorpusCase,
  type SastQualificationCorpusSnapshot,
  type SastQualificationPriorReleaseManifest
} from './sast-qualification-corpus';
import {
  SAST_APPROVED_PROFILE_DIGESTS,
  SAST_PROFILE_IDS,
  SAST_SCAN_PROFILES,
  type SastProfileId
} from './sast-runtime';

export const SAST_END_TO_END_QUALIFICATION_MANIFEST_VERSION =
  'sast-end-to-end-qualification-manifest-v1' as const;
export const SAST_END_TO_END_QUALIFICATION_CELL_VERSION =
  'sast-end-to-end-qualification-cell-v1' as const;
export const SAST_END_TO_END_QUALIFICATION_DEPENDENCY_SET_VERSION =
  'sast-end-to-end-qualification-dependency-set-v1' as const;
export const SAST_END_TO_END_QUALIFICATION_ENTRY_ATTESTATION_VERSION =
  'sast-end-to-end-qualification-entry-attestation-v1' as const;
export const SAST_END_TO_END_QUALIFICATION_ARTIFACT_VERIFICATION_SET_VERSION =
  'sast-end-to-end-qualification-artifact-verification-set-v1' as const;
export const SAST_END_TO_END_QUALIFICATION_ARTIFACT_PROVENANCE_VERSION =
  'sast-end-to-end-qualification-artifact-provenance-v1' as const;
export const SAST_END_TO_END_QUALIFICATION_PLAN_VERSION =
  'sast-end-to-end-qualification-plan-v1' as const;
export const SAST_END_TO_END_QUALIFICATION_SIGNATURE_VERSION =
  'sast-end-to-end-qualification-signature-v1' as const;
export const SAST_END_TO_END_QUALIFICATION_ATTEMPT_VERSION =
  'sast-end-to-end-qualification-attempt-v1' as const;
export const SAST_END_TO_END_QUALIFICATION_RECEIPT_VERSION =
  'sast-end-to-end-qualification-receipt-v1' as const;
export const SAST_END_TO_END_QUALIFICATION_RESULT_VERSION =
  'sast-end-to-end-qualification-result-v1' as const;

export const SAST_END_TO_END_QUALIFICATION_CELL_KINDS = [
  'GOLDEN_CANDIDATE',
  'GOLDEN_NEGATIVE_BASELINE',
  'END_TO_END_CANDIDATE',
  'PERFORMANCE_CANDIDATE',
  'PERFORMANCE_BASELINE'
] as const;
export type SastEndToEndQualificationCellKind =
  (typeof SAST_END_TO_END_QUALIFICATION_CELL_KINDS)[number];

export const SAST_END_TO_END_QUALIFICATION_ARMS = [
  'CANDIDATE',
  'BASELINE'
] as const;
export type SastEndToEndQualificationArm =
  (typeof SAST_END_TO_END_QUALIFICATION_ARMS)[number];

export const SAST_END_TO_END_QUALIFICATION_PIPELINE_PHASES = [
  'QUEUE_ADMISSION',
  'SANDBOX_EXECUTION',
  'RESULT_INGRESS',
  'NORMALIZATION',
  'FINGERPRINT_CORRELATION',
  'COVERAGE',
  'POLICY',
  'EVIDENCE',
  'CLEANUP'
] as const;
export type SastEndToEndQualificationPipelinePhase =
  (typeof SAST_END_TO_END_QUALIFICATION_PIPELINE_PHASES)[number];

export const SAST_END_TO_END_QUALIFICATION_PHASE_STATUSES = [
  'PASSED',
  'FAILED',
  'NOT_REACHED'
] as const;
export type SastEndToEndQualificationPhaseStatus =
  (typeof SAST_END_TO_END_QUALIFICATION_PHASE_STATUSES)[number];

export const SAST_END_TO_END_QUALIFICATION_ATTEMPT_OUTCOMES = [
  'COMPLETED',
  'INFRASTRUCTURE_FAILURE',
  'SCANNER_DEFECT'
] as const;
export type SastEndToEndQualificationAttemptOutcome =
  (typeof SAST_END_TO_END_QUALIFICATION_ATTEMPT_OUTCOMES)[number];

export const SAST_END_TO_END_QUALIFICATION_STATUSES = [
  'BLOCKED_T053_QUALIFICATION',
  'PENDING_PROVIDER_EXECUTION',
  'FAILED',
  'PASSED'
] as const;
export type SastEndToEndQualificationStatus =
  (typeof SAST_END_TO_END_QUALIFICATION_STATUSES)[number];

export const SAST_END_TO_END_QUALIFICATION_SIGNATURE_ROLES = [
  'QUALIFICATION_AUTHORITY',
  'SUPPLY_CHAIN_AUTHORITY',
  'SECURITY_ENGINEERING',
  'SCAN_PLATFORM',
  'MICROVM_PROVIDER',
  'QUALIFICATION_RUNTIME',
  'TELEMETRY_AUTHORITY'
] as const;
export type SastEndToEndQualificationSignatureRole =
  (typeof SAST_END_TO_END_QUALIFICATION_SIGNATURE_ROLES)[number];

export const SAST_END_TO_END_QUALIFICATION_APPROVAL_ROLES = [
  'SECURITY_ENGINEERING',
  'SCAN_PLATFORM'
] as const;
export type SastEndToEndQualificationApprovalRole =
  (typeof SAST_END_TO_END_QUALIFICATION_APPROVAL_ROLES)[number];

export const SAST_END_TO_END_QUALIFICATION_RECEIPT_SIGNATURE_ROLES = [
  'MICROVM_PROVIDER',
  'QUALIFICATION_RUNTIME',
  'TELEMETRY_AUTHORITY'
] as const;
export type SastEndToEndQualificationReceiptSignatureRole =
  (typeof SAST_END_TO_END_QUALIFICATION_RECEIPT_SIGNATURE_ROLES)[number];

export const SAST_END_TO_END_QUALIFICATION_ARTIFACT_KEYS = [
  'CANDIDATE_SCANNER_SET',
  'CANDIDATE_OPENGREP_IMAGE',
  'CANDIDATE_TRIVY_IMAGE',
  'CANDIDATE_SYFT_IMAGE',
  'CANDIDATE_OPENGREP_WRAPPER',
  'CANDIDATE_TRIVY_WRAPPER',
  'CANDIDATE_SYFT_WRAPPER',
  'CANDIDATE_OPENGREP_RULE_BUNDLE',
  'CANDIDATE_TRIVY_CHECKS_BUNDLE',
  'CANDIDATE_TRIVY_DATABASE',
  'BASELINE_SCANNER_SET',
  'BASELINE_OPENGREP_IMAGE',
  'BASELINE_TRIVY_IMAGE',
  'BASELINE_SYFT_IMAGE',
  'BASELINE_OPENGREP_WRAPPER',
  'BASELINE_TRIVY_WRAPPER',
  'BASELINE_SYFT_WRAPPER',
  'BASELINE_OPENGREP_RULE_BUNDLE',
  'BASELINE_TRIVY_CHECKS_BUNDLE',
  'BASELINE_TRIVY_DATABASE',
  'RESULT_SCHEMA_BUNDLE',
  'NORMALIZER_BUNDLE',
  'FINGERPRINT_CORRELATION_BUNDLE',
  'COVERAGE_POLICY_BUNDLE',
  'POLICY_ENGINE_BUNDLE',
  'EVIDENCE_POLICY_BUNDLE',
  'QUEUE_ADMISSION_BUNDLE',
  'RESULT_INGRESS_BUNDLE',
  'CLEANUP_ORCHESTRATOR_BUNDLE',
  'MICROVM_KERNEL',
  'MICROVM_ROOTFS',
  'QUALIFICATION_RUNNER_IMAGE',
  'QUALIFICATION_HARNESS_IMAGE',
  'PROVIDER_POLICY',
  'TELEMETRY_POLICY',
  'TRUST_POLICY'
] as const;
export type SastEndToEndQualificationArtifactKey =
  (typeof SAST_END_TO_END_QUALIFICATION_ARTIFACT_KEYS)[number];

export const SAST_END_TO_END_QUALIFICATION_FAILURE_REASONS = [
  'T053_ENTRY_INVALID',
  'DEPENDENCY_SET_INVALID',
  'ARTIFACT_VERIFICATION_INVALID',
  'EXECUTION_PLAN_INVALID',
  'APPROVAL_SET_INVALID',
  'RECEIPT_INVALID',
  'RECEIPT_SIGNATURE_INVALID',
  'RECEIPT_DUPLICATE',
  'CELL_BINDING_INVALID',
  'IDENTITY_REUSED',
  'ATTEMPT_CHAIN_INVALID',
  'PROVIDER_MISMATCH',
  'HARDWARE_MISMATCH',
  'PIPELINE_INCOMPLETE',
  'OUTCOME_MISMATCH',
  'RESOURCE_LIMIT_EXCEEDED',
  'TIMESTAMP_INVALID',
  'EVIDENCE_STALE',
  'SAMPLE_INCOMPLETE',
  'GOLDEN_CONFORMANCE_FAILED',
  'MUST_DETECT_RECALL_FAILED',
  'CRITICAL_HIGH_PRECISION_FAILED',
  'PRIOR_MUST_DETECT_FAILED',
  'FALSE_POSITIVE_REGRESSION',
  'SCANNER_FAILURE_RATE_EXCEEDED',
  'LATENCY_REGRESSION',
  'ABSOLUTE_SLO_EXCEEDED',
  'FINGERPRINT_CORRELATION_FAILED',
  'EVIDENCE_PRIVACY_FAILED',
  'CAPACITY_GATE_FAILED',
  'ZERO_TOLERANCE_EVENT'
] as const;
export type SastEndToEndQualificationFailureReason =
  (typeof SAST_END_TO_END_QUALIFICATION_FAILURE_REASONS)[number];

export const SAST_END_TO_END_QUALIFICATION_LIMITS = Object.freeze({
  expectedGoldenCandidateCellCount: 1_880,
  expectedGoldenNegativeBaselineCellCount: 940,
  expectedEndToEndCandidateCellCount: 102,
  expectedPerformanceBucketCount: 9,
  requiredPerformanceRunsPerArmBucket: 30,
  expectedPerformanceCellCount: 540,
  expectedCellCount: 3_462,
  maximumAttemptsPerCell: 2,
  cleanupSloSeconds: 60,
  maximumExecutionWindowSeconds: 7 * 24 * 60 * 60,
  maximumEvidenceAgeSeconds: 24 * 60 * 60,
  maximumReferenceBytes: 2_048,
  maximumIdentifierBytes: 256,
  maximumFailureReasons: 64,
  maximumArtifacts: 64,
  maximumReceiptCount: 3_462
});

type Sha256Digest = `sha256:${string}`;
export type SastEndToEndQualificationCanonicalDigester = (
  canonicalValue: string
) => Sha256Digest;

export interface SastEndToEndQualificationCellCore {
  version: typeof SAST_END_TO_END_QUALIFICATION_CELL_VERSION;
  cellKind: SastEndToEndQualificationCellKind;
  arm: SastEndToEndQualificationArm;
  sourceCorpus: 'T051_GOLDEN' | 'T052_MULTI_CLASS';
  sourceSnapshotDigest: string;
  caseId: string;
  caseDigest: string;
  caseKey: string;
  corpusClass: string;
  scenario: string | null;
  profileId: SastProfileId;
  profileDigest: string;
  scanner: string | null;
  capability: string | null;
  ruleSemanticId: string | null;
  severity: string | null;
  expectedOutcome: string;
  expectedFindingCount: number | null;
  priorMustDetect: boolean;
  fixtureId: string | null;
  fixtureDigest: string | null;
  hardwareClassRef: string | null;
  hardwareClassDigest: string | null;
  runOrdinal: number | null;
  queueToCleanupRequired: true;
  externalPublicationAllowed: false;
  customerContentAccepted: false;
  customerCodeExecutionAllowed: false;
  packageInstallAllowed: false;
  repositoryBuildAllowed: false;
  dynamicTestAllowed: false;
  publicInternetEgressAllowed: false;
  productionReadinessAuthority: false;
}

export interface SastEndToEndQualificationCell
  extends SastEndToEndQualificationCellCore {
  cellId: string;
  cellDigest: string;
}

export interface SastEndToEndQualificationProfileBinding {
  profileId: SastProfileId;
  profileDigest: string;
}

export interface SastEndToEndQualificationManifestCore {
  version: typeof SAST_END_TO_END_QUALIFICATION_MANIFEST_VERSION;
  revision: string;
  publishedAt: string;
  ownerRef: string;
  t051Revision: string;
  t051SnapshotDigest: string;
  t051PriorReleaseManifestDigest: string;
  t052Revision: string;
  t052SnapshotDigest: string;
  t053ManifestId: string;
  t053ManifestDigest: string;
  measurementPolicyRef: string;
  measurementPolicyDigest: string;
  profiles: SastEndToEndQualificationProfileBinding[];
  cells: SastEndToEndQualificationCell[];
  goldenCandidateCellCount: number;
  goldenNegativeBaselineCellCount: number;
  endToEndCandidateCellCount: number;
  performanceCellCount: number;
  performanceBucketCount: number;
  requiredPerformanceRunsPerArmBucket: number;
  executionCellCount: number;
  cellSetDigest: string;
  providerExecutionStatus: 'BLOCKED_T053_QUALIFICATION';
  t053PassRequired: true;
  externalEvidenceRequired: true;
  aggregateMetricsRecomputedFromReceipts: true;
  customerContentAccepted: false;
  customerCodeExecutionAllowed: false;
  packageInstallAllowed: false;
  repositoryBuildAllowed: false;
  dynamicTestAllowed: false;
  publicInternetEgressAllowed: false;
  findingAuthority: false;
  policyAuthority: false;
  publicationAuthority: false;
  deploymentAuthority: false;
  productionReadinessAuthority: false;
  immutable: true;
}

export interface SastEndToEndQualificationManifest
  extends SastEndToEndQualificationManifestCore {
  manifestId: string;
  manifestDigest: string;
}

export interface SastEndToEndQualificationManifestInput {
  revision: string;
  publishedAt: string;
  ownerRef: string;
  goldenSnapshot: SastQualificationCorpusSnapshot;
  priorReleaseManifest: SastQualificationPriorReleaseManifest;
  multiClassSnapshot: SastMultiClassQualificationSnapshot;
  t053Manifest: SastIsolatedQualificationManifest;
  measurementPolicyRef: string;
  measurementPolicyDigest: string;
}

export interface SastEndToEndQualificationArtifactBinding {
  artifactKey: SastEndToEndQualificationArtifactKey;
  artifactRef: string;
  artifactDigest: string;
  signatureRef: string;
  provenanceRef: string;
}

export interface SastEndToEndQualificationDependencySetCore {
  version: typeof SAST_END_TO_END_QUALIFICATION_DEPENDENCY_SET_VERSION;
  revision: string;
  providerId: string;
  providerAdapterRef: string;
  validFrom: string;
  validUntil: string;
  candidateScannerSetDigest: string;
  baselineScannerSetDigest: string;
  performanceHardwareClassRef: string;
  performanceHardwareClassDigest: string;
  artifacts: SastEndToEndQualificationArtifactBinding[];
  executionEnvironment: 'PRODUCTION_EQUIVALENT';
  liveProviderAdapterRequired: true;
  platformManaged: true;
  customerContentAccepted: false;
  publicInternetEgressAllowed: false;
  immutable: true;
}

export interface SastEndToEndQualificationDependencySet
  extends SastEndToEndQualificationDependencySetCore {
  dependencySetId: string;
  dependencySetDigest: string;
}

export interface SastEndToEndQualificationDependencySetInput {
  revision: string;
  providerId: string;
  providerAdapterRef: string;
  validFrom: string;
  validUntil: string;
  candidateScannerSetDigest: string;
  baselineScannerSetDigest: string;
  performanceHardwareClassRef: string;
  performanceHardwareClassDigest: string;
  artifacts: SastEndToEndQualificationArtifactBinding[];
}

export interface SastEndToEndQualificationSignature {
  version: typeof SAST_END_TO_END_QUALIFICATION_SIGNATURE_VERSION;
  role: SastEndToEndQualificationSignatureRole;
  keyId: string;
  payloadDigest: string;
  signedAt: string;
  algorithm: 'ED25519';
  valueBase64: string;
}

export interface SastEndToEndQualificationArtifactProvenanceCore {
  version: typeof SAST_END_TO_END_QUALIFICATION_ARTIFACT_PROVENANCE_VERSION;
  artifactKey: SastEndToEndQualificationArtifactKey;
  artifactRef: string;
  artifactDigest: string;
  builderRef: string;
  sourceRef: string;
  sourceDigest: string;
  materialsDigest: string;
  generatedAt: string;
  customerContentIncluded: false;
  immutable: true;
}

export interface SastEndToEndQualificationArtifactProvenance
  extends SastEndToEndQualificationArtifactProvenanceCore {
  provenanceDigest: string;
  signature: SastEndToEndQualificationSignature;
}

export interface SastEndToEndQualificationArtifactVerification {
  artifactKey: SastEndToEndQualificationArtifactKey;
  artifactDigest: string;
  signatureRef: string;
  signatureEnvelopeDigest: string;
  artifactSignature: SastEndToEndQualificationSignature;
  provenanceRef: string;
  provenanceEnvelopeDigest: string;
  provenance: SastEndToEndQualificationArtifactProvenance;
}

export interface SastEndToEndQualificationArtifactVerificationSetCore {
  version: typeof SAST_END_TO_END_QUALIFICATION_ARTIFACT_VERIFICATION_SET_VERSION;
  dependencySetId: string;
  dependencySetDigest: string;
  verifications: SastEndToEndQualificationArtifactVerification[];
  verifiedAt: string;
  verifierRef: string;
  everyArtifactSignatureVerified: true;
  everyArtifactProvenanceVerified: true;
  immutable: true;
}

export interface SastEndToEndQualificationArtifactVerificationSet
  extends SastEndToEndQualificationArtifactVerificationSetCore {
  verificationSetId: string;
  verificationSetDigest: string;
  signature: SastEndToEndQualificationSignature;
}

export interface SastEndToEndQualificationEntryAttestationCore {
  version: typeof SAST_END_TO_END_QUALIFICATION_ENTRY_ATTESTATION_VERSION;
  t053ManifestId: string;
  t053ManifestDigest: string;
  t053ResultId: string;
  t053ResultDigest: string;
  t053DependencySetDigest: string;
  verifiedAt: string;
  verifierRef: string;
  t054EntryAuthorized: true;
  findingAuthority: false;
  policyAuthority: false;
  publicationAuthority: false;
  deploymentAuthority: false;
  productionReadinessAuthority: false;
}

export interface SastEndToEndQualificationEntryAttestation
  extends SastEndToEndQualificationEntryAttestationCore {
  attestationId: string;
  attestationDigest: string;
  signature: SastEndToEndQualificationSignature;
}

export interface SastEndToEndQualificationExecutionPlanCore {
  version: typeof SAST_END_TO_END_QUALIFICATION_PLAN_VERSION;
  manifestId: string;
  manifestDigest: string;
  dependencySetId: string;
  dependencySetDigest: string;
  t053DependencySetId: string;
  t053DependencySetDigest: string;
  t053ProviderId: string;
  t053ProviderAdapterRef: string;
  artifactVerificationSetId: string;
  artifactVerificationSetDigest: string;
  t053ResultId: string;
  t053ResultDigest: string;
  t053EntryAttestationId: string;
  t053EntryAttestationDigest: string;
  executionCellCount: number;
  requiredApprovalRoles: SastEndToEndQualificationApprovalRole[];
  requiredReceiptSignatureRoles: SastEndToEndQualificationReceiptSignatureRole[];
  plannedAt: string;
  executionAuthority: 'DETACHED_DUAL_APPROVAL_REQUIRED';
  oneFreshMicroVmPerAttempt: true;
  sandboxReuseAllowed: false;
  aggregateMetricsAcceptedFromCaller: false;
  customerContentAccepted: false;
  customerCodeExecutionAllowed: false;
  packageInstallAllowed: false;
  repositoryBuildAllowed: false;
  dynamicTestAllowed: false;
  publicInternetEgressAllowed: false;
  findingAuthority: false;
  policyAuthority: false;
  publicationAuthority: false;
  deploymentAuthority: false;
  productionReadinessAuthority: false;
}

export interface SastEndToEndQualificationExecutionPlan
  extends SastEndToEndQualificationExecutionPlanCore {
  planId: string;
  planDigest: string;
}

export interface SastEndToEndQualificationZeroToleranceCounts {
  crossTenantLeakCount: number;
  secretLeakCount: number;
  sandboxEscapeCount: number;
  staleExternalPublicationCount: number;
  unauthorizedEgressCount: number;
  missingDestructionEvidenceCount: number;
  evidencePolicyViolationCount: number;
  unsignedArtifactExecutionCount: number;
}

export interface SastEndToEndQualificationAttemptCore {
  version: typeof SAST_END_TO_END_QUALIFICATION_ATTEMPT_VERSION;
  attemptId: string;
  sandboxId: string;
  workloadId: string;
  providerAttestationRef: string;
  runtimeAttestationRef: string;
  telemetryAttestationRef: string;
  startedAt: string;
  completedAt: string;
  cleanupCompletedAt: string;
  outcome: SastEndToEndQualificationAttemptOutcome;
  latencyMilliseconds: number;
  cpuMilliseconds: number;
  peakMemoryBytes: number;
  peakDiskBytes: number;
  phaseEgressCount: 0;
  zeroToleranceCounts: SastEndToEndQualificationZeroToleranceCounts;
  cleanupControls: (typeof SAST_ISOLATED_QUALIFICATION_CLEANUP_CONTROLS)[number][];
  cleanupComplete: true;
}

export interface SastEndToEndQualificationAttempt
  extends SastEndToEndQualificationAttemptCore {
  attemptDigest: string;
}

export type SastEndToEndQualificationAttemptInput = Omit<
  SastEndToEndQualificationAttemptCore,
  'version'
>;

export interface SastEndToEndQualificationPhaseObservation {
  phase: SastEndToEndQualificationPipelinePhase;
  status: SastEndToEndQualificationPhaseStatus;
  evidenceDigest: string | null;
}

export interface SastEndToEndQualificationReceiptCore {
  version: typeof SAST_END_TO_END_QUALIFICATION_RECEIPT_VERSION;
  manifestId: string;
  manifestDigest: string;
  dependencySetId: string;
  dependencySetDigest: string;
  planId: string;
  planDigest: string;
  cellId: string;
  cellDigest: string;
  cellKind: SastEndToEndQualificationCellKind;
  arm: SastEndToEndQualificationArm;
  caseId: string;
  caseDigest: string;
  profileId: SastProfileId;
  profileDigest: string;
  providerId: string;
  candidateScannerSetDigest: string;
  baselineScannerSetDigest: string;
  hardwareClassRef: string | null;
  hardwareClassDigest: string | null;
  attempts: SastEndToEndQualificationAttempt[];
  attemptSetDigest: string;
  phaseObservations: SastEndToEndQualificationPhaseObservation[];
  observedControlOutcome: string;
  observedFindingCount: number;
  matchedExpectedFindingCount: number;
  observedCriticalHighFindingCount: number;
  matchedCriticalHighFindingCount: number;
  normalizedOutputDigest: string | null;
  fingerprintDigest: string | null;
  correlationDigest: string | null;
  coverageDecisionDigest: string | null;
  policyDecisionDigest: string | null;
  evidenceDecisionDigest: string | null;
  externalPublicationAttempted: false;
  customerContentObserved: false;
  customerCodeExecuted: false;
  packageInstallObserved: false;
  repositoryBuildObserved: false;
  dynamicTestObserved: false;
  publicInternetEgressObserved: false;
  completedAt: string;
}

export type SastEndToEndQualificationReceiptInput = Omit<
  SastEndToEndQualificationReceiptCore,
  'version'
>;

export interface SastEndToEndQualificationReceipt
  extends SastEndToEndQualificationReceiptCore {
  receiptId: string;
  receiptDigest: string;
}

export interface SastEndToEndQualificationSignedReceipt {
  receipt: SastEndToEndQualificationReceipt;
  signatures: SastEndToEndQualificationSignature[];
}

export interface SastEndToEndQualificationPerformanceBucketMeasurement {
  profileId: SastProfileId;
  scenario: string;
  candidateRunCount: number;
  baselineRunCount: number;
  candidateP50Milliseconds: number;
  candidateP95Milliseconds: number;
  baselineP50Milliseconds: number;
  baselineP95Milliseconds: number;
  p95LatencyIncrease: number;
  candidateMaximumCpuMilliseconds: number;
  candidateMaximumMemoryBytes: number;
  candidateMaximumDiskBytes: number;
}

export interface SastEndToEndQualificationMeasurements {
  eligibleAttemptCount: number;
  completedCellCount: number;
  performanceRunsPerArmProfileSizeBucket: number;
  goldenCorpusPassRate: number;
  criticalHighPrecision: number;
  mustDetectRecall: number;
  priorMustDetectRegressionRecall: number;
  candidateFalsePositiveRate: number;
  baselineFalsePositiveRate: number;
  falsePositiveIncrease: number;
  scannerFailureRate: number;
  fingerprintFixturePassRate: number;
  evidencePrivacyPassRate: number;
  capacityPassRate: number;
  fastLaneP95Milliseconds: number;
  deepLaneP95Milliseconds: number;
  zeroToleranceCounts: SastEndToEndQualificationZeroToleranceCounts;
  performanceBuckets: SastEndToEndQualificationPerformanceBucketMeasurement[];
  measurementsDigest: string;
}

export interface SastEndToEndQualificationResultCore {
  version: typeof SAST_END_TO_END_QUALIFICATION_RESULT_VERSION;
  status: SastEndToEndQualificationStatus;
  manifestId: string;
  manifestDigest: string;
  t053ResultId: string | null;
  t053ResultDigest: string | null;
  dependencySetId: string | null;
  dependencySetDigest: string | null;
  planId: string | null;
  planDigest: string | null;
  expectedReceiptCount: number;
  observedReceiptCount: number;
  validReceiptCount: number;
  measurements: SastEndToEndQualificationMeasurements | null;
  failureReasons: SastEndToEndQualificationFailureReason[];
  evaluatedAt: string;
  t055EntryAuthorized: boolean;
  findingAuthority: false;
  policyAuthority: false;
  publicationAuthority: false;
  deploymentAuthority: false;
  productionReadinessAuthority: false;
}

export interface SastEndToEndQualificationResult
  extends SastEndToEndQualificationResultCore {
  resultId: string;
  resultDigest: string;
}

export type SastEndToEndQualificationSignatureVerifier = (
  signature: SastEndToEndQualificationSignature,
  payload: string
) => boolean;

export interface SastEndToEndQualificationEvaluationInput {
  manifest: SastEndToEndQualificationManifest;
  t053Result: SastIsolatedQualificationResult | null;
  t053DependencySet: SastIsolatedQualificationDependencySet | null;
  entryAttestation: SastEndToEndQualificationEntryAttestation | null;
  dependencySet: SastEndToEndQualificationDependencySet | null;
  artifactVerificationSet:
    | SastEndToEndQualificationArtifactVerificationSet
    | null;
  plan: SastEndToEndQualificationExecutionPlan | null;
  approvals: SastEndToEndQualificationSignature[];
  signedReceipts: SastEndToEndQualificationSignedReceipt[];
  trustedEvaluatedAt: string;
  verifySignature: SastEndToEndQualificationSignatureVerifier;
}

const CELL_CORE_KEYS = [
  'version', 'cellKind', 'arm', 'sourceCorpus', 'sourceSnapshotDigest', 'caseId',
  'caseDigest', 'caseKey', 'corpusClass', 'scenario', 'profileId', 'profileDigest',
  'scanner', 'capability', 'ruleSemanticId', 'severity', 'expectedOutcome',
  'expectedFindingCount', 'priorMustDetect', 'fixtureId', 'fixtureDigest',
  'hardwareClassRef', 'hardwareClassDigest', 'runOrdinal', 'queueToCleanupRequired',
  'externalPublicationAllowed', 'customerContentAccepted', 'customerCodeExecutionAllowed',
  'packageInstallAllowed', 'repositoryBuildAllowed', 'dynamicTestAllowed',
  'publicInternetEgressAllowed', 'productionReadinessAuthority'
] as const;

const CELL_KEYS = [...CELL_CORE_KEYS, 'cellId', 'cellDigest'] as const;

export function buildSastEndToEndQualificationManifest(
  input: SastEndToEndQualificationManifestInput,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): SastEndToEndQualificationManifest | null {
  try {
    if (
      !hasExactKeys(input, [
        'revision', 'publishedAt', 'ownerRef', 'goldenSnapshot', 'priorReleaseManifest',
        'multiClassSnapshot', 't053Manifest', 'measurementPolicyRef',
        'measurementPolicyDigest'
      ]) ||
      !isSemanticVersion(input.revision) ||
      !isIsoInstant(input.publishedAt) ||
      !isReference(input.ownerRef) ||
      !isSastQualificationCorpusSnapshotValid(
        input.goldenSnapshot,
        digestCanonical,
        input.priorReleaseManifest
      ) ||
      !isSastQualificationPriorReleaseManifestValid(
        input.priorReleaseManifest,
        digestCanonical
      ) ||
      !isSastMultiClassQualificationSnapshotValid(
        input.multiClassSnapshot,
        digestCanonical
      ) ||
      !isSastIsolatedQualificationManifestValid(input.t053Manifest, digestCanonical) ||
      input.goldenSnapshot.revision !== '1.0.0' ||
      input.multiClassSnapshot.revision !== '1.0.2' ||
      input.goldenSnapshot.priorReleaseManifestDigest !==
        input.priorReleaseManifest.manifestDigest ||
      !isDigestBoundReference(input.measurementPolicyRef, input.measurementPolicyDigest)
    ) {
      return null;
    }

    const priorIds = new Set(
      input.priorReleaseManifest.bindings.map((item) => item.caseId)
    );
    const cells: SastEndToEndQualificationCell[] = [];
    for (const sourceCase of input.goldenSnapshot.cases) {
      for (const profileId of sourceCase.profiles) {
        const candidate = buildCell(
          goldenCellCore(
            sourceCase,
            profileId,
            'GOLDEN_CANDIDATE',
            'CANDIDATE',
            input.goldenSnapshot.snapshotDigest,
            priorIds.has(sourceCase.caseId)
          ),
          digestCanonical
        );
        if (!candidate) return null;
        cells.push(candidate);
        if (sourceCase.corpusClass === 'GOLDEN_NEGATIVE') {
          const baseline = buildCell(
            goldenCellCore(
              sourceCase,
              profileId,
              'GOLDEN_NEGATIVE_BASELINE',
              'BASELINE',
              input.goldenSnapshot.snapshotDigest,
              false
            ),
            digestCanonical
          );
          if (!baseline) return null;
          cells.push(baseline);
        }
      }
    }

    for (const sourceCase of input.multiClassSnapshot.cases) {
      if (sourceCase.evidenceStage === 'T054_END_TO_END') {
        for (const profileId of sourceCase.profiles) {
          const cell = buildCell(
            multiClassCellCore(
              sourceCase,
              profileId,
              'END_TO_END_CANDIDATE',
              'CANDIDATE',
              input.multiClassSnapshot.snapshotDigest,
              null
            ),
            digestCanonical
          );
          if (!cell) return null;
          cells.push(cell);
        }
      }
      if (sourceCase.evidenceStage === 'T054_PERFORMANCE') {
        if (sourceCase.profiles.length !== 1 || sourceCase.minimumRuns !== 30) return null;
        for (const arm of SAST_END_TO_END_QUALIFICATION_ARMS) {
          for (
            let runOrdinal = 1;
            runOrdinal <= SAST_END_TO_END_QUALIFICATION_LIMITS.requiredPerformanceRunsPerArmBucket;
            runOrdinal += 1
          ) {
            const cell = buildCell(
              multiClassCellCore(
                sourceCase,
                sourceCase.profiles[0],
                arm === 'CANDIDATE'
                  ? 'PERFORMANCE_CANDIDATE'
                  : 'PERFORMANCE_BASELINE',
                arm,
                input.multiClassSnapshot.snapshotDigest,
                runOrdinal
              ),
              digestCanonical
            );
            if (!cell) return null;
            cells.push(cell);
          }
        }
      }
    }

    cells.sort(compareCells);
    if (new Set(cells.map((item) => item.cellId)).size !== cells.length) return null;
    const counts = countCellKinds(cells);
    if (
      counts.GOLDEN_CANDIDATE !==
        SAST_END_TO_END_QUALIFICATION_LIMITS.expectedGoldenCandidateCellCount ||
      counts.GOLDEN_NEGATIVE_BASELINE !==
        SAST_END_TO_END_QUALIFICATION_LIMITS.expectedGoldenNegativeBaselineCellCount ||
      counts.END_TO_END_CANDIDATE !==
        SAST_END_TO_END_QUALIFICATION_LIMITS.expectedEndToEndCandidateCellCount ||
      counts.PERFORMANCE_CANDIDATE + counts.PERFORMANCE_BASELINE !==
        SAST_END_TO_END_QUALIFICATION_LIMITS.expectedPerformanceCellCount ||
      cells.length !== SAST_END_TO_END_QUALIFICATION_LIMITS.expectedCellCount
    ) {
      return null;
    }

    const performanceBuckets = new Set(
      cells
        .filter((item) => item.cellKind === 'PERFORMANCE_CANDIDATE')
        .map((item) => `${item.profileId}\u0000${item.scenario}`)
    );
    if (
      performanceBuckets.size !==
      SAST_END_TO_END_QUALIFICATION_LIMITS.expectedPerformanceBucketCount
    ) {
      return null;
    }

    const profiles = SAST_PROFILE_IDS.map((profileId) => ({
      profileId,
      profileDigest: SAST_APPROVED_PROFILE_DIGESTS[profileId]
    }));
    const cellSetDigest = digestCanonical(
      stableJson(cells.map((item) => ({ cellId: item.cellId, cellDigest: item.cellDigest })))
    );
    if (!isDigest(cellSetDigest)) return null;
    const core: SastEndToEndQualificationManifestCore = {
      version: SAST_END_TO_END_QUALIFICATION_MANIFEST_VERSION,
      revision: input.revision,
      publishedAt: input.publishedAt,
      ownerRef: input.ownerRef,
      t051Revision: input.goldenSnapshot.revision,
      t051SnapshotDigest: input.goldenSnapshot.snapshotDigest,
      t051PriorReleaseManifestDigest: input.priorReleaseManifest.manifestDigest,
      t052Revision: input.multiClassSnapshot.revision,
      t052SnapshotDigest: input.multiClassSnapshot.snapshotDigest,
      t053ManifestId: input.t053Manifest.manifestId,
      t053ManifestDigest: input.t053Manifest.manifestDigest,
      measurementPolicyRef: input.measurementPolicyRef,
      measurementPolicyDigest: input.measurementPolicyDigest,
      profiles,
      cells,
      goldenCandidateCellCount: counts.GOLDEN_CANDIDATE,
      goldenNegativeBaselineCellCount: counts.GOLDEN_NEGATIVE_BASELINE,
      endToEndCandidateCellCount: counts.END_TO_END_CANDIDATE,
      performanceCellCount:
        counts.PERFORMANCE_CANDIDATE + counts.PERFORMANCE_BASELINE,
      performanceBucketCount: performanceBuckets.size,
      requiredPerformanceRunsPerArmBucket:
        SAST_END_TO_END_QUALIFICATION_LIMITS.requiredPerformanceRunsPerArmBucket,
      executionCellCount: cells.length,
      cellSetDigest,
      providerExecutionStatus: 'BLOCKED_T053_QUALIFICATION',
      t053PassRequired: true,
      externalEvidenceRequired: true,
      aggregateMetricsRecomputedFromReceipts: true,
      customerContentAccepted: false,
      customerCodeExecutionAllowed: false,
      packageInstallAllowed: false,
      repositoryBuildAllowed: false,
      dynamicTestAllowed: false,
      publicInternetEgressAllowed: false,
      findingAuthority: false,
      policyAuthority: false,
      publicationAuthority: false,
      deploymentAuthority: false,
      productionReadinessAuthority: false,
      immutable: true
    };
    const manifestDigest = digestCanonical(stableJson(core));
    if (!isDigest(manifestDigest)) return null;
    return {
      ...core,
      manifestId:
        `sast-end-to-end-qualification-manifest://${manifestDigest.slice('sha256:'.length)}`,
      manifestDigest
    };
  } catch {
    return null;
  }
}

export function isSastEndToEndQualificationManifestValid(
  value: unknown,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): value is SastEndToEndQualificationManifest {
  try {
    if (!isRecord(value) || !hasExactKeys(value, [...MANIFEST_CORE_KEYS, 'manifestId', 'manifestDigest'])) {
      return false;
    }
    const candidate = value as unknown as SastEndToEndQualificationManifest;
    if (
      candidate.version !== SAST_END_TO_END_QUALIFICATION_MANIFEST_VERSION ||
      !isSemanticVersion(candidate.revision) ||
      !isIsoInstant(candidate.publishedAt) ||
      !isReference(candidate.ownerRef) ||
      candidate.t051Revision !== '1.0.0' ||
      candidate.t052Revision !== '1.0.2' ||
      !isDigest(candidate.t051SnapshotDigest) ||
      !isDigest(candidate.t051PriorReleaseManifestDigest) ||
      !isDigest(candidate.t052SnapshotDigest) ||
      !isDirectQualificationIdentity(candidate.t053ManifestId, 'sast-isolated-qualification-manifest://') ||
      !isDigest(candidate.t053ManifestDigest) ||
      !candidate.t053ManifestId.endsWith(candidate.t053ManifestDigest.slice('sha256:'.length)) ||
      !isDigestBoundReference(candidate.measurementPolicyRef, candidate.measurementPolicyDigest) ||
      !Array.isArray(candidate.profiles) ||
      !Array.isArray(candidate.cells) ||
      candidate.cells.length !== SAST_END_TO_END_QUALIFICATION_LIMITS.expectedCellCount ||
      !arraysEqual(candidate.profiles, SAST_PROFILE_IDS.map((profileId) => ({
        profileId,
        profileDigest: SAST_APPROVED_PROFILE_DIGESTS[profileId]
      }))) ||
      candidate.cells.some((item) => !isCellValid(item, digestCanonical)) ||
      !isDigest(candidate.cellSetDigest) ||
      digestCanonical(stableJson(candidate.cells.map((item) => ({
        cellId: item.cellId,
        cellDigest: item.cellDigest
      })))) !== candidate.cellSetDigest ||
      !arraysEqual([...candidate.cells].sort(compareCells), candidate.cells) ||
      new Set(candidate.cells.map((item) => item.cellId)).size !== candidate.cells.length ||
      candidate.goldenCandidateCellCount !== SAST_END_TO_END_QUALIFICATION_LIMITS.expectedGoldenCandidateCellCount ||
      candidate.goldenNegativeBaselineCellCount !== SAST_END_TO_END_QUALIFICATION_LIMITS.expectedGoldenNegativeBaselineCellCount ||
      candidate.endToEndCandidateCellCount !== SAST_END_TO_END_QUALIFICATION_LIMITS.expectedEndToEndCandidateCellCount ||
      candidate.performanceCellCount !== SAST_END_TO_END_QUALIFICATION_LIMITS.expectedPerformanceCellCount ||
      candidate.performanceBucketCount !== SAST_END_TO_END_QUALIFICATION_LIMITS.expectedPerformanceBucketCount ||
      candidate.requiredPerformanceRunsPerArmBucket !== 30 ||
      candidate.executionCellCount !== SAST_END_TO_END_QUALIFICATION_LIMITS.expectedCellCount ||
      candidate.providerExecutionStatus !== 'BLOCKED_T053_QUALIFICATION' ||
      !hasClosedManifestAuthority(candidate) ||
      !isDigest(candidate.manifestDigest) ||
      !isDirectQualificationIdentity(candidate.manifestId, 'sast-end-to-end-qualification-manifest://') ||
      !candidate.manifestId.endsWith(candidate.manifestDigest.slice('sha256:'.length))
    ) {
      return false;
    }
    const counts = countCellKinds(candidate.cells);
    const performanceBuckets = new Set(
      candidate.cells
        .filter((cell) => cell.cellKind === 'PERFORMANCE_CANDIDATE')
        .map((cell) => `${cell.profileId}\u0000${cell.scenario ?? ''}`)
    );
    if (
      counts.GOLDEN_CANDIDATE !== candidate.goldenCandidateCellCount ||
      counts.GOLDEN_NEGATIVE_BASELINE !==
        candidate.goldenNegativeBaselineCellCount ||
      counts.END_TO_END_CANDIDATE !== candidate.endToEndCandidateCellCount ||
      counts.PERFORMANCE_CANDIDATE !== 270 ||
      counts.PERFORMANCE_BASELINE !== 270 ||
      performanceBuckets.size !== candidate.performanceBucketCount ||
      performanceHardwareClassRef(candidate) === '' ||
      performanceHardwareClassDigest(candidate) === '' ||
      candidate.cells.some((cell) =>
        cell.sourceCorpus === 'T051_GOLDEN'
          ? cell.sourceSnapshotDigest !== candidate.t051SnapshotDigest
          : cell.sourceSnapshotDigest !== candidate.t052SnapshotDigest
      )
    ) {
      return false;
    }
    const core = omitKeys(candidate, ['manifestId', 'manifestDigest']);
    return digestCanonical(stableJson(core)) === candidate.manifestDigest;
  } catch {
    return false;
  }
}

const MANIFEST_CORE_KEYS = [
  'version', 'revision', 'publishedAt', 'ownerRef', 't051Revision', 't051SnapshotDigest',
  't051PriorReleaseManifestDigest', 't052Revision', 't052SnapshotDigest', 't053ManifestId',
  't053ManifestDigest', 'measurementPolicyRef', 'measurementPolicyDigest', 'profiles', 'cells',
  'goldenCandidateCellCount', 'goldenNegativeBaselineCellCount', 'endToEndCandidateCellCount',
  'performanceCellCount', 'performanceBucketCount', 'requiredPerformanceRunsPerArmBucket',
  'executionCellCount', 'cellSetDigest', 'providerExecutionStatus', 't053PassRequired',
  'externalEvidenceRequired', 'aggregateMetricsRecomputedFromReceipts', 'customerContentAccepted',
  'customerCodeExecutionAllowed', 'packageInstallAllowed', 'repositoryBuildAllowed',
  'dynamicTestAllowed', 'publicInternetEgressAllowed', 'findingAuthority', 'policyAuthority',
  'publicationAuthority', 'deploymentAuthority', 'productionReadinessAuthority', 'immutable'
] as const;

const ARTIFACT_KEYS = [
  'artifactKey',
  'artifactRef',
  'artifactDigest',
  'signatureRef',
  'provenanceRef'
] as const;

const DEPENDENCY_SET_CORE_KEYS = [
  'version', 'revision', 'providerId', 'providerAdapterRef', 'validFrom', 'validUntil',
  'candidateScannerSetDigest', 'baselineScannerSetDigest', 'performanceHardwareClassRef',
  'performanceHardwareClassDigest', 'artifacts', 'executionEnvironment',
  'liveProviderAdapterRequired', 'platformManaged', 'customerContentAccepted',
  'publicInternetEgressAllowed', 'immutable'
] as const;

export function buildSastEndToEndQualificationDependencySet(
  input: SastEndToEndQualificationDependencySetInput,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): SastEndToEndQualificationDependencySet | null {
  try {
    if (
      !hasExactKeys(input, [
        'revision', 'providerId', 'providerAdapterRef', 'validFrom', 'validUntil',
        'candidateScannerSetDigest', 'baselineScannerSetDigest',
        'performanceHardwareClassRef', 'performanceHardwareClassDigest', 'artifacts'
      ]) ||
      !isSemanticVersion(input.revision) ||
      !isIdentifier(input.providerId) ||
      !isDigestBoundReference(input.providerAdapterRef) ||
      !isIsoInstant(input.validFrom) ||
      !isIsoInstant(input.validUntil) ||
      Date.parse(input.validUntil) <= Date.parse(input.validFrom) ||
      secondsBetween(input.validFrom, input.validUntil) >
        SAST_END_TO_END_QUALIFICATION_LIMITS.maximumExecutionWindowSeconds ||
      !isDigest(input.candidateScannerSetDigest) ||
      !isDigest(input.baselineScannerSetDigest) ||
      input.candidateScannerSetDigest === input.baselineScannerSetDigest ||
      !isDigestBoundReference(
        input.performanceHardwareClassRef,
        input.performanceHardwareClassDigest
      ) ||
      !Array.isArray(input.artifacts) ||
      input.artifacts.length !== SAST_END_TO_END_QUALIFICATION_ARTIFACT_KEYS.length ||
      input.artifacts.length > SAST_END_TO_END_QUALIFICATION_LIMITS.maximumArtifacts ||
      input.artifacts.some((item) => !isArtifactBindingValid(item))
    ) {
      return null;
    }
    const byKey = new Map(
      input.artifacts.map((item) => [item.artifactKey, cloneArtifact(item)])
    );
    if (byKey.size !== SAST_END_TO_END_QUALIFICATION_ARTIFACT_KEYS.length) return null;
    const artifacts = SAST_END_TO_END_QUALIFICATION_ARTIFACT_KEYS.map((key) =>
      byKey.get(key)
    );
    if (artifacts.some((item) => !item)) return null;
    if (
      byKey.get('CANDIDATE_SCANNER_SET')?.artifactDigest !==
        input.candidateScannerSetDigest ||
      byKey.get('BASELINE_SCANNER_SET')?.artifactDigest !==
        input.baselineScannerSetDigest
    ) {
      return null;
    }
    const core: SastEndToEndQualificationDependencySetCore = {
      version: SAST_END_TO_END_QUALIFICATION_DEPENDENCY_SET_VERSION,
      revision: input.revision,
      providerId: input.providerId,
      providerAdapterRef: input.providerAdapterRef,
      validFrom: input.validFrom,
      validUntil: input.validUntil,
      candidateScannerSetDigest: input.candidateScannerSetDigest,
      baselineScannerSetDigest: input.baselineScannerSetDigest,
      performanceHardwareClassRef: input.performanceHardwareClassRef,
      performanceHardwareClassDigest: input.performanceHardwareClassDigest,
      artifacts: artifacts as SastEndToEndQualificationArtifactBinding[],
      executionEnvironment: 'PRODUCTION_EQUIVALENT',
      liveProviderAdapterRequired: true,
      platformManaged: true,
      customerContentAccepted: false,
      publicInternetEgressAllowed: false,
      immutable: true
    };
    const dependencySetDigest = digestCanonical(stableJson(core));
    if (!isDigest(dependencySetDigest)) return null;
    return {
      ...core,
      dependencySetId:
        `sast-end-to-end-qualification-dependency-set://${dependencySetDigest.slice('sha256:'.length)}`,
      dependencySetDigest
    };
  } catch {
    return null;
  }
}

export function isSastEndToEndQualificationDependencySetValid(
  value: unknown,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): value is SastEndToEndQualificationDependencySet {
  try {
    if (!isRecord(value) || !hasExactKeys(value, [...DEPENDENCY_SET_CORE_KEYS, 'dependencySetId', 'dependencySetDigest'])) {
      return false;
    }
    const candidate = value as unknown as SastEndToEndQualificationDependencySet;
    const rebuilt = buildSastEndToEndQualificationDependencySet(
      dependencySetInput(candidate),
      digestCanonical
    );
    return (
      rebuilt !== null &&
      isDirectQualificationIdentity(candidate.dependencySetId, 'sast-end-to-end-qualification-dependency-set://') &&
      isDigest(candidate.dependencySetDigest) &&
      stableJson(rebuilt) === stableJson(candidate)
    );
  } catch {
    return false;
  }
}

const ARTIFACT_VERIFICATION_KEYS = [
  'artifactKey', 'artifactDigest', 'signatureRef', 'signatureEnvelopeDigest',
  'artifactSignature', 'provenanceRef', 'provenanceEnvelopeDigest', 'provenance'
] as const;

const ARTIFACT_PROVENANCE_CORE_KEYS = [
  'version', 'artifactKey', 'artifactRef', 'artifactDigest', 'builderRef',
  'sourceRef', 'sourceDigest', 'materialsDigest', 'generatedAt',
  'customerContentIncluded', 'immutable'
] as const;

const ARTIFACT_PROVENANCE_KEYS = [
  ...ARTIFACT_PROVENANCE_CORE_KEYS, 'provenanceDigest', 'signature'
] as const;

const ARTIFACT_VERIFICATION_SET_CORE_KEYS = [
  'version', 'dependencySetId', 'dependencySetDigest', 'verifications',
  'verifiedAt', 'verifierRef', 'everyArtifactSignatureVerified',
  'everyArtifactProvenanceVerified', 'immutable'
] as const;

export function buildSastEndToEndQualificationArtifactProvenance(
  input: Omit<
    SastEndToEndQualificationArtifactProvenanceCore,
    'version' | 'customerContentIncluded' | 'immutable'
  >,
  signature: SastEndToEndQualificationSignature,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): SastEndToEndQualificationArtifactProvenance | null {
  try {
    if (
      !hasExactKeys(input, [
        'artifactKey', 'artifactRef', 'artifactDigest', 'builderRef', 'sourceRef',
        'sourceDigest', 'materialsDigest', 'generatedAt'
      ]) ||
      !SAST_END_TO_END_QUALIFICATION_ARTIFACT_KEYS.includes(input.artifactKey) ||
      !isDigestBoundReference(input.artifactRef, input.artifactDigest) ||
      !isDigestBoundReference(input.builderRef) ||
      !isDigestBoundReference(input.sourceRef, input.sourceDigest) ||
      !isDigest(input.materialsDigest) ||
      !isIsoInstant(input.generatedAt)
    ) {
      return null;
    }
    const core: SastEndToEndQualificationArtifactProvenanceCore = {
      version: SAST_END_TO_END_QUALIFICATION_ARTIFACT_PROVENANCE_VERSION,
      ...input,
      customerContentIncluded: false,
      immutable: true
    };
    const provenanceDigest = digestCanonical(stableJson(core));
    if (
      !isDigest(provenanceDigest) ||
      !isSastEndToEndQualificationSignatureValid(signature) ||
      signature.role !== 'SUPPLY_CHAIN_AUTHORITY' ||
      signature.payloadDigest !== provenanceDigest ||
      signature.signedAt !== input.generatedAt
    ) {
      return null;
    }
    return { ...core, provenanceDigest, signature };
  } catch {
    return null;
  }
}

export function isSastEndToEndQualificationArtifactProvenanceValid(
  value: unknown,
  verifySignature: SastEndToEndQualificationSignatureVerifier,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): value is SastEndToEndQualificationArtifactProvenance {
  try {
    if (!isRecord(value) || !hasExactKeys(value, ARTIFACT_PROVENANCE_KEYS)) {
      return false;
    }
    const candidate =
      value as unknown as SastEndToEndQualificationArtifactProvenance;
    const rebuilt = buildSastEndToEndQualificationArtifactProvenance(
      omitKeys(candidate, [
        'version', 'customerContentIncluded', 'immutable', 'provenanceDigest',
        'signature'
      ]) as Omit<
        SastEndToEndQualificationArtifactProvenanceCore,
        'version' | 'customerContentIncluded' | 'immutable'
      >,
      candidate.signature,
      digestCanonical
    );
    if (rebuilt === null || stableJson(rebuilt) !== stableJson(candidate)) {
      return false;
    }
    const payload = serializeSastEndToEndQualificationSignaturePayload(
      candidate.signature
    );
    return payload !== null && verifySignature(candidate.signature, payload);
  } catch {
    return false;
  }
}

export function buildSastEndToEndQualificationArtifactVerificationSet(
  input: Readonly<{
    dependencySet: SastEndToEndQualificationDependencySet;
    verifications: SastEndToEndQualificationArtifactVerification[];
    verifiedAt: string;
    verifierRef: string;
  }>,
  signature: SastEndToEndQualificationSignature,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): SastEndToEndQualificationArtifactVerificationSet | null {
  try {
    if (
      !hasExactKeys(input, [
        'dependencySet', 'verifications', 'verifiedAt', 'verifierRef'
      ]) ||
      !isSastEndToEndQualificationDependencySetValid(
        input.dependencySet,
        digestCanonical
      ) ||
      !Array.isArray(input.verifications) ||
      input.verifications.length !== input.dependencySet.artifacts.length ||
      input.verifications.length >
        SAST_END_TO_END_QUALIFICATION_LIMITS.maximumArtifacts ||
      !isIsoInstant(input.verifiedAt) ||
      Date.parse(input.verifiedAt) < Date.parse(input.dependencySet.validFrom) ||
      Date.parse(input.verifiedAt) > Date.parse(input.dependencySet.validUntil) ||
      !isDigestBoundReference(input.verifierRef)
    ) {
      return null;
    }
    const byKey = new Map<
      SastEndToEndQualificationArtifactKey,
      SastEndToEndQualificationArtifactVerification
    >();
    for (const verification of input.verifications) {
      if (
        !isArtifactVerificationValid(verification, digestCanonical) ||
        byKey.has(verification.artifactKey)
      ) {
        return null;
      }
      byKey.set(verification.artifactKey, { ...verification });
    }
    const verifications = input.dependencySet.artifacts.map((artifact) => {
      const verification = byKey.get(artifact.artifactKey);
      if (
        !verification ||
        verification.artifactDigest !== artifact.artifactDigest ||
        verification.signatureRef !== artifact.signatureRef ||
        verification.provenanceRef !== artifact.provenanceRef ||
        verification.provenance.artifactRef !== artifact.artifactRef ||
        Date.parse(verification.artifactSignature.signedAt) >
          Date.parse(input.verifiedAt) ||
        Date.parse(verification.provenance.generatedAt) >
          Date.parse(input.verifiedAt)
      ) {
        return null;
      }
      return verification;
    });
    if (verifications.some((item) => item === null)) return null;
    const core: SastEndToEndQualificationArtifactVerificationSetCore = {
      version: SAST_END_TO_END_QUALIFICATION_ARTIFACT_VERIFICATION_SET_VERSION,
      dependencySetId: input.dependencySet.dependencySetId,
      dependencySetDigest: input.dependencySet.dependencySetDigest,
      verifications:
        verifications as SastEndToEndQualificationArtifactVerification[],
      verifiedAt: input.verifiedAt,
      verifierRef: input.verifierRef,
      everyArtifactSignatureVerified: true,
      everyArtifactProvenanceVerified: true,
      immutable: true
    };
    const verificationSetDigest = digestCanonical(stableJson(core));
    if (!isDigest(verificationSetDigest)) return null;
    if (
      !isSastEndToEndQualificationSignatureValid(signature) ||
      signature.role !== 'SUPPLY_CHAIN_AUTHORITY' ||
      signature.payloadDigest !== verificationSetDigest ||
      signature.signedAt !== input.verifiedAt
    ) {
      return null;
    }
    return {
      ...core,
      verificationSetId:
        `sast-end-to-end-qualification-artifact-verification-set://${verificationSetDigest.slice('sha256:'.length)}`,
      verificationSetDigest,
      signature
    };
  } catch {
    return null;
  }
}

export function isSastEndToEndQualificationArtifactVerificationSetValid(
  value: unknown,
  dependencySet: SastEndToEndQualificationDependencySet,
  verifySignature: SastEndToEndQualificationSignatureVerifier,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): value is SastEndToEndQualificationArtifactVerificationSet {
  try {
    if (
      !isRecord(value) ||
      !hasExactKeys(value, [
        ...ARTIFACT_VERIFICATION_SET_CORE_KEYS,
        'verificationSetId', 'verificationSetDigest', 'signature'
      ])
    ) {
      return false;
    }
    const candidate =
      value as unknown as SastEndToEndQualificationArtifactVerificationSet;
    const rebuilt = buildSastEndToEndQualificationArtifactVerificationSet(
      {
        dependencySet,
        verifications: candidate.verifications,
        verifiedAt: candidate.verifiedAt,
        verifierRef: candidate.verifierRef
      },
      candidate.signature,
      digestCanonical
    );
    if (
      rebuilt === null ||
      stableJson(rebuilt) !== stableJson(candidate) ||
      !isDirectQualificationIdentity(
        candidate.verificationSetId,
        'sast-end-to-end-qualification-artifact-verification-set://'
      ) ||
      !isDigest(candidate.verificationSetDigest)
    ) {
      return false;
    }
    const payload = serializeSastEndToEndQualificationSignaturePayload(
      candidate.signature
    );
    return (
      payload !== null &&
      verifySignature(candidate.signature, payload) &&
      candidate.verifications.every((verification) => {
        const artifactPayload =
          serializeSastEndToEndQualificationSignaturePayload(
            verification.artifactSignature
          );
        return (
          artifactPayload !== null &&
          verifySignature(verification.artifactSignature, artifactPayload) &&
          isSastEndToEndQualificationArtifactProvenanceValid(
            verification.provenance,
            verifySignature,
            digestCanonical
          )
        );
      })
    );
  } catch {
    return false;
  }
}

const ENTRY_ATTESTATION_CORE_KEYS = [
  'version', 't053ManifestId', 't053ManifestDigest', 't053ResultId', 't053ResultDigest',
  't053DependencySetDigest', 'verifiedAt', 'verifierRef', 't054EntryAuthorized',
  'findingAuthority', 'policyAuthority', 'publicationAuthority', 'deploymentAuthority',
  'productionReadinessAuthority'
] as const;

export function buildSastEndToEndQualificationEntryAttestation(
  input: Omit<
    SastEndToEndQualificationEntryAttestationCore,
    'version' | 't054EntryAuthorized' | 'findingAuthority' | 'policyAuthority' |
      'publicationAuthority' | 'deploymentAuthority' | 'productionReadinessAuthority'
  >,
  signature: SastEndToEndQualificationSignature,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): SastEndToEndQualificationEntryAttestation | null {
  try {
    if (
      !hasExactKeys(input, [
        't053ManifestId', 't053ManifestDigest', 't053ResultId', 't053ResultDigest',
        't053DependencySetDigest', 'verifiedAt', 'verifierRef'
      ]) ||
      !isDirectQualificationIdentity(input.t053ManifestId, 'sast-isolated-qualification-manifest://') ||
      !isDigest(input.t053ManifestDigest) ||
      !input.t053ManifestId.endsWith(input.t053ManifestDigest.slice('sha256:'.length)) ||
      !isDirectQualificationIdentity(input.t053ResultId, 'sast-isolated-qualification-result://') ||
      !isDigest(input.t053ResultDigest) ||
      !input.t053ResultId.endsWith(input.t053ResultDigest.slice('sha256:'.length)) ||
      !isDigest(input.t053DependencySetDigest) ||
      !isIsoInstant(input.verifiedAt) ||
      !isDigestBoundReference(input.verifierRef)
    ) {
      return null;
    }
    const core: SastEndToEndQualificationEntryAttestationCore = {
      version: SAST_END_TO_END_QUALIFICATION_ENTRY_ATTESTATION_VERSION,
      ...input,
      t054EntryAuthorized: true,
      findingAuthority: false,
      policyAuthority: false,
      publicationAuthority: false,
      deploymentAuthority: false,
      productionReadinessAuthority: false
    };
    const attestationDigest = digestCanonical(stableJson(core));
    if (!isDigest(attestationDigest)) return null;
    const attestationId =
      `sast-end-to-end-qualification-entry-attestation://${attestationDigest.slice('sha256:'.length)}`;
    if (
      !isSastEndToEndQualificationSignatureValid(signature) ||
      signature.role !== 'QUALIFICATION_AUTHORITY' ||
      signature.payloadDigest !== attestationDigest ||
      signature.signedAt !== input.verifiedAt
    ) {
      return null;
    }
    return { ...core, attestationId, attestationDigest, signature };
  } catch {
    return null;
  }
}

export function isSastEndToEndQualificationEntryAttestationValid(
  value: unknown,
  t053Result: SastIsolatedQualificationResult,
  manifest: SastEndToEndQualificationManifest,
  verifySignature: SastEndToEndQualificationSignatureVerifier,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): value is SastEndToEndQualificationEntryAttestation {
  try {
    if (
      !isRecord(value) ||
      !hasExactKeys(value, [
        ...ENTRY_ATTESTATION_CORE_KEYS,
        'attestationId', 'attestationDigest', 'signature'
      ])
    ) {
      return false;
    }
    const candidate = value as unknown as SastEndToEndQualificationEntryAttestation;
    const rebuilt = buildSastEndToEndQualificationEntryAttestation(
      omitKeys(candidate, [
        'version', 't054EntryAuthorized', 'findingAuthority', 'policyAuthority',
        'publicationAuthority', 'deploymentAuthority', 'productionReadinessAuthority',
        'attestationId', 'attestationDigest', 'signature'
      ]) as Omit<
        SastEndToEndQualificationEntryAttestationCore,
        'version' | 't054EntryAuthorized' | 'findingAuthority' | 'policyAuthority' |
          'publicationAuthority' | 'deploymentAuthority' | 'productionReadinessAuthority'
      >,
      candidate.signature,
      digestCanonical
    );
    if (
      rebuilt === null ||
      stableJson(rebuilt) !== stableJson(candidate) ||
      !isSastIsolatedQualificationResultValid(t053Result, digestCanonical) ||
      t053Result.status !== 'PASSED' ||
      t053Result.t054EntryAuthorized !== true ||
      t053Result.productionReadinessAuthority !== false ||
      candidate.t053ManifestId !== manifest.t053ManifestId ||
      candidate.t053ManifestDigest !== manifest.t053ManifestDigest ||
      candidate.t053ResultId !== t053Result.resultId ||
      candidate.t053ResultDigest !== t053Result.resultDigest ||
      candidate.t053DependencySetDigest !== t053Result.dependencySetDigest ||
      Date.parse(candidate.verifiedAt) < Date.parse(t053Result.evaluatedAt) ||
      secondsBetween(t053Result.evaluatedAt, candidate.verifiedAt) >
        SAST_END_TO_END_QUALIFICATION_LIMITS.maximumEvidenceAgeSeconds
    ) {
      return false;
    }
    const payload = serializeSastEndToEndQualificationSignaturePayload(
      candidate.signature
    );
    return payload !== null && verifySignature(candidate.signature, payload);
  } catch {
    return false;
  }
}

const PLAN_CORE_KEYS = [
  'version', 'manifestId', 'manifestDigest', 'dependencySetId', 'dependencySetDigest',
  't053DependencySetId', 't053DependencySetDigest', 't053ProviderId',
  't053ProviderAdapterRef', 'artifactVerificationSetId',
  'artifactVerificationSetDigest',
  't053ResultId', 't053ResultDigest', 't053EntryAttestationId',
  't053EntryAttestationDigest', 'executionCellCount', 'requiredApprovalRoles',
  'requiredReceiptSignatureRoles', 'plannedAt', 'executionAuthority',
  'oneFreshMicroVmPerAttempt', 'sandboxReuseAllowed', 'aggregateMetricsAcceptedFromCaller',
  'customerContentAccepted', 'customerCodeExecutionAllowed', 'packageInstallAllowed',
  'repositoryBuildAllowed', 'dynamicTestAllowed', 'publicInternetEgressAllowed',
  'findingAuthority', 'policyAuthority', 'publicationAuthority', 'deploymentAuthority',
  'productionReadinessAuthority'
] as const;

export function buildSastEndToEndQualificationExecutionPlan(
  input: Readonly<{
    manifest: SastEndToEndQualificationManifest;
    t053DependencySet: SastIsolatedQualificationDependencySet;
    dependencySet: SastEndToEndQualificationDependencySet;
    artifactVerificationSet: SastEndToEndQualificationArtifactVerificationSet;
    t053Result: SastIsolatedQualificationResult;
    entryAttestation: SastEndToEndQualificationEntryAttestation;
    plannedAt: string;
    verifySignature: SastEndToEndQualificationSignatureVerifier;
  }>,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): SastEndToEndQualificationExecutionPlan | null {
  try {
    if (
      !hasExactKeys(input, [
        'manifest', 't053DependencySet', 'dependencySet',
        'artifactVerificationSet', 't053Result', 'entryAttestation', 'plannedAt',
        'verifySignature'
      ]) ||
      !isSastEndToEndQualificationManifestValid(input.manifest, digestCanonical) ||
      !isSastIsolatedQualificationDependencySetValid(
        input.t053DependencySet,
        digestCanonical
      ) ||
      !isSastEndToEndQualificationDependencySetValid(
        input.dependencySet,
        digestCanonical
      ) ||
      !isSastEndToEndQualificationArtifactVerificationSetValid(
        input.artifactVerificationSet,
        input.dependencySet,
        input.verifySignature,
        digestCanonical
      ) ||
      !isSastEndToEndQualificationEntryAttestationValid(
        input.entryAttestation,
        input.t053Result,
        input.manifest,
        input.verifySignature,
        digestCanonical
      ) ||
      !isIsoInstant(input.plannedAt) ||
      Date.parse(input.plannedAt) < Date.parse(input.entryAttestation.verifiedAt) ||
      Date.parse(input.plannedAt) <
        Date.parse(input.artifactVerificationSet.verifiedAt) ||
      Date.parse(input.plannedAt) < Date.parse(input.dependencySet.validFrom) ||
      Date.parse(input.plannedAt) > Date.parse(input.dependencySet.validUntil) ||
      Date.parse(input.plannedAt) > Date.parse(input.t053DependencySet.validUntil) ||
      input.t053DependencySet.dependencySetDigest !==
        input.t053Result.dependencySetDigest ||
      input.t053DependencySet.dependencySetDigest !==
        input.entryAttestation.t053DependencySetDigest ||
      input.t053DependencySet.providerId !== input.dependencySet.providerId ||
      input.t053DependencySet.providerAdapterRef !==
        input.dependencySet.providerAdapterRef ||
      input.dependencySet.performanceHardwareClassRef !==
        performanceHardwareClassRef(input.manifest) ||
      input.dependencySet.performanceHardwareClassDigest !==
        performanceHardwareClassDigest(input.manifest)
    ) {
      return null;
    }
    const core: SastEndToEndQualificationExecutionPlanCore = {
      version: SAST_END_TO_END_QUALIFICATION_PLAN_VERSION,
      manifestId: input.manifest.manifestId,
      manifestDigest: input.manifest.manifestDigest,
      dependencySetId: input.dependencySet.dependencySetId,
      dependencySetDigest: input.dependencySet.dependencySetDigest,
      t053DependencySetId: input.t053DependencySet.dependencySetId,
      t053DependencySetDigest: input.t053DependencySet.dependencySetDigest,
      t053ProviderId: input.t053DependencySet.providerId,
      t053ProviderAdapterRef: input.t053DependencySet.providerAdapterRef,
      artifactVerificationSetId:
        input.artifactVerificationSet.verificationSetId,
      artifactVerificationSetDigest:
        input.artifactVerificationSet.verificationSetDigest,
      t053ResultId: input.t053Result.resultId,
      t053ResultDigest: input.t053Result.resultDigest,
      t053EntryAttestationId: input.entryAttestation.attestationId,
      t053EntryAttestationDigest: input.entryAttestation.attestationDigest,
      executionCellCount: input.manifest.executionCellCount,
      requiredApprovalRoles: [...SAST_END_TO_END_QUALIFICATION_APPROVAL_ROLES],
      requiredReceiptSignatureRoles: [
        ...SAST_END_TO_END_QUALIFICATION_RECEIPT_SIGNATURE_ROLES
      ],
      plannedAt: input.plannedAt,
      executionAuthority: 'DETACHED_DUAL_APPROVAL_REQUIRED',
      oneFreshMicroVmPerAttempt: true,
      sandboxReuseAllowed: false,
      aggregateMetricsAcceptedFromCaller: false,
      customerContentAccepted: false,
      customerCodeExecutionAllowed: false,
      packageInstallAllowed: false,
      repositoryBuildAllowed: false,
      dynamicTestAllowed: false,
      publicInternetEgressAllowed: false,
      findingAuthority: false,
      policyAuthority: false,
      publicationAuthority: false,
      deploymentAuthority: false,
      productionReadinessAuthority: false
    };
    const planDigest = digestCanonical(stableJson(core));
    if (!isDigest(planDigest)) return null;
    return {
      ...core,
      planId:
        `sast-end-to-end-qualification-plan://${planDigest.slice('sha256:'.length)}`,
      planDigest
    };
  } catch {
    return null;
  }
}

export function isSastEndToEndQualificationExecutionPlanValid(
  value: unknown,
  manifest: SastEndToEndQualificationManifest,
  t053DependencySet: SastIsolatedQualificationDependencySet,
  dependencySet: SastEndToEndQualificationDependencySet,
  artifactVerificationSet: SastEndToEndQualificationArtifactVerificationSet,
  t053Result: SastIsolatedQualificationResult,
  entryAttestation: SastEndToEndQualificationEntryAttestation,
  verifySignature: SastEndToEndQualificationSignatureVerifier,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): value is SastEndToEndQualificationExecutionPlan {
  try {
    if (!isRecord(value) || !hasExactKeys(value, [...PLAN_CORE_KEYS, 'planId', 'planDigest'])) {
      return false;
    }
    const candidate = value as unknown as SastEndToEndQualificationExecutionPlan;
    const rebuilt = buildSastEndToEndQualificationExecutionPlan(
      {
        manifest,
        t053DependencySet,
        dependencySet,
        artifactVerificationSet,
        t053Result,
        entryAttestation,
        plannedAt: candidate.plannedAt,
        verifySignature
      },
      digestCanonical
    );
    return rebuilt !== null && stableJson(rebuilt) === stableJson(candidate);
  } catch {
    return false;
  }
}

const ZERO_TOLERANCE_KEYS = [
  'crossTenantLeakCount',
  'secretLeakCount',
  'sandboxEscapeCount',
  'staleExternalPublicationCount',
  'unauthorizedEgressCount',
  'missingDestructionEvidenceCount',
  'evidencePolicyViolationCount',
  'unsignedArtifactExecutionCount'
] as const;

const ATTEMPT_CORE_KEYS = [
  'version', 'attemptId', 'sandboxId', 'workloadId', 'providerAttestationRef',
  'runtimeAttestationRef', 'telemetryAttestationRef', 'startedAt', 'completedAt',
  'cleanupCompletedAt', 'outcome', 'latencyMilliseconds', 'cpuMilliseconds',
  'peakMemoryBytes', 'peakDiskBytes', 'phaseEgressCount', 'zeroToleranceCounts',
  'cleanupControls', 'cleanupComplete'
] as const;

const ATTEMPT_INPUT_KEYS = ATTEMPT_CORE_KEYS.filter((key) => key !== 'version');
const ATTEMPT_KEYS = [...ATTEMPT_CORE_KEYS, 'attemptDigest'] as const;

const PHASE_OBSERVATION_KEYS = [
  'phase',
  'status',
  'evidenceDigest'
] as const;

const RECEIPT_CORE_KEYS = [
  'version', 'manifestId', 'manifestDigest', 'dependencySetId',
  'dependencySetDigest', 'planId', 'planDigest', 'cellId', 'cellDigest',
  'cellKind', 'arm', 'caseId', 'caseDigest', 'profileId', 'profileDigest',
  'providerId', 'candidateScannerSetDigest', 'baselineScannerSetDigest',
  'hardwareClassRef', 'hardwareClassDigest', 'attempts', 'attemptSetDigest',
  'phaseObservations', 'observedControlOutcome', 'observedFindingCount',
  'matchedExpectedFindingCount', 'observedCriticalHighFindingCount',
  'matchedCriticalHighFindingCount', 'normalizedOutputDigest',
  'fingerprintDigest', 'correlationDigest', 'coverageDecisionDigest',
  'policyDecisionDigest', 'evidenceDecisionDigest', 'externalPublicationAttempted',
  'customerContentObserved', 'customerCodeExecuted', 'packageInstallObserved',
  'repositoryBuildObserved', 'dynamicTestObserved', 'publicInternetEgressObserved',
  'completedAt'
] as const;

const RECEIPT_INPUT_KEYS = RECEIPT_CORE_KEYS.filter((key) => key !== 'version');
const RECEIPT_KEYS = [...RECEIPT_CORE_KEYS, 'receiptId', 'receiptDigest'] as const;
const SIGNED_RECEIPT_KEYS = ['receipt', 'signatures'] as const;
const SIGNATURE_KEYS = [
  'version', 'role', 'keyId', 'payloadDigest', 'signedAt', 'algorithm',
  'valueBase64'
] as const;

export function buildSastEndToEndQualificationAttempt(
  input: Readonly<SastEndToEndQualificationAttemptInput>,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): SastEndToEndQualificationAttempt | null {
  try {
    if (!hasExactKeys(input, ATTEMPT_INPUT_KEYS)) return null;
    const core: SastEndToEndQualificationAttemptCore = {
      version: SAST_END_TO_END_QUALIFICATION_ATTEMPT_VERSION,
      ...input,
      zeroToleranceCounts: { ...input.zeroToleranceCounts },
      cleanupControls: [...input.cleanupControls]
    };
    if (!isAttemptCoreValid(core)) return null;
    const attemptDigest = digestCanonical(stableJson(core));
    return isDigest(attemptDigest) ? { ...core, attemptDigest } : null;
  } catch {
    return null;
  }
}

export function isSastEndToEndQualificationAttemptValid(
  value: unknown,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): value is SastEndToEndQualificationAttempt {
  try {
    if (!hasExactKeys(value, ATTEMPT_KEYS)) return false;
    const candidate = value as SastEndToEndQualificationAttempt;
    const core = attemptCore(candidate);
    return (
      isAttemptCoreValid(core) &&
      isDigest(candidate.attemptDigest) &&
      digestCanonical(stableJson(core)) === candidate.attemptDigest
    );
  } catch {
    return false;
  }
}

export function buildSastEndToEndQualificationReceipt(
  input: Readonly<SastEndToEndQualificationReceiptInput>,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): SastEndToEndQualificationReceipt | null {
  try {
    if (!hasExactKeys(input, RECEIPT_INPUT_KEYS)) return null;
    const core: SastEndToEndQualificationReceiptCore = {
      version: SAST_END_TO_END_QUALIFICATION_RECEIPT_VERSION,
      ...input,
      attempts: input.attempts.map((attempt) => ({
        ...attempt,
        zeroToleranceCounts: { ...attempt.zeroToleranceCounts },
        cleanupControls: [...attempt.cleanupControls]
      })),
      phaseObservations: input.phaseObservations.map((observation) => ({
        ...observation
      }))
    };
    if (!isReceiptCoreValid(core, digestCanonical)) return null;
    const receiptDigest = digestCanonical(stableJson(core));
    if (!isDigest(receiptDigest)) return null;
    return {
      ...core,
      receiptId:
        `sast-end-to-end-qualification-receipt://${receiptDigest.slice('sha256:'.length)}`,
      receiptDigest
    };
  } catch {
    return null;
  }
}

export function isSastEndToEndQualificationReceiptValid(
  value: unknown,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): value is SastEndToEndQualificationReceipt {
  try {
    if (!hasExactKeys(value, RECEIPT_KEYS)) return false;
    const candidate = value as SastEndToEndQualificationReceipt;
    if (
      !isDirectQualificationIdentity(
        candidate.receiptId,
        'sast-end-to-end-qualification-receipt://'
      ) ||
      !isDigest(candidate.receiptDigest)
    ) {
      return false;
    }
    const core = receiptCore(candidate);
    if (!isReceiptCoreValid(core, digestCanonical)) return false;
    const expectedDigest = digestCanonical(stableJson(core));
    return (
      candidate.receiptDigest === expectedDigest &&
      candidate.receiptId ===
        `sast-end-to-end-qualification-receipt://${expectedDigest.slice('sha256:'.length)}`
    );
  } catch {
    return false;
  }
}

export function serializeSastEndToEndQualificationSignaturePayload(
  signature: Readonly<SastEndToEndQualificationSignature>
): string | null {
  if (!isSastEndToEndQualificationSignatureValid(signature)) return null;
  return `${SAST_END_TO_END_QUALIFICATION_SIGNATURE_VERSION}\n${stableJson({
    role: signature.role,
    keyId: signature.keyId,
    payloadDigest: signature.payloadDigest,
    signedAt: signature.signedAt,
    algorithm: signature.algorithm
  })}`;
}

export function isSastEndToEndQualificationSignatureValid(
  value: unknown
): value is SastEndToEndQualificationSignature {
  if (!hasExactKeys(value, SIGNATURE_KEYS)) return false;
  const candidate = value as SastEndToEndQualificationSignature;
  return (
    candidate.version === SAST_END_TO_END_QUALIFICATION_SIGNATURE_VERSION &&
    SAST_END_TO_END_QUALIFICATION_SIGNATURE_ROLES.includes(candidate.role) &&
    typeof candidate.keyId === 'string' &&
    candidate.keyId.startsWith('qualification-key://') &&
    isDigestBoundReference(candidate.keyId) &&
    isDigest(candidate.payloadDigest) &&
    isIsoInstant(candidate.signedAt) &&
    candidate.algorithm === 'ED25519' &&
    isCanonicalEd25519Signature(candidate.valueBase64)
  );
}

function isAttemptCoreValid(value: SastEndToEndQualificationAttemptCore): boolean {
  return (
    hasExactKeys(value, ATTEMPT_CORE_KEYS) &&
    value.version === SAST_END_TO_END_QUALIFICATION_ATTEMPT_VERSION &&
    isQualificationIdentity(value.attemptId, 'qualification-attempt://') &&
    isQualificationIdentity(value.sandboxId, 'qualification-sandbox://') &&
    isQualificationIdentity(value.workloadId, 'qualification-workload://') &&
    isQualificationIdentity(
      value.providerAttestationRef,
      'provider-attestation://'
    ) &&
    isQualificationIdentity(
      value.runtimeAttestationRef,
      'runtime-attestation://'
    ) &&
    isQualificationIdentity(
      value.telemetryAttestationRef,
      'telemetry-attestation://'
    ) &&
    isIsoInstant(value.startedAt) &&
    isIsoInstant(value.completedAt) &&
    isIsoInstant(value.cleanupCompletedAt) &&
    Date.parse(value.completedAt) >= Date.parse(value.startedAt) &&
    Date.parse(value.cleanupCompletedAt) >= Date.parse(value.completedAt) &&
    value.latencyMilliseconds ===
      Date.parse(value.completedAt) - Date.parse(value.startedAt) &&
    secondsBetween(value.completedAt, value.cleanupCompletedAt) <=
      SAST_END_TO_END_QUALIFICATION_LIMITS.cleanupSloSeconds &&
    SAST_END_TO_END_QUALIFICATION_ATTEMPT_OUTCOMES.includes(value.outcome) &&
    isBoundedInteger(value.latencyMilliseconds, 0, 24 * 60 * 60 * 1_000) &&
    isBoundedInteger(value.cpuMilliseconds, 0, Number.MAX_SAFE_INTEGER) &&
    isBoundedInteger(value.peakMemoryBytes, 0, Number.MAX_SAFE_INTEGER) &&
    isBoundedInteger(value.peakDiskBytes, 0, Number.MAX_SAFE_INTEGER) &&
    value.phaseEgressCount === 0 &&
    isZeroToleranceCountsValid(value.zeroToleranceCounts) &&
    arraysEqual(
      value.cleanupControls,
      [...SAST_ISOLATED_QUALIFICATION_CLEANUP_CONTROLS]
    ) &&
    value.cleanupComplete === true
  );
}

function isReceiptCoreValid(
  value: SastEndToEndQualificationReceiptCore,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): boolean {
  if (
    !hasExactKeys(value, RECEIPT_CORE_KEYS) ||
    value.version !== SAST_END_TO_END_QUALIFICATION_RECEIPT_VERSION ||
    !isDirectQualificationIdentity(
      value.manifestId,
      'sast-end-to-end-qualification-manifest://'
    ) ||
    !isDigest(value.manifestDigest) ||
    !isDirectQualificationIdentity(
      value.dependencySetId,
      'sast-end-to-end-qualification-dependency-set://'
    ) ||
    !isDigest(value.dependencySetDigest) ||
    !isDirectQualificationIdentity(
      value.planId,
      'sast-end-to-end-qualification-plan://'
    ) ||
    !isDigest(value.planDigest) ||
    !isDirectQualificationIdentity(
      value.cellId,
      'sast-end-to-end-qualification-cell://'
    ) ||
    !isDigest(value.cellDigest) ||
    !SAST_END_TO_END_QUALIFICATION_CELL_KINDS.includes(value.cellKind) ||
    !SAST_END_TO_END_QUALIFICATION_ARMS.includes(value.arm) ||
    !isQualificationSourceCaseId(value.caseId) ||
    !isDigest(value.caseDigest) ||
    !SAST_PROFILE_IDS.includes(value.profileId) ||
    value.profileDigest !== SAST_APPROVED_PROFILE_DIGESTS[value.profileId] ||
    !isProviderId(value.providerId) ||
    !isDigest(value.candidateScannerSetDigest) ||
    !isDigest(value.baselineScannerSetDigest) ||
    value.candidateScannerSetDigest === value.baselineScannerSetDigest ||
    !isNullableDigestBoundReference(
      value.hardwareClassRef,
      value.hardwareClassDigest
    ) ||
    !Array.isArray(value.attempts) ||
    value.attempts.length < 1 ||
    value.attempts.length >
      SAST_END_TO_END_QUALIFICATION_LIMITS.maximumAttemptsPerCell ||
    value.attempts.some(
      (attempt) =>
        !isSastEndToEndQualificationAttemptValid(attempt, digestCanonical)
    ) ||
    !isAttemptChainValid(value.attempts) ||
    !isDigest(value.attemptSetDigest) ||
    digestCanonical(
      stableJson(
        value.attempts.map((attempt) => ({
          attemptId: attempt.attemptId,
          attemptDigest: attempt.attemptDigest
        }))
      )
    ) !== value.attemptSetDigest ||
    !isPhaseObservationSetValid(value.phaseObservations) ||
    !isControlOutcome(value.observedControlOutcome) ||
    !isBoundedInteger(
      value.observedFindingCount,
      0,
      SAST_SCAN_PROFILES[value.profileId].limits.maxFindings
    ) ||
    !isBoundedInteger(
      value.matchedExpectedFindingCount,
      0,
      value.observedFindingCount
    ) ||
    !isBoundedInteger(
      value.observedCriticalHighFindingCount,
      0,
      value.observedFindingCount
    ) ||
    !isBoundedInteger(
      value.matchedCriticalHighFindingCount,
      0,
      value.observedCriticalHighFindingCount
    ) ||
    !isNullableDigest(value.normalizedOutputDigest) ||
    !isNullableDigest(value.fingerprintDigest) ||
    !isNullableDigest(value.correlationDigest) ||
    !isNullableDigest(value.coverageDecisionDigest) ||
    !isNullableDigest(value.policyDecisionDigest) ||
    !isNullableDigest(value.evidenceDecisionDigest) ||
    value.externalPublicationAttempted !== false ||
    value.customerContentObserved !== false ||
    value.customerCodeExecuted !== false ||
    value.packageInstallObserved !== false ||
    value.repositoryBuildObserved !== false ||
    value.dynamicTestObserved !== false ||
    value.publicInternetEgressObserved !== false ||
    !isIsoInstant(value.completedAt) ||
    value.completedAt !== value.attempts.at(-1)?.cleanupCompletedAt
  ) {
    return false;
  }
  const finalAttempt = value.attempts.at(-1);
  if (!finalAttempt) return false;
  if (finalAttempt.outcome === 'COMPLETED') {
    return (
      value.phaseObservations.every((item) => item.status === 'PASSED') &&
      [
        value.normalizedOutputDigest,
        value.fingerprintDigest,
        value.correlationDigest,
        value.coverageDecisionDigest,
        value.policyDecisionDigest,
        value.evidenceDecisionDigest
      ].every(isDigest)
    );
  }
  return isCanonicalFailedPhaseSequence(value.phaseObservations);
}

function isAttemptChainValid(
  attempts: readonly SastEndToEndQualificationAttempt[]
): boolean {
  if (
    !unique(attempts.map((attempt) => attempt.attemptId)) ||
    !unique(attempts.map((attempt) => attempt.sandboxId)) ||
    !unique(attempts.map((attempt) => attempt.workloadId)) ||
    !unique(
      attempts.flatMap((attempt) => [
        attempt.providerAttestationRef,
        attempt.runtimeAttestationRef,
        attempt.telemetryAttestationRef
      ])
    )
  ) {
    return false;
  }
  if (attempts.length === 2 && attempts[0]?.outcome !== 'INFRASTRUCTURE_FAILURE') {
    return false;
  }
  if (attempts.length === 1 && attempts[0]?.outcome === 'INFRASTRUCTURE_FAILURE') {
    return false;
  }
  for (let index = 1; index < attempts.length; index += 1) {
    const previous = attempts[index - 1];
    const current = attempts[index];
    if (
      !previous ||
      !current ||
      Date.parse(current.startedAt) < Date.parse(previous.cleanupCompletedAt)
    ) {
      return false;
    }
  }
  return true;
}

function isPhaseObservationSetValid(
  value: unknown
): value is SastEndToEndQualificationPhaseObservation[] {
  if (
    !Array.isArray(value) ||
    value.length !== SAST_END_TO_END_QUALIFICATION_PIPELINE_PHASES.length
  ) {
    return false;
  }
  return value.every((item, index) => {
    if (!hasExactKeys(item, PHASE_OBSERVATION_KEYS)) return false;
    const candidate = item as SastEndToEndQualificationPhaseObservation;
    return (
      candidate.phase === SAST_END_TO_END_QUALIFICATION_PIPELINE_PHASES[index] &&
      SAST_END_TO_END_QUALIFICATION_PHASE_STATUSES.includes(candidate.status) &&
      (candidate.status === 'NOT_REACHED'
        ? candidate.evidenceDigest === null
        : isDigest(candidate.evidenceDigest))
    );
  });
}

function isCanonicalFailedPhaseSequence(
  observations: readonly SastEndToEndQualificationPhaseObservation[]
): boolean {
  const cleanup = observations.at(-1);
  const execution = observations.slice(0, -1);
  const failedIndex = execution.findIndex((item) => item.status === 'FAILED');
  return (
    cleanup?.phase === 'CLEANUP' &&
    cleanup.status === 'PASSED' &&
    failedIndex >= 0 &&
    execution.every((item, index) =>
      index < failedIndex
        ? item.status === 'PASSED'
        : index === failedIndex
          ? item.status === 'FAILED'
          : item.status === 'NOT_REACHED'
    )
  );
}

const MEASUREMENTS_CORE_KEYS = [
  'eligibleAttemptCount', 'completedCellCount',
  'performanceRunsPerArmProfileSizeBucket', 'goldenCorpusPassRate',
  'criticalHighPrecision', 'mustDetectRecall',
  'priorMustDetectRegressionRecall', 'candidateFalsePositiveRate',
  'baselineFalsePositiveRate', 'falsePositiveIncrease', 'scannerFailureRate',
  'fingerprintFixturePassRate', 'evidencePrivacyPassRate', 'capacityPassRate',
  'fastLaneP95Milliseconds', 'deepLaneP95Milliseconds', 'zeroToleranceCounts',
  'performanceBuckets'
] as const;

const MEASUREMENTS_KEYS = [...MEASUREMENTS_CORE_KEYS, 'measurementsDigest'] as const;
const PERFORMANCE_BUCKET_KEYS = [
  'profileId', 'scenario', 'candidateRunCount', 'baselineRunCount',
  'candidateP50Milliseconds', 'candidateP95Milliseconds',
  'baselineP50Milliseconds', 'baselineP95Milliseconds', 'p95LatencyIncrease',
  'candidateMaximumCpuMilliseconds', 'candidateMaximumMemoryBytes',
  'candidateMaximumDiskBytes'
] as const;

const RESULT_CORE_KEYS = [
  'version', 'status', 'manifestId', 'manifestDigest', 't053ResultId',
  't053ResultDigest', 'dependencySetId', 'dependencySetDigest', 'planId',
  'planDigest', 'expectedReceiptCount', 'observedReceiptCount',
  'validReceiptCount', 'measurements', 'failureReasons', 'evaluatedAt',
  't055EntryAuthorized', 'findingAuthority', 'policyAuthority',
  'publicationAuthority', 'deploymentAuthority', 'productionReadinessAuthority'
] as const;
const RESULT_KEYS = [...RESULT_CORE_KEYS, 'resultId', 'resultDigest'] as const;

const EVALUATION_INPUT_KEYS = [
  'manifest', 't053Result', 't053DependencySet', 'entryAttestation',
  'dependencySet', 'artifactVerificationSet', 'plan', 'approvals',
  'signedReceipts', 'trustedEvaluatedAt', 'verifySignature'
] as const;

export function evaluateSastEndToEndQualificationEvidence(
  input: Readonly<SastEndToEndQualificationEvaluationInput>,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): SastEndToEndQualificationResult | null {
  try {
    if (
      !hasExactKeys(input, EVALUATION_INPUT_KEYS) ||
      !isSastEndToEndQualificationManifestValid(input.manifest, digestCanonical) ||
      !Array.isArray(input.approvals) ||
      !Array.isArray(input.signedReceipts) ||
      !isIsoInstant(input.trustedEvaluatedAt) ||
      typeof input.verifySignature !== 'function'
    ) {
      return null;
    }

    const downstreamEvidencePresent =
      input.t053DependencySet !== null ||
      input.entryAttestation !== null ||
      input.dependencySet !== null ||
      input.artifactVerificationSet !== null ||
      input.plan !== null ||
      input.approvals.length > 0 ||
      input.signedReceipts.length > 0;
    const t053Valid =
      input.t053Result !== null &&
      isSastIsolatedQualificationResultValid(input.t053Result, digestCanonical);
    if (
      input.t053Result === null ||
      (t053Valid && input.t053Result?.status !== 'PASSED')
    ) {
      if (!downstreamEvidencePresent) {
        return buildEndToEndResult(
          {
            version: SAST_END_TO_END_QUALIFICATION_RESULT_VERSION,
            status: 'BLOCKED_T053_QUALIFICATION',
            manifestId: input.manifest.manifestId,
            manifestDigest: input.manifest.manifestDigest,
            t053ResultId: t053Valid ? input.t053Result?.resultId ?? null : null,
            t053ResultDigest: t053Valid
              ? input.t053Result?.resultDigest ?? null
              : null,
            dependencySetId: null,
            dependencySetDigest: null,
            planId: null,
            planDigest: null,
            expectedReceiptCount: input.manifest.executionCellCount,
            observedReceiptCount: 0,
            validReceiptCount: 0,
            measurements: null,
            failureReasons: [],
            evaluatedAt: input.trustedEvaluatedAt,
            t055EntryAuthorized: false,
            findingAuthority: false,
            policyAuthority: false,
            publicationAuthority: false,
            deploymentAuthority: false,
            productionReadinessAuthority: false
          },
          digestCanonical
        );
      }
      return failedResult(
        input,
        ['T053_ENTRY_INVALID'],
        0,
        null,
        digestCanonical
      );
    }

    if (!t053Valid || !input.t053Result) {
      return failedResult(
        input,
        ['T053_ENTRY_INVALID'],
        0,
        null,
        digestCanonical
      );
    }

    const failureReasons: SastEndToEndQualificationFailureReason[] = [];
    const t053DependencyValid =
      input.t053DependencySet !== null &&
      isSastIsolatedQualificationDependencySetValid(
        input.t053DependencySet,
        digestCanonical
      ) &&
      input.t053DependencySet.dependencySetDigest ===
        input.t053Result.dependencySetDigest;
    if (!t053DependencyValid) failureReasons.push('T053_ENTRY_INVALID');

    const entryValid =
      input.entryAttestation !== null &&
      isSastEndToEndQualificationEntryAttestationValid(
        input.entryAttestation,
        input.t053Result,
        input.manifest,
        input.verifySignature,
        digestCanonical
      );
    if (!entryValid) failureReasons.push('T053_ENTRY_INVALID');

    const dependencyValid =
      input.dependencySet !== null &&
      isSastEndToEndQualificationDependencySetValid(
        input.dependencySet,
        digestCanonical
      );
    if (!dependencyValid) failureReasons.push('DEPENDENCY_SET_INVALID');

    const artifactVerificationValid =
      dependencyValid &&
      input.artifactVerificationSet !== null &&
      isSastEndToEndQualificationArtifactVerificationSetValid(
        input.artifactVerificationSet,
        input.dependencySet as SastEndToEndQualificationDependencySet,
        input.verifySignature,
        digestCanonical
      );
    if (!artifactVerificationValid) {
      failureReasons.push('ARTIFACT_VERIFICATION_INVALID');
    }

    const providerBindingValid =
      t053DependencyValid &&
      dependencyValid &&
      input.t053DependencySet?.providerId === input.dependencySet?.providerId &&
      input.t053DependencySet?.providerAdapterRef ===
        input.dependencySet?.providerAdapterRef;
    if (!providerBindingValid) failureReasons.push('PROVIDER_MISMATCH');

    const planValid =
      t053DependencyValid &&
      entryValid &&
      dependencyValid &&
      artifactVerificationValid &&
      providerBindingValid &&
      input.plan !== null &&
      isSastEndToEndQualificationExecutionPlanValid(
        input.plan,
        input.manifest,
        input.t053DependencySet as SastIsolatedQualificationDependencySet,
        input.dependencySet as SastEndToEndQualificationDependencySet,
        input.artifactVerificationSet as SastEndToEndQualificationArtifactVerificationSet,
        input.t053Result,
        input.entryAttestation as SastEndToEndQualificationEntryAttestation,
        input.verifySignature,
        digestCanonical
      );
    if (!planValid) failureReasons.push('EXECUTION_PLAN_INVALID');

    if (
      !t053DependencyValid ||
      !entryValid ||
      !dependencyValid ||
      !artifactVerificationValid ||
      !providerBindingValid ||
      !planValid
    ) {
      if (input.approvals.length > 0) failureReasons.push('APPROVAL_SET_INVALID');
      if (input.signedReceipts.length > 0) failureReasons.push('RECEIPT_INVALID');
      return failedResult(
        input,
        failureReasons,
        0,
        null,
        digestCanonical
      );
    }

    const dependencySet =
      input.dependencySet as SastEndToEndQualificationDependencySet;
    const plan = input.plan as SastEndToEndQualificationExecutionPlan;
    const evaluatedAtMs = Date.parse(input.trustedEvaluatedAt);
    if (evaluatedAtMs < Date.parse(dependencySet.validFrom)) {
      failureReasons.push('TIMESTAMP_INVALID');
    }
    if (evaluatedAtMs > Date.parse(dependencySet.validUntil)) {
      failureReasons.push('EVIDENCE_STALE');
    }
    const earliestReceiptStart = earliestReceiptStartMilliseconds(
      input.signedReceipts,
      digestCanonical
    );
    const approvalsRequired = input.signedReceipts.length > 0;
    const approvalsValid =
      (!approvalsRequired && input.approvals.length === 0) ||
      isSignatureSetValid(
        input.approvals,
        SAST_END_TO_END_QUALIFICATION_APPROVAL_ROLES,
        plan.planDigest as Sha256Digest,
        plan.plannedAt,
        input.trustedEvaluatedAt,
        input.verifySignature
      );
    if (
      !approvalsValid ||
      (earliestReceiptStart !== null &&
        input.approvals.some(
          (approval) => Date.parse(approval.signedAt) >= earliestReceiptStart
        ))
    ) {
      failureReasons.push('APPROVAL_SET_INVALID');
    }

    if (
      input.signedReceipts.length >
      SAST_END_TO_END_QUALIFICATION_LIMITS.maximumReceiptCount
    ) {
      failureReasons.push('RECEIPT_INVALID');
    }

    const acceptedReceipts: SastEndToEndQualificationReceipt[] = [];
    const seenReceiptIds = new Set<string>();
    const seenReceiptDigests = new Set<string>();
    const seenCellIds = new Set<string>();
    const seenAttemptIds = new Set<string>();
    const seenSandboxIds = new Set<string>();
    const seenWorkloadIds = new Set<string>();
    const seenAttestationRefs = new Set<string>();

    for (const signedReceipt of input.signedReceipts.slice(
      0,
      SAST_END_TO_END_QUALIFICATION_LIMITS.maximumReceiptCount
    )) {
      if (!hasExactKeys(signedReceipt, SIGNED_RECEIPT_KEYS)) {
        failureReasons.push('RECEIPT_INVALID');
        continue;
      }
      const receipt = signedReceipt.receipt;
      if (!isSastEndToEndQualificationReceiptValid(receipt, digestCanonical)) {
        failureReasons.push('RECEIPT_INVALID');
        continue;
      }
      let receiptAccepted = true;
      const cell = input.manifest.cells.find((item) => item.cellId === receipt.cellId);
      if (!cell || !isReceiptBoundToExecution(receipt, cell, plan, dependencySet)) {
        failureReasons.push('CELL_BINDING_INVALID');
        receiptAccepted = false;
      }
      if (receipt.providerId !== dependencySet.providerId) {
        failureReasons.push('PROVIDER_MISMATCH');
        receiptAccepted = false;
      }
      if (
        !isSignatureSetValid(
          signedReceipt.signatures,
          SAST_END_TO_END_QUALIFICATION_RECEIPT_SIGNATURE_ROLES,
          receipt.receiptDigest as Sha256Digest,
          receipt.completedAt,
          input.trustedEvaluatedAt,
          input.verifySignature
        )
      ) {
        failureReasons.push('RECEIPT_SIGNATURE_INVALID');
        receiptAccepted = false;
      }

      const receiptDuplicate =
        seenReceiptIds.has(receipt.receiptId) ||
        seenReceiptDigests.has(receipt.receiptDigest) ||
        seenCellIds.has(receipt.cellId);
      if (receiptDuplicate) {
        failureReasons.push('RECEIPT_DUPLICATE');
        receiptAccepted = false;
      }
      seenReceiptIds.add(receipt.receiptId);
      seenReceiptDigests.add(receipt.receiptDigest);
      seenCellIds.add(receipt.cellId);

      for (const attempt of receipt.attempts) {
        const identities = [
          [seenAttemptIds, attempt.attemptId],
          [seenSandboxIds, attempt.sandboxId],
          [seenWorkloadIds, attempt.workloadId]
        ] as const;
        for (const [seen, identity] of identities) {
          if (seen.has(identity)) {
            failureReasons.push('IDENTITY_REUSED');
            receiptAccepted = false;
          }
          seen.add(identity);
        }
        for (const reference of [
          attempt.providerAttestationRef,
          attempt.runtimeAttestationRef,
          attempt.telemetryAttestationRef
        ]) {
          if (seenAttestationRefs.has(reference)) {
            failureReasons.push('IDENTITY_REUSED');
            receiptAccepted = false;
          }
          seenAttestationRefs.add(reference);
        }
      }

      const receiptReasons = receiptFailureReasons(
        receipt,
        cell ?? null,
        plan,
        dependencySet,
        input.trustedEvaluatedAt
      );
      failureReasons.push(...receiptReasons);
      if (receiptAccepted) acceptedReceipts.push(receipt);
    }

    let measurements: SastEndToEndQualificationMeasurements | null = null;
    if (
      acceptedReceipts.length === input.manifest.executionCellCount &&
      seenCellIds.size === input.manifest.executionCellCount
    ) {
      measurements = recomputeMeasurements(
        input.manifest,
        acceptedReceipts,
        digestCanonical
      );
      if (measurements === null) {
        failureReasons.push('SAMPLE_INCOMPLETE');
      } else {
        failureReasons.push(...measurementFailureReasons(measurements));
      }
    }

    const canonicalFailures = canonicalFailureReasons(failureReasons);
    const status: SastEndToEndQualificationStatus =
      canonicalFailures.length > 0
        ? 'FAILED'
        : acceptedReceipts.length === input.manifest.executionCellCount &&
            measurements !== null
          ? 'PASSED'
          : 'PENDING_PROVIDER_EXECUTION';
    return buildEndToEndResult(
      {
        version: SAST_END_TO_END_QUALIFICATION_RESULT_VERSION,
        status,
        manifestId: input.manifest.manifestId,
        manifestDigest: input.manifest.manifestDigest,
        t053ResultId: input.t053Result.resultId,
        t053ResultDigest: input.t053Result.resultDigest,
        dependencySetId: dependencySet.dependencySetId,
        dependencySetDigest: dependencySet.dependencySetDigest,
        planId: plan.planId,
        planDigest: plan.planDigest,
        expectedReceiptCount: input.manifest.executionCellCount,
        observedReceiptCount: input.signedReceipts.length,
        validReceiptCount: acceptedReceipts.length,
        measurements,
        failureReasons: canonicalFailures,
        evaluatedAt: input.trustedEvaluatedAt,
        t055EntryAuthorized: status === 'PASSED',
        findingAuthority: false,
        policyAuthority: false,
        publicationAuthority: false,
        deploymentAuthority: false,
        productionReadinessAuthority: false
      },
      digestCanonical
    );
  } catch {
    return null;
  }
}

export function isSastEndToEndQualificationResultValid(
  value: unknown,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): value is SastEndToEndQualificationResult {
  try {
    if (!hasExactKeys(value, RESULT_KEYS)) return false;
    const candidate = value as SastEndToEndQualificationResult;
    if (
      !isDirectQualificationIdentity(
        candidate.resultId,
        'sast-end-to-end-qualification-result://'
      ) ||
      !isDigest(candidate.resultDigest)
    ) {
      return false;
    }
    const core = resultCore(candidate);
    if (!isResultCoreValid(core, digestCanonical)) return false;
    const expectedDigest = digestCanonical(stableJson(core));
    return (
      candidate.resultDigest === expectedDigest &&
      candidate.resultId ===
        `sast-end-to-end-qualification-result://${expectedDigest.slice('sha256:'.length)}`
    );
  } catch {
    return false;
  }
}

function failedResult(
  input: Readonly<SastEndToEndQualificationEvaluationInput>,
  reasons: readonly SastEndToEndQualificationFailureReason[],
  validReceiptCount: number,
  measurements: SastEndToEndQualificationMeasurements | null,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): SastEndToEndQualificationResult | null {
  const t053Valid =
    input.t053Result !== null &&
    isSastIsolatedQualificationResultValid(input.t053Result, digestCanonical);
  const dependencyValid =
    input.dependencySet !== null &&
    isSastEndToEndQualificationDependencySetValid(
      input.dependencySet,
      digestCanonical
    );
  const planIdentityValid =
    input.plan !== null &&
    isDirectQualificationIdentity(
      input.plan.planId,
      'sast-end-to-end-qualification-plan://'
    ) &&
    isDigest(input.plan.planDigest) &&
    input.plan.planId.endsWith(
      input.plan.planDigest.slice('sha256:'.length)
    );
  return buildEndToEndResult(
    {
      version: SAST_END_TO_END_QUALIFICATION_RESULT_VERSION,
      status: 'FAILED',
      manifestId: input.manifest.manifestId,
      manifestDigest: input.manifest.manifestDigest,
      t053ResultId: t053Valid ? input.t053Result?.resultId ?? null : null,
      t053ResultDigest: t053Valid ? input.t053Result?.resultDigest ?? null : null,
      dependencySetId: dependencyValid
        ? input.dependencySet?.dependencySetId ?? null
        : null,
      dependencySetDigest: dependencyValid
        ? input.dependencySet?.dependencySetDigest ?? null
        : null,
      planId: planIdentityValid ? input.plan?.planId ?? null : null,
      planDigest: planIdentityValid ? input.plan?.planDigest ?? null : null,
      expectedReceiptCount: input.manifest.executionCellCount,
      observedReceiptCount: input.signedReceipts.length,
      validReceiptCount,
      measurements,
      failureReasons: canonicalFailureReasons(reasons),
      evaluatedAt: input.trustedEvaluatedAt,
      t055EntryAuthorized: false,
      findingAuthority: false,
      policyAuthority: false,
      publicationAuthority: false,
      deploymentAuthority: false,
      productionReadinessAuthority: false
    },
    digestCanonical
  );
}

function buildEndToEndResult(
  core: SastEndToEndQualificationResultCore,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): SastEndToEndQualificationResult | null {
  if (!isResultCoreValid(core, digestCanonical)) return null;
  const resultDigest = digestCanonical(stableJson(core));
  if (!isDigest(resultDigest)) return null;
  return {
    ...core,
    resultId:
      `sast-end-to-end-qualification-result://${resultDigest.slice('sha256:'.length)}`,
    resultDigest
  };
}

function recomputeMeasurements(
  manifest: SastEndToEndQualificationManifest,
  receipts: readonly SastEndToEndQualificationReceipt[],
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): SastEndToEndQualificationMeasurements | null {
  const receiptByCell = new Map(receipts.map((receipt) => [receipt.cellId, receipt]));
  if (
    receiptByCell.size !== manifest.executionCellCount ||
    manifest.cells.some((cell) => !receiptByCell.has(cell.cellId))
  ) {
    return null;
  }
  const bound = manifest.cells.map((cell) => ({
    cell,
    receipt: receiptByCell.get(cell.cellId) as SastEndToEndQualificationReceipt
  }));
  const completed = bound.filter(
    ({ receipt }) => receipt.attempts.at(-1)?.outcome === 'COMPLETED'
  );
  const attempts = receipts.flatMap((receipt) => receipt.attempts);
  if (attempts.length === 0) return null;

  const golden = bound.filter(
    ({ cell }) => cell.cellKind === 'GOLDEN_CANDIDATE'
  );
  const goldenConforming = golden.filter(({ cell, receipt }) =>
    isGoldenCellConforming(cell, receipt)
  ).length;
  const mustDetect = golden.filter(
    ({ cell }) => cell.expectedOutcome === 'DETECT'
  );
  const detectedMustDetect = mustDetect.filter(
    ({ cell, receipt }) =>
      isCompletedReceipt(receipt) &&
      receipt.observedControlOutcome === cell.expectedOutcome &&
      receipt.matchedExpectedFindingCount >= 1
  ).length;
  const priorMustDetect = mustDetect.filter(({ cell }) => cell.priorMustDetect);
  const detectedPriorMustDetect = priorMustDetect.filter(
    ({ cell, receipt }) =>
      isCompletedReceipt(receipt) &&
      receipt.observedControlOutcome === cell.expectedOutcome &&
      receipt.matchedExpectedFindingCount >= 1
  ).length;
  const observedCriticalHigh = golden.reduce(
    (total, { receipt }) => total + receipt.observedCriticalHighFindingCount,
    0
  );
  const matchedCriticalHigh = golden.reduce(
    (total, { receipt }) => total + receipt.matchedCriticalHighFindingCount,
    0
  );
  const candidateNegatives = bound.filter(
    ({ cell }) =>
      cell.cellKind === 'GOLDEN_CANDIDATE' &&
      cell.expectedOutcome === 'NO_FINDING'
  );
  const baselineNegatives = bound.filter(
    ({ cell }) => cell.cellKind === 'GOLDEN_NEGATIVE_BASELINE'
  );
  const candidateFalsePositiveRate = ratio(
    candidateNegatives.filter(({ receipt }) => receipt.observedFindingCount > 0)
      .length,
    candidateNegatives.length
  );
  const baselineFalsePositiveRate = ratio(
    baselineNegatives.filter(({ receipt }) => receipt.observedFindingCount > 0)
      .length,
    baselineNegatives.length
  );
  const fingerprint = bound.filter(
    ({ cell }) =>
      cell.cellKind === 'END_TO_END_CANDIDATE' &&
      cell.corpusClass === 'FINGERPRINT_CORRELATION'
  );
  const evidencePrivacy = bound.filter(
    ({ cell }) =>
      cell.cellKind === 'END_TO_END_CANDIDATE' &&
      cell.corpusClass === 'EVIDENCE_PRIVACY'
  );
  const performance = bound.filter(({ cell }) =>
    cell.cellKind.startsWith('PERFORMANCE_')
  );
  const performanceBuckets = buildPerformanceMeasurements(performance);
  if (
    golden.length !==
      SAST_END_TO_END_QUALIFICATION_LIMITS.expectedGoldenCandidateCellCount ||
    candidateNegatives.length !==
      SAST_END_TO_END_QUALIFICATION_LIMITS.expectedGoldenNegativeBaselineCellCount ||
    baselineNegatives.length !==
      SAST_END_TO_END_QUALIFICATION_LIMITS.expectedGoldenNegativeBaselineCellCount ||
    mustDetect.length === 0 ||
    priorMustDetect.length === 0 ||
    observedCriticalHigh === 0 ||
    fingerprint.length === 0 ||
    evidencePrivacy.length === 0 ||
    performanceBuckets === null
  ) {
    return null;
  }

  const zeroToleranceCounts = emptyZeroToleranceCounts();
  for (const attempt of attempts) {
    for (const key of ZERO_TOLERANCE_KEYS) {
      zeroToleranceCounts[key] += attempt.zeroToleranceCounts[key];
    }
  }
  const candidatePerformance = performance.filter(
    ({ cell }) => cell.arm === 'CANDIDATE'
  );
  const fastLatencies = candidatePerformance
    .filter(({ cell }) => SAST_SCAN_PROFILES[cell.profileId].lane === 'FAST')
    .map(({ receipt }) => receiptLatencyMilliseconds(receipt));
  const deepLatencies = candidatePerformance
    .filter(({ cell }) => SAST_SCAN_PROFILES[cell.profileId].lane === 'DEEP')
    .map(({ receipt }) => receiptLatencyMilliseconds(receipt));
  if (fastLatencies.length === 0 || deepLatencies.length === 0) return null;

  const core: Omit<
    SastEndToEndQualificationMeasurements,
    'measurementsDigest'
  > = {
    eligibleAttemptCount: attempts.length,
    completedCellCount: completed.length,
    performanceRunsPerArmProfileSizeBucket: Math.min(
      ...performanceBuckets.flatMap((bucket) => [
        bucket.candidateRunCount,
        bucket.baselineRunCount
      ])
    ),
    goldenCorpusPassRate: ratio(goldenConforming, golden.length),
    criticalHighPrecision: ratio(matchedCriticalHigh, observedCriticalHigh),
    mustDetectRecall: ratio(detectedMustDetect, mustDetect.length),
    priorMustDetectRegressionRecall: ratio(
      detectedPriorMustDetect,
      priorMustDetect.length
    ),
    candidateFalsePositiveRate,
    baselineFalsePositiveRate,
    falsePositiveIncrease:
      candidateFalsePositiveRate - baselineFalsePositiveRate,
    scannerFailureRate: ratio(
      attempts.filter((attempt) => attempt.outcome !== 'COMPLETED').length,
      attempts.length
    ),
    fingerprintFixturePassRate: ratio(
      fingerprint.filter(({ cell, receipt }) =>
        isControlCellConforming(cell, receipt)
      ).length,
      fingerprint.length
    ),
    evidencePrivacyPassRate: ratio(
      evidencePrivacy.filter(({ cell, receipt }) =>
        isControlCellConforming(cell, receipt)
      ).length,
      evidencePrivacy.length
    ),
    capacityPassRate: ratio(
      performance.filter(({ receipt }) => isCompletedReceipt(receipt)).length,
      performance.length
    ),
    fastLaneP95Milliseconds: nearestRank(fastLatencies, 0.95),
    deepLaneP95Milliseconds: nearestRank(deepLatencies, 0.95),
    zeroToleranceCounts,
    performanceBuckets
  };
  const measurementsDigest = digestCanonical(stableJson(core));
  return isDigest(measurementsDigest)
    ? { ...core, measurementsDigest }
    : null;
}

function buildPerformanceMeasurements(
  values: readonly {
    cell: SastEndToEndQualificationCell;
    receipt: SastEndToEndQualificationReceipt;
  }[]
): SastEndToEndQualificationPerformanceBucketMeasurement[] | null {
  const keys = [
    ...new Set(
      values.map(({ cell }) => `${cell.profileId}\u0000${cell.scenario ?? ''}`)
    )
  ].sort(compareText);
  if (
    keys.length !== SAST_END_TO_END_QUALIFICATION_LIMITS.expectedPerformanceBucketCount
  ) {
    return null;
  }
  const output: SastEndToEndQualificationPerformanceBucketMeasurement[] = [];
  for (const key of keys) {
    const [profileId, scenario] = key.split('\u0000') as [SastProfileId, string];
    const candidate = values.filter(
      ({ cell }) =>
        cell.profileId === profileId &&
        cell.scenario === scenario &&
        cell.arm === 'CANDIDATE'
    );
    const baseline = values.filter(
      ({ cell }) =>
        cell.profileId === profileId &&
        cell.scenario === scenario &&
        cell.arm === 'BASELINE'
    );
    if (
      candidate.length !==
        SAST_END_TO_END_QUALIFICATION_LIMITS.requiredPerformanceRunsPerArmBucket ||
      baseline.length !==
        SAST_END_TO_END_QUALIFICATION_LIMITS.requiredPerformanceRunsPerArmBucket ||
      !SAST_PROFILE_IDS.includes(profileId) ||
      scenario.length === 0
    ) {
      return null;
    }
    const candidateLatency = candidate.map(({ receipt }) =>
      receiptLatencyMilliseconds(receipt)
    );
    const baselineLatency = baseline.map(({ receipt }) =>
      receiptLatencyMilliseconds(receipt)
    );
    const candidateP95 = nearestRank(candidateLatency, 0.95);
    const baselineP95 = nearestRank(baselineLatency, 0.95);
    if (baselineP95 <= 0) return null;
    const candidateAttempts = candidate.flatMap(({ receipt }) => receipt.attempts);
    output.push({
      profileId,
      scenario,
      candidateRunCount: candidate.length,
      baselineRunCount: baseline.length,
      candidateP50Milliseconds: nearestRank(candidateLatency, 0.5),
      candidateP95Milliseconds: candidateP95,
      baselineP50Milliseconds: nearestRank(baselineLatency, 0.5),
      baselineP95Milliseconds: baselineP95,
      p95LatencyIncrease: candidateP95 / baselineP95 - 1,
      candidateMaximumCpuMilliseconds: Math.max(
        ...candidateAttempts.map((attempt) => attempt.cpuMilliseconds)
      ),
      candidateMaximumMemoryBytes: Math.max(
        ...candidateAttempts.map((attempt) => attempt.peakMemoryBytes)
      ),
      candidateMaximumDiskBytes: Math.max(
        ...candidateAttempts.map((attempt) => attempt.peakDiskBytes)
      )
    });
  }
  return output;
}

function measurementFailureReasons(
  value: SastEndToEndQualificationMeasurements
): SastEndToEndQualificationFailureReason[] {
  const reasons: SastEndToEndQualificationFailureReason[] = [];
  if (
    value.completedCellCount !==
      SAST_END_TO_END_QUALIFICATION_LIMITS.expectedCellCount ||
    value.performanceRunsPerArmProfileSizeBucket !==
      SAST_END_TO_END_QUALIFICATION_LIMITS.requiredPerformanceRunsPerArmBucket
  ) {
    reasons.push('SAMPLE_INCOMPLETE');
  }
  if (value.goldenCorpusPassRate !== 1) {
    reasons.push('GOLDEN_CONFORMANCE_FAILED');
  }
  if (value.mustDetectRecall < 0.95) reasons.push('MUST_DETECT_RECALL_FAILED');
  if (value.criticalHighPrecision < 0.9) {
    reasons.push('CRITICAL_HIGH_PRECISION_FAILED');
  }
  if (value.priorMustDetectRegressionRecall !== 1) {
    reasons.push('PRIOR_MUST_DETECT_FAILED');
  }
  if (value.falsePositiveIncrease > 0.02) {
    reasons.push('FALSE_POSITIVE_REGRESSION');
  }
  if (value.scannerFailureRate > 0.02) {
    reasons.push('SCANNER_FAILURE_RATE_EXCEEDED');
  }
  if (
    value.performanceBuckets.some((bucket) => bucket.p95LatencyIncrease > 0.2)
  ) {
    reasons.push('LATENCY_REGRESSION');
  }
  if (
    value.fastLaneP95Milliseconds > 10 * 60 * 1_000 ||
    value.deepLaneP95Milliseconds > 45 * 60 * 1_000 ||
    value.performanceBuckets.some(
      (bucket) =>
        bucket.candidateP95Milliseconds >
        (SAST_SCAN_PROFILES[bucket.profileId].lane === 'FAST'
          ? 10 * 60 * 1_000
          : 45 * 60 * 1_000)
    )
  ) {
    reasons.push('ABSOLUTE_SLO_EXCEEDED');
  }
  if (value.fingerprintFixturePassRate !== 1) {
    reasons.push('FINGERPRINT_CORRELATION_FAILED');
  }
  if (value.evidencePrivacyPassRate !== 1) {
    reasons.push('EVIDENCE_PRIVACY_FAILED');
  }
  if (value.capacityPassRate !== 1) reasons.push('CAPACITY_GATE_FAILED');
  if (ZERO_TOLERANCE_KEYS.some((key) => value.zeroToleranceCounts[key] !== 0)) {
    reasons.push('ZERO_TOLERANCE_EVENT');
  }
  return canonicalFailureReasons(reasons);
}

function isResultCoreValid(
  value: SastEndToEndQualificationResultCore,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): boolean {
  if (
    !hasExactKeys(value, RESULT_CORE_KEYS) ||
    value.version !== SAST_END_TO_END_QUALIFICATION_RESULT_VERSION ||
    !SAST_END_TO_END_QUALIFICATION_STATUSES.includes(value.status) ||
    !isDirectQualificationIdentity(
      value.manifestId,
      'sast-end-to-end-qualification-manifest://'
    ) ||
    !isDigest(value.manifestDigest) ||
    !isNullableIdentityDigestPair(
      value.t053ResultId,
      value.t053ResultDigest,
      'sast-isolated-qualification-result://'
    ) ||
    !isNullableIdentityDigestPair(
      value.dependencySetId,
      value.dependencySetDigest,
      'sast-end-to-end-qualification-dependency-set://'
    ) ||
    !isNullableIdentityDigestPair(
      value.planId,
      value.planDigest,
      'sast-end-to-end-qualification-plan://'
    ) ||
    value.expectedReceiptCount !==
      SAST_END_TO_END_QUALIFICATION_LIMITS.expectedCellCount ||
    !isBoundedInteger(value.observedReceiptCount, 0, Number.MAX_SAFE_INTEGER) ||
    !isBoundedInteger(
      value.validReceiptCount,
      0,
      SAST_END_TO_END_QUALIFICATION_LIMITS.expectedCellCount
    ) ||
    (value.measurements !== null &&
      !isMeasurementsValid(value.measurements, digestCanonical)) ||
    !Array.isArray(value.failureReasons) ||
    value.failureReasons.length >
      SAST_END_TO_END_QUALIFICATION_LIMITS.maximumFailureReasons ||
    value.failureReasons.some(
      (reason) => !SAST_END_TO_END_QUALIFICATION_FAILURE_REASONS.includes(reason)
    ) ||
    !arraysEqual(
      value.failureReasons,
      canonicalFailureReasons(value.failureReasons)
    ) ||
    !isIsoInstant(value.evaluatedAt) ||
    value.findingAuthority !== false ||
    value.policyAuthority !== false ||
    value.publicationAuthority !== false ||
    value.deploymentAuthority !== false ||
    value.productionReadinessAuthority !== false
  ) {
    return false;
  }
  if (value.status === 'BLOCKED_T053_QUALIFICATION') {
    return (
      value.dependencySetId === null &&
      value.planId === null &&
      value.observedReceiptCount === 0 &&
      value.validReceiptCount === 0 &&
      value.measurements === null &&
      value.failureReasons.length === 0 &&
      value.t055EntryAuthorized === false
    );
  }
  if (value.status === 'PENDING_PROVIDER_EXECUTION') {
    return (
      value.t053ResultId !== null &&
      value.dependencySetId !== null &&
      value.planId !== null &&
      value.validReceiptCount < value.expectedReceiptCount &&
      value.measurements === null &&
      value.failureReasons.length === 0 &&
      value.t055EntryAuthorized === false
    );
  }
  if (value.status === 'PASSED') {
    return (
      value.t053ResultId !== null &&
      value.dependencySetId !== null &&
      value.planId !== null &&
      value.observedReceiptCount === value.expectedReceiptCount &&
      value.validReceiptCount === value.expectedReceiptCount &&
      value.measurements !== null &&
      measurementFailureReasons(value.measurements).length === 0 &&
      value.failureReasons.length === 0 &&
      value.t055EntryAuthorized === true
    );
  }
  return value.failureReasons.length > 0 && value.t055EntryAuthorized === false;
}

function isMeasurementsValid(
  value: unknown,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): value is SastEndToEndQualificationMeasurements {
  if (!hasExactKeys(value, MEASUREMENTS_KEYS)) return false;
  const candidate = value as SastEndToEndQualificationMeasurements;
  if (
    !isBoundedInteger(candidate.eligibleAttemptCount, 1, 6_924) ||
    !isBoundedInteger(
      candidate.completedCellCount,
      0,
      SAST_END_TO_END_QUALIFICATION_LIMITS.expectedCellCount
    ) ||
    !isBoundedInteger(candidate.performanceRunsPerArmProfileSizeBucket, 0, 30) ||
    ![
      candidate.goldenCorpusPassRate,
      candidate.criticalHighPrecision,
      candidate.mustDetectRecall,
      candidate.priorMustDetectRegressionRecall,
      candidate.candidateFalsePositiveRate,
      candidate.baselineFalsePositiveRate,
      candidate.scannerFailureRate,
      candidate.fingerprintFixturePassRate,
      candidate.evidencePrivacyPassRate,
      candidate.capacityPassRate
    ].every(isRate) ||
    !isFiniteNumber(candidate.falsePositiveIncrease) ||
    candidate.falsePositiveIncrease < -1 ||
    candidate.falsePositiveIncrease > 1 ||
    !isBoundedInteger(
      candidate.fastLaneP95Milliseconds,
      0,
      Number.MAX_SAFE_INTEGER
    ) ||
    !isBoundedInteger(
      candidate.deepLaneP95Milliseconds,
      0,
      Number.MAX_SAFE_INTEGER
    ) ||
    !isZeroToleranceCountsValid(candidate.zeroToleranceCounts) ||
    !Array.isArray(candidate.performanceBuckets) ||
    candidate.performanceBuckets.length !==
      SAST_END_TO_END_QUALIFICATION_LIMITS.expectedPerformanceBucketCount ||
    candidate.performanceBuckets.some((bucket) =>
      !isPerformanceBucketValid(bucket)
    ) ||
    !isDigest(candidate.measurementsDigest)
  ) {
    return false;
  }
  const core = omitKeys(candidate, ['measurementsDigest']);
  return digestCanonical(stableJson(core)) === candidate.measurementsDigest;
}

function isPerformanceBucketValid(value: unknown): boolean {
  if (!hasExactKeys(value, PERFORMANCE_BUCKET_KEYS)) return false;
  const candidate = value as SastEndToEndQualificationPerformanceBucketMeasurement;
  return (
    SAST_PROFILE_IDS.includes(candidate.profileId) &&
    isControlOutcome(candidate.scenario) &&
    candidate.candidateRunCount === 30 &&
    candidate.baselineRunCount === 30 &&
    [
      candidate.candidateP50Milliseconds,
      candidate.candidateP95Milliseconds,
      candidate.baselineP50Milliseconds,
      candidate.baselineP95Milliseconds,
      candidate.candidateMaximumCpuMilliseconds,
      candidate.candidateMaximumMemoryBytes,
      candidate.candidateMaximumDiskBytes
    ].every((item) => isBoundedInteger(item, 0, Number.MAX_SAFE_INTEGER)) &&
    candidate.baselineP95Milliseconds > 0 &&
    isFiniteNumber(candidate.p95LatencyIncrease) &&
    candidate.p95LatencyIncrease >= -1
  );
}

function isReceiptBoundToExecution(
  receipt: SastEndToEndQualificationReceipt,
  cell: SastEndToEndQualificationCell,
  plan: SastEndToEndQualificationExecutionPlan,
  dependencySet: SastEndToEndQualificationDependencySet
): boolean {
  return (
    receipt.manifestId === plan.manifestId &&
    receipt.manifestDigest === plan.manifestDigest &&
    receipt.dependencySetId === dependencySet.dependencySetId &&
    receipt.dependencySetDigest === dependencySet.dependencySetDigest &&
    receipt.planId === plan.planId &&
    receipt.planDigest === plan.planDigest &&
    receipt.cellId === cell.cellId &&
    receipt.cellDigest === cell.cellDigest &&
    receipt.cellKind === cell.cellKind &&
    receipt.arm === cell.arm &&
    receipt.caseId === cell.caseId &&
    receipt.caseDigest === cell.caseDigest &&
    receipt.profileId === cell.profileId &&
    receipt.profileDigest === cell.profileDigest &&
    receipt.candidateScannerSetDigest ===
      dependencySet.candidateScannerSetDigest &&
    receipt.baselineScannerSetDigest === dependencySet.baselineScannerSetDigest &&
    receipt.hardwareClassRef === cell.hardwareClassRef &&
    receipt.hardwareClassDigest === cell.hardwareClassDigest
  );
}

function receiptFailureReasons(
  receipt: SastEndToEndQualificationReceipt,
  cell: SastEndToEndQualificationCell | null,
  plan: SastEndToEndQualificationExecutionPlan,
  dependencySet: SastEndToEndQualificationDependencySet,
  evaluatedAt: string
): SastEndToEndQualificationFailureReason[] {
  const reasons: SastEndToEndQualificationFailureReason[] = [];
  const firstAttempt = receipt.attempts[0];
  const finalAttempt = receipt.attempts.at(-1);
  if (
    !firstAttempt ||
    !finalAttempt ||
    Date.parse(firstAttempt.startedAt) < Date.parse(plan.plannedAt) ||
    Date.parse(firstAttempt.startedAt) < Date.parse(dependencySet.validFrom) ||
    Date.parse(receipt.completedAt) > Date.parse(dependencySet.validUntil) ||
    Date.parse(receipt.completedAt) > Date.parse(evaluatedAt) ||
    receipt.attempts.some(
      (attempt) =>
        Date.parse(attempt.startedAt) < Date.parse(dependencySet.validFrom) ||
        Date.parse(attempt.cleanupCompletedAt) >
          Date.parse(dependencySet.validUntil)
    )
  ) {
    reasons.push('TIMESTAMP_INVALID');
  }
  if (
    secondsBetween(receipt.completedAt, evaluatedAt) >
    SAST_END_TO_END_QUALIFICATION_LIMITS.maximumEvidenceAgeSeconds
  ) {
    reasons.push('EVIDENCE_STALE');
  }
  if (!isAttemptChainValid(receipt.attempts)) {
    reasons.push('ATTEMPT_CHAIN_INVALID');
  }
  if (!cell) {
    reasons.push('CELL_BINDING_INVALID');
  } else {
    if (
      cell.cellKind.startsWith('PERFORMANCE_') &&
      (receipt.hardwareClassRef !== dependencySet.performanceHardwareClassRef ||
        receipt.hardwareClassDigest !==
          dependencySet.performanceHardwareClassDigest)
    ) {
      reasons.push('HARDWARE_MISMATCH');
    }
    const limits = SAST_SCAN_PROFILES[cell.profileId].limits;
    if (
      receipt.attempts.some(
        (attempt) =>
          attempt.latencyMilliseconds > limits.wallClockTimeoutSeconds * 1_000 ||
          attempt.cpuMilliseconds > limits.wallClockTimeoutSeconds * limits.cpuMillicores ||
          attempt.peakMemoryBytes > limits.memoryMiB * 1024 * 1024 ||
          attempt.peakDiskBytes > limits.ephemeralDiskMiB * 1024 * 1024
      )
    ) {
      reasons.push('RESOURCE_LIMIT_EXCEEDED');
    }
    if (
      cell.arm === 'CANDIDATE' &&
      (!isCompletedReceipt(receipt) ||
        receipt.observedControlOutcome !== cell.expectedOutcome)
    ) {
      reasons.push('OUTCOME_MISMATCH');
    }
    if (
      cell.cellKind === 'GOLDEN_CANDIDATE' &&
      !isGoldenCellConforming(cell, receipt)
    ) {
      reasons.push('GOLDEN_CONFORMANCE_FAILED');
    }
    if (
      cell.cellKind === 'END_TO_END_CANDIDATE' &&
      !isControlCellConforming(cell, receipt)
    ) {
      reasons.push(
        cell.corpusClass === 'FINGERPRINT_CORRELATION'
          ? 'FINGERPRINT_CORRELATION_FAILED'
          : 'EVIDENCE_PRIVACY_FAILED'
      );
    }
  }
  if (
    !finalAttempt ||
    finalAttempt.outcome !== 'COMPLETED' ||
    receipt.phaseObservations.some((item) => item.status !== 'PASSED')
  ) {
    reasons.push('PIPELINE_INCOMPLETE');
  }
  if (
    receipt.attempts.some((attempt) =>
      ZERO_TOLERANCE_KEYS.some(
        (key) => attempt.zeroToleranceCounts[key] !== 0
      )
    )
  ) {
    reasons.push('ZERO_TOLERANCE_EVENT');
  }
  return canonicalFailureReasons(reasons);
}

function earliestReceiptStartMilliseconds(
  signedReceipts: readonly SastEndToEndQualificationSignedReceipt[],
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): number | null {
  let earliest: number | null = null;
  for (const signedReceipt of signedReceipts) {
    if (
      !hasExactKeys(signedReceipt, SIGNED_RECEIPT_KEYS) ||
      !isSastEndToEndQualificationReceiptValid(
        signedReceipt.receipt,
        digestCanonical
      )
    ) {
      continue;
    }
    const startedAt = Date.parse(signedReceipt.receipt.attempts[0]?.startedAt ?? '');
    if (!Number.isFinite(startedAt)) continue;
    earliest = earliest === null ? startedAt : Math.min(earliest, startedAt);
  }
  return earliest;
}

function isSignatureSetValid<
  T extends SastEndToEndQualificationSignatureRole
>(
  signatures: readonly SastEndToEndQualificationSignature[],
  requiredRoles: readonly T[],
  payloadDigest: Sha256Digest,
  earliestSignedAt: string,
  latestSignedAt: string,
  verifySignature: SastEndToEndQualificationSignatureVerifier
): boolean {
  if (
    !Array.isArray(signatures) ||
    signatures.length !== requiredRoles.length ||
    !arraysEqual(
      signatures.map((signature) => signature.role),
      requiredRoles
    ) ||
    !unique(signatures.map((signature) => signature.keyId))
  ) {
    return false;
  }
  return signatures.every((signature) => {
    if (
      !isSastEndToEndQualificationSignatureValid(signature) ||
      signature.payloadDigest !== payloadDigest ||
      Date.parse(signature.signedAt) < Date.parse(earliestSignedAt) ||
      Date.parse(signature.signedAt) > Date.parse(latestSignedAt)
    ) {
      return false;
    }
    const payload = serializeSastEndToEndQualificationSignaturePayload(signature);
    if (payload === null) return false;
    try {
      return verifySignature(signature, payload) === true;
    } catch {
      return false;
    }
  });
}

function isGoldenCellConforming(
  cell: SastEndToEndQualificationCell,
  receipt: SastEndToEndQualificationReceipt
): boolean {
  const expectedCriticalHigh =
    cell.expectedOutcome === 'DETECT' &&
    (cell.severity === 'CRITICAL' || cell.severity === 'HIGH')
      ? 1
      : 0;
  return (
    cell.expectedFindingCount !== null &&
    isCompletedReceipt(receipt) &&
    receipt.observedControlOutcome === cell.expectedOutcome &&
    receipt.observedFindingCount === cell.expectedFindingCount &&
    receipt.matchedExpectedFindingCount === cell.expectedFindingCount &&
    receipt.observedCriticalHighFindingCount === expectedCriticalHigh &&
    receipt.matchedCriticalHighFindingCount === expectedCriticalHigh
  );
}

function isControlCellConforming(
  cell: SastEndToEndQualificationCell,
  receipt: SastEndToEndQualificationReceipt
): boolean {
  return (
    isCompletedReceipt(receipt) &&
    receipt.observedControlOutcome === cell.expectedOutcome
  );
}

function isCompletedReceipt(
  receipt: SastEndToEndQualificationReceipt
): boolean {
  return (
    receipt.attempts.at(-1)?.outcome === 'COMPLETED' &&
    receipt.phaseObservations.every((item) => item.status === 'PASSED')
  );
}

function receiptLatencyMilliseconds(
  receipt: SastEndToEndQualificationReceipt
): number {
  return Math.max(
    0,
    Date.parse(receipt.completedAt) -
      Date.parse(receipt.attempts[0]?.startedAt ?? receipt.completedAt)
  );
}

function nearestRank(values: readonly number[], percentile: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((left, right) => left - right);
  const rank = Math.max(1, Math.ceil(percentile * sorted.length));
  return sorted[rank - 1] ?? 0;
}

function ratio(numerator: number, denominator: number): number {
  return denominator > 0 ? numerator / denominator : 0;
}

function emptyZeroToleranceCounts(): SastEndToEndQualificationZeroToleranceCounts {
  return {
    crossTenantLeakCount: 0,
    secretLeakCount: 0,
    sandboxEscapeCount: 0,
    staleExternalPublicationCount: 0,
    unauthorizedEgressCount: 0,
    missingDestructionEvidenceCount: 0,
    evidencePolicyViolationCount: 0,
    unsignedArtifactExecutionCount: 0
  };
}

function goldenCellCore(
  sourceCase: SastQualificationCorpusCase,
  profileId: SastProfileId,
  cellKind: 'GOLDEN_CANDIDATE' | 'GOLDEN_NEGATIVE_BASELINE',
  arm: SastEndToEndQualificationArm,
  sourceSnapshotDigest: string,
  priorMustDetect: boolean
): SastEndToEndQualificationCellCore {
  return {
    version: SAST_END_TO_END_QUALIFICATION_CELL_VERSION,
    cellKind,
    arm,
    sourceCorpus: 'T051_GOLDEN',
    sourceSnapshotDigest,
    caseId: sourceCase.caseId,
    caseDigest: sourceCase.caseDigest,
    caseKey: sourceCase.caseKey,
    corpusClass: sourceCase.corpusClass,
    scenario: null,
    profileId,
    profileDigest: SAST_APPROVED_PROFILE_DIGESTS[profileId],
    scanner: sourceCase.scanner,
    capability: sourceCase.capability,
    ruleSemanticId: sourceCase.ruleSemanticId,
    severity: sourceCase.severity,
    expectedOutcome: sourceCase.expectedOutcome,
    expectedFindingCount: sourceCase.expectedFindingCount,
    priorMustDetect,
    fixtureId: null,
    fixtureDigest: null,
    hardwareClassRef: null,
    hardwareClassDigest: null,
    runOrdinal: null,
    queueToCleanupRequired: true,
    externalPublicationAllowed: false,
    customerContentAccepted: false,
    customerCodeExecutionAllowed: false,
    packageInstallAllowed: false,
    repositoryBuildAllowed: false,
    dynamicTestAllowed: false,
    publicInternetEgressAllowed: false,
    productionReadinessAuthority: false
  };
}

function multiClassCellCore(
  sourceCase: SastMultiClassQualificationCase,
  profileId: SastProfileId,
  cellKind:
    | 'END_TO_END_CANDIDATE'
    | 'PERFORMANCE_CANDIDATE'
    | 'PERFORMANCE_BASELINE',
  arm: SastEndToEndQualificationArm,
  sourceSnapshotDigest: string,
  runOrdinal: number | null
): SastEndToEndQualificationCellCore {
  return {
    version: SAST_END_TO_END_QUALIFICATION_CELL_VERSION,
    cellKind,
    arm,
    sourceCorpus: 'T052_MULTI_CLASS',
    sourceSnapshotDigest,
    caseId: sourceCase.caseId,
    caseDigest: sourceCase.caseDigest,
    caseKey: sourceCase.caseKey,
    corpusClass: sourceCase.corpusClass,
    scenario: sourceCase.scenario,
    profileId,
    profileDigest: SAST_APPROVED_PROFILE_DIGESTS[profileId],
    scanner: null,
    capability: null,
    ruleSemanticId: null,
    severity: null,
    expectedOutcome: sourceCase.expectedOutcome,
    expectedFindingCount: null,
    priorMustDetect: false,
    fixtureId: sourceCase.fixtureId,
    fixtureDigest: sourceCase.fixtureDigest,
    hardwareClassRef: sourceCase.hardwareClassRef,
    hardwareClassDigest: sourceCase.hardwareClassRef
      ? digestFromReference(sourceCase.hardwareClassRef)
      : null,
    runOrdinal,
    queueToCleanupRequired: true,
    externalPublicationAllowed: false,
    customerContentAccepted: false,
    customerCodeExecutionAllowed: false,
    packageInstallAllowed: false,
    repositoryBuildAllowed: false,
    dynamicTestAllowed: false,
    publicInternetEgressAllowed: false,
    productionReadinessAuthority: false
  };
}

function buildCell(
  core: SastEndToEndQualificationCellCore,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): SastEndToEndQualificationCell | null {
  if (!isCellCoreValid(core)) return null;
  const cellDigest = digestCanonical(stableJson(core));
  if (!isDigest(cellDigest)) return null;
  return {
    ...core,
    cellId:
      `sast-end-to-end-qualification-cell://${cellDigest.slice('sha256:'.length)}`,
    cellDigest
  };
}

function isCellValid(
  value: unknown,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): value is SastEndToEndQualificationCell {
  if (!hasExactKeys(value, CELL_KEYS)) return false;
  const candidate = value as SastEndToEndQualificationCell;
  if (
    !isDirectQualificationIdentity(
      candidate.cellId,
      'sast-end-to-end-qualification-cell://'
    ) ||
    !isDigest(candidate.cellDigest)
  ) {
    return false;
  }
  const core = cellCore(candidate);
  const expectedDigest = digestCanonical(stableJson(core));
  return (
    isCellCoreValid(core) &&
    expectedDigest === candidate.cellDigest &&
    candidate.cellId ===
      `sast-end-to-end-qualification-cell://${expectedDigest.slice('sha256:'.length)}`
  );
}

function isCellCoreValid(value: SastEndToEndQualificationCellCore): boolean {
  if (
    !hasExactKeys(value, CELL_CORE_KEYS) ||
    value.version !== SAST_END_TO_END_QUALIFICATION_CELL_VERSION ||
    !SAST_END_TO_END_QUALIFICATION_CELL_KINDS.includes(value.cellKind) ||
    !SAST_END_TO_END_QUALIFICATION_ARMS.includes(value.arm) ||
    !isDigest(value.sourceSnapshotDigest) ||
    !isQualificationSourceCaseId(value.caseId) ||
    !isDigest(value.caseDigest) ||
    !isCaseKey(value.caseKey) ||
    !isControlOutcome(value.corpusClass) ||
    !(value.scenario === null || isControlOutcome(value.scenario)) ||
    !SAST_PROFILE_IDS.includes(value.profileId) ||
    value.profileDigest !== SAST_APPROVED_PROFILE_DIGESTS[value.profileId] ||
    !(value.scanner === null || isCaseKey(value.scanner)) ||
    !(value.capability === null || isCaseKey(value.capability)) ||
    !(value.ruleSemanticId === null || isCaseKey(value.ruleSemanticId)) ||
    !(value.severity === null || isControlOutcome(value.severity)) ||
    !isControlOutcome(value.expectedOutcome) ||
    !(
      value.expectedFindingCount === null ||
      value.expectedFindingCount === 0 ||
      value.expectedFindingCount === 1
    ) ||
    typeof value.priorMustDetect !== 'boolean' ||
    !isNullableDirectIdentityDigestPair(
      value.fixtureId,
      value.fixtureDigest,
      'sast-multi-class-qualification-fixture://'
    ) ||
    !isNullableDigestBoundReference(
      value.hardwareClassRef,
      value.hardwareClassDigest
    ) ||
    !(value.runOrdinal === null || isBoundedInteger(value.runOrdinal, 1, 30)) ||
    value.queueToCleanupRequired !== true ||
    value.externalPublicationAllowed !== false ||
    value.customerContentAccepted !== false ||
    value.customerCodeExecutionAllowed !== false ||
    value.packageInstallAllowed !== false ||
    value.repositoryBuildAllowed !== false ||
    value.dynamicTestAllowed !== false ||
    value.publicInternetEgressAllowed !== false ||
    value.productionReadinessAuthority !== false
  ) {
    return false;
  }

  if (value.cellKind === 'GOLDEN_CANDIDATE') {
    return (
      value.arm === 'CANDIDATE' &&
      value.sourceCorpus === 'T051_GOLDEN' &&
      value.caseId.startsWith('sast-qualification-case://') &&
      (value.corpusClass === 'GOLDEN_POSITIVE' ||
        value.corpusClass === 'GOLDEN_NEGATIVE') &&
      value.scenario === null &&
      value.scanner !== null &&
      value.capability !== null &&
      value.ruleSemanticId !== null &&
      value.severity !== null &&
      value.expectedFindingCount !== null &&
      value.fixtureId === null &&
      value.hardwareClassRef === null &&
      value.runOrdinal === null &&
      ((value.corpusClass === 'GOLDEN_POSITIVE' &&
        value.expectedOutcome === 'DETECT' &&
        value.expectedFindingCount === 1) ||
        (value.corpusClass === 'GOLDEN_NEGATIVE' &&
          value.expectedOutcome === 'NO_FINDING' &&
          value.expectedFindingCount === 0)) &&
      (!value.priorMustDetect ||
        (value.corpusClass === 'GOLDEN_POSITIVE' &&
          (value.severity === 'CRITICAL' || value.severity === 'HIGH')))
    );
  }
  if (value.cellKind === 'GOLDEN_NEGATIVE_BASELINE') {
    return (
      value.arm === 'BASELINE' &&
      value.sourceCorpus === 'T051_GOLDEN' &&
      value.caseId.startsWith('sast-qualification-case://') &&
      value.corpusClass === 'GOLDEN_NEGATIVE' &&
      value.scenario === null &&
      value.expectedOutcome === 'NO_FINDING' &&
      value.expectedFindingCount === 0 &&
      value.priorMustDetect === false &&
      value.scanner !== null &&
      value.capability !== null &&
      value.ruleSemanticId !== null &&
      value.severity !== null &&
      value.fixtureId === null &&
      value.hardwareClassRef === null &&
      value.runOrdinal === null
    );
  }
  if (value.cellKind === 'END_TO_END_CANDIDATE') {
    return (
      value.arm === 'CANDIDATE' &&
      value.sourceCorpus === 'T052_MULTI_CLASS' &&
      value.caseId.startsWith('sast-multi-class-qualification-case://') &&
      (value.corpusClass === 'FINGERPRINT_CORRELATION' ||
        value.corpusClass === 'EVIDENCE_PRIVACY') &&
      value.scenario !== null &&
      value.scanner === null &&
      value.capability === null &&
      value.ruleSemanticId === null &&
      value.severity === null &&
      value.expectedFindingCount === null &&
      value.priorMustDetect === false &&
      value.fixtureId !== null &&
      value.hardwareClassRef === null &&
      value.runOrdinal === null
    );
  }
  return (
    value.sourceCorpus === 'T052_MULTI_CLASS' &&
    value.caseId.startsWith('sast-multi-class-qualification-case://') &&
    value.corpusClass === 'PERFORMANCE' &&
    value.scenario !== null &&
    value.scanner === null &&
    value.capability === null &&
    value.ruleSemanticId === null &&
    value.severity === null &&
    value.expectedOutcome === 'MEASURE' &&
    value.expectedFindingCount === null &&
    value.priorMustDetect === false &&
    value.fixtureId !== null &&
    value.hardwareClassRef !== null &&
    value.runOrdinal !== null &&
    ((value.cellKind === 'PERFORMANCE_CANDIDATE' && value.arm === 'CANDIDATE') ||
      (value.cellKind === 'PERFORMANCE_BASELINE' && value.arm === 'BASELINE'))
  );
}

function countCellKinds(
  cells: readonly SastEndToEndQualificationCell[]
): Record<SastEndToEndQualificationCellKind, number> {
  const counts: Record<SastEndToEndQualificationCellKind, number> = {
    GOLDEN_CANDIDATE: 0,
    GOLDEN_NEGATIVE_BASELINE: 0,
    END_TO_END_CANDIDATE: 0,
    PERFORMANCE_CANDIDATE: 0,
    PERFORMANCE_BASELINE: 0
  };
  for (const cell of cells) counts[cell.cellKind] += 1;
  return counts;
}

function compareCells(
  left: SastEndToEndQualificationCell,
  right: SastEndToEndQualificationCell
): number {
  const kind =
    SAST_END_TO_END_QUALIFICATION_CELL_KINDS.indexOf(left.cellKind) -
    SAST_END_TO_END_QUALIFICATION_CELL_KINDS.indexOf(right.cellKind);
  if (kind !== 0) return kind;
  const caseKey = compareText(left.caseKey, right.caseKey);
  if (caseKey !== 0) return caseKey;
  const profile =
    SAST_PROFILE_IDS.indexOf(left.profileId) -
    SAST_PROFILE_IDS.indexOf(right.profileId);
  if (profile !== 0) return profile;
  return (left.runOrdinal ?? 0) - (right.runOrdinal ?? 0);
}

function performanceHardwareClassRef(
  manifest: SastEndToEndQualificationManifest
): string {
  const values = [
    ...new Set(
      manifest.cells
        .filter((cell) => cell.cellKind.startsWith('PERFORMANCE_'))
        .map((cell) => cell.hardwareClassRef)
        .filter((value): value is string => value !== null)
    )
  ];
  return values.length === 1 ? values[0] ?? '' : '';
}

function performanceHardwareClassDigest(
  manifest: SastEndToEndQualificationManifest
): string {
  const values = [
    ...new Set(
      manifest.cells
        .filter((cell) => cell.cellKind.startsWith('PERFORMANCE_'))
        .map((cell) => cell.hardwareClassDigest)
        .filter((value): value is string => value !== null)
    )
  ];
  return values.length === 1 ? values[0] ?? '' : '';
}

function hasClosedManifestAuthority(
  value: SastEndToEndQualificationManifest
): boolean {
  return (
    value.t053PassRequired === true &&
    value.externalEvidenceRequired === true &&
    value.aggregateMetricsRecomputedFromReceipts === true &&
    value.customerContentAccepted === false &&
    value.customerCodeExecutionAllowed === false &&
    value.packageInstallAllowed === false &&
    value.repositoryBuildAllowed === false &&
    value.dynamicTestAllowed === false &&
    value.publicInternetEgressAllowed === false &&
    value.findingAuthority === false &&
    value.policyAuthority === false &&
    value.publicationAuthority === false &&
    value.deploymentAuthority === false &&
    value.productionReadinessAuthority === false &&
    value.immutable === true
  );
}

function isArtifactBindingValid(
  value: unknown
): value is SastEndToEndQualificationArtifactBinding {
  if (!hasExactKeys(value, ARTIFACT_KEYS)) return false;
  const candidate = value as SastEndToEndQualificationArtifactBinding;
  return (
    SAST_END_TO_END_QUALIFICATION_ARTIFACT_KEYS.includes(candidate.artifactKey) &&
    isDigestBoundReference(candidate.artifactRef, candidate.artifactDigest) &&
    isDigestBoundReference(candidate.signatureRef) &&
    isDigestBoundReference(candidate.provenanceRef)
  );
}

function isArtifactVerificationValid(
  value: unknown,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): value is SastEndToEndQualificationArtifactVerification {
  if (!isRecord(value) || !hasExactKeys(value, ARTIFACT_VERIFICATION_KEYS)) {
    return false;
  }
  const candidate = value as unknown as SastEndToEndQualificationArtifactVerification;
  return (
    SAST_END_TO_END_QUALIFICATION_ARTIFACT_KEYS.includes(candidate.artifactKey) &&
    isDigest(candidate.artifactDigest) &&
    isSastEndToEndQualificationSignatureValid(candidate.artifactSignature) &&
    candidate.artifactSignature.role === 'SUPPLY_CHAIN_AUTHORITY' &&
    candidate.artifactSignature.payloadDigest === candidate.artifactDigest &&
    isDigest(candidate.signatureEnvelopeDigest) &&
    digestCanonical(stableJson(candidate.artifactSignature)) ===
      candidate.signatureEnvelopeDigest &&
    isDigest(candidate.provenanceEnvelopeDigest) &&
    isSastEndToEndQualificationArtifactProvenanceValid(
      candidate.provenance,
      () => true,
      digestCanonical
    ) &&
    candidate.provenance.artifactKey === candidate.artifactKey &&
    candidate.provenance.artifactDigest === candidate.artifactDigest &&
    digestCanonical(stableJson(candidate.provenance)) ===
      candidate.provenanceEnvelopeDigest &&
    isDigestBoundReference(
      candidate.signatureRef,
      candidate.signatureEnvelopeDigest
    ) &&
    isDigestBoundReference(
      candidate.provenanceRef,
      candidate.provenanceEnvelopeDigest
    )
  );
}

function cloneArtifact(
  value: SastEndToEndQualificationArtifactBinding
): SastEndToEndQualificationArtifactBinding {
  return { ...value };
}

function dependencySetInput(
  value: SastEndToEndQualificationDependencySet
): SastEndToEndQualificationDependencySetInput {
  return {
    revision: value.revision,
    providerId: value.providerId,
    providerAdapterRef: value.providerAdapterRef,
    validFrom: value.validFrom,
    validUntil: value.validUntil,
    candidateScannerSetDigest: value.candidateScannerSetDigest,
    baselineScannerSetDigest: value.baselineScannerSetDigest,
    performanceHardwareClassRef: value.performanceHardwareClassRef,
    performanceHardwareClassDigest: value.performanceHardwareClassDigest,
    artifacts: value.artifacts
  };
}

function cellCore(
  value: SastEndToEndQualificationCell
): SastEndToEndQualificationCellCore {
  return Object.fromEntries(
    CELL_CORE_KEYS.map((key) => [key, value[key]])
  ) as unknown as SastEndToEndQualificationCellCore;
}

function attemptCore(
  value: SastEndToEndQualificationAttempt
): SastEndToEndQualificationAttemptCore {
  return Object.fromEntries(
    ATTEMPT_CORE_KEYS.map((key) => [key, value[key]])
  ) as unknown as SastEndToEndQualificationAttemptCore;
}

function receiptCore(
  value: SastEndToEndQualificationReceipt
): SastEndToEndQualificationReceiptCore {
  return Object.fromEntries(
    RECEIPT_CORE_KEYS.map((key) => [key, value[key]])
  ) as unknown as SastEndToEndQualificationReceiptCore;
}

function resultCore(
  value: SastEndToEndQualificationResult
): SastEndToEndQualificationResultCore {
  return Object.fromEntries(
    RESULT_CORE_KEYS.map((key) => [key, value[key]])
  ) as unknown as SastEndToEndQualificationResultCore;
}

function canonicalFailureReasons(
  values: readonly SastEndToEndQualificationFailureReason[]
): SastEndToEndQualificationFailureReason[] {
  const order = new Map(
    SAST_END_TO_END_QUALIFICATION_FAILURE_REASONS.map((value, index) => [
      value,
      index
    ])
  );
  return [...new Set(values)].sort(
    (left, right) => (order.get(left) ?? 0) - (order.get(right) ?? 0)
  );
}

const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const SEMANTIC_VERSION_PATTERN =
  /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/u;
const DIGEST_BOUND_REFERENCE_PATTERN =
  /^[a-z][a-z0-9+.-]*:\/\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+\/sha256:[a-f0-9]{64}$/u;
const CANONICAL_BASE64_PATTERN =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;
const DIRECT_DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const STABLE_JSON_INVALID_SENTINEL =
  '"__invalid_sast_end_to_end_qualification_shape__"';
const STABLE_JSON_MAXIMUM_DEPTH = 64;

function isDigestBoundReference(value: unknown, digest?: unknown): value is string {
  return (
    isBoundedText(
      value,
      SAST_END_TO_END_QUALIFICATION_LIMITS.maximumReferenceBytes
    ) &&
    DIGEST_BOUND_REFERENCE_PATTERN.test(value) &&
    (digest === undefined || (isDigest(digest) && value.endsWith(`/${digest}`)))
  );
}

function isQualificationIdentity(value: unknown, prefix: string): value is string {
  return (
    typeof value === 'string' &&
    value.startsWith(prefix) &&
    isDigestBoundReference(value)
  );
}

function isDirectQualificationIdentity(
  value: unknown,
  prefix: string
): value is string {
  return (
    typeof value === 'string' &&
    value.startsWith(prefix) &&
    DIRECT_DIGEST_PATTERN.test(value.slice(prefix.length))
  );
}

function isNullableIdentityDigestPair(
  identity: unknown,
  digest: unknown,
  prefix: string
): boolean {
  return (
    (identity === null && digest === null) ||
    (isDirectQualificationIdentity(identity, prefix) &&
      isDigest(digest) &&
      identity.endsWith(digest.slice('sha256:'.length)))
  );
}

function isNullableDirectIdentityDigestPair(
  identity: unknown,
  digest: unknown,
  prefix: string
): boolean {
  return isNullableIdentityDigestPair(identity, digest, prefix);
}

function isNullableDigestBoundReference(
  reference: unknown,
  digest: unknown
): boolean {
  return (
    (reference === null && digest === null) ||
    isDigestBoundReference(reference, digest)
  );
}

function isQualificationSourceCaseId(value: unknown): value is string {
  return (
    isDirectQualificationIdentity(value, 'sast-qualification-case://') ||
    isDirectQualificationIdentity(
      value,
      'sast-multi-class-qualification-case://'
    )
  );
}

function digestFromReference(value: string): string | null {
  const match = value.match(/(sha256:[a-f0-9]{64})$/u);
  return match?.[1] ?? null;
}

function isProviderId(value: unknown): value is string {
  return (
    isBoundedText(
      value,
      SAST_END_TO_END_QUALIFICATION_LIMITS.maximumReferenceBytes
    ) &&
    /^microvm-provider:\/\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{1,512}$/u.test(
      value
    )
  );
}

function isIdentifier(value: unknown): value is string {
  return isProviderId(value);
}

function isReference(value: unknown): value is string {
  return (
    isBoundedText(
      value,
      SAST_END_TO_END_QUALIFICATION_LIMITS.maximumReferenceBytes
    ) &&
    /^team:\/\/[a-z0-9][a-z0-9._/-]{0,255}$/u.test(value)
  );
}

function isCaseKey(value: unknown): value is string {
  return (
    isBoundedText(
      value,
      SAST_END_TO_END_QUALIFICATION_LIMITS.maximumIdentifierBytes
    ) && /^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$/u.test(value)
  );
}

function isControlOutcome(value: unknown): value is string {
  return (
    isBoundedText(
      value,
      SAST_END_TO_END_QUALIFICATION_LIMITS.maximumIdentifierBytes
    ) && /^[A-Z][A-Z0-9_]{0,255}$/u.test(value)
  );
}

function isZeroToleranceCountsValid(
  value: unknown
): value is SastEndToEndQualificationZeroToleranceCounts {
  if (!hasExactKeys(value, ZERO_TOLERANCE_KEYS)) return false;
  const candidate = value as SastEndToEndQualificationZeroToleranceCounts;
  return ZERO_TOLERANCE_KEYS.every((key) =>
    isBoundedInteger(candidate[key], 0, 1_000_000)
  );
}

function isCanonicalEd25519Signature(value: unknown): value is string {
  if (
    typeof value !== 'string' ||
    value.length !== 88 ||
    !value.endsWith('==') ||
    !CANONICAL_BASE64_PATTERN.test(value) ||
    decodedBase64Bytes(value) !== 64
  ) {
    return false;
  }
  const alphabet =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const finalDataIndex = alphabet.indexOf(value[85] ?? '');
  return finalDataIndex >= 0 && finalDataIndex % 16 === 0;
}

function isSemanticVersion(value: unknown): value is string {
  return typeof value === 'string' && SEMANTIC_VERSION_PATTERN.test(value);
}

function isIsoInstant(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) &&
    Number.isFinite(Date.parse(value)) &&
    new Date(value).toISOString() === value
  );
}

function isDigest(value: unknown): value is Sha256Digest {
  return typeof value === 'string' && SHA256_PATTERN.test(value);
}

function isNullableDigest(value: unknown): value is Sha256Digest | null {
  return value === null || isDigest(value);
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value);
}

function isRate(value: unknown): value is number {
  return isFiniteNumber(value) && value >= 0 && value <= 1;
}

function isBoundedInteger(
  value: unknown,
  minimum: number,
  maximum: number
): value is number {
  return (
    typeof value === 'number' &&
    Number.isSafeInteger(value) &&
    value >= minimum &&
    value <= maximum
  );
}

function isBoundedText(value: unknown, maximumBytes: number): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value === value.normalize('NFC') &&
    new TextEncoder().encode(value).byteLength <= maximumBytes &&
    !Array.from(value).some((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return (
        codePoint === 0 ||
        codePoint === 0x7f ||
        (codePoint >= 1 && codePoint <= 8) ||
        codePoint === 11 ||
        codePoint === 12 ||
        (codePoint >= 14 && codePoint <= 31) ||
        (codePoint >= 0xd800 && codePoint <= 0xdfff)
      );
    })
  );
}

function secondsBetween(start: string, end: string): number {
  return (Date.parse(end) - Date.parse(start)) / 1_000;
}

function decodedBase64Bytes(value: string): number {
  if (value.length === 0) return 0;
  const padding = value.endsWith('==') ? 2 : value.endsWith('=') ? 1 : 0;
  return (value.length / 4) * 3 - padding;
}

function hasExactKeys(value: unknown, keys: readonly string[]): boolean {
  if (!isPlainObject(value)) return false;
  return arraysEqual(Object.keys(value).sort(compareText), [...keys].sort(compareText));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return isPlainObject(value);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function omitKeys<T extends object, K extends keyof T>(
  value: T,
  keys: readonly K[]
): Omit<T, K> {
  const blocked = new Set<PropertyKey>(keys);
  return Object.fromEntries(
    Object.entries(value).filter(([key]) => !blocked.has(key))
  ) as Omit<T, K>;
}

function stableJson(value: unknown): string {
  return stableJsonValue(value, new Set<object>(), 0);
}

function stableJsonValue(
  value: unknown,
  ancestors: Set<object>,
  depth: number
): string {
  if (depth > STABLE_JSON_MAXIMUM_DEPTH) return STABLE_JSON_INVALID_SENTINEL;
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'string') {
    return isBoundedText(value, 16 * 1024 * 1024)
      ? JSON.stringify(value)
      : STABLE_JSON_INVALID_SENTINEL;
  }
  if (typeof value === 'number') {
    return Number.isFinite(value)
      ? JSON.stringify(value)
      : STABLE_JSON_INVALID_SENTINEL;
  }
  if (typeof value !== 'object') return STABLE_JSON_INVALID_SENTINEL;
  if (ancestors.has(value)) return STABLE_JSON_INVALID_SENTINEL;
  ancestors.add(value);
  let output: string;
  if (Array.isArray(value)) {
    output = `[${value
      .map((item) => stableJsonValue(item, ancestors, depth + 1))
      .join(',')}]`;
  } else if (isPlainObject(value)) {
    output = `{${Object.keys(value)
      .sort(compareText)
      .map(
        (key) =>
          `${JSON.stringify(key)}:${stableJsonValue(
            value[key],
            ancestors,
            depth + 1
          )}`
      )
      .join(',')}}`;
  } else {
    output = STABLE_JSON_INVALID_SENTINEL;
  }
  ancestors.delete(value);
  return output;
}

function arraysEqual<T>(left: readonly T[], right: readonly T[]): boolean {
  return (
    left.length === right.length &&
    left.every((item, index) => stableJson(item) === stableJson(right[index]))
  );
}

function unique(values: readonly string[]): boolean {
  return new Set(values).size === values.length;
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
