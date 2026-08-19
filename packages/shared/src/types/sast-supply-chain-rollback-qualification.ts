import {
  SAST_END_TO_END_QUALIFICATION_APPROVAL_ROLES,
  SAST_END_TO_END_QUALIFICATION_ARTIFACT_KEYS,
  SAST_END_TO_END_QUALIFICATION_PLAN_VERSION,
  SAST_END_TO_END_QUALIFICATION_RECEIPT_SIGNATURE_ROLES,
  SAST_END_TO_END_QUALIFICATION_SIGNATURE_VERSION,
  isSastEndToEndQualificationArtifactVerificationSetValid,
  isSastEndToEndQualificationDependencySetValid,
  isSastEndToEndQualificationManifestValid,
  isSastEndToEndQualificationResultValid,
  isSastEndToEndQualificationSignatureValid,
  serializeSastEndToEndQualificationSignaturePayload,
  type SastEndToEndQualificationArtifactKey,
  type SastEndToEndQualificationArtifactBinding,
  type SastEndToEndQualificationArtifactVerification,
  type SastEndToEndQualificationArtifactVerificationSet,
  type SastEndToEndQualificationCanonicalDigester,
  type SastEndToEndQualificationDependencySet,
  type SastEndToEndQualificationExecutionPlan,
  type SastEndToEndQualificationManifest,
  type SastEndToEndQualificationResult,
  type SastEndToEndQualificationSignature,
  type SastEndToEndQualificationSignatureRole,
  type SastEndToEndQualificationSignatureVerifier
} from './sast-end-to-end-qualification';
import {
  SAST_PROFILE_IDS,
  type SastProfileId
} from './sast-runtime';

export const SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_MANIFEST_VERSION =
  'sast-supply-chain-rollback-qualification-manifest-v1' as const;
export const SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_CELL_VERSION =
  'sast-supply-chain-rollback-qualification-cell-v1' as const;
export const SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_ENTRY_ATTESTATION_VERSION =
  'sast-supply-chain-rollback-qualification-entry-attestation-v1' as const;
export const SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_PLAN_VERSION =
  'sast-supply-chain-rollback-qualification-plan-v1' as const;
export const SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_RECEIPT_VERSION =
  'sast-supply-chain-rollback-qualification-receipt-v1' as const;
export const SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_RESULT_VERSION =
  'sast-supply-chain-rollback-qualification-result-v1' as const;
export const SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LEDGER_ENTRY_VERSION =
  'sast-supply-chain-rollback-qualification-ledger-entry-v1' as const;
export const SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LEDGER_HEAD_ATTESTATION_VERSION =
  'sast-supply-chain-rollback-qualification-ledger-head-attestation-v1' as const;

export const SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_DRILL_KINDS = [
  'ARTIFACT_MOUNT_REHASH_ACCEPT',
  'ARTIFACT_DIGEST_SUBSTITUTION_REJECT',
  'ARTIFACT_SIGNATURE_SUBSTITUTION_REJECT',
  'ARTIFACT_PROVENANCE_SUBSTITUTION_REJECT',
  'UNLISTED_COMPONENT_REJECT',
  'DATABASE_INTERNAL_MIRROR_ACCEPT',
  'DATABASE_STALE_SNAPSHOT_REJECT',
  'DATABASE_NETWORK_ENRICHMENT_REJECT',
  'SCHEMA_CANONICAL_ACCEPT',
  'SCHEMA_INCOMPATIBLE_VERSION_REJECT',
  'SCHEMA_MALFORMED_OR_OVERSIZED_REJECT',
  'ROLLBACK_CANDIDATE_SUSPEND',
  'ROLLBACK_QUEUE_ADMISSION_FENCE',
  'ROLLBACK_IN_FLIGHT_ABORT_AND_CLEANUP',
  'ROLLBACK_DERIVE_AND_REVERIFY_LAST_KNOWN_GOOD',
  'ROLLBACK_ACTIVATE_BASELINE_APPEND_ONLY'
] as const;
export type SastSupplyChainRollbackQualificationDrillKind =
  (typeof SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_DRILL_KINDS)[number];

export const SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_ROLLBACK_SEQUENCE = [
  'ROLLBACK_CANDIDATE_SUSPEND',
  'ROLLBACK_QUEUE_ADMISSION_FENCE',
  'ROLLBACK_IN_FLIGHT_ABORT_AND_CLEANUP',
  'ROLLBACK_DERIVE_AND_REVERIFY_LAST_KNOWN_GOOD',
  'ROLLBACK_ACTIVATE_BASELINE_APPEND_ONLY'
] as const satisfies readonly SastSupplyChainRollbackQualificationDrillKind[];

export const SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_STATUSES = [
  'BLOCKED_T054_QUALIFICATION',
  'PENDING_DRILL_EXECUTION',
  'FAILED',
  'PASSED'
] as const;
export type SastSupplyChainRollbackQualificationStatus =
  (typeof SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_STATUSES)[number];

export const SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_DECISIONS = [
  'ACCEPTED',
  'REJECTED',
  'COMPLETED'
] as const;
export type SastSupplyChainRollbackQualificationDecision =
  (typeof SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_DECISIONS)[number];

export const SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_ROLLBACK_STATES = [
  'ACTIVE',
  'STANDBY',
  'SUSPENDED',
  'ROLLED_BACK'
] as const;
export type SastSupplyChainRollbackQualificationRollbackState =
  (typeof SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_ROLLBACK_STATES)[number];

export const SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_RECEIPT_SIGNATURE_ROLES = [
  'SUPPLY_CHAIN_AUTHORITY',
  'MICROVM_PROVIDER',
  'QUALIFICATION_RUNTIME'
] as const satisfies readonly SastEndToEndQualificationSignatureRole[];

export const SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LEDGER_HEAD_SIGNATURE_ROLES = [
  'QUALIFICATION_AUTHORITY',
  'SUPPLY_CHAIN_AUTHORITY'
] as const satisfies readonly SastEndToEndQualificationSignatureRole[];

export const SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_FAILURE_REASONS = [
  'T054_ENTRY_INVALID',
  'DEPENDENCY_SET_INVALID',
  'ARTIFACT_VERIFICATION_INVALID',
  'ENTRY_ATTESTATION_INVALID',
  'EXECUTION_PLAN_INVALID',
  'APPROVAL_SET_INVALID',
  'RECEIPT_INVALID',
  'RECEIPT_SIGNATURE_INVALID',
  'RECEIPT_DUPLICATE',
  'CELL_BINDING_INVALID',
  'IDENTITY_REUSED',
  'PROVIDER_MISMATCH',
  'TIMESTAMP_INVALID',
  'EVIDENCE_STALE',
  'DRILL_OUTCOME_MISMATCH',
  'ROLLBACK_SEQUENCE_INVALID',
  'CLEANUP_SLO_EXCEEDED',
  'ZERO_TOLERANCE_EVENT'
] as const;
export type SastSupplyChainRollbackQualificationFailureReason =
  (typeof SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_FAILURE_REASONS)[number];

export const SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LIMITS = Object.freeze({
  artifactCount: 36,
  artifactDrillsPerArtifact: 4,
  artifactSupplyChainDrillCount: 144,
  allowlistDrillCount: 1,
  databaseDrillCount: 6,
  schemaDrillCount: 3,
  rollbackDrillsPerProfile: 5,
  rollbackDrillCount: 15,
  expectedCellCount: 169,
  expectedPreExecutionRejectionCount: 115,
  expectedArtifactInvocationCount: 39,
  maximumExecutionWindowSeconds: 7 * 24 * 60 * 60,
  maximumEvidenceAgeSeconds: 24 * 60 * 60,
  cleanupSloSeconds: 60,
  maximumIdentifierBytes: 512,
  maximumReferenceBytes: 2_048,
  maximumFailureReasons: 32,
  maximumReceiptCount: 169
});

type Sha256Digest = `sha256:${string}`;

export interface SastSupplyChainRollbackQualificationCellCore {
  version: typeof SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_CELL_VERSION;
  drillKind: SastSupplyChainRollbackQualificationDrillKind;
  artifactKey: SastEndToEndQualificationArtifactKey | null;
  profileId: SastProfileId | null;
  expectedDecision: SastSupplyChainRollbackQualificationDecision;
  preExecutionRejectionRequired: boolean;
  artifactInvocationAllowed: boolean;
  productionEquivalentProviderRequired: true;
  freshIsolatedEnvironmentRequired: true;
  customerContentAccepted: false;
  customerCodeExecutionAllowed: false;
  packageInstallAllowed: false;
  repositoryBuildAllowed: false;
  dynamicTestAllowed: false;
  publicInternetEgressAllowed: false;
  productionMutationAllowed: false;
  findingAuthority: false;
  policyAuthority: false;
  publicationAuthority: false;
  deploymentAuthority: false;
  productionReadinessAuthority: false;
}

export interface SastSupplyChainRollbackQualificationCell
  extends SastSupplyChainRollbackQualificationCellCore {
  cellId: string;
  cellDigest: string;
}

export interface SastSupplyChainRollbackQualificationManifestCore {
  version: typeof SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_MANIFEST_VERSION;
  revision: string;
  publishedAt: string;
  ownerRef: string;
  drillPolicyRef: string;
  drillPolicyDigest: string;
  t054ManifestId: string;
  t054ManifestDigest: string;
  artifactKeys: SastEndToEndQualificationArtifactKey[];
  artifactKeySetDigest: string;
  profiles: SastProfileId[];
  profileSetDigest: string;
  cells: SastSupplyChainRollbackQualificationCell[];
  cellSetDigest: string;
  artifactSupplyChainDrillCount: number;
  allowlistDrillCount: number;
  databaseDrillCount: number;
  schemaDrillCount: number;
  rollbackDrillCount: number;
  preExecutionRejectionCount: number;
  executionCellCount: number;
  providerExecutionStatus: 'BLOCKED_T054_QUALIFICATION';
  t054PassRequired: true;
  externalEvidenceRequired: true;
  aggregateMetricsAcceptedFromCaller: false;
  customerContentAccepted: false;
  customerCodeExecutionAllowed: false;
  packageInstallAllowed: false;
  repositoryBuildAllowed: false;
  dynamicTestAllowed: false;
  publicInternetEgressAllowed: false;
  productionMutationAllowed: false;
  findingAuthority: false;
  policyAuthority: false;
  publicationAuthority: false;
  deploymentAuthority: false;
  productionReadinessAuthority: false;
  immutable: true;
}

export interface SastSupplyChainRollbackQualificationManifest
  extends SastSupplyChainRollbackQualificationManifestCore {
  manifestId: string;
  manifestDigest: string;
}

export interface SastSupplyChainRollbackQualificationManifestInput {
  revision: string;
  publishedAt: string;
  ownerRef: string;
  drillPolicyRef: string;
  drillPolicyDigest: string;
  t054Manifest: SastEndToEndQualificationManifest;
}

export interface SastSupplyChainRollbackQualificationEntryAttestationCore {
  version: typeof SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_ENTRY_ATTESTATION_VERSION;
  manifestId: string;
  manifestDigest: string;
  t054ResultId: string;
  t054ResultDigest: string;
  t054DependencySetId: string;
  t054DependencySetDigest: string;
  t054ArtifactVerificationSetId: string;
  t054ArtifactVerificationSetDigest: string;
  t054PlanId: string;
  t054PlanDigest: string;
  verifiedAt: string;
  verifierRef: string;
  t055EntryAuthorized: true;
  findingAuthority: false;
  policyAuthority: false;
  publicationAuthority: false;
  deploymentAuthority: false;
  productionReadinessAuthority: false;
}

export interface SastSupplyChainRollbackQualificationEntryAttestation
  extends SastSupplyChainRollbackQualificationEntryAttestationCore {
  attestationId: string;
  attestationDigest: string;
  signature: SastEndToEndQualificationSignature;
}

export interface SastSupplyChainRollbackQualificationLedgerHeadAttestationCore {
  version: typeof SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LEDGER_HEAD_ATTESTATION_VERSION;
  manifestId: string;
  manifestDigest: string;
  dependencySetId: string;
  dependencySetDigest: string;
  providerId: string;
  providerAdapterRef: string;
  profileId: SastProfileId;
  candidateReleaseSetDigest: string;
  baselineReleaseSetDigest: string;
  ledgerHeadDigest: string;
  ledgerHeadSequence: number;
  ledgerHeadRef: string;
  observedAt: string;
  appendOnlyLedgerVerified: true;
  productionMutationAuthority: false;
}

export interface SastSupplyChainRollbackQualificationLedgerHeadAttestation
  extends SastSupplyChainRollbackQualificationLedgerHeadAttestationCore {
  attestationId: string;
  attestationDigest: string;
  signatures: SastEndToEndQualificationSignature[];
}

export interface SastSupplyChainRollbackQualificationPlanCore {
  version: typeof SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_PLAN_VERSION;
  manifestId: string;
  manifestDigest: string;
  t054ResultId: string;
  t054ResultDigest: string;
  t054DependencySetId: string;
  t054DependencySetDigest: string;
  t054ArtifactVerificationSetId: string;
  t054ArtifactVerificationSetDigest: string;
  t054PlanId: string;
  t054PlanDigest: string;
  entryAttestationId: string;
  entryAttestationDigest: string;
  providerId: string;
  providerAdapterRef: string;
  rollbackLedgerHeadAttestations:
    SastSupplyChainRollbackQualificationLedgerHeadAttestation[];
  executionCellCount: number;
  requiredApprovalRoles: string[];
  requiredReceiptSignatureRoles: string[];
  plannedAt: string;
  executionEnvironment: 'PRODUCTION_EQUIVALENT';
  detachedDualApprovalRequired: true;
  oneFreshIsolatedEnvironmentPerDrill: true;
  aggregateMetricsAcceptedFromCaller: false;
  customerContentAccepted: false;
  customerCodeExecutionAllowed: false;
  packageInstallAllowed: false;
  repositoryBuildAllowed: false;
  dynamicTestAllowed: false;
  publicInternetEgressAllowed: false;
  productionMutationAllowed: false;
  findingAuthority: false;
  policyAuthority: false;
  publicationAuthority: false;
  deploymentAuthority: false;
  productionReadinessAuthority: false;
}

export interface SastSupplyChainRollbackQualificationPlan
  extends SastSupplyChainRollbackQualificationPlanCore {
  planId: string;
  planDigest: string;
}

export interface SastSupplyChainRollbackQualificationReceiptCore {
  version: typeof SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_RECEIPT_VERSION;
  manifestId: string;
  manifestDigest: string;
  planId: string;
  planDigest: string;
  dependencySetId: string;
  dependencySetDigest: string;
  cellId: string;
  cellDigest: string;
  drillKind: SastSupplyChainRollbackQualificationDrillKind;
  artifactKey: SastEndToEndQualificationArtifactKey | null;
  profileId: SastProfileId | null;
  providerId: string;
  providerAdapterRef: string;
  attemptId: string;
  sandboxId: string;
  workloadId: string;
  startedAt: string;
  completedAt: string;
  cleanupCompletedAt: string;
  observedDecision: SastSupplyChainRollbackQualificationDecision;
  observedArtifactDigest: string | null;
  mountRehashDigest: string | null;
  observedSignatureEnvelopeDigest: string | null;
  observedProvenanceEnvelopeDigest: string | null;
  artifactMountedReadOnly: boolean | null;
  signatureVerified: boolean | null;
  provenanceVerified: boolean | null;
  allowlisted: boolean | null;
  internalMirrorUsed: boolean | null;
  databaseFresh: boolean | null;
  networkEgressAttempted: boolean;
  schemaCompatible: boolean | null;
  candidateStateBefore: SastSupplyChainRollbackQualificationRollbackState | null;
  candidateStateAfter: SastSupplyChainRollbackQualificationRollbackState | null;
  baselineStateBefore: SastSupplyChainRollbackQualificationRollbackState | null;
  baselineStateAfter: SastSupplyChainRollbackQualificationRollbackState | null;
  queueFenceApplied: boolean;
  rollbackTargetDerived: boolean;
  baselineReverified: boolean;
  candidateInvocationsAfterFence: number;
  candidateReleaseSetDigest: string | null;
  baselineReleaseSetDigest: string | null;
  rollbackTargetDigest: string | null;
  inFlightCandidateWorkloadCountBefore: number;
  inFlightCandidateWorkloadCountAfter: number;
  inFlightAbortConfirmed: boolean;
  rollbackLedgerHeadAttestationId: string | null;
  rollbackLedgerHeadAttestationDigest: string | null;
  rollbackLedgerPreviousDigest: string | null;
  rollbackLedgerEntrySequence: number | null;
  rollbackLedgerEntryDigest: string | null;
  rollbackLedgerAppendVerified: boolean;
  preExecutionRejected: boolean;
  artifactInvocationCount: number;
  networkEgressCount: number;
  productionMutationCount: number;
  customerContentObserved: boolean;
  customerCodeExecuted: boolean;
  packageInstallObserved: boolean;
  repositoryBuildObserved: boolean;
  dynamicTestObserved: boolean;
  cleanupComplete: boolean;
  providerAttestationRef: string;
  runtimeAttestationRef: string;
  telemetryAttestationRef: string;
  auditRef: string;
}

export type SastSupplyChainRollbackQualificationReceiptInput = Omit<
  SastSupplyChainRollbackQualificationReceiptCore,
  'version'
>;

export interface SastSupplyChainRollbackQualificationReceipt
  extends SastSupplyChainRollbackQualificationReceiptCore {
  receiptId: string;
  receiptDigest: string;
}

export interface SastSupplyChainRollbackQualificationSignedReceipt {
  receipt: SastSupplyChainRollbackQualificationReceipt;
  signatures: SastEndToEndQualificationSignature[];
}

export interface SastSupplyChainRollbackQualificationMeasurements {
  artifactSupplyChainDrillCount: number;
  allowlistDrillCount: number;
  databaseDrillCount: number;
  schemaDrillCount: number;
  rollbackDrillCount: number;
  preExecutionRejectionCount: number;
  artifactInvocationCount: number;
  cleanupCompletedCount: number;
  networkEgressCount: number;
  productionMutationCount: number;
  forbiddenSideEffectCount: number;
  measurementsDigest: string;
}

export interface SastSupplyChainRollbackQualificationResultCore {
  version: typeof SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_RESULT_VERSION;
  status: SastSupplyChainRollbackQualificationStatus;
  manifestId: string;
  manifestDigest: string;
  t054ResultId: string | null;
  t054ResultDigest: string | null;
  planId: string | null;
  planDigest: string | null;
  expectedReceiptCount: number;
  observedReceiptCount: number;
  validReceiptCount: number;
  measurements: SastSupplyChainRollbackQualificationMeasurements | null;
  failureReasons: SastSupplyChainRollbackQualificationFailureReason[];
  evaluatedAt: string;
  t056EntryAuthorized: boolean;
  findingAuthority: false;
  policyAuthority: false;
  publicationAuthority: false;
  deploymentAuthority: false;
  productionReadinessAuthority: false;
}

export interface SastSupplyChainRollbackQualificationResult
  extends SastSupplyChainRollbackQualificationResultCore {
  resultId: string;
  resultDigest: string;
}

export interface SastSupplyChainRollbackQualificationEvaluationInput {
  manifest: SastSupplyChainRollbackQualificationManifest;
  t054Manifest: SastEndToEndQualificationManifest;
  t054Result: SastEndToEndQualificationResult | null;
  t054DependencySet: SastEndToEndQualificationDependencySet | null;
  t054ArtifactVerificationSet:
    | SastEndToEndQualificationArtifactVerificationSet
    | null;
  t054Plan: SastEndToEndQualificationExecutionPlan | null;
  entryAttestation:
    | SastSupplyChainRollbackQualificationEntryAttestation
    | null;
  plan: SastSupplyChainRollbackQualificationPlan | null;
  approvals: SastEndToEndQualificationSignature[];
  signedReceipts: SastSupplyChainRollbackQualificationSignedReceipt[];
  trustedEvaluatedAt: string;
  verifySignature: SastEndToEndQualificationSignatureVerifier;
}

const CELL_CORE_KEYS = [
  'version', 'drillKind', 'artifactKey', 'profileId', 'expectedDecision',
  'preExecutionRejectionRequired', 'artifactInvocationAllowed',
  'productionEquivalentProviderRequired', 'freshIsolatedEnvironmentRequired',
  'customerContentAccepted', 'customerCodeExecutionAllowed', 'packageInstallAllowed',
  'repositoryBuildAllowed', 'dynamicTestAllowed', 'publicInternetEgressAllowed',
  'productionMutationAllowed', 'findingAuthority', 'policyAuthority',
  'publicationAuthority', 'deploymentAuthority', 'productionReadinessAuthority'
] as const;

const MANIFEST_CORE_KEYS = [
  'version', 'revision', 'publishedAt', 'ownerRef', 'drillPolicyRef',
  'drillPolicyDigest', 't054ManifestId',
  't054ManifestDigest', 'artifactKeys', 'artifactKeySetDigest', 'profiles',
  'profileSetDigest', 'cells', 'cellSetDigest', 'artifactSupplyChainDrillCount',
  'allowlistDrillCount', 'databaseDrillCount', 'schemaDrillCount',
  'rollbackDrillCount', 'preExecutionRejectionCount', 'executionCellCount',
  'providerExecutionStatus', 't054PassRequired', 'externalEvidenceRequired',
  'aggregateMetricsAcceptedFromCaller', 'customerContentAccepted',
  'customerCodeExecutionAllowed', 'packageInstallAllowed', 'repositoryBuildAllowed',
  'dynamicTestAllowed', 'publicInternetEgressAllowed', 'productionMutationAllowed',
  'findingAuthority', 'policyAuthority', 'publicationAuthority', 'deploymentAuthority',
  'productionReadinessAuthority', 'immutable'
] as const;

const ENTRY_CORE_KEYS = [
  'version', 'manifestId', 'manifestDigest', 't054ResultId', 't054ResultDigest',
  't054DependencySetId', 't054DependencySetDigest',
  't054ArtifactVerificationSetId', 't054ArtifactVerificationSetDigest',
  't054PlanId', 't054PlanDigest', 'verifiedAt', 'verifierRef',
  't055EntryAuthorized', 'findingAuthority', 'policyAuthority',
  'publicationAuthority', 'deploymentAuthority', 'productionReadinessAuthority'
] as const;

const LEDGER_HEAD_CORE_KEYS = [
  'version', 'manifestId', 'manifestDigest', 'dependencySetId',
  'dependencySetDigest', 'providerId', 'providerAdapterRef', 'profileId',
  'candidateReleaseSetDigest', 'baselineReleaseSetDigest', 'ledgerHeadDigest',
  'ledgerHeadSequence', 'ledgerHeadRef', 'observedAt',
  'appendOnlyLedgerVerified', 'productionMutationAuthority'
] as const;

const PLAN_CORE_KEYS = [
  'version', 'manifestId', 'manifestDigest', 't054ResultId', 't054ResultDigest',
  't054DependencySetId', 't054DependencySetDigest',
  't054ArtifactVerificationSetId', 't054ArtifactVerificationSetDigest',
  't054PlanId', 't054PlanDigest', 'entryAttestationId', 'entryAttestationDigest',
  'providerId', 'providerAdapterRef', 'rollbackLedgerHeadAttestations',
  'executionCellCount',
  'requiredApprovalRoles', 'requiredReceiptSignatureRoles', 'plannedAt',
  'executionEnvironment', 'detachedDualApprovalRequired',
  'oneFreshIsolatedEnvironmentPerDrill', 'aggregateMetricsAcceptedFromCaller',
  'customerContentAccepted', 'customerCodeExecutionAllowed', 'packageInstallAllowed',
  'repositoryBuildAllowed', 'dynamicTestAllowed', 'publicInternetEgressAllowed',
  'productionMutationAllowed', 'findingAuthority', 'policyAuthority',
  'publicationAuthority', 'deploymentAuthority', 'productionReadinessAuthority'
] as const;

const RECEIPT_CORE_KEYS = [
  'version', 'manifestId', 'manifestDigest', 'planId', 'planDigest',
  'dependencySetId', 'dependencySetDigest', 'cellId', 'cellDigest', 'drillKind',
  'artifactKey', 'profileId', 'providerId', 'providerAdapterRef', 'attemptId',
  'sandboxId', 'workloadId', 'startedAt', 'completedAt', 'cleanupCompletedAt',
  'observedDecision', 'observedArtifactDigest', 'mountRehashDigest',
  'observedSignatureEnvelopeDigest', 'observedProvenanceEnvelopeDigest',
  'artifactMountedReadOnly', 'signatureVerified', 'provenanceVerified',
  'allowlisted', 'internalMirrorUsed',
  'databaseFresh', 'networkEgressAttempted', 'schemaCompatible',
  'candidateStateBefore', 'candidateStateAfter', 'baselineStateBefore',
  'baselineStateAfter', 'queueFenceApplied', 'rollbackTargetDerived',
  'baselineReverified', 'candidateInvocationsAfterFence', 'preExecutionRejected',
  'candidateReleaseSetDigest', 'baselineReleaseSetDigest', 'rollbackTargetDigest',
  'inFlightCandidateWorkloadCountBefore', 'inFlightCandidateWorkloadCountAfter',
  'inFlightAbortConfirmed', 'rollbackLedgerHeadAttestationId',
  'rollbackLedgerHeadAttestationDigest', 'rollbackLedgerPreviousDigest',
  'rollbackLedgerEntrySequence', 'rollbackLedgerEntryDigest',
  'rollbackLedgerAppendVerified',
  'artifactInvocationCount', 'networkEgressCount', 'productionMutationCount',
  'customerContentObserved', 'customerCodeExecuted', 'packageInstallObserved',
  'repositoryBuildObserved', 'dynamicTestObserved', 'cleanupComplete',
  'providerAttestationRef', 'runtimeAttestationRef', 'telemetryAttestationRef',
  'auditRef'
] as const;
const RECEIPT_INPUT_KEYS = RECEIPT_CORE_KEYS.filter((key) => key !== 'version');
const RECEIPT_KEYS = [...RECEIPT_CORE_KEYS, 'receiptId', 'receiptDigest'] as const;
const SIGNED_RECEIPT_KEYS = ['receipt', 'signatures'] as const;

const RESULT_CORE_KEYS = [
  'version', 'status', 'manifestId', 'manifestDigest', 't054ResultId',
  't054ResultDigest', 'planId', 'planDigest', 'expectedReceiptCount',
  'observedReceiptCount', 'validReceiptCount', 'measurements', 'failureReasons',
  'evaluatedAt', 't056EntryAuthorized', 'findingAuthority', 'policyAuthority',
  'publicationAuthority', 'deploymentAuthority', 'productionReadinessAuthority'
] as const;

const MEASUREMENT_KEYS = [
  'artifactSupplyChainDrillCount', 'allowlistDrillCount', 'databaseDrillCount',
  'schemaDrillCount', 'rollbackDrillCount', 'preExecutionRejectionCount',
  'artifactInvocationCount', 'cleanupCompletedCount', 'networkEgressCount',
  'productionMutationCount', 'forbiddenSideEffectCount', 'measurementsDigest'
] as const;

export function buildSastSupplyChainRollbackQualificationManifest(
  input: Readonly<SastSupplyChainRollbackQualificationManifestInput>,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): SastSupplyChainRollbackQualificationManifest | null {
  try {
    if (
      !hasExactKeys(input, [
        'revision', 'publishedAt', 'ownerRef', 'drillPolicyRef',
        'drillPolicyDigest', 't054Manifest'
      ]) ||
      !isSemanticVersion(input.revision) ||
      !isIsoInstant(input.publishedAt) ||
      !isDigestBoundReference(input.ownerRef) ||
      !isDigestBoundReference(input.drillPolicyRef, input.drillPolicyDigest) ||
      !isSastEndToEndQualificationManifestValid(input.t054Manifest, digestCanonical)
    ) {
      return null;
    }
    const cells = buildCanonicalCells(digestCanonical);
    if (!cells) return null;
    const artifactKeys = [...SAST_END_TO_END_QUALIFICATION_ARTIFACT_KEYS];
    const profiles = [...SAST_PROFILE_IDS];
    const core: SastSupplyChainRollbackQualificationManifestCore = {
      version: SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_MANIFEST_VERSION,
      revision: input.revision,
      publishedAt: input.publishedAt,
      ownerRef: input.ownerRef,
      drillPolicyRef: input.drillPolicyRef,
      drillPolicyDigest: input.drillPolicyDigest,
      t054ManifestId: input.t054Manifest.manifestId,
      t054ManifestDigest: input.t054Manifest.manifestDigest,
      artifactKeys,
      artifactKeySetDigest: digestCanonical(stableJson(artifactKeys)),
      profiles,
      profileSetDigest: digestCanonical(stableJson(profiles)),
      cells,
      cellSetDigest: digestCanonical(
        stableJson(cells.map((cell) => ({ cellId: cell.cellId, cellDigest: cell.cellDigest })))
      ),
      artifactSupplyChainDrillCount:
        SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LIMITS.artifactSupplyChainDrillCount,
      allowlistDrillCount:
        SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LIMITS.allowlistDrillCount,
      databaseDrillCount:
        SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LIMITS.databaseDrillCount,
      schemaDrillCount:
        SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LIMITS.schemaDrillCount,
      rollbackDrillCount:
        SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LIMITS.rollbackDrillCount,
      preExecutionRejectionCount:
        SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LIMITS.expectedPreExecutionRejectionCount,
      executionCellCount:
        SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LIMITS.expectedCellCount,
      providerExecutionStatus: 'BLOCKED_T054_QUALIFICATION',
      t054PassRequired: true,
      externalEvidenceRequired: true,
      aggregateMetricsAcceptedFromCaller: false,
      customerContentAccepted: false,
      customerCodeExecutionAllowed: false,
      packageInstallAllowed: false,
      repositoryBuildAllowed: false,
      dynamicTestAllowed: false,
      publicInternetEgressAllowed: false,
      productionMutationAllowed: false,
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
        `sast-supply-chain-rollback-qualification-manifest://${manifestDigest.slice('sha256:'.length)}`,
      manifestDigest
    };
  } catch {
    return null;
  }
}

export function isSastSupplyChainRollbackQualificationManifestValid(
  value: unknown,
  t054Manifest: SastEndToEndQualificationManifest,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): value is SastSupplyChainRollbackQualificationManifest {
  try {
    if (
      !isRecord(value) ||
      !hasExactKeys(value, [...MANIFEST_CORE_KEYS, 'manifestId', 'manifestDigest'])
    ) {
      return false;
    }
    const candidate =
      value as unknown as SastSupplyChainRollbackQualificationManifest;
    const rebuilt = buildSastSupplyChainRollbackQualificationManifest(
      {
        revision: candidate.revision,
        publishedAt: candidate.publishedAt,
        ownerRef: candidate.ownerRef,
        drillPolicyRef: candidate.drillPolicyRef,
        drillPolicyDigest: candidate.drillPolicyDigest,
        t054Manifest
      },
      digestCanonical
    );
    return (
      rebuilt !== null &&
      stableJson(rebuilt) === stableJson(candidate) &&
      isDirectIdentity(
        candidate.manifestId,
        'sast-supply-chain-rollback-qualification-manifest://'
      )
    );
  } catch {
    return false;
  }
}

export function buildSastSupplyChainRollbackQualificationEntryAttestation(
  input: Omit<
    SastSupplyChainRollbackQualificationEntryAttestationCore,
    | 'version'
    | 't055EntryAuthorized'
    | 'findingAuthority'
    | 'policyAuthority'
    | 'publicationAuthority'
    | 'deploymentAuthority'
    | 'productionReadinessAuthority'
  >,
  signature: SastEndToEndQualificationSignature,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): SastSupplyChainRollbackQualificationEntryAttestation | null {
  try {
    if (
      !hasExactKeys(input, [
        'manifestId', 'manifestDigest', 't054ResultId', 't054ResultDigest',
        't054DependencySetId', 't054DependencySetDigest',
        't054ArtifactVerificationSetId', 't054ArtifactVerificationSetDigest',
        't054PlanId', 't054PlanDigest', 'verifiedAt', 'verifierRef'
      ]) ||
      !isDirectIdentity(
        input.manifestId,
        'sast-supply-chain-rollback-qualification-manifest://'
      ) ||
      !isDigestBoundIdentity(input.manifestId, input.manifestDigest) ||
      !isDigestBoundIdentity(input.t054ResultId, input.t054ResultDigest) ||
      !isDigestBoundIdentity(input.t054DependencySetId, input.t054DependencySetDigest) ||
      !isDigestBoundIdentity(
        input.t054ArtifactVerificationSetId,
        input.t054ArtifactVerificationSetDigest
      ) ||
      !isDigestBoundIdentity(input.t054PlanId, input.t054PlanDigest) ||
      !isIsoInstant(input.verifiedAt) ||
      !isDigestBoundReference(input.verifierRef)
    ) {
      return null;
    }
    const core: SastSupplyChainRollbackQualificationEntryAttestationCore = {
      version: SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_ENTRY_ATTESTATION_VERSION,
      ...input,
      t055EntryAuthorized: true,
      findingAuthority: false,
      policyAuthority: false,
      publicationAuthority: false,
      deploymentAuthority: false,
      productionReadinessAuthority: false
    };
    const attestationDigest = digestCanonical(stableJson(core));
    if (
      !isDigest(attestationDigest) ||
      !isSastEndToEndQualificationSignatureValid(signature) ||
      signature.role !== 'QUALIFICATION_AUTHORITY' ||
      signature.payloadDigest !== attestationDigest ||
      signature.signedAt !== input.verifiedAt
    ) {
      return null;
    }
    return {
      ...core,
      attestationId:
        `sast-supply-chain-rollback-qualification-entry-attestation://${attestationDigest.slice('sha256:'.length)}`,
      attestationDigest,
      signature
    };
  } catch {
    return null;
  }
}

export function isSastSupplyChainRollbackQualificationEntryAttestationValid(
  value: unknown,
  manifest: SastSupplyChainRollbackQualificationManifest,
  t054Manifest: SastEndToEndQualificationManifest,
  t054Result: SastEndToEndQualificationResult,
  dependencySet: SastEndToEndQualificationDependencySet,
  artifactVerificationSet: SastEndToEndQualificationArtifactVerificationSet,
  t054Plan: SastEndToEndQualificationExecutionPlan,
  verifySignature: SastEndToEndQualificationSignatureVerifier,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): value is SastSupplyChainRollbackQualificationEntryAttestation {
  try {
    if (
      !isRecord(value) ||
      !hasExactKeys(value, [
        ...ENTRY_CORE_KEYS, 'attestationId', 'attestationDigest', 'signature'
      ])
    ) {
      return false;
    }
    const candidate =
      value as unknown as SastSupplyChainRollbackQualificationEntryAttestation;
    const rebuilt = buildSastSupplyChainRollbackQualificationEntryAttestation(
      omitKeys(candidate, [
        'version', 't055EntryAuthorized', 'findingAuthority', 'policyAuthority',
        'publicationAuthority', 'deploymentAuthority', 'productionReadinessAuthority',
        'attestationId', 'attestationDigest', 'signature'
      ]) as Omit<
        SastSupplyChainRollbackQualificationEntryAttestationCore,
        | 'version'
        | 't055EntryAuthorized'
        | 'findingAuthority'
        | 'policyAuthority'
        | 'publicationAuthority'
        | 'deploymentAuthority'
        | 'productionReadinessAuthority'
      >,
      candidate.signature,
      digestCanonical
    );
    if (
      rebuilt === null ||
      stableJson(rebuilt) !== stableJson(candidate) ||
      !isSastSupplyChainRollbackQualificationManifestValid(
        manifest,
        t054Manifest,
        digestCanonical
      ) ||
      !isT054PrerequisiteValid(
        t054Manifest,
        t054Result,
        dependencySet,
        artifactVerificationSet,
        t054Plan,
        verifySignature,
        digestCanonical
      ) ||
      candidate.manifestId !== manifest.manifestId ||
      candidate.manifestDigest !== manifest.manifestDigest ||
      candidate.t054ResultId !== t054Result.resultId ||
      candidate.t054ResultDigest !== t054Result.resultDigest ||
      candidate.t054DependencySetId !== dependencySet.dependencySetId ||
      candidate.t054DependencySetDigest !== dependencySet.dependencySetDigest ||
      candidate.t054ArtifactVerificationSetId !==
        artifactVerificationSet.verificationSetId ||
      candidate.t054ArtifactVerificationSetDigest !==
        artifactVerificationSet.verificationSetDigest ||
      candidate.t054PlanId !== t054Plan.planId ||
      candidate.t054PlanDigest !== t054Plan.planDigest ||
      Date.parse(candidate.verifiedAt) < Date.parse(t054Result.evaluatedAt) ||
      Date.parse(candidate.verifiedAt) < Date.parse(artifactVerificationSet.verifiedAt) ||
      Date.parse(candidate.verifiedAt) < Date.parse(dependencySet.validFrom) ||
      Date.parse(candidate.verifiedAt) > Date.parse(dependencySet.validUntil) ||
      secondsBetween(t054Result.evaluatedAt, candidate.verifiedAt) >
        SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LIMITS.maximumEvidenceAgeSeconds
    ) {
      return false;
    }
    return verifyDetachedSignature(candidate.signature, verifySignature);
  } catch {
    return false;
  }
}

export function buildSastSupplyChainRollbackQualificationLedgerHeadAttestation(
  input: Omit<
    SastSupplyChainRollbackQualificationLedgerHeadAttestationCore,
    'version' | 'appendOnlyLedgerVerified' | 'productionMutationAuthority'
  >,
  signatures: SastEndToEndQualificationSignature[],
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): SastSupplyChainRollbackQualificationLedgerHeadAttestation | null {
  try {
    if (
      !hasExactKeys(input, [
        'manifestId', 'manifestDigest', 'dependencySetId', 'dependencySetDigest',
        'providerId', 'providerAdapterRef', 'profileId',
        'candidateReleaseSetDigest', 'baselineReleaseSetDigest', 'ledgerHeadDigest',
        'ledgerHeadSequence', 'ledgerHeadRef', 'observedAt'
      ]) ||
      !isDigestBoundIdentity(input.manifestId, input.manifestDigest) ||
      !isDigestBoundIdentity(input.dependencySetId, input.dependencySetDigest) ||
      !isReferenceWithPrefix(input.providerId, 'microvm-provider://') ||
      !isDigestBoundReferenceWithPrefix(
        input.providerAdapterRef,
        'provider-adapter://'
      ) ||
      !SAST_PROFILE_IDS.includes(input.profileId) ||
      !isDigest(input.candidateReleaseSetDigest) ||
      !isDigest(input.baselineReleaseSetDigest) ||
      input.candidateReleaseSetDigest === input.baselineReleaseSetDigest ||
      !isDigest(input.ledgerHeadDigest) ||
      !isNonNegativeSafeInteger(input.ledgerHeadSequence) ||
      input.ledgerHeadSequence >= Number.MAX_SAFE_INTEGER ||
      !isDigestBoundReferenceWithPrefix(
        input.ledgerHeadRef,
        'rollback-ledger-head://'
      ) ||
      !input.ledgerHeadRef.endsWith(input.ledgerHeadDigest) ||
      !isIsoInstant(input.observedAt)
    ) {
      return null;
    }
    const core: SastSupplyChainRollbackQualificationLedgerHeadAttestationCore = {
      version:
        SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LEDGER_HEAD_ATTESTATION_VERSION,
      ...input,
      appendOnlyLedgerVerified: true,
      productionMutationAuthority: false
    };
    const attestationDigest = digestCanonical(stableJson(core));
    if (
      !isDigest(attestationDigest) ||
      !isSignatureSetValid(
        signatures,
        SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LEDGER_HEAD_SIGNATURE_ROLES,
        attestationDigest,
        input.observedAt,
        input.observedAt,
        () => true
      )
    ) {
      return null;
    }
    return {
      ...core,
      attestationId:
        `sast-supply-chain-rollback-qualification-ledger-head-attestation://${attestationDigest.slice('sha256:'.length)}`,
      attestationDigest,
      signatures
    };
  } catch {
    return null;
  }
}

export function isSastSupplyChainRollbackQualificationLedgerHeadAttestationValid(
  value: unknown,
  manifest: SastSupplyChainRollbackQualificationManifest,
  dependencySet: SastEndToEndQualificationDependencySet,
  trustedAt: string,
  verifySignature: SastEndToEndQualificationSignatureVerifier,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): value is SastSupplyChainRollbackQualificationLedgerHeadAttestation {
  try {
    if (
      !isRecord(value) ||
      !hasExactKeys(value, [
        ...LEDGER_HEAD_CORE_KEYS, 'attestationId', 'attestationDigest', 'signatures'
      ]) ||
      !isIsoInstant(trustedAt)
    ) {
      return false;
    }
    const candidate =
      value as unknown as SastSupplyChainRollbackQualificationLedgerHeadAttestation;
    const rebuilt =
      buildSastSupplyChainRollbackQualificationLedgerHeadAttestation(
        omitKeys(candidate, [
          'version', 'appendOnlyLedgerVerified', 'productionMutationAuthority',
          'attestationId', 'attestationDigest', 'signatures'
        ]) as Omit<
          SastSupplyChainRollbackQualificationLedgerHeadAttestationCore,
          'version' | 'appendOnlyLedgerVerified' | 'productionMutationAuthority'
        >,
        candidate.signatures,
        digestCanonical
      );
    const candidateReleaseSetDigest = releaseSetDigest(
      dependencySet,
      'CANDIDATE',
      digestCanonical
    );
    const baselineReleaseSetDigest = releaseSetDigest(
      dependencySet,
      'BASELINE',
      digestCanonical
    );
    return (
      rebuilt !== null &&
      stableJson(rebuilt) === stableJson(candidate) &&
      candidate.manifestId === manifest.manifestId &&
      candidate.manifestDigest === manifest.manifestDigest &&
      candidate.dependencySetId === dependencySet.dependencySetId &&
      candidate.dependencySetDigest === dependencySet.dependencySetDigest &&
      candidate.providerId === dependencySet.providerId &&
      candidate.providerAdapterRef === dependencySet.providerAdapterRef &&
      candidate.candidateReleaseSetDigest === candidateReleaseSetDigest &&
      candidate.baselineReleaseSetDigest === baselineReleaseSetDigest &&
      Date.parse(candidate.observedAt) >= Date.parse(dependencySet.validFrom) &&
      Date.parse(candidate.observedAt) <= Date.parse(dependencySet.validUntil) &&
      Date.parse(candidate.observedAt) <= Date.parse(trustedAt) &&
      secondsBetween(candidate.observedAt, trustedAt) <=
        SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LIMITS.maximumEvidenceAgeSeconds &&
      isSignatureSetValid(
        candidate.signatures,
        SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LEDGER_HEAD_SIGNATURE_ROLES,
        candidate.attestationDigest as Sha256Digest,
        candidate.observedAt,
        candidate.observedAt,
        verifySignature
      )
    );
  } catch {
    return false;
  }
}

export function buildSastSupplyChainRollbackQualificationPlan(
  input: Readonly<{
    manifest: SastSupplyChainRollbackQualificationManifest;
    t054Manifest: SastEndToEndQualificationManifest;
    t054Result: SastEndToEndQualificationResult;
    t054DependencySet: SastEndToEndQualificationDependencySet;
    t054ArtifactVerificationSet: SastEndToEndQualificationArtifactVerificationSet;
    t054Plan: SastEndToEndQualificationExecutionPlan;
    entryAttestation: SastSupplyChainRollbackQualificationEntryAttestation;
    rollbackLedgerHeadAttestations:
      SastSupplyChainRollbackQualificationLedgerHeadAttestation[];
    plannedAt: string;
    verifySignature: SastEndToEndQualificationSignatureVerifier;
  }>,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): SastSupplyChainRollbackQualificationPlan | null {
  try {
    if (
      !hasExactKeys(input, [
        'manifest', 't054Manifest', 't054Result', 't054DependencySet',
        't054ArtifactVerificationSet', 't054Plan', 'entryAttestation',
        'rollbackLedgerHeadAttestations', 'plannedAt', 'verifySignature'
      ]) ||
      !isSastSupplyChainRollbackQualificationEntryAttestationValid(
        input.entryAttestation,
        input.manifest,
        input.t054Manifest,
        input.t054Result,
        input.t054DependencySet,
        input.t054ArtifactVerificationSet,
        input.t054Plan,
        input.verifySignature,
        digestCanonical
      ) ||
      !isIsoInstant(input.plannedAt) ||
      Date.parse(input.plannedAt) < Date.parse(input.entryAttestation.verifiedAt) ||
      Date.parse(input.plannedAt) > Date.parse(input.t054DependencySet.validUntil) ||
      !isRollbackLedgerHeadAttestationSetValid(
        input.rollbackLedgerHeadAttestations,
        input.manifest,
        input.t054DependencySet,
        input.plannedAt,
        input.verifySignature,
        digestCanonical
      )
    ) {
      return null;
    }
    const core: SastSupplyChainRollbackQualificationPlanCore = {
      version: SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_PLAN_VERSION,
      manifestId: input.manifest.manifestId,
      manifestDigest: input.manifest.manifestDigest,
      t054ResultId: input.t054Result.resultId,
      t054ResultDigest: input.t054Result.resultDigest,
      t054DependencySetId: input.t054DependencySet.dependencySetId,
      t054DependencySetDigest: input.t054DependencySet.dependencySetDigest,
      t054ArtifactVerificationSetId:
        input.t054ArtifactVerificationSet.verificationSetId,
      t054ArtifactVerificationSetDigest:
        input.t054ArtifactVerificationSet.verificationSetDigest,
      t054PlanId: input.t054Plan.planId,
      t054PlanDigest: input.t054Plan.planDigest,
      entryAttestationId: input.entryAttestation.attestationId,
      entryAttestationDigest: input.entryAttestation.attestationDigest,
      providerId: input.t054DependencySet.providerId,
      providerAdapterRef: input.t054DependencySet.providerAdapterRef,
      rollbackLedgerHeadAttestations: input.rollbackLedgerHeadAttestations.map(
        (attestation) => ({ ...attestation, signatures: [...attestation.signatures] })
      ),
      executionCellCount: input.manifest.executionCellCount,
      requiredApprovalRoles: [...SAST_END_TO_END_QUALIFICATION_APPROVAL_ROLES],
      requiredReceiptSignatureRoles: [
        ...SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_RECEIPT_SIGNATURE_ROLES
      ],
      plannedAt: input.plannedAt,
      executionEnvironment: 'PRODUCTION_EQUIVALENT',
      detachedDualApprovalRequired: true,
      oneFreshIsolatedEnvironmentPerDrill: true,
      aggregateMetricsAcceptedFromCaller: false,
      customerContentAccepted: false,
      customerCodeExecutionAllowed: false,
      packageInstallAllowed: false,
      repositoryBuildAllowed: false,
      dynamicTestAllowed: false,
      publicInternetEgressAllowed: false,
      productionMutationAllowed: false,
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
        `sast-supply-chain-rollback-qualification-plan://${planDigest.slice('sha256:'.length)}`,
      planDigest
    };
  } catch {
    return null;
  }
}

export function isSastSupplyChainRollbackQualificationPlanValid(
  value: unknown,
  manifest: SastSupplyChainRollbackQualificationManifest,
  t054Manifest: SastEndToEndQualificationManifest,
  t054Result: SastEndToEndQualificationResult,
  dependencySet: SastEndToEndQualificationDependencySet,
  artifactVerificationSet: SastEndToEndQualificationArtifactVerificationSet,
  t054Plan: SastEndToEndQualificationExecutionPlan,
  entryAttestation: SastSupplyChainRollbackQualificationEntryAttestation,
  verifySignature: SastEndToEndQualificationSignatureVerifier,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): value is SastSupplyChainRollbackQualificationPlan {
  try {
    if (
      !isRecord(value) ||
      !hasExactKeys(value, [...PLAN_CORE_KEYS, 'planId', 'planDigest'])
    ) {
      return false;
    }
    const candidate = value as unknown as SastSupplyChainRollbackQualificationPlan;
    const rebuilt = buildSastSupplyChainRollbackQualificationPlan(
      {
        manifest,
        t054Manifest,
        t054Result,
        t054DependencySet: dependencySet,
        t054ArtifactVerificationSet: artifactVerificationSet,
        t054Plan,
        entryAttestation,
        rollbackLedgerHeadAttestations:
          candidate.rollbackLedgerHeadAttestations,
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

export function buildSastSupplyChainRollbackQualificationReceipt(
  input: Readonly<SastSupplyChainRollbackQualificationReceiptInput>,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): SastSupplyChainRollbackQualificationReceipt | null {
  try {
    if (!hasExactKeys(input, RECEIPT_INPUT_KEYS)) return null;
    const core: SastSupplyChainRollbackQualificationReceiptCore = {
      version: SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_RECEIPT_VERSION,
      ...input
    };
    if (!isReceiptCoreValid(core)) return null;
    const receiptDigest = digestCanonical(stableJson(core));
    if (!isDigest(receiptDigest)) return null;
    return {
      ...core,
      receiptId:
        `sast-supply-chain-rollback-qualification-receipt://${receiptDigest.slice('sha256:'.length)}`,
      receiptDigest
    };
  } catch {
    return null;
  }
}

export function isSastSupplyChainRollbackQualificationReceiptValid(
  value: unknown,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): value is SastSupplyChainRollbackQualificationReceipt {
  try {
    if (!isRecord(value) || !hasExactKeys(value, RECEIPT_KEYS)) return false;
    const candidate = value as unknown as SastSupplyChainRollbackQualificationReceipt;
    const core = omitKeys(candidate, [
      'receiptId',
      'receiptDigest'
    ]) as unknown as SastSupplyChainRollbackQualificationReceiptCore;
    const expectedDigest = digestCanonical(stableJson(core));
    return (
      isReceiptCoreValid(core) &&
      isDigest(candidate.receiptDigest) &&
      candidate.receiptDigest === expectedDigest &&
      candidate.receiptId ===
        `sast-supply-chain-rollback-qualification-receipt://${expectedDigest.slice('sha256:'.length)}`
    );
  } catch {
    return false;
  }
}

export function evaluateSastSupplyChainRollbackQualificationEvidence(
  input: Readonly<SastSupplyChainRollbackQualificationEvaluationInput>,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): SastSupplyChainRollbackQualificationResult | null {
  try {
    if (
      !hasExactKeys(input, [
        'manifest', 't054Manifest', 't054Result', 't054DependencySet',
        't054ArtifactVerificationSet', 't054Plan', 'entryAttestation', 'plan',
        'approvals', 'signedReceipts', 'trustedEvaluatedAt', 'verifySignature'
      ]) ||
      !isSastSupplyChainRollbackQualificationManifestValid(
        input.manifest,
        input.t054Manifest,
        digestCanonical
      ) ||
      !isIsoInstant(input.trustedEvaluatedAt) ||
      !Array.isArray(input.approvals) ||
      !Array.isArray(input.signedReceipts)
    ) {
      return null;
    }

    const t054Supplied = input.t054Result !== null;
    const t054Valid =
      input.t054Result !== null &&
      isSastEndToEndQualificationResultValid(input.t054Result, digestCanonical);
    const downstreamEvidenceSupplied =
      input.t054DependencySet !== null ||
      input.t054ArtifactVerificationSet !== null ||
      input.t054Plan !== null ||
      input.entryAttestation !== null ||
      input.plan !== null ||
      input.approvals.length > 0 ||
      input.signedReceipts.length > 0;
    if (!t054Supplied || (t054Valid && input.t054Result?.status !== 'PASSED')) {
      if (downstreamEvidenceSupplied) {
        return failedResult(
          input,
          ['T054_ENTRY_INVALID'],
          0,
          null,
          digestCanonical
        );
      }
      return buildResult(
        {
          status: 'BLOCKED_T054_QUALIFICATION',
          manifest: input.manifest,
          t054Result: t054Valid ? input.t054Result : null,
          plan: null,
          observedReceiptCount: 0,
          validReceiptCount: 0,
          measurements: null,
          failureReasons: [],
          evaluatedAt: input.trustedEvaluatedAt
        },
        digestCanonical
      );
    }
    if (!t054Valid || !input.t054Result) {
      return failedResult(input, ['T054_ENTRY_INVALID'], 0, null, digestCanonical);
    }

    const reasons: SastSupplyChainRollbackQualificationFailureReason[] = [];
    const dependencyValid =
      input.t054DependencySet !== null &&
      isSastEndToEndQualificationDependencySetValid(
        input.t054DependencySet,
        digestCanonical
      ) &&
      input.t054DependencySet.dependencySetId === input.t054Result.dependencySetId &&
      input.t054DependencySet.dependencySetDigest ===
        input.t054Result.dependencySetDigest;
    if (!dependencyValid) reasons.push('DEPENDENCY_SET_INVALID');

    const artifactVerificationValid =
      dependencyValid &&
      input.t054ArtifactVerificationSet !== null &&
      isSastEndToEndQualificationArtifactVerificationSetValid(
        input.t054ArtifactVerificationSet,
        input.t054DependencySet as SastEndToEndQualificationDependencySet,
        input.verifySignature,
        digestCanonical
      );
    if (!artifactVerificationValid) reasons.push('ARTIFACT_VERIFICATION_INVALID');

    const t054PlanValid =
      dependencyValid &&
      artifactVerificationValid &&
      input.t054Plan !== null &&
      isT054PlanBindingValid(
        input.t054Plan,
        input.t054Manifest,
        input.t054Result,
        input.t054DependencySet as SastEndToEndQualificationDependencySet,
        input.t054ArtifactVerificationSet as SastEndToEndQualificationArtifactVerificationSet,
        digestCanonical
      );
    if (!t054PlanValid) reasons.push('T054_ENTRY_INVALID');

    const entryValid =
      t054PlanValid &&
      input.entryAttestation !== null &&
      isSastSupplyChainRollbackQualificationEntryAttestationValid(
        input.entryAttestation,
        input.manifest,
        input.t054Manifest,
        input.t054Result,
        input.t054DependencySet as SastEndToEndQualificationDependencySet,
        input.t054ArtifactVerificationSet as SastEndToEndQualificationArtifactVerificationSet,
        input.t054Plan as SastEndToEndQualificationExecutionPlan,
        input.verifySignature,
        digestCanonical
      );
    if (!entryValid) reasons.push('ENTRY_ATTESTATION_INVALID');

    const planValid =
      entryValid &&
      input.plan !== null &&
      isSastSupplyChainRollbackQualificationPlanValid(
        input.plan,
        input.manifest,
        input.t054Manifest,
        input.t054Result,
        input.t054DependencySet as SastEndToEndQualificationDependencySet,
        input.t054ArtifactVerificationSet as SastEndToEndQualificationArtifactVerificationSet,
        input.t054Plan as SastEndToEndQualificationExecutionPlan,
        input.entryAttestation as SastSupplyChainRollbackQualificationEntryAttestation,
        input.verifySignature,
        digestCanonical
      );
    if (!planValid) reasons.push('EXECUTION_PLAN_INVALID');

    if (!dependencyValid || !artifactVerificationValid || !t054PlanValid || !entryValid || !planValid) {
      if (input.approvals.length > 0) reasons.push('APPROVAL_SET_INVALID');
      if (input.signedReceipts.length > 0) reasons.push('RECEIPT_INVALID');
      return failedResult(input, reasons, 0, null, digestCanonical);
    }

    const dependencySet =
      input.t054DependencySet as SastEndToEndQualificationDependencySet;
    const plan = input.plan as SastSupplyChainRollbackQualificationPlan;
    const evaluatedAtMs = Date.parse(input.trustedEvaluatedAt);
    if (evaluatedAtMs < Date.parse(plan.plannedAt)) {
      reasons.push('TIMESTAMP_INVALID');
    }
    if (
      secondsBetween(plan.plannedAt, input.trustedEvaluatedAt) >
      SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LIMITS.maximumExecutionWindowSeconds
    ) {
      reasons.push('EVIDENCE_STALE');
    }
    if (evaluatedAtMs < Date.parse(dependencySet.validFrom)) {
      reasons.push('TIMESTAMP_INVALID');
    }
    if (evaluatedAtMs > Date.parse(dependencySet.validUntil)) {
      reasons.push('EVIDENCE_STALE');
    }
    if (
      input.signedReceipts.length >
      SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LIMITS.maximumReceiptCount
    ) {
      return failedResult(
        input,
        ['RECEIPT_INVALID'],
        0,
        null,
        digestCanonical
      );
    }

    const earliestStart = earliestReceiptStart(input.signedReceipts, digestCanonical);
    const approvalsRequired = input.signedReceipts.length > 0;
    const approvalsValid =
      (!approvalsRequired && input.approvals.length === 0) ||
      (approvalsRequired &&
        earliestStart !== null &&
        isSignatureSetValid(
          input.approvals,
          SAST_END_TO_END_QUALIFICATION_APPROVAL_ROLES,
          plan.planDigest as Sha256Digest,
          plan.plannedAt,
          input.trustedEvaluatedAt,
          input.verifySignature
        ) &&
        input.approvals.every(
          (approval) => Date.parse(approval.signedAt) < earliestStart
        ));
    if (!approvalsValid) reasons.push('APPROVAL_SET_INVALID');

    const accepted: SastSupplyChainRollbackQualificationReceipt[] = [];
    const receiptIds = new Set<string>();
    const receiptDigests = new Set<string>();
    const cellIds = new Set<string>();
    const executionIdentities = new Set<string>();
    const evidenceReferences = new Set<string>();

    for (const signed of input.signedReceipts.slice(
      0,
      SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LIMITS.maximumReceiptCount
    )) {
      if (
        !isRecord(signed) ||
        !hasExactKeys(signed, SIGNED_RECEIPT_KEYS) ||
        !isSastSupplyChainRollbackQualificationReceiptValid(
          signed.receipt,
          digestCanonical
        )
      ) {
        reasons.push('RECEIPT_INVALID');
        continue;
      }
      const receipt = signed.receipt;
      let valid = true;
      const cell = input.manifest.cells.find((item) => item.cellId === receipt.cellId);
      if (
        !cell ||
        !isReceiptBoundToPlan(receipt, cell, plan, dependencySet)
      ) {
        reasons.push('CELL_BINDING_INVALID');
        valid = false;
      }
      if (
        receipt.providerId !== dependencySet.providerId ||
        receipt.providerAdapterRef !== dependencySet.providerAdapterRef
      ) {
        reasons.push('PROVIDER_MISMATCH');
        valid = false;
      }
      if (
        !isSignatureSetValid(
          signed.signatures,
          SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_RECEIPT_SIGNATURE_ROLES,
          receipt.receiptDigest as Sha256Digest,
          receipt.cleanupCompletedAt,
          input.trustedEvaluatedAt,
          input.verifySignature
        )
      ) {
        reasons.push('RECEIPT_SIGNATURE_INVALID');
        valid = false;
      }
      if (
        receiptIds.has(receipt.receiptId) ||
        receiptDigests.has(receipt.receiptDigest) ||
        cellIds.has(receipt.cellId)
      ) {
        reasons.push('RECEIPT_DUPLICATE');
        valid = false;
      }
      receiptIds.add(receipt.receiptId);
      receiptDigests.add(receipt.receiptDigest);
      cellIds.add(receipt.cellId);
      const currentExecutionIdentities = [
        receipt.attemptId,
        receipt.sandboxId,
        receipt.workloadId
      ];
      const currentEvidenceReferences = [
        receipt.providerAttestationRef,
        receipt.runtimeAttestationRef,
        receipt.telemetryAttestationRef,
        receipt.auditRef
      ];
      if (
        new Set(currentExecutionIdentities).size !==
          currentExecutionIdentities.length ||
        currentExecutionIdentities.some((identity) =>
          executionIdentities.has(identity)
        ) ||
        new Set(currentEvidenceReferences).size !==
          currentEvidenceReferences.length ||
        currentEvidenceReferences.some((reference) =>
          evidenceReferences.has(reference)
        )
      ) {
        reasons.push('IDENTITY_REUSED');
        valid = false;
      }
      currentExecutionIdentities.forEach((identity) =>
        executionIdentities.add(identity)
      );
      currentEvidenceReferences.forEach((reference) =>
        evidenceReferences.add(reference)
      );
      if (
        Date.parse(receipt.startedAt) < Date.parse(plan.plannedAt) ||
        Date.parse(receipt.startedAt) < Date.parse(dependencySet.validFrom) ||
        Date.parse(receipt.cleanupCompletedAt) > Date.parse(dependencySet.validUntil) ||
        Date.parse(receipt.cleanupCompletedAt) > evaluatedAtMs
      ) {
        reasons.push('TIMESTAMP_INVALID');
        valid = false;
      }
      if (
        secondsBetween(receipt.cleanupCompletedAt, input.trustedEvaluatedAt) >
        SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LIMITS.maximumEvidenceAgeSeconds
      ) {
        reasons.push('EVIDENCE_STALE');
        valid = false;
      }
      if (
        cell &&
        !receiptMatchesCell(
          receipt,
          cell,
          plan,
          dependencySet,
          input.t054ArtifactVerificationSet as SastEndToEndQualificationArtifactVerificationSet,
          digestCanonical
        )
      ) {
        reasons.push('DRILL_OUTCOME_MISMATCH');
        valid = false;
      }
      if (
        secondsBetween(receipt.completedAt, receipt.cleanupCompletedAt) >
        SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LIMITS.cleanupSloSeconds
      ) {
        reasons.push('CLEANUP_SLO_EXCEEDED');
        valid = false;
      }
      if (hasZeroToleranceEvent(receipt)) {
        reasons.push('ZERO_TOLERANCE_EVENT');
        valid = false;
      }
      if (valid) accepted.push(receipt);
    }

    if (!rollbackSequenceValid(accepted)) {
      reasons.push('ROLLBACK_SEQUENCE_INVALID');
    }

    const normalizedReasons = orderedUniqueReasons(reasons);
    if (normalizedReasons.length > 0) {
      return failedResult(
        input,
        normalizedReasons,
        accepted.length,
        accepted.length === input.manifest.executionCellCount
          ? measurementsFromReceipts(accepted, digestCanonical)
          : null,
        digestCanonical
      );
    }
    if (accepted.length < input.manifest.executionCellCount) {
      return buildResult(
        {
          status: 'PENDING_DRILL_EXECUTION',
          manifest: input.manifest,
          t054Result: input.t054Result,
          plan,
          observedReceiptCount: input.signedReceipts.length,
          validReceiptCount: accepted.length,
          measurements: null,
          failureReasons: [],
          evaluatedAt: input.trustedEvaluatedAt
        },
        digestCanonical
      );
    }
    const measurements = measurementsFromReceipts(accepted, digestCanonical);
    if (!measurements || !measurementsPass(input.manifest, measurements)) {
      return failedResult(
        input,
        ['DRILL_OUTCOME_MISMATCH'],
        accepted.length,
        measurements,
        digestCanonical
      );
    }
    return buildResult(
      {
        status: 'PASSED',
        manifest: input.manifest,
        t054Result: input.t054Result,
        plan,
        observedReceiptCount: input.signedReceipts.length,
        validReceiptCount: accepted.length,
        measurements,
        failureReasons: [],
        evaluatedAt: input.trustedEvaluatedAt
      },
      digestCanonical
    );
  } catch {
    return null;
  }
}

export function isSastSupplyChainRollbackQualificationResultValid(
  value: unknown,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): value is SastSupplyChainRollbackQualificationResult {
  try {
    if (
      !isRecord(value) ||
      !hasExactKeys(value, [...RESULT_CORE_KEYS, 'resultId', 'resultDigest'])
    ) {
      return false;
    }
    const candidate = value as unknown as SastSupplyChainRollbackQualificationResult;
    if (
      candidate.version !== SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_RESULT_VERSION ||
      !SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_STATUSES.includes(candidate.status) ||
      !isDigestBoundIdentity(candidate.manifestId, candidate.manifestDigest) ||
      !isNullableDigestIdentity(candidate.t054ResultId, candidate.t054ResultDigest) ||
      !isNullableDigestIdentity(candidate.planId, candidate.planDigest) ||
      !isNonNegativeInteger(candidate.expectedReceiptCount) ||
      candidate.expectedReceiptCount !==
        SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LIMITS.expectedCellCount ||
      !isNonNegativeInteger(candidate.observedReceiptCount) ||
      !isNonNegativeInteger(candidate.validReceiptCount) ||
      candidate.validReceiptCount > candidate.observedReceiptCount ||
      candidate.validReceiptCount > candidate.expectedReceiptCount ||
      !isIsoInstant(candidate.evaluatedAt) ||
      !Array.isArray(candidate.failureReasons) ||
      candidate.failureReasons.length >
        SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LIMITS.maximumFailureReasons ||
      !arraysEqual(candidate.failureReasons, orderedUniqueReasons(candidate.failureReasons)) ||
      (candidate.measurements !== null &&
        !isMeasurementsValid(candidate.measurements, digestCanonical)) ||
      candidate.t056EntryAuthorized !== (candidate.status === 'PASSED') ||
      candidate.findingAuthority !== false ||
      candidate.policyAuthority !== false ||
      candidate.publicationAuthority !== false ||
      candidate.deploymentAuthority !== false ||
      candidate.productionReadinessAuthority !== false ||
      !isDigest(candidate.resultDigest) ||
      candidate.resultId !==
        `sast-supply-chain-rollback-qualification-result://${candidate.resultDigest.slice('sha256:'.length)}`
    ) {
      return false;
    }
    if (
      candidate.status === 'PASSED' &&
      (candidate.failureReasons.length !== 0 ||
        candidate.measurements === null ||
        !measurementsMatchFixedDenominator(candidate.measurements) ||
        candidate.observedReceiptCount !== candidate.expectedReceiptCount ||
        candidate.validReceiptCount !== candidate.expectedReceiptCount ||
        candidate.t054ResultId === null ||
        candidate.planId === null)
    ) {
      return false;
    }
    if (
      candidate.status === 'BLOCKED_T054_QUALIFICATION' &&
      (candidate.planId !== null ||
        candidate.planDigest !== null ||
        candidate.observedReceiptCount !== 0 ||
        candidate.validReceiptCount !== 0 ||
        candidate.measurements !== null ||
        candidate.failureReasons.length !== 0)
    ) {
      return false;
    }
    if (
      candidate.status === 'PENDING_DRILL_EXECUTION' &&
      (candidate.t054ResultId === null ||
        candidate.planId === null ||
        candidate.measurements !== null ||
        candidate.failureReasons.length !== 0 ||
        candidate.observedReceiptCount !== candidate.validReceiptCount ||
        candidate.validReceiptCount >= candidate.expectedReceiptCount)
    ) {
      return false;
    }
    if (
      candidate.status === 'FAILED' &&
      candidate.failureReasons.length === 0
    ) {
      return false;
    }
    const core = omitKeys(candidate, ['resultId', 'resultDigest']);
    return digestCanonical(stableJson(core)) === candidate.resultDigest;
  } catch {
    return false;
  }
}

function buildCanonicalCells(
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): SastSupplyChainRollbackQualificationCell[] | null {
  const cores: SastSupplyChainRollbackQualificationCellCore[] = [];
  const artifactKinds = [
    'ARTIFACT_MOUNT_REHASH_ACCEPT',
    'ARTIFACT_DIGEST_SUBSTITUTION_REJECT',
    'ARTIFACT_SIGNATURE_SUBSTITUTION_REJECT',
    'ARTIFACT_PROVENANCE_SUBSTITUTION_REJECT'
  ] as const;
  for (const artifactKey of SAST_END_TO_END_QUALIFICATION_ARTIFACT_KEYS) {
    for (const drillKind of artifactKinds) {
      cores.push(cellCore(drillKind, artifactKey, null));
    }
  }
  cores.push(cellCore('UNLISTED_COMPONENT_REJECT', null, null));
  const databaseKeys = [
    'CANDIDATE_TRIVY_DATABASE',
    'BASELINE_TRIVY_DATABASE'
  ] as const;
  const databaseKinds = [
    'DATABASE_INTERNAL_MIRROR_ACCEPT',
    'DATABASE_STALE_SNAPSHOT_REJECT',
    'DATABASE_NETWORK_ENRICHMENT_REJECT'
  ] as const;
  for (const artifactKey of databaseKeys) {
    for (const drillKind of databaseKinds) {
      cores.push(cellCore(drillKind, artifactKey, null));
    }
  }
  for (const drillKind of [
    'SCHEMA_CANONICAL_ACCEPT',
    'SCHEMA_INCOMPATIBLE_VERSION_REJECT',
    'SCHEMA_MALFORMED_OR_OVERSIZED_REJECT'
  ] as const) {
    cores.push(cellCore(drillKind, 'RESULT_SCHEMA_BUNDLE', null));
  }
  for (const profileId of SAST_PROFILE_IDS) {
    for (const drillKind of SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_ROLLBACK_SEQUENCE) {
      cores.push(cellCore(drillKind, null, profileId));
    }
  }
  if (
    cores.length !==
    SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LIMITS.expectedCellCount
  ) {
    return null;
  }
  const cells = cores.map((core) => buildCell(core, digestCanonical));
  return cells.some((cell) => cell === null)
    ? null
    : (cells as SastSupplyChainRollbackQualificationCell[]);
}

function cellCore(
  drillKind: SastSupplyChainRollbackQualificationDrillKind,
  artifactKey: SastEndToEndQualificationArtifactKey | null,
  profileId: SastProfileId | null
): SastSupplyChainRollbackQualificationCellCore {
  const preExecutionRejectionRequired = drillKind.includes('_REJECT');
  const artifactInvocationAllowed =
    drillKind === 'ARTIFACT_MOUNT_REHASH_ACCEPT' ||
    drillKind === 'DATABASE_INTERNAL_MIRROR_ACCEPT' ||
    drillKind === 'SCHEMA_CANONICAL_ACCEPT';
  const expectedDecision = drillKind.startsWith('ROLLBACK_')
    ? 'COMPLETED'
    : preExecutionRejectionRequired
      ? 'REJECTED'
      : 'ACCEPTED';
  return {
    version: SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_CELL_VERSION,
    drillKind,
    artifactKey,
    profileId,
    expectedDecision,
    preExecutionRejectionRequired,
    artifactInvocationAllowed,
    productionEquivalentProviderRequired: true,
    freshIsolatedEnvironmentRequired: true,
    customerContentAccepted: false,
    customerCodeExecutionAllowed: false,
    packageInstallAllowed: false,
    repositoryBuildAllowed: false,
    dynamicTestAllowed: false,
    publicInternetEgressAllowed: false,
    productionMutationAllowed: false,
    findingAuthority: false,
    policyAuthority: false,
    publicationAuthority: false,
    deploymentAuthority: false,
    productionReadinessAuthority: false
  };
}

function buildCell(
  core: SastSupplyChainRollbackQualificationCellCore,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): SastSupplyChainRollbackQualificationCell | null {
  if (!isCellCoreValid(core)) return null;
  const cellDigest = digestCanonical(stableJson(core));
  if (!isDigest(cellDigest)) return null;
  return {
    ...core,
    cellId:
      `sast-supply-chain-rollback-qualification-cell://${cellDigest.slice('sha256:'.length)}`,
    cellDigest
  };
}

function isCellCoreValid(
  value: unknown
): value is SastSupplyChainRollbackQualificationCellCore {
  if (!isRecord(value) || !hasExactKeys(value, CELL_CORE_KEYS)) return false;
  const candidate = value as unknown as SastSupplyChainRollbackQualificationCellCore;
  const rollback = candidate.drillKind.startsWith('ROLLBACK_');
  const expected = cellCore(
    candidate.drillKind,
    candidate.artifactKey,
    candidate.profileId
  );
  return (
    candidate.version === SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_CELL_VERSION &&
    SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_DRILL_KINDS.includes(
      candidate.drillKind
    ) &&
    (candidate.artifactKey === null ||
      SAST_END_TO_END_QUALIFICATION_ARTIFACT_KEYS.includes(candidate.artifactKey)) &&
    (candidate.profileId === null || SAST_PROFILE_IDS.includes(candidate.profileId)) &&
    (rollback ? candidate.profileId !== null && candidate.artifactKey === null : true) &&
    (!rollback && candidate.drillKind !== 'UNLISTED_COMPONENT_REJECT'
      ? candidate.artifactKey !== null && candidate.profileId === null
      : true) &&
    (candidate.drillKind === 'UNLISTED_COMPONENT_REJECT'
      ? candidate.artifactKey === null && candidate.profileId === null
      : true) &&
    stableJson(candidate) === stableJson(expected)
  );
}

function isReceiptCoreValid(
  value: SastSupplyChainRollbackQualificationReceiptCore
): boolean {
  return (
    hasExactKeys(value, RECEIPT_CORE_KEYS) &&
    value.version === SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_RECEIPT_VERSION &&
    isDigestBoundIdentity(value.manifestId, value.manifestDigest) &&
    isDigestBoundIdentity(value.planId, value.planDigest) &&
    isDigestBoundIdentity(value.dependencySetId, value.dependencySetDigest) &&
    isDigestBoundIdentity(value.cellId, value.cellDigest) &&
    SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_DRILL_KINDS.includes(value.drillKind) &&
    (value.artifactKey === null ||
      SAST_END_TO_END_QUALIFICATION_ARTIFACT_KEYS.includes(value.artifactKey)) &&
    (value.profileId === null || SAST_PROFILE_IDS.includes(value.profileId)) &&
    isReferenceWithPrefix(value.providerId, 'microvm-provider://') &&
    isDigestBoundReferenceWithPrefix(
      value.providerAdapterRef,
      'provider-adapter://'
    ) &&
    isDigestBoundReferenceWithPrefix(
      value.attemptId,
      'qualification-attempt://'
    ) &&
    isDigestBoundReferenceWithPrefix(
      value.sandboxId,
      'qualification-sandbox://'
    ) &&
    isDigestBoundReferenceWithPrefix(
      value.workloadId,
      'qualification-workload://'
    ) &&
    isIsoInstant(value.startedAt) &&
    isIsoInstant(value.completedAt) &&
    isIsoInstant(value.cleanupCompletedAt) &&
    Date.parse(value.completedAt) >= Date.parse(value.startedAt) &&
    Date.parse(value.cleanupCompletedAt) >= Date.parse(value.completedAt) &&
    SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_DECISIONS.includes(
      value.observedDecision
    ) &&
    isNullableDigest(value.observedArtifactDigest) &&
    isNullableDigest(value.mountRehashDigest) &&
    isNullableDigest(value.observedSignatureEnvelopeDigest) &&
    isNullableDigest(value.observedProvenanceEnvelopeDigest) &&
    isNullableBoolean(value.artifactMountedReadOnly) &&
    isNullableBoolean(value.signatureVerified) &&
    isNullableBoolean(value.provenanceVerified) &&
    isNullableBoolean(value.allowlisted) &&
    isNullableBoolean(value.internalMirrorUsed) &&
    isNullableBoolean(value.databaseFresh) &&
    typeof value.networkEgressAttempted === 'boolean' &&
    isNullableBoolean(value.schemaCompatible) &&
    isNullableRollbackState(value.candidateStateBefore) &&
    isNullableRollbackState(value.candidateStateAfter) &&
    isNullableRollbackState(value.baselineStateBefore) &&
    isNullableRollbackState(value.baselineStateAfter) &&
    typeof value.queueFenceApplied === 'boolean' &&
    typeof value.rollbackTargetDerived === 'boolean' &&
    typeof value.baselineReverified === 'boolean' &&
    isNonNegativeInteger(value.candidateInvocationsAfterFence) &&
    isNullableDigest(value.candidateReleaseSetDigest) &&
    isNullableDigest(value.baselineReleaseSetDigest) &&
    isNullableDigest(value.rollbackTargetDigest) &&
    isNonNegativeInteger(value.inFlightCandidateWorkloadCountBefore) &&
    isNonNegativeInteger(value.inFlightCandidateWorkloadCountAfter) &&
    typeof value.inFlightAbortConfirmed === 'boolean' &&
    isNullableDigestIdentity(
      value.rollbackLedgerHeadAttestationId,
      value.rollbackLedgerHeadAttestationDigest
    ) &&
    isNullableDigest(value.rollbackLedgerPreviousDigest) &&
    (value.rollbackLedgerEntrySequence === null ||
      isNonNegativeSafeInteger(value.rollbackLedgerEntrySequence)) &&
    isNullableDigest(value.rollbackLedgerEntryDigest) &&
    typeof value.rollbackLedgerAppendVerified === 'boolean' &&
    typeof value.preExecutionRejected === 'boolean' &&
    isNonNegativeInteger(value.artifactInvocationCount) &&
    isNonNegativeInteger(value.networkEgressCount) &&
    isNonNegativeInteger(value.productionMutationCount) &&
    typeof value.customerContentObserved === 'boolean' &&
    typeof value.customerCodeExecuted === 'boolean' &&
    typeof value.packageInstallObserved === 'boolean' &&
    typeof value.repositoryBuildObserved === 'boolean' &&
    typeof value.dynamicTestObserved === 'boolean' &&
    typeof value.cleanupComplete === 'boolean' &&
    isDigestBoundReferenceWithPrefix(
      value.providerAttestationRef,
      'provider-attestation://'
    ) &&
    isDigestBoundReferenceWithPrefix(
      value.runtimeAttestationRef,
      'runtime-attestation://'
    ) &&
    isDigestBoundReferenceWithPrefix(
      value.telemetryAttestationRef,
      'telemetry-attestation://'
    ) &&
    isDigestBoundReferenceWithPrefix(value.auditRef, 'qualification-audit://')
  );
}

function isReceiptBoundToPlan(
  receipt: SastSupplyChainRollbackQualificationReceipt,
  cell: SastSupplyChainRollbackQualificationCell,
  plan: SastSupplyChainRollbackQualificationPlan,
  dependencySet: SastEndToEndQualificationDependencySet
): boolean {
  return (
    receipt.manifestId === plan.manifestId &&
    receipt.manifestDigest === plan.manifestDigest &&
    receipt.planId === plan.planId &&
    receipt.planDigest === plan.planDigest &&
    receipt.dependencySetId === dependencySet.dependencySetId &&
    receipt.dependencySetDigest === dependencySet.dependencySetDigest &&
    receipt.cellId === cell.cellId &&
    receipt.cellDigest === cell.cellDigest &&
    receipt.drillKind === cell.drillKind &&
    receipt.artifactKey === cell.artifactKey &&
    receipt.profileId === cell.profileId
  );
}

function receiptMatchesCell(
  receipt: SastSupplyChainRollbackQualificationReceipt,
  cell: SastSupplyChainRollbackQualificationCell,
  plan: SastSupplyChainRollbackQualificationPlan,
  dependencySet: SastEndToEndQualificationDependencySet,
  artifactVerificationSet: SastEndToEndQualificationArtifactVerificationSet,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): boolean {
  if (
    receipt.observedDecision !== cell.expectedDecision ||
    receipt.preExecutionRejected !== cell.preExecutionRejectionRequired ||
    receipt.artifactInvocationCount !== (cell.artifactInvocationAllowed ? 1 : 0)
  ) {
    return false;
  }
  if (cell.drillKind.startsWith('ROLLBACK_')) {
    return rollbackReceiptMatches(
      receipt,
      cell.drillKind,
      plan,
      dependencySet,
      digestCanonical
    );
  }
  if (!nonRollbackStateFieldsClosed(receipt)) return false;
  const artifact = cell.artifactKey
    ? dependencySet.artifacts.find((item) => item.artifactKey === cell.artifactKey)
    : null;
  const verification = cell.artifactKey
    ? artifactVerificationSet.verifications.find(
        (item) => item.artifactKey === cell.artifactKey
      )
    : null;
  switch (cell.drillKind) {
    case 'ARTIFACT_MOUNT_REHASH_ACCEPT':
      return artifactPositive(receipt, artifact ?? null, verification ?? null) &&
        commonArtifactAuxiliaryFields(receipt);
    case 'ARTIFACT_DIGEST_SUBSTITUTION_REJECT':
      return (
        artifact !== undefined &&
        artifact !== null &&
        verification !== undefined &&
        verification !== null &&
        isDigest(receipt.observedArtifactDigest) &&
        receipt.observedArtifactDigest !== artifact.artifactDigest &&
        receipt.mountRehashDigest === receipt.observedArtifactDigest &&
        receipt.observedSignatureEnvelopeDigest ===
          verification.signatureEnvelopeDigest &&
        receipt.observedProvenanceEnvelopeDigest ===
          verification.provenanceEnvelopeDigest &&
        receipt.signatureVerified === false &&
        receipt.provenanceVerified === false &&
        receipt.allowlisted === false &&
        commonArtifactAuxiliaryFields(receipt)
      );
    case 'ARTIFACT_SIGNATURE_SUBSTITUTION_REJECT':
      return (
        artifactNegativeBase(receipt, artifact ?? null, verification ?? null) &&
        isDigest(receipt.observedSignatureEnvelopeDigest) &&
        receipt.observedSignatureEnvelopeDigest !==
          verification?.signatureEnvelopeDigest &&
        receipt.observedProvenanceEnvelopeDigest ===
          verification?.provenanceEnvelopeDigest &&
        receipt.signatureVerified === false &&
        receipt.provenanceVerified === true
      );
    case 'ARTIFACT_PROVENANCE_SUBSTITUTION_REJECT':
      return (
        artifactNegativeBase(receipt, artifact ?? null, verification ?? null) &&
        receipt.observedSignatureEnvelopeDigest ===
          verification?.signatureEnvelopeDigest &&
        isDigest(receipt.observedProvenanceEnvelopeDigest) &&
        receipt.observedProvenanceEnvelopeDigest !==
          verification?.provenanceEnvelopeDigest &&
        receipt.signatureVerified === true &&
        receipt.provenanceVerified === false
      );
    case 'UNLISTED_COMPONENT_REJECT':
      return (
        isDigest(receipt.observedArtifactDigest) &&
        !dependencySet.artifacts.some(
          (item) => item.artifactDigest === receipt.observedArtifactDigest
        ) &&
        receipt.mountRehashDigest === receipt.observedArtifactDigest &&
        isDigest(receipt.observedSignatureEnvelopeDigest) &&
        !artifactVerificationSet.verifications.some(
          (item) =>
            item.signatureEnvelopeDigest ===
            receipt.observedSignatureEnvelopeDigest
        ) &&
        isDigest(receipt.observedProvenanceEnvelopeDigest) &&
        !artifactVerificationSet.verifications.some(
          (item) =>
            item.provenanceEnvelopeDigest ===
            receipt.observedProvenanceEnvelopeDigest
        ) &&
        receipt.signatureVerified === true &&
        receipt.provenanceVerified === true &&
        receipt.allowlisted === false &&
        commonArtifactAuxiliaryFields(receipt)
      );
    case 'DATABASE_INTERNAL_MIRROR_ACCEPT':
      return (
        artifactPositive(receipt, artifact ?? null, verification ?? null) &&
        receipt.internalMirrorUsed === true &&
        receipt.databaseFresh === true &&
        receipt.schemaCompatible === null
      );
    case 'DATABASE_STALE_SNAPSHOT_REJECT':
      return (
        artifact !== undefined &&
        artifact !== null &&
        verification !== undefined &&
        verification !== null &&
        isDigest(receipt.observedArtifactDigest) &&
        receipt.observedArtifactDigest !== artifact.artifactDigest &&
        receipt.mountRehashDigest === receipt.observedArtifactDigest &&
        isDigest(receipt.observedSignatureEnvelopeDigest) &&
        receipt.observedSignatureEnvelopeDigest !==
          verification.signatureEnvelopeDigest &&
        isDigest(receipt.observedProvenanceEnvelopeDigest) &&
        receipt.observedProvenanceEnvelopeDigest !==
          verification.provenanceEnvelopeDigest &&
        receipt.signatureVerified === true &&
        receipt.provenanceVerified === true &&
        receipt.allowlisted === false &&
        receipt.artifactMountedReadOnly === true &&
        receipt.internalMirrorUsed === true &&
        receipt.databaseFresh === false &&
        receipt.schemaCompatible === null &&
        receipt.networkEgressAttempted === false
      );
    case 'DATABASE_NETWORK_ENRICHMENT_REJECT':
      return (
        artifactIdentityMatches(receipt, artifact ?? null, verification ?? null) &&
        receipt.signatureVerified === true &&
        receipt.provenanceVerified === true &&
        receipt.allowlisted === true &&
        receipt.internalMirrorUsed === true &&
        receipt.databaseFresh === true &&
        receipt.schemaCompatible === null &&
        receipt.networkEgressAttempted === true
      );
    case 'SCHEMA_CANONICAL_ACCEPT':
      return (
        artifactPositive(receipt, artifact ?? null, verification ?? null) &&
        receipt.schemaCompatible === true &&
        receipt.internalMirrorUsed === null &&
        receipt.databaseFresh === null
      );
    case 'SCHEMA_INCOMPATIBLE_VERSION_REJECT':
    case 'SCHEMA_MALFORMED_OR_OVERSIZED_REJECT':
      return (
        artifact !== undefined &&
        artifact !== null &&
        verification !== undefined &&
        verification !== null &&
        isDigest(receipt.observedArtifactDigest) &&
        receipt.observedArtifactDigest !== artifact.artifactDigest &&
        receipt.mountRehashDigest === receipt.observedArtifactDigest &&
        isDigest(receipt.observedSignatureEnvelopeDigest) &&
        receipt.observedSignatureEnvelopeDigest !==
          verification.signatureEnvelopeDigest &&
        isDigest(receipt.observedProvenanceEnvelopeDigest) &&
        receipt.observedProvenanceEnvelopeDigest !==
          verification.provenanceEnvelopeDigest &&
        receipt.signatureVerified === true &&
        receipt.provenanceVerified === true &&
        receipt.allowlisted === false &&
        receipt.artifactMountedReadOnly === true &&
        receipt.schemaCompatible === false &&
        receipt.internalMirrorUsed === null &&
        receipt.databaseFresh === null &&
        receipt.networkEgressAttempted === false
      );
    default:
      return false;
  }
}

function artifactPositive(
  receipt: SastSupplyChainRollbackQualificationReceipt,
  artifact: SastEndToEndQualificationArtifactBinding | null,
  verification: SastEndToEndQualificationArtifactVerification | null
): boolean {
  return (
    artifactIdentityMatches(receipt, artifact, verification) &&
    receipt.signatureVerified === true &&
    receipt.provenanceVerified === true &&
    receipt.allowlisted === true &&
    receipt.networkEgressAttempted === false
  );
}

function artifactNegativeBase(
  receipt: SastSupplyChainRollbackQualificationReceipt,
  artifact: SastEndToEndQualificationArtifactBinding | null,
  verification: SastEndToEndQualificationArtifactVerification | null
): boolean {
  return (
    artifact !== null &&
    verification !== null &&
    artifact.artifactKey === verification.artifactKey &&
    artifact.artifactDigest === verification.artifactDigest &&
    receipt.observedArtifactDigest === artifact.artifactDigest &&
    receipt.mountRehashDigest === artifact.artifactDigest &&
    receipt.allowlisted === false &&
    commonArtifactAuxiliaryFields(receipt)
  );
}

function artifactIdentityMatches(
  receipt: SastSupplyChainRollbackQualificationReceipt,
  artifact: SastEndToEndQualificationArtifactBinding | null,
  verification: SastEndToEndQualificationArtifactVerification | null
): boolean {
  return (
    artifact !== null &&
    verification !== null &&
    artifact.artifactKey === verification.artifactKey &&
    artifact.artifactDigest === verification.artifactDigest &&
    receipt.observedArtifactDigest === artifact.artifactDigest &&
    receipt.mountRehashDigest === artifact.artifactDigest &&
    receipt.observedSignatureEnvelopeDigest ===
      verification.signatureEnvelopeDigest &&
    receipt.observedProvenanceEnvelopeDigest ===
      verification.provenanceEnvelopeDigest &&
    receipt.artifactMountedReadOnly === true
  );
}

function commonArtifactAuxiliaryFields(
  receipt: SastSupplyChainRollbackQualificationReceipt
): boolean {
  return (
    receipt.internalMirrorUsed === null &&
    receipt.databaseFresh === null &&
    receipt.schemaCompatible === null &&
    receipt.networkEgressAttempted === false &&
    receipt.artifactMountedReadOnly === true
  );
}

function nonRollbackStateFieldsClosed(
  receipt: SastSupplyChainRollbackQualificationReceipt
): boolean {
  return (
    receipt.candidateStateBefore === null &&
    receipt.candidateStateAfter === null &&
    receipt.baselineStateBefore === null &&
    receipt.baselineStateAfter === null &&
    receipt.queueFenceApplied === false &&
    receipt.rollbackTargetDerived === false &&
    receipt.baselineReverified === false &&
    receipt.candidateInvocationsAfterFence === 0 &&
    receipt.candidateReleaseSetDigest === null &&
    receipt.baselineReleaseSetDigest === null &&
    receipt.rollbackTargetDigest === null &&
    receipt.inFlightCandidateWorkloadCountBefore === 0 &&
    receipt.inFlightCandidateWorkloadCountAfter === 0 &&
    receipt.inFlightAbortConfirmed === false &&
    receipt.rollbackLedgerHeadAttestationId === null &&
    receipt.rollbackLedgerHeadAttestationDigest === null &&
    receipt.rollbackLedgerPreviousDigest === null &&
    receipt.rollbackLedgerEntrySequence === null &&
    receipt.rollbackLedgerEntryDigest === null &&
    receipt.rollbackLedgerAppendVerified === false
  );
}

function rollbackReceiptMatches(
  receipt: SastSupplyChainRollbackQualificationReceipt,
  drillKind: SastSupplyChainRollbackQualificationDrillKind,
  plan: SastSupplyChainRollbackQualificationPlan,
  dependencySet: SastEndToEndQualificationDependencySet,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): boolean {
  const candidateReleaseSetDigest = releaseSetDigest(
    dependencySet,
    'CANDIDATE',
    digestCanonical
  );
  const baselineReleaseSetDigest = releaseSetDigest(
    dependencySet,
    'BASELINE',
    digestCanonical
  );
  const ledgerHeadAttestation = plan.rollbackLedgerHeadAttestations.find(
    (attestation) => attestation.profileId === receipt.profileId
  );
  if (
    candidateReleaseSetDigest === null ||
    baselineReleaseSetDigest === null ||
    ledgerHeadAttestation === undefined ||
    receipt.observedArtifactDigest !== null ||
    receipt.mountRehashDigest !== null ||
    receipt.observedSignatureEnvelopeDigest !== null ||
    receipt.observedProvenanceEnvelopeDigest !== null ||
    receipt.artifactMountedReadOnly !== null ||
    receipt.signatureVerified !== null ||
    receipt.provenanceVerified !== null ||
    receipt.allowlisted !== null ||
    receipt.internalMirrorUsed !== null ||
    receipt.databaseFresh !== null ||
    receipt.networkEgressAttempted !== false ||
    receipt.schemaCompatible !== null ||
    receipt.preExecutionRejected !== false ||
    receipt.artifactInvocationCount !== 0 ||
    receipt.candidateInvocationsAfterFence !== 0 ||
    receipt.candidateReleaseSetDigest !== candidateReleaseSetDigest ||
    receipt.baselineReleaseSetDigest !== baselineReleaseSetDigest
  ) {
    return false;
  }
  switch (drillKind) {
    case 'ROLLBACK_CANDIDATE_SUSPEND':
      return (
        receipt.candidateStateBefore === 'ACTIVE' &&
        receipt.candidateStateAfter === 'SUSPENDED' &&
        receipt.baselineStateBefore === 'STANDBY' &&
        receipt.baselineStateAfter === 'STANDBY' &&
        receipt.queueFenceApplied === false &&
        receipt.rollbackTargetDerived === false &&
        receipt.baselineReverified === false &&
        rollbackTargetClosed(receipt) &&
        inFlightEvidenceClosed(receipt) &&
        rollbackLedgerClosed(receipt)
      );
    case 'ROLLBACK_QUEUE_ADMISSION_FENCE':
      return (
        receipt.candidateStateBefore === 'SUSPENDED' &&
        receipt.candidateStateAfter === 'SUSPENDED' &&
        receipt.baselineStateBefore === 'STANDBY' &&
        receipt.baselineStateAfter === 'STANDBY' &&
        receipt.queueFenceApplied === true &&
        receipt.rollbackTargetDerived === false &&
        receipt.baselineReverified === false &&
        rollbackTargetClosed(receipt) &&
        inFlightEvidenceClosed(receipt) &&
        rollbackLedgerClosed(receipt)
      );
    case 'ROLLBACK_IN_FLIGHT_ABORT_AND_CLEANUP':
      return (
        receipt.candidateStateBefore === 'SUSPENDED' &&
        receipt.candidateStateAfter === 'SUSPENDED' &&
        receipt.baselineStateBefore === 'STANDBY' &&
        receipt.baselineStateAfter === 'STANDBY' &&
        receipt.queueFenceApplied === true &&
        receipt.rollbackTargetDerived === false &&
        receipt.baselineReverified === false &&
        rollbackTargetClosed(receipt) &&
        receipt.inFlightCandidateWorkloadCountBefore > 0 &&
        receipt.inFlightCandidateWorkloadCountAfter === 0 &&
        receipt.inFlightAbortConfirmed === true &&
        rollbackLedgerClosed(receipt)
      );
    case 'ROLLBACK_DERIVE_AND_REVERIFY_LAST_KNOWN_GOOD':
      return (
        receipt.candidateStateBefore === 'SUSPENDED' &&
        receipt.candidateStateAfter === 'SUSPENDED' &&
        receipt.baselineStateBefore === 'STANDBY' &&
        receipt.baselineStateAfter === 'STANDBY' &&
        receipt.queueFenceApplied === true &&
        receipt.rollbackTargetDerived === true &&
        receipt.baselineReverified === true &&
        receipt.rollbackTargetDigest === baselineReleaseSetDigest &&
        inFlightEvidenceClosed(receipt) &&
        rollbackLedgerClosed(receipt)
      );
    case 'ROLLBACK_ACTIVATE_BASELINE_APPEND_ONLY':
      return (
        receipt.candidateStateBefore === 'SUSPENDED' &&
        receipt.candidateStateAfter === 'ROLLED_BACK' &&
        receipt.baselineStateBefore === 'STANDBY' &&
        receipt.baselineStateAfter === 'ACTIVE' &&
        receipt.queueFenceApplied === true &&
        receipt.rollbackTargetDerived === true &&
        receipt.baselineReverified === true &&
        receipt.rollbackTargetDigest === baselineReleaseSetDigest &&
        inFlightEvidenceClosed(receipt) &&
        rollbackLedgerMatches(
          receipt,
          ledgerHeadAttestation,
          candidateReleaseSetDigest,
          baselineReleaseSetDigest,
          digestCanonical
        )
      );
    default:
      return false;
  }
}

function rollbackTargetClosed(
  receipt: SastSupplyChainRollbackQualificationReceipt
): boolean {
  return receipt.rollbackTargetDigest === null;
}

function inFlightEvidenceClosed(
  receipt: SastSupplyChainRollbackQualificationReceipt
): boolean {
  return (
    receipt.inFlightCandidateWorkloadCountBefore === 0 &&
    receipt.inFlightCandidateWorkloadCountAfter === 0 &&
    receipt.inFlightAbortConfirmed === false
  );
}

function rollbackLedgerClosed(
  receipt: SastSupplyChainRollbackQualificationReceipt
): boolean {
  return (
    receipt.rollbackLedgerHeadAttestationId === null &&
    receipt.rollbackLedgerHeadAttestationDigest === null &&
    receipt.rollbackLedgerPreviousDigest === null &&
    receipt.rollbackLedgerEntrySequence === null &&
    receipt.rollbackLedgerEntryDigest === null &&
    receipt.rollbackLedgerAppendVerified === false
  );
}

function rollbackLedgerMatches(
  receipt: SastSupplyChainRollbackQualificationReceipt,
  ledgerHeadAttestation:
    SastSupplyChainRollbackQualificationLedgerHeadAttestation,
  candidateReleaseSetDigest: string,
  baselineReleaseSetDigest: string,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): boolean {
  if (
    receipt.profileId === null ||
    receipt.rollbackLedgerHeadAttestationId !==
      ledgerHeadAttestation.attestationId ||
    receipt.rollbackLedgerHeadAttestationDigest !==
      ledgerHeadAttestation.attestationDigest ||
    receipt.rollbackLedgerPreviousDigest !==
      ledgerHeadAttestation.ledgerHeadDigest ||
    receipt.rollbackLedgerEntrySequence !==
      ledgerHeadAttestation.ledgerHeadSequence + 1 ||
    !isDigest(receipt.rollbackLedgerEntryDigest) ||
    receipt.rollbackLedgerAppendVerified !== true
  ) {
    return false;
  }
  const expectedEntryDigest = digestCanonical(
    stableJson({
      version: SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LEDGER_ENTRY_VERSION,
      headAttestationDigest: ledgerHeadAttestation.attestationDigest,
      previousDigest: ledgerHeadAttestation.ledgerHeadDigest,
      previousSequence: ledgerHeadAttestation.ledgerHeadSequence,
      sequence: receipt.rollbackLedgerEntrySequence,
      profileId: receipt.profileId,
      candidateReleaseSetDigest,
      baselineReleaseSetDigest,
      rollbackTargetDigest: baselineReleaseSetDigest,
      action: 'ACTIVATE_BASELINE',
      activatedAt: receipt.completedAt
    })
  );
  return (
    isDigest(expectedEntryDigest) &&
    receipt.rollbackLedgerEntryDigest === expectedEntryDigest &&
    isDigestBoundReference(receipt.auditRef, expectedEntryDigest)
  );
}

function isRollbackLedgerHeadAttestationSetValid(
  attestations: readonly SastSupplyChainRollbackQualificationLedgerHeadAttestation[],
  manifest: SastSupplyChainRollbackQualificationManifest,
  dependencySet: SastEndToEndQualificationDependencySet,
  trustedAt: string,
  verifySignature: SastEndToEndQualificationSignatureVerifier,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): boolean {
  if (
    !Array.isArray(attestations) ||
    attestations.length !== SAST_PROFILE_IDS.length ||
    !arraysEqual(
      attestations.map((attestation) => attestation.profileId),
      SAST_PROFILE_IDS
    ) ||
    new Set(attestations.map((attestation) => attestation.attestationId)).size !==
      attestations.length ||
    new Set(attestations.map((attestation) => attestation.attestationDigest)).size !==
      attestations.length ||
    new Set(attestations.map((attestation) => attestation.ledgerHeadRef)).size !==
      attestations.length
  ) {
    return false;
  }
  return attestations.every((attestation) =>
    isSastSupplyChainRollbackQualificationLedgerHeadAttestationValid(
      attestation,
      manifest,
      dependencySet,
      trustedAt,
      verifySignature,
      digestCanonical
    )
  );
}

function releaseSetDigest(
  dependencySet: SastEndToEndQualificationDependencySet,
  arm: 'CANDIDATE' | 'BASELINE',
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): string | null {
  const excludedPrefix = arm === 'CANDIDATE' ? 'BASELINE_' : 'CANDIDATE_';
  const artifacts = dependencySet.artifacts
    .filter((artifact) => !artifact.artifactKey.startsWith(excludedPrefix))
    .map((artifact) => ({
      artifactKey: artifact.artifactKey,
      artifactDigest: artifact.artifactDigest
    }));
  const value = digestCanonical(stableJson({ arm, artifacts }));
  return isDigest(value) ? value : null;
}

function rollbackSequenceValid(
  receipts: readonly SastSupplyChainRollbackQualificationReceipt[]
): boolean {
  for (const profileId of SAST_PROFILE_IDS) {
    const byKind = new Map(
      receipts
        .filter(
          (receipt) =>
            receipt.profileId === profileId &&
            receipt.drillKind.startsWith('ROLLBACK_')
        )
        .map((receipt) => [receipt.drillKind, receipt] as const)
    );
    if (byKind.size === 0) continue;
    const observed =
      SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_ROLLBACK_SEQUENCE.filter(
        (kind) => byKind.has(kind)
      );
    if (
      !arraysEqual(
        observed,
        SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_ROLLBACK_SEQUENCE.slice(
          0,
          observed.length
        )
      )
    ) {
      return false;
    }
    for (let index = 1; index < observed.length; index += 1) {
      const previous = byKind.get(observed[index - 1]);
      const current = byKind.get(observed[index]);
      if (
        !previous ||
        !current ||
        Date.parse(current.startedAt) < Date.parse(previous.cleanupCompletedAt)
      ) {
        return false;
      }
    }
  }
  return true;
}

function hasZeroToleranceEvent(
  receipt: SastSupplyChainRollbackQualificationReceipt
): boolean {
  return (
    receipt.networkEgressCount !== 0 ||
    receipt.productionMutationCount !== 0 ||
    receipt.customerContentObserved !== false ||
    receipt.customerCodeExecuted !== false ||
    receipt.packageInstallObserved !== false ||
    receipt.repositoryBuildObserved !== false ||
    receipt.dynamicTestObserved !== false ||
    receipt.cleanupComplete !== true
  );
}

function measurementsFromReceipts(
  receipts: readonly SastSupplyChainRollbackQualificationReceipt[],
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): SastSupplyChainRollbackQualificationMeasurements | null {
  if (
    receipts.length !==
    SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LIMITS.expectedCellCount
  ) {
    return null;
  }
  const core = {
    artifactSupplyChainDrillCount: receipts.filter((receipt) =>
      receipt.drillKind.startsWith('ARTIFACT_')
    ).length,
    allowlistDrillCount: receipts.filter(
      (receipt) => receipt.drillKind === 'UNLISTED_COMPONENT_REJECT'
    ).length,
    databaseDrillCount: receipts.filter((receipt) =>
      receipt.drillKind.startsWith('DATABASE_')
    ).length,
    schemaDrillCount: receipts.filter((receipt) =>
      receipt.drillKind.startsWith('SCHEMA_')
    ).length,
    rollbackDrillCount: receipts.filter((receipt) =>
      receipt.drillKind.startsWith('ROLLBACK_')
    ).length,
    preExecutionRejectionCount: receipts.filter(
      (receipt) => receipt.preExecutionRejected
    ).length,
    artifactInvocationCount: receipts.reduce(
      (sum, receipt) => sum + receipt.artifactInvocationCount,
      0
    ),
    cleanupCompletedCount: receipts.filter((receipt) => receipt.cleanupComplete).length,
    networkEgressCount: receipts.reduce(
      (sum, receipt) => sum + receipt.networkEgressCount,
      0
    ),
    productionMutationCount: receipts.reduce(
      (sum, receipt) => sum + receipt.productionMutationCount,
      0
    ),
    forbiddenSideEffectCount: receipts.filter((receipt) =>
      hasZeroToleranceEvent(receipt)
    ).length
  };
  const measurementsDigest = digestCanonical(stableJson(core));
  return isDigest(measurementsDigest) ? { ...core, measurementsDigest } : null;
}

function measurementsPass(
  manifest: SastSupplyChainRollbackQualificationManifest,
  measurements: SastSupplyChainRollbackQualificationMeasurements
): boolean {
  return (
    measurementsMatchFixedDenominator(measurements) &&
    measurements.artifactSupplyChainDrillCount ===
      manifest.artifactSupplyChainDrillCount &&
    measurements.allowlistDrillCount === manifest.allowlistDrillCount &&
    measurements.databaseDrillCount === manifest.databaseDrillCount &&
    measurements.schemaDrillCount === manifest.schemaDrillCount &&
    measurements.rollbackDrillCount === manifest.rollbackDrillCount &&
    measurements.preExecutionRejectionCount ===
      manifest.preExecutionRejectionCount &&
    measurements.cleanupCompletedCount === manifest.executionCellCount
  );
}

function measurementsMatchFixedDenominator(
  measurements: SastSupplyChainRollbackQualificationMeasurements
): boolean {
  return (
    measurements.artifactSupplyChainDrillCount ===
      SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LIMITS.artifactSupplyChainDrillCount &&
    measurements.allowlistDrillCount ===
      SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LIMITS.allowlistDrillCount &&
    measurements.databaseDrillCount ===
      SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LIMITS.databaseDrillCount &&
    measurements.schemaDrillCount ===
      SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LIMITS.schemaDrillCount &&
    measurements.rollbackDrillCount ===
      SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LIMITS.rollbackDrillCount &&
    measurements.preExecutionRejectionCount ===
      SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LIMITS.expectedPreExecutionRejectionCount &&
    measurements.artifactInvocationCount ===
      SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LIMITS.expectedArtifactInvocationCount &&
    measurements.cleanupCompletedCount ===
      SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LIMITS.expectedCellCount &&
    measurements.networkEgressCount === 0 &&
    measurements.productionMutationCount === 0 &&
    measurements.forbiddenSideEffectCount === 0
  );
}

function isMeasurementsValid(
  value: unknown,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): value is SastSupplyChainRollbackQualificationMeasurements {
  if (!isRecord(value) || !hasExactKeys(value, MEASUREMENT_KEYS)) return false;
  const candidate = value as unknown as SastSupplyChainRollbackQualificationMeasurements;
  const core = omitKeys(candidate, ['measurementsDigest']);
  return (
    Object.values(core).every(isNonNegativeInteger) &&
    isDigest(candidate.measurementsDigest) &&
    digestCanonical(stableJson(core)) === candidate.measurementsDigest
  );
}

function buildResult(
  input: Readonly<{
    status: SastSupplyChainRollbackQualificationStatus;
    manifest: SastSupplyChainRollbackQualificationManifest;
    t054Result: SastEndToEndQualificationResult | null;
    plan: SastSupplyChainRollbackQualificationPlan | null;
    observedReceiptCount: number;
    validReceiptCount: number;
    measurements: SastSupplyChainRollbackQualificationMeasurements | null;
    failureReasons: SastSupplyChainRollbackQualificationFailureReason[];
    evaluatedAt: string;
  }>,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): SastSupplyChainRollbackQualificationResult | null {
  const core: SastSupplyChainRollbackQualificationResultCore = {
    version: SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_RESULT_VERSION,
    status: input.status,
    manifestId: input.manifest.manifestId,
    manifestDigest: input.manifest.manifestDigest,
    t054ResultId: input.t054Result?.resultId ?? null,
    t054ResultDigest: input.t054Result?.resultDigest ?? null,
    planId: input.plan?.planId ?? null,
    planDigest: input.plan?.planDigest ?? null,
    expectedReceiptCount: input.manifest.executionCellCount,
    observedReceiptCount: input.observedReceiptCount,
    validReceiptCount: input.validReceiptCount,
    measurements: input.measurements,
    failureReasons: orderedUniqueReasons(input.failureReasons),
    evaluatedAt: input.evaluatedAt,
    t056EntryAuthorized: input.status === 'PASSED',
    findingAuthority: false,
    policyAuthority: false,
    publicationAuthority: false,
    deploymentAuthority: false,
    productionReadinessAuthority: false
  };
  const resultDigest = digestCanonical(stableJson(core));
  if (!isDigest(resultDigest)) return null;
  const result = {
    ...core,
    resultId:
      `sast-supply-chain-rollback-qualification-result://${resultDigest.slice('sha256:'.length)}`,
    resultDigest
  };
  return isSastSupplyChainRollbackQualificationResultValid(result, digestCanonical)
    ? result
    : null;
}

function failedResult(
  input: Readonly<SastSupplyChainRollbackQualificationEvaluationInput>,
  failureReasons: SastSupplyChainRollbackQualificationFailureReason[],
  validReceiptCount: number,
  measurements: SastSupplyChainRollbackQualificationMeasurements | null,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): SastSupplyChainRollbackQualificationResult | null {
  const t054Result =
    isRecord(input.t054Result) &&
    isDigestBoundIdentity(
      input.t054Result.resultId,
      input.t054Result.resultDigest
    )
      ? input.t054Result
      : null;
  const plan =
    isRecord(input.plan) &&
    isDigestBoundIdentity(input.plan.planId, input.plan.planDigest)
      ? input.plan
      : null;
  return buildResult(
    {
      status: 'FAILED',
      manifest: input.manifest,
      t054Result,
      plan,
      observedReceiptCount: input.signedReceipts.length,
      validReceiptCount,
      measurements,
      failureReasons,
      evaluatedAt: input.trustedEvaluatedAt
    },
    digestCanonical
  );
}

function isT054PrerequisiteValid(
  t054Manifest: SastEndToEndQualificationManifest,
  t054Result: SastEndToEndQualificationResult,
  dependencySet: SastEndToEndQualificationDependencySet,
  artifactVerificationSet: SastEndToEndQualificationArtifactVerificationSet,
  t054Plan: SastEndToEndQualificationExecutionPlan,
  verifySignature: SastEndToEndQualificationSignatureVerifier,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): boolean {
  return (
    isSastEndToEndQualificationManifestValid(t054Manifest, digestCanonical) &&
    isSastEndToEndQualificationResultValid(t054Result, digestCanonical) &&
    t054Result.status === 'PASSED' &&
    t054Result.t055EntryAuthorized === true &&
    t054Result.manifestId === t054Manifest.manifestId &&
    t054Result.manifestDigest === t054Manifest.manifestDigest &&
    t054Result.expectedReceiptCount === t054Manifest.executionCellCount &&
    t054Result.validReceiptCount === t054Manifest.executionCellCount &&
    t054Result.dependencySetId === dependencySet.dependencySetId &&
    t054Result.dependencySetDigest === dependencySet.dependencySetDigest &&
    isSastEndToEndQualificationDependencySetValid(dependencySet, digestCanonical) &&
    isSastEndToEndQualificationArtifactVerificationSetValid(
      artifactVerificationSet,
      dependencySet,
      verifySignature,
      digestCanonical
    ) &&
    isT054PlanBindingValid(
      t054Plan,
      t054Manifest,
      t054Result,
      dependencySet,
      artifactVerificationSet,
      digestCanonical
    )
  );
}

function isT054PlanBindingValid(
  plan: unknown,
  manifest: SastEndToEndQualificationManifest,
  result: SastEndToEndQualificationResult,
  dependencySet: SastEndToEndQualificationDependencySet,
  artifactVerificationSet: SastEndToEndQualificationArtifactVerificationSet,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): plan is SastEndToEndQualificationExecutionPlan {
  if (
    !isRecord(plan) ||
    !hasExactKeys(plan, [
      'version', 'manifestId', 'manifestDigest', 'dependencySetId',
      'dependencySetDigest', 't053DependencySetId', 't053DependencySetDigest',
      't053ProviderId', 't053ProviderAdapterRef', 'artifactVerificationSetId',
      'artifactVerificationSetDigest', 't053ResultId', 't053ResultDigest',
      't053EntryAttestationId', 't053EntryAttestationDigest', 'executionCellCount',
      'requiredApprovalRoles', 'requiredReceiptSignatureRoles', 'plannedAt',
      'executionAuthority', 'oneFreshMicroVmPerAttempt', 'sandboxReuseAllowed',
      'aggregateMetricsAcceptedFromCaller', 'customerContentAccepted',
      'customerCodeExecutionAllowed', 'packageInstallAllowed',
      'repositoryBuildAllowed', 'dynamicTestAllowed', 'publicInternetEgressAllowed',
      'findingAuthority', 'policyAuthority', 'publicationAuthority',
      'deploymentAuthority', 'productionReadinessAuthority', 'planId', 'planDigest'
    ])
  ) {
    return false;
  }
  const candidate = plan as unknown as SastEndToEndQualificationExecutionPlan;
  const core = omitKeys(candidate, ['planId', 'planDigest']);
  return (
    candidate.version === SAST_END_TO_END_QUALIFICATION_PLAN_VERSION &&
    isDigest(candidate.planDigest) &&
    candidate.planId ===
      `sast-end-to-end-qualification-plan://${candidate.planDigest.slice('sha256:'.length)}` &&
    digestCanonical(stableJson(core)) === candidate.planDigest &&
    candidate.manifestId === manifest.manifestId &&
    candidate.manifestDigest === manifest.manifestDigest &&
    isDigestBoundIdentity(
      candidate.t053DependencySetId,
      candidate.t053DependencySetDigest
    ) &&
    candidate.dependencySetId === dependencySet.dependencySetId &&
    candidate.dependencySetDigest === dependencySet.dependencySetDigest &&
    candidate.artifactVerificationSetId === artifactVerificationSet.verificationSetId &&
    candidate.artifactVerificationSetDigest ===
      artifactVerificationSet.verificationSetDigest &&
    candidate.planId === result.planId &&
    candidate.planDigest === result.planDigest &&
    candidate.t053ResultId === result.t053ResultId &&
    candidate.t053ResultDigest === result.t053ResultDigest &&
    isDigestBoundIdentity(
      candidate.t053EntryAttestationId,
      candidate.t053EntryAttestationDigest
    ) &&
    candidate.t053ProviderId === dependencySet.providerId &&
    candidate.t053ProviderAdapterRef === dependencySet.providerAdapterRef &&
    candidate.executionCellCount === manifest.executionCellCount &&
    arraysEqual(
      candidate.requiredApprovalRoles,
      SAST_END_TO_END_QUALIFICATION_APPROVAL_ROLES
    ) &&
    arraysEqual(
      candidate.requiredReceiptSignatureRoles,
      SAST_END_TO_END_QUALIFICATION_RECEIPT_SIGNATURE_ROLES
    ) &&
    isIsoInstant(candidate.plannedAt) &&
    Date.parse(candidate.plannedAt) >= Date.parse(dependencySet.validFrom) &&
    Date.parse(candidate.plannedAt) <= Date.parse(dependencySet.validUntil) &&
    candidate.executionAuthority === 'DETACHED_DUAL_APPROVAL_REQUIRED' &&
    candidate.oneFreshMicroVmPerAttempt === true &&
    candidate.sandboxReuseAllowed === false &&
    candidate.aggregateMetricsAcceptedFromCaller === false &&
    candidate.customerContentAccepted === false &&
    candidate.customerCodeExecutionAllowed === false &&
    candidate.packageInstallAllowed === false &&
    candidate.repositoryBuildAllowed === false &&
    candidate.dynamicTestAllowed === false &&
    candidate.publicInternetEgressAllowed === false &&
    candidate.findingAuthority === false &&
    candidate.policyAuthority === false &&
    candidate.publicationAuthority === false &&
    candidate.deploymentAuthority === false &&
    candidate.productionReadinessAuthority === false
  );
}

function earliestReceiptStart(
  signedReceipts: readonly SastSupplyChainRollbackQualificationSignedReceipt[],
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): number | null {
  let earliest: number | null = null;
  for (const signed of signedReceipts) {
    if (
      !isRecord(signed) ||
      !hasExactKeys(signed, SIGNED_RECEIPT_KEYS) ||
      !isSastSupplyChainRollbackQualificationReceiptValid(
        signed.receipt,
        digestCanonical
      )
    ) {
      continue;
    }
    const startedAt = Date.parse(signed.receipt.startedAt);
    earliest = earliest === null ? startedAt : Math.min(earliest, startedAt);
  }
  return earliest;
}

function isSignatureSetValid<T extends SastEndToEndQualificationSignatureRole>(
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
    new Set(signatures.map((signature) => signature.keyId)).size !== signatures.length
  ) {
    return false;
  }
  return signatures.every(
    (signature) =>
      isSastEndToEndQualificationSignatureValid(signature) &&
      signature.version === SAST_END_TO_END_QUALIFICATION_SIGNATURE_VERSION &&
      signature.payloadDigest === payloadDigest &&
      Date.parse(signature.signedAt) >= Date.parse(earliestSignedAt) &&
      Date.parse(signature.signedAt) <= Date.parse(latestSignedAt) &&
      verifyDetachedSignature(signature, verifySignature)
  );
}

function verifyDetachedSignature(
  signature: SastEndToEndQualificationSignature,
  verifySignature: SastEndToEndQualificationSignatureVerifier
): boolean {
  try {
    const payload = serializeSastEndToEndQualificationSignaturePayload(signature);
    return payload !== null && verifySignature(signature, payload) === true;
  } catch {
    return false;
  }
}

function orderedUniqueReasons(
  reasons: readonly SastSupplyChainRollbackQualificationFailureReason[]
): SastSupplyChainRollbackQualificationFailureReason[] {
  const present = new Set(reasons);
  return SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_FAILURE_REASONS.filter((reason) =>
    present.has(reason)
  );
}

function isNullableDigest(value: unknown): value is string | null {
  return value === null || isDigest(value);
}

function isNullableBoolean(value: unknown): value is boolean | null {
  return value === null || typeof value === 'boolean';
}

function isNullableRollbackState(
  value: unknown
): value is SastSupplyChainRollbackQualificationRollbackState | null {
  return (
    value === null ||
    (typeof value === 'string' &&
      SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_ROLLBACK_STATES.includes(
        value as SastSupplyChainRollbackQualificationRollbackState
      ))
  );
}

function isNullableDigestIdentity(
  identity: unknown,
  digest: unknown
): boolean {
  return (
    (identity === null && digest === null) ||
    (typeof identity === 'string' &&
      typeof digest === 'string' &&
      isDigestBoundIdentity(identity, digest))
  );
}

function isDigestBoundIdentity(identity: unknown, digest: unknown): boolean {
  return (
    typeof identity === 'string' &&
    isDigest(digest) &&
    (identity.endsWith(digest) ||
      identity.endsWith(digest.slice('sha256:'.length)))
  );
}

function isDirectIdentity(value: unknown, prefix: string): boolean {
  return (
    typeof value === 'string' &&
    value.startsWith(prefix) &&
    value.length <=
      SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LIMITS.maximumReferenceBytes &&
    !value.slice(prefix.length).includes('/')
  );
}

function isReferenceWithPrefix(value: unknown, prefix: string): boolean {
  return (
    typeof value === 'string' &&
    value.startsWith(prefix) &&
    value.length > prefix.length &&
    value.length <=
      SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LIMITS.maximumReferenceBytes &&
    !hasControlOrWhitespace(value)
  );
}

function isDigestBoundReferenceWithPrefix(
  value: unknown,
  prefix: string
): boolean {
  return isReferenceWithPrefix(value, prefix) && isDigestBoundReference(value);
}

function isDigestBoundReference(value: unknown, digest?: unknown): boolean {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <=
      SAST_SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_LIMITS.maximumReferenceBytes &&
    !hasControlOrWhitespace(value) &&
    /^[-a-z][a-z0-9+.-]*:\/\//u.test(value) &&
    isDigest(digest ?? digestFromReference(value)) &&
    value.endsWith(String(digest ?? digestFromReference(value)))
  );
}

function hasControlOrWhitespace(value: string): boolean {
  return Array.from(value).some((character) => {
    const codePoint = character.codePointAt(0);
    return (
      codePoint === undefined ||
      codePoint <= 0x1f ||
      codePoint === 0x7f ||
      /\s/u.test(character)
    );
  });
}

function digestFromReference(value: string): string {
  const match = /sha256:[a-f0-9]{64}$/u.exec(value);
  return match?.[0] ?? '';
}

function isDigest(value: unknown): value is Sha256Digest {
  return typeof value === 'string' && /^sha256:[a-f0-9]{64}$/u.test(value);
}

function isSemanticVersion(value: unknown): boolean {
  return (
    typeof value === 'string' &&
    /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/u.test(
      value
    )
  );
}

function isIsoInstant(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) &&
    Number.isFinite(Date.parse(value)) &&
    new Date(value).toISOString() === value
  );
}

function secondsBetween(from: string, to: string): number {
  return (Date.parse(to) - Date.parse(from)) / 1_000;
}

function isNonNegativeInteger(value: unknown): value is number {
  return Number.isInteger(value) && Number(value) >= 0;
}

function isNonNegativeSafeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasExactKeys(value: unknown, keys: readonly string[]): boolean {
  return (
    isRecord(value) &&
    arraysEqual(Object.keys(value).sort(compareText), [...keys].sort(compareText))
  );
}

function omitKeys<T extends object>(
  value: T,
  keys: readonly string[]
): Record<string, unknown> {
  const omitted = new Set(keys);
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>).filter(
      ([key]) => !omitted.has(key)
    )
  );
}

function arraysEqual<T>(left: readonly T[], right: readonly T[]): boolean {
  return left.length === right.length && left.every((item, index) => item === right[index]);
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function stableJson(value: unknown): string {
  if (
    value === null ||
    typeof value === 'boolean' ||
    typeof value === 'number'
  ) {
    return JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value)
      .sort(compareText)
      .map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`)
      .join(',')}}`;
  }
  throw new TypeError('qualification values must be JSON-compatible');
}
