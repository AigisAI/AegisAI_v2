import {
  SAST_END_TO_END_QUALIFICATION_APPROVAL_ROLES,
  isSastEndToEndQualificationArtifactVerificationSetValid,
  isSastEndToEndQualificationDependencySetValid,
  isSastEndToEndQualificationManifestValid,
  isSastEndToEndQualificationResultValid,
  isSastEndToEndQualificationSignatureValid,
  serializeSastEndToEndQualificationSignaturePayload,
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
  isSastSupplyChainRollbackQualificationEntryAttestationValid,
  isSastSupplyChainRollbackQualificationManifestValid,
  isSastSupplyChainRollbackQualificationPlanValid,
  isSastSupplyChainRollbackQualificationResultValid,
  type SastSupplyChainRollbackQualificationEntryAttestation,
  type SastSupplyChainRollbackQualificationManifest,
  type SastSupplyChainRollbackQualificationPlan,
  type SastSupplyChainRollbackQualificationResult
} from './sast-supply-chain-rollback-qualification';

export const SAST_PRODUCTION_GO_NO_GO_MANIFEST_VERSION =
  'sast-production-go-no-go-manifest-v1' as const;
export const SAST_PRODUCTION_GO_NO_GO_GATE_VERSION =
  'sast-production-go-no-go-gate-v1' as const;
export const SAST_PRODUCTION_GO_NO_GO_ENTRY_ATTESTATION_VERSION =
  'sast-production-go-no-go-entry-attestation-v1' as const;
export const SAST_PRODUCTION_GO_NO_GO_OBSERVATION_VERSION =
  'sast-production-go-no-go-observation-v1' as const;
export const SAST_PRODUCTION_GO_NO_GO_EVIDENCE_ATTESTATION_VERSION =
  'sast-production-go-no-go-evidence-attestation-v1' as const;
export const SAST_PRODUCTION_GO_NO_GO_PLAN_VERSION =
  'sast-production-go-no-go-plan-v1' as const;
export const SAST_PRODUCTION_GO_NO_GO_GATE_RESULT_VERSION =
  'sast-production-go-no-go-gate-result-v1' as const;
export const SAST_PRODUCTION_GO_NO_GO_RECORD_VERSION =
  'sast-production-go-no-go-record-v1' as const;

export const SAST_PRODUCTION_GO_NO_GO_STATUSES = [
  'BLOCKED_T055_QUALIFICATION',
  'PENDING_FINAL_EVIDENCE',
  'NO_GO',
  'GO'
] as const;
export type SastProductionGoNoGoStatus =
  (typeof SAST_PRODUCTION_GO_NO_GO_STATUSES)[number];

export const SAST_PRODUCTION_GO_NO_GO_EVIDENCE_KINDS = [
  'UPSTREAM_QUALIFICATION',
  'REPOSITORY_VALIDATION',
  'CANARY_TELEMETRY_REPLAY',
  'KILL_SWITCH_PROPAGATION',
  'ROLLBACK_READINESS',
  'DEPLOYMENT_HANDOFF_BOUNDARY'
] as const;
export type SastProductionGoNoGoEvidenceKind =
  (typeof SAST_PRODUCTION_GO_NO_GO_EVIDENCE_KINDS)[number];

export const SAST_PRODUCTION_GO_NO_GO_GATE_CATEGORIES = [
  'CORRECTNESS',
  'SECURITY_PRIVACY',
  'PERFORMANCE_RELIABILITY',
  'SUPPLY_CHAIN_ROLLBACK',
  'REPOSITORY_ASSURANCE',
  'CANARY',
  'KILL_SWITCH',
  'DEPLOYMENT_BOUNDARY'
] as const;
export type SastProductionGoNoGoGateCategory =
  (typeof SAST_PRODUCTION_GO_NO_GO_GATE_CATEGORIES)[number];

export const SAST_PRODUCTION_GO_NO_GO_THRESHOLD_OPERATORS = [
  'EXACT',
  'AT_LEAST',
  'AT_MOST'
] as const;
export type SastProductionGoNoGoThresholdOperator =
  (typeof SAST_PRODUCTION_GO_NO_GO_THRESHOLD_OPERATORS)[number];

export const SAST_PRODUCTION_GO_NO_GO_UNITS = [
  'BOOLEAN',
  'COUNT',
  'BASIS_POINTS',
  'MILLISECONDS',
  'HOURS'
] as const;
export type SastProductionGoNoGoUnit =
  (typeof SAST_PRODUCTION_GO_NO_GO_UNITS)[number];

export const SAST_PRODUCTION_GO_NO_GO_OBSERVATION_DISPOSITIONS = [
  'MEASURED',
  'NOT_APPLICABLE'
] as const;
export type SastProductionGoNoGoObservationDisposition =
  (typeof SAST_PRODUCTION_GO_NO_GO_OBSERVATION_DISPOSITIONS)[number];

export const SAST_PRODUCTION_GO_NO_GO_GATE_OUTCOMES = [
  'PASSED',
  'FAILED',
  'NOT_APPLICABLE'
] as const;
export type SastProductionGoNoGoGateOutcome =
  (typeof SAST_PRODUCTION_GO_NO_GO_GATE_OUTCOMES)[number];

export const SAST_PRODUCTION_GO_NO_GO_FAILURE_REASONS = [
  'T055_PREREQUISITE_MISSING',
  'UPSTREAM_BINDING_INVALID',
  'ENTRY_ATTESTATION_INVALID',
  'EVIDENCE_INCOMPLETE',
  'EVIDENCE_INVALID',
  'EVIDENCE_STALE',
  'UPSTREAM_MEASUREMENT_MISMATCH',
  'NOT_APPLICABLE_PROHIBITED',
  'GATE_THRESHOLD_BREACH',
  'PLAN_INVALID',
  'APPROVALS_INCOMPLETE',
  'APPROVALS_INVALID'
] as const;
export type SastProductionGoNoGoFailureReason =
  (typeof SAST_PRODUCTION_GO_NO_GO_FAILURE_REASONS)[number];

export const SAST_PRODUCTION_GO_NO_GO_GATE_IDS = [
  'T053_ISOLATED_INTEGRATION',
  'ARTIFACT_SIGNATURE_PROVENANCE',
  'SCANNER_PROFILE_COMPATIBILITY',
  'GOLDEN_CORPUS_EXACT',
  'MUST_DETECT_RECALL',
  'CRITICAL_HIGH_PRECISION',
  'PRIOR_MUST_DETECT_RECALL',
  'FALSE_POSITIVE_INCREASE',
  'SCANNER_FAILURE_RATE',
  'P95_LATENCY_REGRESSION',
  'FAST_LANE_ABSOLUTE_P95',
  'DEEP_LANE_ABSOLUTE_P95',
  'FINGERPRINT_CORRELATION',
  'EVIDENCE_PRIVACY',
  'CAPACITY_RESOURCE_LIMITS',
  'ZERO_CROSS_TENANT_LEAK',
  'ZERO_SECRET_LEAK',
  'ZERO_SANDBOX_ESCAPE',
  'ZERO_STALE_PUBLICATION',
  'ZERO_UNAUTHORIZED_EGRESS',
  'ZERO_MISSING_DESTRUCTION',
  'ZERO_EVIDENCE_POLICY_VIOLATION',
  'ZERO_UNSIGNED_ARTIFACT_EXECUTION',
  'T055_ARTIFACT_DRILLS',
  'T055_ALLOWLIST_DRILLS',
  'T055_DATABASE_DRILLS',
  'T055_SCHEMA_DRILLS',
  'T055_ROLLBACK_PHASES',
  'T055_PRE_EXECUTION_REJECTIONS',
  'T055_ARTIFACT_INVOCATIONS',
  'T055_CLEANUP_COMPLETION',
  'T055_ZERO_NETWORK_EGRESS',
  'T055_ZERO_PRODUCTION_MUTATION',
  'T055_ZERO_FORBIDDEN_EFFECTS',
  'REPOSITORY_CONTRACT_TESTS',
  'REPOSITORY_STATIC_VALIDATION',
  'REPOSITORY_DATABASE_VALIDATION',
  'NORMALIZATION_DATA_INTEGRITY',
  'EVIDENCE_RETENTION_DELETION',
  'AI_ADVISORY_ZERO_AUTHORITY',
  'CANARY_SIX_STEP_REPLAY',
  'CANARY_SAMPLE_SUFFICIENCY',
  'CANARY_OBSERVATION_WINDOW',
  'CANARY_TELEMETRY_COMPLETE',
  'CANARY_THRESHOLDS_ZERO_TOLERANCE',
  'KILL_SWITCH_PROPAGATION_BOUNDARIES',
  'KILL_SWITCH_FAIL_CLOSED',
  'KILL_SWITCH_DEACTIVATION_RECOVERY',
  'KILL_SWITCH_FORBIDDEN_SIDE_EFFECTS',
  'ROLLBACK_SIGNED_CHAIN',
  'ROLLBACK_TARGET_DERIVED',
  'ROLLBACK_POST_FENCE_INVOCATIONS',
  'DEPLOYMENT_OPERATIONS_REFERENCE_ONLY',
  'KUBERNETES_EXECUTION_NOT_PERFORMED'
] as const;
export type SastProductionGoNoGoGateId =
  (typeof SAST_PRODUCTION_GO_NO_GO_GATE_IDS)[number];

export interface SastProductionGoNoGoGateDefinitionInput {
  gateId: SastProductionGoNoGoGateId;
  category: SastProductionGoNoGoGateCategory;
  evidenceKind: SastProductionGoNoGoEvidenceKind;
  thresholdOperator: SastProductionGoNoGoThresholdOperator;
  thresholdValue: number;
  unit: SastProductionGoNoGoUnit;
  rationaleCode: string;
  requiredSignatureRoles: SastEndToEndQualificationSignatureRole[];
}

const QA_SUPPLY_CHAIN = [
  'QUALIFICATION_AUTHORITY',
  'SUPPLY_CHAIN_AUTHORITY'
] as const satisfies readonly SastEndToEndQualificationSignatureRole[];
const QA_RUNTIME = [
  'QUALIFICATION_AUTHORITY',
  'QUALIFICATION_RUNTIME'
] as const satisfies readonly SastEndToEndQualificationSignatureRole[];
const TELEMETRY_RUNTIME = [
  'TELEMETRY_AUTHORITY',
  'QUALIFICATION_RUNTIME'
] as const satisfies readonly SastEndToEndQualificationSignatureRole[];
const QA_ONLY = [
  'QUALIFICATION_AUTHORITY'
] as const satisfies readonly SastEndToEndQualificationSignatureRole[];

function gate(
  gateId: SastProductionGoNoGoGateId,
  category: SastProductionGoNoGoGateCategory,
  evidenceKind: SastProductionGoNoGoEvidenceKind,
  thresholdOperator: SastProductionGoNoGoThresholdOperator,
  thresholdValue: number,
  unit: SastProductionGoNoGoUnit,
  rationaleCode: string,
  requiredSignatureRoles: readonly SastEndToEndQualificationSignatureRole[]
): SastProductionGoNoGoGateDefinitionInput {
  return {
    gateId,
    category,
    evidenceKind,
    thresholdOperator,
    thresholdValue,
    unit,
    rationaleCode,
    requiredSignatureRoles: [...requiredSignatureRoles]
  };
}

export const SAST_PRODUCTION_GO_NO_GO_GATE_CATALOG = Object.freeze([
  gate('T053_ISOLATED_INTEGRATION', 'SECURITY_PRIVACY', 'UPSTREAM_QUALIFICATION', 'EXACT', 1, 'BOOLEAN', 'T053_PASSED', QA_SUPPLY_CHAIN),
  gate('ARTIFACT_SIGNATURE_PROVENANCE', 'SUPPLY_CHAIN_ROLLBACK', 'UPSTREAM_QUALIFICATION', 'EXACT', 1, 'BOOLEAN', 'ARTIFACTS_VERIFIED', QA_SUPPLY_CHAIN),
  gate('SCANNER_PROFILE_COMPATIBILITY', 'CORRECTNESS', 'UPSTREAM_QUALIFICATION', 'EXACT', 1, 'BOOLEAN', 'COMPATIBILITY_VERIFIED', QA_SUPPLY_CHAIN),
  gate('GOLDEN_CORPUS_EXACT', 'CORRECTNESS', 'UPSTREAM_QUALIFICATION', 'EXACT', 10_000, 'BASIS_POINTS', 'GOLDEN_EXACT', QA_SUPPLY_CHAIN),
  gate('MUST_DETECT_RECALL', 'CORRECTNESS', 'UPSTREAM_QUALIFICATION', 'AT_LEAST', 9_500, 'BASIS_POINTS', 'RECALL_THRESHOLD', QA_SUPPLY_CHAIN),
  gate('CRITICAL_HIGH_PRECISION', 'CORRECTNESS', 'UPSTREAM_QUALIFICATION', 'AT_LEAST', 9_000, 'BASIS_POINTS', 'PRECISION_THRESHOLD', QA_SUPPLY_CHAIN),
  gate('PRIOR_MUST_DETECT_RECALL', 'CORRECTNESS', 'UPSTREAM_QUALIFICATION', 'EXACT', 10_000, 'BASIS_POINTS', 'PRIOR_RECALL_EXACT', QA_SUPPLY_CHAIN),
  gate('FALSE_POSITIVE_INCREASE', 'CORRECTNESS', 'UPSTREAM_QUALIFICATION', 'AT_MOST', 200, 'BASIS_POINTS', 'FALSE_POSITIVE_DELTA', QA_SUPPLY_CHAIN),
  gate('SCANNER_FAILURE_RATE', 'PERFORMANCE_RELIABILITY', 'UPSTREAM_QUALIFICATION', 'AT_MOST', 200, 'BASIS_POINTS', 'FAILURE_RATE', QA_SUPPLY_CHAIN),
  gate('P95_LATENCY_REGRESSION', 'PERFORMANCE_RELIABILITY', 'UPSTREAM_QUALIFICATION', 'AT_MOST', 2_000, 'BASIS_POINTS', 'P95_REGRESSION', QA_SUPPLY_CHAIN),
  gate('FAST_LANE_ABSOLUTE_P95', 'PERFORMANCE_RELIABILITY', 'UPSTREAM_QUALIFICATION', 'AT_MOST', 600_000, 'MILLISECONDS', 'FAST_P95', QA_SUPPLY_CHAIN),
  gate('DEEP_LANE_ABSOLUTE_P95', 'PERFORMANCE_RELIABILITY', 'UPSTREAM_QUALIFICATION', 'AT_MOST', 2_700_000, 'MILLISECONDS', 'DEEP_P95', QA_SUPPLY_CHAIN),
  gate('FINGERPRINT_CORRELATION', 'CORRECTNESS', 'UPSTREAM_QUALIFICATION', 'EXACT', 10_000, 'BASIS_POINTS', 'FINGERPRINT_EXACT', QA_SUPPLY_CHAIN),
  gate('EVIDENCE_PRIVACY', 'SECURITY_PRIVACY', 'UPSTREAM_QUALIFICATION', 'EXACT', 10_000, 'BASIS_POINTS', 'EVIDENCE_PRIVACY_EXACT', QA_SUPPLY_CHAIN),
  gate('CAPACITY_RESOURCE_LIMITS', 'PERFORMANCE_RELIABILITY', 'UPSTREAM_QUALIFICATION', 'EXACT', 10_000, 'BASIS_POINTS', 'CAPACITY_EXACT', QA_SUPPLY_CHAIN),
  gate('ZERO_CROSS_TENANT_LEAK', 'SECURITY_PRIVACY', 'UPSTREAM_QUALIFICATION', 'EXACT', 0, 'COUNT', 'ZERO_TOLERANCE', QA_SUPPLY_CHAIN),
  gate('ZERO_SECRET_LEAK', 'SECURITY_PRIVACY', 'UPSTREAM_QUALIFICATION', 'EXACT', 0, 'COUNT', 'ZERO_TOLERANCE', QA_SUPPLY_CHAIN),
  gate('ZERO_SANDBOX_ESCAPE', 'SECURITY_PRIVACY', 'UPSTREAM_QUALIFICATION', 'EXACT', 0, 'COUNT', 'ZERO_TOLERANCE', QA_SUPPLY_CHAIN),
  gate('ZERO_STALE_PUBLICATION', 'SECURITY_PRIVACY', 'UPSTREAM_QUALIFICATION', 'EXACT', 0, 'COUNT', 'ZERO_TOLERANCE', QA_SUPPLY_CHAIN),
  gate('ZERO_UNAUTHORIZED_EGRESS', 'SECURITY_PRIVACY', 'UPSTREAM_QUALIFICATION', 'EXACT', 0, 'COUNT', 'ZERO_TOLERANCE', QA_SUPPLY_CHAIN),
  gate('ZERO_MISSING_DESTRUCTION', 'SECURITY_PRIVACY', 'UPSTREAM_QUALIFICATION', 'EXACT', 0, 'COUNT', 'ZERO_TOLERANCE', QA_SUPPLY_CHAIN),
  gate('ZERO_EVIDENCE_POLICY_VIOLATION', 'SECURITY_PRIVACY', 'UPSTREAM_QUALIFICATION', 'EXACT', 0, 'COUNT', 'ZERO_TOLERANCE', QA_SUPPLY_CHAIN),
  gate('ZERO_UNSIGNED_ARTIFACT_EXECUTION', 'SUPPLY_CHAIN_ROLLBACK', 'UPSTREAM_QUALIFICATION', 'EXACT', 0, 'COUNT', 'ZERO_TOLERANCE', QA_SUPPLY_CHAIN),
  gate('T055_ARTIFACT_DRILLS', 'SUPPLY_CHAIN_ROLLBACK', 'UPSTREAM_QUALIFICATION', 'EXACT', 144, 'COUNT', 'T055_DENOMINATOR', QA_SUPPLY_CHAIN),
  gate('T055_ALLOWLIST_DRILLS', 'SUPPLY_CHAIN_ROLLBACK', 'UPSTREAM_QUALIFICATION', 'EXACT', 1, 'COUNT', 'T055_DENOMINATOR', QA_SUPPLY_CHAIN),
  gate('T055_DATABASE_DRILLS', 'SUPPLY_CHAIN_ROLLBACK', 'UPSTREAM_QUALIFICATION', 'EXACT', 6, 'COUNT', 'T055_DENOMINATOR', QA_SUPPLY_CHAIN),
  gate('T055_SCHEMA_DRILLS', 'SUPPLY_CHAIN_ROLLBACK', 'UPSTREAM_QUALIFICATION', 'EXACT', 3, 'COUNT', 'T055_DENOMINATOR', QA_SUPPLY_CHAIN),
  gate('T055_ROLLBACK_PHASES', 'SUPPLY_CHAIN_ROLLBACK', 'UPSTREAM_QUALIFICATION', 'EXACT', 15, 'COUNT', 'T055_DENOMINATOR', QA_SUPPLY_CHAIN),
  gate('T055_PRE_EXECUTION_REJECTIONS', 'SUPPLY_CHAIN_ROLLBACK', 'UPSTREAM_QUALIFICATION', 'EXACT', 115, 'COUNT', 'T055_DENOMINATOR', QA_SUPPLY_CHAIN),
  gate('T055_ARTIFACT_INVOCATIONS', 'SUPPLY_CHAIN_ROLLBACK', 'UPSTREAM_QUALIFICATION', 'EXACT', 39, 'COUNT', 'T055_DENOMINATOR', QA_SUPPLY_CHAIN),
  gate('T055_CLEANUP_COMPLETION', 'SUPPLY_CHAIN_ROLLBACK', 'UPSTREAM_QUALIFICATION', 'EXACT', 169, 'COUNT', 'T055_CLEANUP', QA_SUPPLY_CHAIN),
  gate('T055_ZERO_NETWORK_EGRESS', 'SUPPLY_CHAIN_ROLLBACK', 'UPSTREAM_QUALIFICATION', 'EXACT', 0, 'COUNT', 'T055_ZERO_TOLERANCE', QA_SUPPLY_CHAIN),
  gate('T055_ZERO_PRODUCTION_MUTATION', 'SUPPLY_CHAIN_ROLLBACK', 'UPSTREAM_QUALIFICATION', 'EXACT', 0, 'COUNT', 'T055_ZERO_TOLERANCE', QA_SUPPLY_CHAIN),
  gate('T055_ZERO_FORBIDDEN_EFFECTS', 'SUPPLY_CHAIN_ROLLBACK', 'UPSTREAM_QUALIFICATION', 'EXACT', 0, 'COUNT', 'T055_ZERO_TOLERANCE', QA_SUPPLY_CHAIN),
  gate('REPOSITORY_CONTRACT_TESTS', 'REPOSITORY_ASSURANCE', 'REPOSITORY_VALIDATION', 'EXACT', 1, 'BOOLEAN', 'REPOSITORY_TESTS', QA_RUNTIME),
  gate('REPOSITORY_STATIC_VALIDATION', 'REPOSITORY_ASSURANCE', 'REPOSITORY_VALIDATION', 'EXACT', 1, 'BOOLEAN', 'LINT_TYPECHECK_BUILD', QA_RUNTIME),
  gate('REPOSITORY_DATABASE_VALIDATION', 'REPOSITORY_ASSURANCE', 'REPOSITORY_VALIDATION', 'EXACT', 1, 'BOOLEAN', 'SCHEMA_MIGRATION_PROBE', QA_RUNTIME),
  gate('NORMALIZATION_DATA_INTEGRITY', 'REPOSITORY_ASSURANCE', 'REPOSITORY_VALIDATION', 'EXACT', 1, 'BOOLEAN', 'DATA_INTEGRITY_TESTS', QA_RUNTIME),
  gate('EVIDENCE_RETENTION_DELETION', 'SECURITY_PRIVACY', 'REPOSITORY_VALIDATION', 'EXACT', 1, 'BOOLEAN', 'RETENTION_TESTS', QA_RUNTIME),
  gate('AI_ADVISORY_ZERO_AUTHORITY', 'SECURITY_PRIVACY', 'REPOSITORY_VALIDATION', 'EXACT', 1, 'BOOLEAN', 'AI_ZERO_AUTHORITY', QA_RUNTIME),
  gate('CANARY_SIX_STEP_REPLAY', 'CANARY', 'CANARY_TELEMETRY_REPLAY', 'EXACT', 6, 'COUNT', 'CANARY_STEPS', TELEMETRY_RUNTIME),
  gate('CANARY_SAMPLE_SUFFICIENCY', 'CANARY', 'CANARY_TELEMETRY_REPLAY', 'AT_LEAST', 1_000, 'COUNT', 'CANARY_MINIMUM_PER_ARM', TELEMETRY_RUNTIME),
  gate('CANARY_OBSERVATION_WINDOW', 'CANARY', 'CANARY_TELEMETRY_REPLAY', 'AT_LEAST', 48, 'HOURS', 'CANARY_WINDOW', TELEMETRY_RUNTIME),
  gate('CANARY_TELEMETRY_COMPLETE', 'CANARY', 'CANARY_TELEMETRY_REPLAY', 'EXACT', 1, 'BOOLEAN', 'CANARY_TELEMETRY', TELEMETRY_RUNTIME),
  gate('CANARY_THRESHOLDS_ZERO_TOLERANCE', 'CANARY', 'CANARY_TELEMETRY_REPLAY', 'EXACT', 1, 'BOOLEAN', 'CANARY_THRESHOLDS', TELEMETRY_RUNTIME),
  gate('KILL_SWITCH_PROPAGATION_BOUNDARIES', 'KILL_SWITCH', 'KILL_SWITCH_PROPAGATION', 'EXACT', 5, 'COUNT', 'KILL_SWITCH_BOUNDARIES', QA_RUNTIME),
  gate('KILL_SWITCH_FAIL_CLOSED', 'KILL_SWITCH', 'KILL_SWITCH_PROPAGATION', 'EXACT', 1, 'BOOLEAN', 'KILL_SWITCH_FAIL_CLOSED', QA_RUNTIME),
  gate('KILL_SWITCH_DEACTIVATION_RECOVERY', 'KILL_SWITCH', 'KILL_SWITCH_PROPAGATION', 'EXACT', 1, 'BOOLEAN', 'KILL_SWITCH_RECOVERY', QA_RUNTIME),
  gate('KILL_SWITCH_FORBIDDEN_SIDE_EFFECTS', 'KILL_SWITCH', 'KILL_SWITCH_PROPAGATION', 'EXACT', 0, 'COUNT', 'KILL_SWITCH_ZERO_EFFECTS', QA_RUNTIME),
  gate('ROLLBACK_SIGNED_CHAIN', 'SUPPLY_CHAIN_ROLLBACK', 'ROLLBACK_READINESS', 'EXACT', 1, 'BOOLEAN', 'ROLLBACK_CHAIN', QA_SUPPLY_CHAIN),
  gate('ROLLBACK_TARGET_DERIVED', 'SUPPLY_CHAIN_ROLLBACK', 'ROLLBACK_READINESS', 'EXACT', 1, 'BOOLEAN', 'ROLLBACK_TARGET', QA_SUPPLY_CHAIN),
  gate('ROLLBACK_POST_FENCE_INVOCATIONS', 'SUPPLY_CHAIN_ROLLBACK', 'ROLLBACK_READINESS', 'EXACT', 0, 'COUNT', 'ROLLBACK_FENCE', QA_SUPPLY_CHAIN),
  gate('DEPLOYMENT_OPERATIONS_REFERENCE_ONLY', 'DEPLOYMENT_BOUNDARY', 'DEPLOYMENT_HANDOFF_BOUNDARY', 'EXACT', 1, 'BOOLEAN', '005_REFERENCE_ONLY', QA_ONLY),
  gate('KUBERNETES_EXECUTION_NOT_PERFORMED', 'DEPLOYMENT_BOUNDARY', 'DEPLOYMENT_HANDOFF_BOUNDARY', 'EXACT', 0, 'COUNT', 'NO_KUBERNETES_EXECUTION', QA_ONLY)
]) satisfies readonly SastProductionGoNoGoGateDefinitionInput[];

export const SAST_PRODUCTION_GO_NO_GO_LIMITS = Object.freeze({
  gateCount: SAST_PRODUCTION_GO_NO_GO_GATE_IDS.length,
  evidenceAttestationCount: SAST_PRODUCTION_GO_NO_GO_EVIDENCE_KINDS.length,
  maximumEvidenceAgeSeconds: 24 * 60 * 60,
  maximumApprovalAgeSeconds: 60 * 60,
  maximumIdentifierBytes: 512,
  maximumReferenceBytes: 2_048,
  maximumFailureReasons: 16
});

export interface SastProductionGoNoGoGateDefinitionCore
  extends SastProductionGoNoGoGateDefinitionInput {
  version: typeof SAST_PRODUCTION_GO_NO_GO_GATE_VERSION;
  notApplicableAllowed: false;
}

export interface SastProductionGoNoGoGateDefinition
  extends SastProductionGoNoGoGateDefinitionCore {
  gateDigest: string;
}

export interface SastProductionGoNoGoManifestCore {
  version: typeof SAST_PRODUCTION_GO_NO_GO_MANIFEST_VERSION;
  revision: string;
  publishedAt: string;
  ownerRef: string;
  gatePolicyRef: string;
  gatePolicyDigest: string;
  t055ManifestId: string;
  t055ManifestDigest: string;
  deploymentOperationsContractRef: string;
  deploymentOperationsContractDigest: string;
  gates: SastProductionGoNoGoGateDefinition[];
  gateSetDigest: string;
  requiredGateCount: number;
  notApplicableGateCount: 0;
  providerExecutionStatus: 'BLOCKED_T055_QUALIFICATION';
  t055PassRequired: true;
  externalEvidenceRequired: true;
  aggregateDecisionAcceptedFromCaller: false;
  notApplicableSubstitutionAllowed: false;
  findingAuthority: false;
  policyAuthority: false;
  publicationAuthority: false;
  scmMutationAuthority: false;
  aiAuthority: false;
  deploymentAuthority: false;
  kubernetesExecutionAuthority: false;
  productionMutationAuthority: false;
  productionReadinessAuthority: false;
  immutable: true;
}

export interface SastProductionGoNoGoManifest
  extends SastProductionGoNoGoManifestCore {
  manifestId: string;
  manifestDigest: string;
}

export interface SastProductionGoNoGoManifestInput {
  revision: string;
  publishedAt: string;
  ownerRef: string;
  gatePolicyRef: string;
  gatePolicyDigest: string;
  t055Manifest: SastSupplyChainRollbackQualificationManifest;
  t054Manifest: SastEndToEndQualificationManifest;
  deploymentOperationsContractRef: string;
  deploymentOperationsContractDigest: string;
}

export interface SastProductionGoNoGoUpstreamBundle {
  t054Result: SastEndToEndQualificationResult;
  t054DependencySet: SastEndToEndQualificationDependencySet;
  t054ArtifactVerificationSet: SastEndToEndQualificationArtifactVerificationSet;
  t054Plan: SastEndToEndQualificationExecutionPlan;
  t055EntryAttestation: SastSupplyChainRollbackQualificationEntryAttestation;
  t055Plan: SastSupplyChainRollbackQualificationPlan;
  t055Result: SastSupplyChainRollbackQualificationResult;
}

export interface SastProductionGoNoGoEntryAttestationCore {
  version: typeof SAST_PRODUCTION_GO_NO_GO_ENTRY_ATTESTATION_VERSION;
  manifestId: string;
  manifestDigest: string;
  t054ManifestId: string;
  t054ManifestDigest: string;
  t054ResultId: string;
  t054ResultDigest: string;
  t054DependencySetId: string;
  t054DependencySetDigest: string;
  t055ManifestId: string;
  t055ManifestDigest: string;
  t055PlanId: string;
  t055PlanDigest: string;
  t055ResultId: string;
  t055ResultDigest: string;
  providerId: string;
  providerAdapterRef: string;
  candidateScannerSetDigest: string;
  baselineScannerSetDigest: string;
  profileSetDigest: string;
  t051SnapshotDigest: string;
  t051PriorReleaseManifestDigest: string;
  t052SnapshotDigest: string;
  t054MeasurementsDigest: string;
  t055MeasurementsDigest: string;
  rollbackTargetDigest: string;
  verifiedAt: string;
  verifierRef: string;
  t056EntryAuthorized: true;
  findingAuthority: false;
  policyAuthority: false;
  publicationAuthority: false;
  scmMutationAuthority: false;
  deploymentAuthority: false;
  kubernetesExecutionAuthority: false;
  productionMutationAuthority: false;
  productionReadinessAuthority: false;
}

export interface SastProductionGoNoGoEntryAttestation
  extends SastProductionGoNoGoEntryAttestationCore {
  attestationId: string;
  attestationDigest: string;
  signature: SastEndToEndQualificationSignature;
}

export interface SastProductionGoNoGoObservationCore {
  version: typeof SAST_PRODUCTION_GO_NO_GO_OBSERVATION_VERSION;
  gateId: SastProductionGoNoGoGateId;
  disposition: SastProductionGoNoGoObservationDisposition;
  observedValue: number | null;
  unit: SastProductionGoNoGoUnit;
  evidenceRef: string;
  evidenceDigest: string;
}

export interface SastProductionGoNoGoObservation
  extends SastProductionGoNoGoObservationCore {
  observationDigest: string;
}

export interface SastProductionGoNoGoEvidenceAttestationCore {
  version: typeof SAST_PRODUCTION_GO_NO_GO_EVIDENCE_ATTESTATION_VERSION;
  manifestId: string;
  manifestDigest: string;
  entryAttestationId: string;
  entryAttestationDigest: string;
  evidenceKind: SastProductionGoNoGoEvidenceKind;
  providerId: string;
  providerAdapterRef: string;
  repositoryCommitSha: string;
  candidateScannerSetDigest: string;
  baselineScannerSetDigest: string;
  profileSetDigest: string;
  t051SnapshotDigest: string;
  t051PriorReleaseManifestDigest: string;
  t052SnapshotDigest: string;
  t054MeasurementsDigest: string;
  t055MeasurementsDigest: string;
  evidenceRef: string;
  evidenceDigest: string;
  observedAt: string;
  validUntil: string;
  observations: SastProductionGoNoGoObservation[];
  observationSetDigest: string;
  externalEvidence: boolean;
  customerContentObserved: false;
  customerCodeExecuted: false;
  packageInstallObserved: false;
  repositoryBuildObserved: false;
  dynamicTestObserved: false;
  publicInternetEgressObserved: false;
  productionMutationObserved: false;
  kubernetesExecutionObserved: false;
}

export interface SastProductionGoNoGoEvidenceAttestation
  extends SastProductionGoNoGoEvidenceAttestationCore {
  attestationId: string;
  attestationDigest: string;
  signatures: SastEndToEndQualificationSignature[];
}

export interface SastProductionGoNoGoPlanCore {
  version: typeof SAST_PRODUCTION_GO_NO_GO_PLAN_VERSION;
  manifestId: string;
  manifestDigest: string;
  entryAttestationId: string;
  entryAttestationDigest: string;
  providerId: string;
  providerAdapterRef: string;
  candidateScannerSetDigest: string;
  baselineScannerSetDigest: string;
  profileSetDigest: string;
  t051SnapshotDigest: string;
  t051PriorReleaseManifestDigest: string;
  t052SnapshotDigest: string;
  t054MeasurementsDigest: string;
  t055MeasurementsDigest: string;
  evidenceAttestationIds: string[];
  evidenceAttestationDigests: string[];
  evidenceAttestationSetDigest: string;
  gateSetDigest: string;
  rollbackTargetRef: string;
  rollbackTargetDigest: string;
  killSwitchEvidenceAttestationId: string;
  killSwitchEvidenceAttestationDigest: string;
  deploymentOperationsContractRef: string;
  deploymentOperationsContractDigest: string;
  decisionActorRef: string;
  decidedAt: string;
  requiredApprovalRoles: string[];
  aggregateDecisionAcceptedFromCaller: false;
  notApplicableSubstitutionAllowed: false;
  deploymentOperationsEntryOnly: true;
  findingAuthority: false;
  policyAuthority: false;
  publicationAuthority: false;
  scmMutationAuthority: false;
  aiAuthority: false;
  deploymentAuthority: false;
  kubernetesExecutionAuthority: false;
  productionMutationAuthority: false;
  productionReadinessAuthority: false;
}

export interface SastProductionGoNoGoPlan
  extends SastProductionGoNoGoPlanCore {
  planId: string;
  planDigest: string;
}

export interface SastProductionGoNoGoGateResultCore {
  version: typeof SAST_PRODUCTION_GO_NO_GO_GATE_RESULT_VERSION;
  gateId: SastProductionGoNoGoGateId;
  outcome: SastProductionGoNoGoGateOutcome;
  observedValue: number | null;
  thresholdOperator: SastProductionGoNoGoThresholdOperator;
  thresholdValue: number;
  unit: SastProductionGoNoGoUnit;
  evidenceAttestationId: string;
  evidenceAttestationDigest: string;
  rationaleCode: string;
}

export interface SastProductionGoNoGoGateResult
  extends SastProductionGoNoGoGateResultCore {
  gateResultDigest: string;
}

export interface SastProductionGoNoGoRecordCore {
  version: typeof SAST_PRODUCTION_GO_NO_GO_RECORD_VERSION;
  status: SastProductionGoNoGoStatus;
  manifestId: string;
  manifestDigest: string;
  entryAttestationId: string | null;
  entryAttestationDigest: string | null;
  planId: string | null;
  planDigest: string | null;
  providerId: string | null;
  providerAdapterRef: string | null;
  candidateScannerSetDigest: string | null;
  baselineScannerSetDigest: string | null;
  profileSetDigest: string | null;
  t051SnapshotDigest: string | null;
  t051PriorReleaseManifestDigest: string | null;
  t052SnapshotDigest: string | null;
  t054MeasurementsDigest: string | null;
  t055MeasurementsDigest: string | null;
  expectedGateCount: number;
  evaluatedGateCount: number;
  passedGateCount: number;
  failedGateCount: number;
  notApplicableGateCount: number;
  gateResults: SastProductionGoNoGoGateResult[];
  gateResultSetDigest: string | null;
  approvalRefs: string[];
  approvalSetDigest: string | null;
  failureReasons: SastProductionGoNoGoFailureReason[];
  rollbackTargetRef: string | null;
  rollbackTargetDigest: string | null;
  killSwitchEvidenceAttestationId: string | null;
  killSwitchEvidenceAttestationDigest: string | null;
  deploymentOperationsContractRef: string;
  deploymentOperationsContractDigest: string;
  decisionActorRef: string | null;
  decidedAt: string;
  deploymentOperationsEntryAuthorized: boolean;
  findingAuthority: false;
  policyAuthority: false;
  publicationAuthority: false;
  scmMutationAuthority: false;
  aiAuthority: false;
  deploymentAuthority: false;
  kubernetesExecutionAuthority: false;
  productionMutationAuthority: false;
  productionReadinessAuthority: false;
}

export interface SastProductionGoNoGoRecord
  extends SastProductionGoNoGoRecordCore {
  recordId: string;
  recordDigest: string;
}

export interface SastProductionGoNoGoEvaluationInput {
  manifest: SastProductionGoNoGoManifest;
  t054Manifest: SastEndToEndQualificationManifest;
  t055Manifest: SastSupplyChainRollbackQualificationManifest;
  upstream: SastProductionGoNoGoUpstreamBundle | null;
  entryAttestation: SastProductionGoNoGoEntryAttestation | null;
  evidenceAttestations: SastProductionGoNoGoEvidenceAttestation[];
  plan: SastProductionGoNoGoPlan | null;
  approvals: SastEndToEndQualificationSignature[];
  trustedEvaluatedAt: string;
  verifySignature: SastEndToEndQualificationSignatureVerifier;
}

const MANIFEST_CORE_KEYS = [
  'version', 'revision', 'publishedAt', 'ownerRef', 'gatePolicyRef',
  'gatePolicyDigest', 't055ManifestId', 't055ManifestDigest',
  'deploymentOperationsContractRef', 'deploymentOperationsContractDigest',
  'gates', 'gateSetDigest', 'requiredGateCount', 'notApplicableGateCount',
  'providerExecutionStatus', 't055PassRequired', 'externalEvidenceRequired',
  'aggregateDecisionAcceptedFromCaller', 'notApplicableSubstitutionAllowed',
  'findingAuthority', 'policyAuthority', 'publicationAuthority',
  'scmMutationAuthority', 'aiAuthority', 'deploymentAuthority',
  'kubernetesExecutionAuthority', 'productionMutationAuthority',
  'productionReadinessAuthority', 'immutable'
] as const;
const ENTRY_CORE_KEYS = [
  'version', 'manifestId', 'manifestDigest', 't054ManifestId',
  't054ManifestDigest', 't054ResultId', 't054ResultDigest',
  't054DependencySetId', 't054DependencySetDigest', 't055ManifestId',
  't055ManifestDigest', 't055PlanId', 't055PlanDigest', 't055ResultId',
  't055ResultDigest', 'providerId', 'providerAdapterRef',
  'candidateScannerSetDigest', 'baselineScannerSetDigest', 'profileSetDigest',
  't051SnapshotDigest', 't051PriorReleaseManifestDigest', 't052SnapshotDigest',
  't054MeasurementsDigest', 't055MeasurementsDigest', 'rollbackTargetDigest',
  'verifiedAt', 'verifierRef', 't056EntryAuthorized', 'findingAuthority',
  'policyAuthority', 'publicationAuthority', 'scmMutationAuthority',
  'deploymentAuthority', 'kubernetesExecutionAuthority',
  'productionMutationAuthority', 'productionReadinessAuthority'
] as const;
const OBSERVATION_CORE_KEYS = [
  'version', 'gateId', 'disposition', 'observedValue', 'unit', 'evidenceRef',
  'evidenceDigest'
] as const;
const EVIDENCE_CORE_KEYS = [
  'version', 'manifestId', 'manifestDigest', 'entryAttestationId',
  'entryAttestationDigest', 'evidenceKind', 'providerId', 'providerAdapterRef',
  'repositoryCommitSha', 'candidateScannerSetDigest',
  'baselineScannerSetDigest', 'profileSetDigest', 't051SnapshotDigest',
  't051PriorReleaseManifestDigest', 't052SnapshotDigest',
  't054MeasurementsDigest', 't055MeasurementsDigest', 'evidenceRef',
  'evidenceDigest', 'observedAt', 'validUntil', 'observations',
  'observationSetDigest', 'externalEvidence', 'customerContentObserved',
  'customerCodeExecuted', 'packageInstallObserved', 'repositoryBuildObserved',
  'dynamicTestObserved', 'publicInternetEgressObserved',
  'productionMutationObserved', 'kubernetesExecutionObserved'
] as const;
const PLAN_CORE_KEYS = [
  'version', 'manifestId', 'manifestDigest', 'entryAttestationId',
  'entryAttestationDigest', 'providerId', 'providerAdapterRef',
  'candidateScannerSetDigest', 'baselineScannerSetDigest', 'profileSetDigest',
  't051SnapshotDigest', 't051PriorReleaseManifestDigest', 't052SnapshotDigest',
  't054MeasurementsDigest', 't055MeasurementsDigest',
  'evidenceAttestationIds', 'evidenceAttestationDigests',
  'evidenceAttestationSetDigest', 'gateSetDigest', 'rollbackTargetRef',
  'rollbackTargetDigest', 'killSwitchEvidenceAttestationId',
  'killSwitchEvidenceAttestationDigest', 'deploymentOperationsContractRef',
  'deploymentOperationsContractDigest', 'decisionActorRef', 'decidedAt',
  'requiredApprovalRoles', 'aggregateDecisionAcceptedFromCaller',
  'notApplicableSubstitutionAllowed', 'deploymentOperationsEntryOnly',
  'findingAuthority', 'policyAuthority', 'publicationAuthority',
  'scmMutationAuthority', 'aiAuthority', 'deploymentAuthority',
  'kubernetesExecutionAuthority', 'productionMutationAuthority',
  'productionReadinessAuthority'
] as const;
const GATE_RESULT_CORE_KEYS = [
  'version', 'gateId', 'outcome', 'observedValue', 'thresholdOperator',
  'thresholdValue', 'unit', 'evidenceAttestationId',
  'evidenceAttestationDigest', 'rationaleCode'
] as const;
const RECORD_CORE_KEYS = [
  'version', 'status', 'manifestId', 'manifestDigest', 'entryAttestationId',
  'entryAttestationDigest', 'planId', 'planDigest', 'providerId',
  'providerAdapterRef', 'candidateScannerSetDigest', 'baselineScannerSetDigest',
  'profileSetDigest', 't051SnapshotDigest', 't051PriorReleaseManifestDigest',
  't052SnapshotDigest', 't054MeasurementsDigest', 't055MeasurementsDigest',
  'expectedGateCount', 'evaluatedGateCount', 'passedGateCount',
  'failedGateCount', 'notApplicableGateCount', 'gateResults',
  'gateResultSetDigest', 'approvalRefs', 'approvalSetDigest', 'failureReasons',
  'rollbackTargetRef', 'rollbackTargetDigest',
  'killSwitchEvidenceAttestationId', 'killSwitchEvidenceAttestationDigest',
  'deploymentOperationsContractRef', 'deploymentOperationsContractDigest',
  'decisionActorRef', 'decidedAt', 'deploymentOperationsEntryAuthorized',
  'findingAuthority', 'policyAuthority', 'publicationAuthority',
  'scmMutationAuthority', 'aiAuthority', 'deploymentAuthority',
  'kubernetesExecutionAuthority', 'productionMutationAuthority',
  'productionReadinessAuthority'
] as const;

export function buildSastProductionGoNoGoManifest(
  input: Readonly<SastProductionGoNoGoManifestInput>,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): SastProductionGoNoGoManifest | null {
  try {
    if (
      !isSemanticVersion(input.revision) ||
      !isIsoInstant(input.publishedAt) ||
      !isReference(input.ownerRef) ||
      !isDigestBoundReference(input.gatePolicyRef) ||
      !isDigest(input.gatePolicyDigest) ||
      !isSastEndToEndQualificationManifestValid(input.t054Manifest, digestCanonical) ||
      !isSastSupplyChainRollbackQualificationManifestValid(
        input.t055Manifest,
        input.t054Manifest,
        digestCanonical
      ) ||
      !isDigestBoundReference(input.deploymentOperationsContractRef) ||
      !isDigest(input.deploymentOperationsContractDigest) ||
      !input.deploymentOperationsContractRef.endsWith(
        `/${input.deploymentOperationsContractDigest}`
      )
    ) {
      return null;
    }
    const gates = SAST_PRODUCTION_GO_NO_GO_GATE_CATALOG.map((definition) => {
      const core: SastProductionGoNoGoGateDefinitionCore = {
        version: SAST_PRODUCTION_GO_NO_GO_GATE_VERSION,
        ...definition,
        requiredSignatureRoles: [...definition.requiredSignatureRoles],
        notApplicableAllowed: false
      };
      return { ...core, gateDigest: digestCanonical(stableJson(core)) };
    });
    const gateSetDigest = digestCanonical(
      stableJson(gates.map((item) => ({ gateId: item.gateId, gateDigest: item.gateDigest })))
    );
    const core: SastProductionGoNoGoManifestCore = {
      version: SAST_PRODUCTION_GO_NO_GO_MANIFEST_VERSION,
      revision: input.revision,
      publishedAt: input.publishedAt,
      ownerRef: input.ownerRef,
      gatePolicyRef: input.gatePolicyRef,
      gatePolicyDigest: input.gatePolicyDigest,
      t055ManifestId: input.t055Manifest.manifestId,
      t055ManifestDigest: input.t055Manifest.manifestDigest,
      deploymentOperationsContractRef: input.deploymentOperationsContractRef,
      deploymentOperationsContractDigest: input.deploymentOperationsContractDigest,
      gates,
      gateSetDigest,
      requiredGateCount: gates.length,
      notApplicableGateCount: 0,
      providerExecutionStatus: 'BLOCKED_T055_QUALIFICATION',
      t055PassRequired: true,
      externalEvidenceRequired: true,
      aggregateDecisionAcceptedFromCaller: false,
      notApplicableSubstitutionAllowed: false,
      findingAuthority: false,
      policyAuthority: false,
      publicationAuthority: false,
      scmMutationAuthority: false,
      aiAuthority: false,
      deploymentAuthority: false,
      kubernetesExecutionAuthority: false,
      productionMutationAuthority: false,
      productionReadinessAuthority: false,
      immutable: true
    };
    const manifestDigest = digestCanonical(stableJson(core));
    return {
      ...core,
      manifestId: `sast-production-go-no-go-manifest://${stripDigest(manifestDigest)}`,
      manifestDigest
    };
  } catch {
    return null;
  }
}

export function isSastProductionGoNoGoManifestValid(
  value: unknown,
  t055Manifest: SastSupplyChainRollbackQualificationManifest,
  t054Manifest: SastEndToEndQualificationManifest,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): value is SastProductionGoNoGoManifest {
  try {
    if (!hasExactKeys(value, [...MANIFEST_CORE_KEYS, 'manifestId', 'manifestDigest'])) {
      return false;
    }
    const candidate = value as unknown as SastProductionGoNoGoManifest;
    const rebuilt = buildSastProductionGoNoGoManifest(
      {
        revision: candidate.revision,
        publishedAt: candidate.publishedAt,
        ownerRef: candidate.ownerRef,
        gatePolicyRef: candidate.gatePolicyRef,
        gatePolicyDigest: candidate.gatePolicyDigest,
        t055Manifest,
        t054Manifest,
        deploymentOperationsContractRef: candidate.deploymentOperationsContractRef,
        deploymentOperationsContractDigest: candidate.deploymentOperationsContractDigest
      },
      digestCanonical
    );
    return rebuilt !== null && stableJson(rebuilt) === stableJson(candidate);
  } catch {
    return false;
  }
}

export function buildSastProductionGoNoGoEntryAttestation(
  input: {
    manifest: SastProductionGoNoGoManifest;
    t054Manifest: SastEndToEndQualificationManifest;
    t055Manifest: SastSupplyChainRollbackQualificationManifest;
    upstream: SastProductionGoNoGoUpstreamBundle;
    verifiedAt: string;
    verifierRef: string;
    signature: SastEndToEndQualificationSignature;
    verifySignature: SastEndToEndQualificationSignatureVerifier;
  },
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): SastProductionGoNoGoEntryAttestation | null {
  try {
    if (
      !isUpstreamBundleValid(input, digestCanonical) ||
      !isIsoInstant(input.verifiedAt) ||
      !isDigestBoundReference(input.verifierRef)
    ) {
      return null;
    }
    const t054Measurements = input.upstream.t054Result.measurements;
    const t055Measurements = input.upstream.t055Result.measurements;
    if (!t054Measurements || !t055Measurements) return null;
    const rollbackTargetDigest = deriveRollbackTargetDigest(input.upstream.t055Plan);
    if (!rollbackTargetDigest) return null;
    const core: SastProductionGoNoGoEntryAttestationCore = {
      version: SAST_PRODUCTION_GO_NO_GO_ENTRY_ATTESTATION_VERSION,
      manifestId: input.manifest.manifestId,
      manifestDigest: input.manifest.manifestDigest,
      t054ManifestId: input.t054Manifest.manifestId,
      t054ManifestDigest: input.t054Manifest.manifestDigest,
      t054ResultId: input.upstream.t054Result.resultId,
      t054ResultDigest: input.upstream.t054Result.resultDigest,
      t054DependencySetId: input.upstream.t054DependencySet.dependencySetId,
      t054DependencySetDigest: input.upstream.t054DependencySet.dependencySetDigest,
      t055ManifestId: input.t055Manifest.manifestId,
      t055ManifestDigest: input.t055Manifest.manifestDigest,
      t055PlanId: input.upstream.t055Plan.planId,
      t055PlanDigest: input.upstream.t055Plan.planDigest,
      t055ResultId: input.upstream.t055Result.resultId,
      t055ResultDigest: input.upstream.t055Result.resultDigest,
      providerId: input.upstream.t054DependencySet.providerId,
      providerAdapterRef: input.upstream.t054DependencySet.providerAdapterRef,
      candidateScannerSetDigest: input.upstream.t054DependencySet.candidateScannerSetDigest,
      baselineScannerSetDigest: input.upstream.t054DependencySet.baselineScannerSetDigest,
      profileSetDigest: deriveProfileSetDigest(input.t054Manifest, digestCanonical),
      t051SnapshotDigest: input.t054Manifest.t051SnapshotDigest,
      t051PriorReleaseManifestDigest: input.t054Manifest.t051PriorReleaseManifestDigest,
      t052SnapshotDigest: input.t054Manifest.t052SnapshotDigest,
      t054MeasurementsDigest: t054Measurements.measurementsDigest,
      t055MeasurementsDigest: t055Measurements.measurementsDigest,
      rollbackTargetDigest,
      verifiedAt: input.verifiedAt,
      verifierRef: input.verifierRef,
      t056EntryAuthorized: true,
      findingAuthority: false,
      policyAuthority: false,
      publicationAuthority: false,
      scmMutationAuthority: false,
      deploymentAuthority: false,
      kubernetesExecutionAuthority: false,
      productionMutationAuthority: false,
      productionReadinessAuthority: false
    };
    const attestationDigest = digestCanonical(stableJson(core));
    if (
      !isSignatureFor(input.signature, 'QUALIFICATION_AUTHORITY', attestationDigest) ||
      input.signature.signedAt !== input.verifiedAt
    ) {
      return null;
    }
    return {
      ...core,
      attestationId: `sast-production-go-no-go-entry-attestation://${stripDigest(attestationDigest)}`,
      attestationDigest,
      signature: input.signature
    };
  } catch {
    return null;
  }
}

export function isSastProductionGoNoGoEntryAttestationValid(
  value: unknown,
  context: Omit<Parameters<typeof buildSastProductionGoNoGoEntryAttestation>[0], 'verifiedAt' | 'verifierRef' | 'signature'>,
  verifySignature: SastEndToEndQualificationSignatureVerifier,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): value is SastProductionGoNoGoEntryAttestation {
  try {
    if (!hasExactKeys(value, [...ENTRY_CORE_KEYS, 'attestationId', 'attestationDigest', 'signature'])) {
      return false;
    }
    const candidate = value as unknown as SastProductionGoNoGoEntryAttestation;
    const rebuilt = buildSastProductionGoNoGoEntryAttestation(
      {
        ...context,
        verifiedAt: candidate.verifiedAt,
        verifierRef: candidate.verifierRef,
        signature: candidate.signature,
        verifySignature
      },
      digestCanonical
    );
    return (
      rebuilt !== null &&
      stableJson(rebuilt) === stableJson(candidate) &&
      Date.parse(candidate.verifiedAt) >=
        Date.parse(context.upstream.t055Result.evaluatedAt) &&
      Date.parse(candidate.verifiedAt) -
        Date.parse(context.upstream.t055Result.evaluatedAt) <=
        SAST_PRODUCTION_GO_NO_GO_LIMITS.maximumEvidenceAgeSeconds * 1_000 &&
      verifyQualificationSignature(candidate.signature, verifySignature)
    );
  } catch {
    return false;
  }
}

export function buildSastProductionGoNoGoEvidenceAttestation(
  input: Omit<
    SastProductionGoNoGoEvidenceAttestationCore,
    | 'version'
    | 'observations'
    | 'observationSetDigest'
    | 'customerContentObserved'
    | 'customerCodeExecuted'
    | 'packageInstallObserved'
    | 'repositoryBuildObserved'
    | 'dynamicTestObserved'
    | 'publicInternetEgressObserved'
    | 'productionMutationObserved'
    | 'kubernetesExecutionObserved'
  > & { observations: Omit<SastProductionGoNoGoObservationCore, 'version'>[] },
  signatures: SastEndToEndQualificationSignature[],
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): SastProductionGoNoGoEvidenceAttestation | null {
  try {
    const observations = input.observations.map((item) => {
      const core: SastProductionGoNoGoObservationCore = {
        version: SAST_PRODUCTION_GO_NO_GO_OBSERVATION_VERSION,
        ...item
      };
      if (!isObservationCoreValid(core)) throw new Error('invalid observation');
      return { ...core, observationDigest: digestCanonical(stableJson(core)) };
    });
    const core: SastProductionGoNoGoEvidenceAttestationCore = {
      version: SAST_PRODUCTION_GO_NO_GO_EVIDENCE_ATTESTATION_VERSION,
      ...input,
      observations,
      observationSetDigest: digestCanonical(
        stableJson(observations.map((item) => ({ gateId: item.gateId, observationDigest: item.observationDigest })))
      ),
      customerContentObserved: false,
      customerCodeExecuted: false,
      packageInstallObserved: false,
      repositoryBuildObserved: false,
      dynamicTestObserved: false,
      publicInternetEgressObserved: false,
      productionMutationObserved: false,
      kubernetesExecutionObserved: false
    };
    if (!isEvidenceCoreValid(core)) return null;
    const attestationDigest = digestCanonical(stableJson(core));
    if (!signatures.every((item) => item.payloadDigest === attestationDigest)) return null;
    return {
      ...core,
      attestationId: `sast-production-go-no-go-evidence-attestation://${stripDigest(attestationDigest)}`,
      attestationDigest,
      signatures: [...signatures]
    };
  } catch {
    return null;
  }
}

export function isSastProductionGoNoGoEvidenceAttestationValid(
  value: unknown,
  manifest: SastProductionGoNoGoManifest,
  entry: SastProductionGoNoGoEntryAttestation,
  verifySignature: SastEndToEndQualificationSignatureVerifier,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): value is SastProductionGoNoGoEvidenceAttestation {
  try {
    if (!hasExactKeys(value, [...EVIDENCE_CORE_KEYS, 'attestationId', 'attestationDigest', 'signatures'])) {
      return false;
    }
    const candidate = value as unknown as SastProductionGoNoGoEvidenceAttestation;
    const expectedGates = manifest.gates.filter((item) => item.evidenceKind === candidate.evidenceKind);
    if (
      candidate.manifestId !== manifest.manifestId ||
      candidate.manifestDigest !== manifest.manifestDigest ||
      candidate.entryAttestationId !== entry.attestationId ||
      candidate.entryAttestationDigest !== entry.attestationDigest ||
      candidate.providerId !== entry.providerId ||
      candidate.providerAdapterRef !== entry.providerAdapterRef ||
      candidate.candidateScannerSetDigest !== entry.candidateScannerSetDigest ||
      candidate.baselineScannerSetDigest !== entry.baselineScannerSetDigest ||
      candidate.profileSetDigest !== entry.profileSetDigest ||
      candidate.t051SnapshotDigest !== entry.t051SnapshotDigest ||
      candidate.t051PriorReleaseManifestDigest !== entry.t051PriorReleaseManifestDigest ||
      candidate.t052SnapshotDigest !== entry.t052SnapshotDigest ||
      candidate.t054MeasurementsDigest !== entry.t054MeasurementsDigest ||
      candidate.t055MeasurementsDigest !== entry.t055MeasurementsDigest ||
      !arraysEqual(candidate.observations.map((item) => item.gateId), expectedGates.map((item) => item.gateId)) ||
      !candidate.observations.every((item, index) => item.unit === expectedGates[index]?.unit) ||
      candidate.externalEvidence !== (candidate.evidenceKind !== 'REPOSITORY_VALIDATION')
    ) {
      return false;
    }
    const rebuilt = buildSastProductionGoNoGoEvidenceAttestation(
      {
        ...pickEvidenceInput(candidate),
        observations: candidate.observations.map(pickObservationInput)
      },
      candidate.signatures,
      digestCanonical
    );
    const roles = expectedGates[0]?.requiredSignatureRoles ?? [];
    return (
      rebuilt !== null &&
      stableJson(rebuilt) === stableJson(candidate) &&
      isSignatureSetValid(candidate.signatures, roles, candidate.attestationDigest, verifySignature) &&
      candidate.signatures.every((item) =>
        Date.parse(item.signedAt) >= Date.parse(candidate.observedAt) &&
        Date.parse(item.signedAt) <= Date.parse(candidate.validUntil)
      )
    );
  } catch {
    return false;
  }
}

export function buildSastProductionGoNoGoPlan(
  input: {
    manifest: SastProductionGoNoGoManifest;
    entryAttestation: SastProductionGoNoGoEntryAttestation;
    evidenceAttestations: SastProductionGoNoGoEvidenceAttestation[];
    decisionActorRef: string;
    decidedAt: string;
    verifySignature: SastEndToEndQualificationSignatureVerifier;
  },
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): SastProductionGoNoGoPlan | null {
  try {
    if (
      !isDigestBoundReference(input.decisionActorRef) ||
      !isIsoInstant(input.decidedAt) ||
      Date.parse(input.decidedAt) < Date.parse(input.entryAttestation.verifiedAt) ||
      input.evidenceAttestations.length !== SAST_PRODUCTION_GO_NO_GO_EVIDENCE_KINDS.length ||
      !arraysEqual(input.evidenceAttestations.map((item) => item.evidenceKind), SAST_PRODUCTION_GO_NO_GO_EVIDENCE_KINDS) ||
      input.evidenceAttestations.some(
        (item) =>
          Date.parse(item.observedAt) > Date.parse(input.decidedAt) ||
          item.signatures.some(
            (signature) => Date.parse(signature.signedAt) > Date.parse(input.decidedAt)
          )
      ) ||
      !input.evidenceAttestations.every((item) =>
        isSastProductionGoNoGoEvidenceAttestationValid(
          item,
          input.manifest,
          input.entryAttestation,
          input.verifySignature,
          digestCanonical
        )
      )
    ) {
      return null;
    }
    const killSwitch = input.evidenceAttestations.find(
      (item) => item.evidenceKind === 'KILL_SWITCH_PROPAGATION'
    );
    if (!killSwitch) return null;
    const evidenceAttestationIds = input.evidenceAttestations.map((item) => item.attestationId);
    const evidenceAttestationDigests = input.evidenceAttestations.map((item) => item.attestationDigest);
    const rollbackTargetRef = `rollback-target://aegisai/t056/${input.entryAttestation.rollbackTargetDigest}`;
    const core: SastProductionGoNoGoPlanCore = {
      version: SAST_PRODUCTION_GO_NO_GO_PLAN_VERSION,
      manifestId: input.manifest.manifestId,
      manifestDigest: input.manifest.manifestDigest,
      entryAttestationId: input.entryAttestation.attestationId,
      entryAttestationDigest: input.entryAttestation.attestationDigest,
      providerId: input.entryAttestation.providerId,
      providerAdapterRef: input.entryAttestation.providerAdapterRef,
      candidateScannerSetDigest: input.entryAttestation.candidateScannerSetDigest,
      baselineScannerSetDigest: input.entryAttestation.baselineScannerSetDigest,
      profileSetDigest: input.entryAttestation.profileSetDigest,
      t051SnapshotDigest: input.entryAttestation.t051SnapshotDigest,
      t051PriorReleaseManifestDigest: input.entryAttestation.t051PriorReleaseManifestDigest,
      t052SnapshotDigest: input.entryAttestation.t052SnapshotDigest,
      t054MeasurementsDigest: input.entryAttestation.t054MeasurementsDigest,
      t055MeasurementsDigest: input.entryAttestation.t055MeasurementsDigest,
      evidenceAttestationIds,
      evidenceAttestationDigests,
      evidenceAttestationSetDigest: digestCanonical(
        stableJson(evidenceAttestationIds.map((id, index) => ({ id, digest: evidenceAttestationDigests[index] })))
      ),
      gateSetDigest: input.manifest.gateSetDigest,
      rollbackTargetRef,
      rollbackTargetDigest: input.entryAttestation.rollbackTargetDigest,
      killSwitchEvidenceAttestationId: killSwitch.attestationId,
      killSwitchEvidenceAttestationDigest: killSwitch.attestationDigest,
      deploymentOperationsContractRef: input.manifest.deploymentOperationsContractRef,
      deploymentOperationsContractDigest: input.manifest.deploymentOperationsContractDigest,
      decisionActorRef: input.decisionActorRef,
      decidedAt: input.decidedAt,
      requiredApprovalRoles: [...SAST_END_TO_END_QUALIFICATION_APPROVAL_ROLES],
      aggregateDecisionAcceptedFromCaller: false,
      notApplicableSubstitutionAllowed: false,
      deploymentOperationsEntryOnly: true,
      findingAuthority: false,
      policyAuthority: false,
      publicationAuthority: false,
      scmMutationAuthority: false,
      aiAuthority: false,
      deploymentAuthority: false,
      kubernetesExecutionAuthority: false,
      productionMutationAuthority: false,
      productionReadinessAuthority: false
    };
    const planDigest = digestCanonical(stableJson(core));
    return {
      ...core,
      planId: `sast-production-go-no-go-plan://${stripDigest(planDigest)}`,
      planDigest
    };
  } catch {
    return null;
  }
}

export function isSastProductionGoNoGoPlanValid(
  value: unknown,
  manifest: SastProductionGoNoGoManifest,
  entryAttestation: SastProductionGoNoGoEntryAttestation,
  evidenceAttestations: SastProductionGoNoGoEvidenceAttestation[],
  verifySignature: SastEndToEndQualificationSignatureVerifier,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): value is SastProductionGoNoGoPlan {
  try {
    if (!hasExactKeys(value, [...PLAN_CORE_KEYS, 'planId', 'planDigest'])) return false;
    const candidate = value as unknown as SastProductionGoNoGoPlan;
    const rebuilt = buildSastProductionGoNoGoPlan(
      {
        manifest,
        entryAttestation,
        evidenceAttestations,
        decisionActorRef: candidate.decisionActorRef,
        decidedAt: candidate.decidedAt,
        verifySignature
      },
      digestCanonical
    );
    return rebuilt !== null && stableJson(rebuilt) === stableJson(candidate);
  } catch {
    return false;
  }
}

export function evaluateSastProductionGoNoGoEvidence(
  input: Readonly<SastProductionGoNoGoEvaluationInput>,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): SastProductionGoNoGoRecord | null {
  try {
    if (
      !isSastProductionGoNoGoManifestValid(
        input.manifest,
        input.t055Manifest,
        input.t054Manifest,
        digestCanonical
      ) ||
      !isIsoInstant(input.trustedEvaluatedAt)
    ) {
      return null;
    }
    if (!input.upstream || input.upstream.t055Result.status !== 'PASSED' || !input.upstream.t055Result.t056EntryAuthorized) {
      return buildRecord(
        { ...input, entryAttestation: null, plan: null },
        'BLOCKED_T055_QUALIFICATION',
        [],
        [],
        ['T055_PREREQUISITE_MISSING'],
        digestCanonical
      );
    }
    if (!isUpstreamBundleValid({ ...input, upstream: input.upstream }, digestCanonical)) {
      return buildRecord(
        { ...input, entryAttestation: null, plan: null },
        'NO_GO',
        [],
        [],
        ['UPSTREAM_BINDING_INVALID'],
        digestCanonical
      );
    }
    if (!input.entryAttestation) {
      return buildRecord(
        { ...input, plan: null },
        'PENDING_FINAL_EVIDENCE',
        [],
        [],
        ['EVIDENCE_INCOMPLETE'],
        digestCanonical
      );
    }
    if (
      !isSastProductionGoNoGoEntryAttestationValid(
        input.entryAttestation,
        {
          manifest: input.manifest,
          t054Manifest: input.t054Manifest,
          t055Manifest: input.t055Manifest,
          upstream: input.upstream,
          verifySignature: input.verifySignature
        },
        input.verifySignature,
        digestCanonical
      ) ||
      Date.parse(input.entryAttestation.verifiedAt) > Date.parse(input.trustedEvaluatedAt) ||
      Date.parse(input.trustedEvaluatedAt) - Date.parse(input.entryAttestation.verifiedAt) >
        SAST_PRODUCTION_GO_NO_GO_LIMITS.maximumEvidenceAgeSeconds * 1_000
    ) {
      return buildRecord(
        { ...input, entryAttestation: null, plan: null },
        'NO_GO',
        [],
        [],
        ['ENTRY_ATTESTATION_INVALID'],
        digestCanonical
      );
    }
    const evidenceState = validateEvidenceSet(
      {
        ...input,
        upstream: input.upstream,
        entryAttestation: input.entryAttestation
      },
      digestCanonical
    );
    if (evidenceState.status === 'INVALID') {
      return buildRecord(
        { ...input, plan: null },
        'NO_GO',
        [],
        [],
        evidenceState.reasons,
        digestCanonical
      );
    }
    const evidenceFailureReasons: SastProductionGoNoGoFailureReason[] = [];
    if (evidenceState.stale) evidenceFailureReasons.push('EVIDENCE_STALE');
    if (evidenceState.upstreamMismatch) {
      evidenceFailureReasons.push('UPSTREAM_MEASUREMENT_MISMATCH');
    }
    if (evidenceState.notApplicable) {
      evidenceFailureReasons.push('NOT_APPLICABLE_PROHIBITED');
    }
    if (evidenceState.gateResults.some((item) => item.outcome === 'FAILED')) {
      evidenceFailureReasons.push('GATE_THRESHOLD_BREACH');
    }
    if (evidenceFailureReasons.length > 0) {
      return buildRecord(
        { ...input, plan: null },
        'NO_GO',
        evidenceState.gateResults,
        [],
        evidenceFailureReasons,
        digestCanonical
      );
    }
    if (!evidenceState.complete) {
      const inconsistentReasons: SastProductionGoNoGoFailureReason[] = [];
      if (input.plan !== null) inconsistentReasons.push('PLAN_INVALID');
      if (input.approvals.length > 0) inconsistentReasons.push('APPROVALS_INVALID');
      if (inconsistentReasons.length > 0) {
        return buildRecord(
          { ...input, plan: null },
          'NO_GO',
          evidenceState.gateResults,
          [],
          inconsistentReasons,
          digestCanonical
        );
      }
      return buildRecord(
        { ...input, plan: null },
        'PENDING_FINAL_EVIDENCE',
        evidenceState.gateResults,
        [],
        ['EVIDENCE_INCOMPLETE'],
        digestCanonical
      );
    }
    if (!input.plan) {
      if (input.approvals.length > 0) {
        return buildRecord(
          { ...input, plan: null },
          'NO_GO',
          evidenceState.gateResults,
          [],
          ['APPROVALS_INVALID'],
          digestCanonical
        );
      }
      return buildRecord(
        { ...input, plan: null },
        'PENDING_FINAL_EVIDENCE',
        evidenceState.gateResults,
        [],
        ['EVIDENCE_INCOMPLETE'],
        digestCanonical
      );
    }
    if (
      !isSastProductionGoNoGoPlanValid(
        input.plan,
        input.manifest,
        input.entryAttestation,
        input.evidenceAttestations,
        input.verifySignature,
        digestCanonical
      )
    ) {
      return buildRecord(
        { ...input, plan: null },
        'NO_GO',
        evidenceState.gateResults,
        [],
        ['PLAN_INVALID'],
        digestCanonical
      );
    }
    const approvalState = validateApprovals(
      input.approvals,
      input.plan,
      input.trustedEvaluatedAt,
      input.verifySignature
    );
    if (approvalState === 'PENDING') {
      return buildRecord(
        input,
        'PENDING_FINAL_EVIDENCE',
        evidenceState.gateResults,
        input.approvals,
        ['APPROVALS_INCOMPLETE'],
        digestCanonical
      );
    }
    if (approvalState === 'INVALID') {
      return buildRecord(
        input,
        'NO_GO',
        evidenceState.gateResults,
        [],
        ['APPROVALS_INVALID'],
        digestCanonical
      );
    }
    return buildRecord(
      input,
      'GO',
      evidenceState.gateResults,
      input.approvals,
      [],
      digestCanonical
    );
  } catch {
    return null;
  }
}

export function isSastProductionGoNoGoRecordValid(
  value: unknown,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): value is SastProductionGoNoGoRecord {
  try {
    if (!hasExactKeys(value, [...RECORD_CORE_KEYS, 'recordId', 'recordDigest'])) return false;
    const candidate = value as unknown as SastProductionGoNoGoRecord;
    if (
      !Array.isArray(candidate.gateResults) ||
      !Array.isArray(candidate.approvalRefs) ||
      !Array.isArray(candidate.failureReasons)
    ) {
      return false;
    }
    const gateIds = candidate.gateResults.map((item) => item.gateId);
    const canonicalGateSubset = SAST_PRODUCTION_GO_NO_GO_GATE_IDS.filter(
      (item) => gateIds.includes(item)
    );
    const fullGateSet = arraysEqual(gateIds, SAST_PRODUCTION_GO_NO_GO_GATE_IDS);
    const expectedGateResultSetDigest = candidate.gateResults.length === 0
      ? null
      : digestCanonical(
          stableJson(
            candidate.gateResults.map((item) => ({
              gateId: item.gateId,
              gateResultDigest: item.gateResultDigest
            }))
          )
        );
    if (
      candidate.version !== SAST_PRODUCTION_GO_NO_GO_RECORD_VERSION ||
      !SAST_PRODUCTION_GO_NO_GO_STATUSES.includes(candidate.status) ||
      !isReference(candidate.manifestId) ||
      !isDigest(candidate.manifestDigest) ||
      candidate.expectedGateCount !== SAST_PRODUCTION_GO_NO_GO_GATE_IDS.length ||
      candidate.gateResults.length > SAST_PRODUCTION_GO_NO_GO_GATE_IDS.length ||
      new Set(gateIds).size !== gateIds.length ||
      !arraysEqual(gateIds, canonicalGateSubset) ||
      candidate.evaluatedGateCount !== candidate.gateResults.length ||
      candidate.passedGateCount !== candidate.gateResults.filter((item) => item.outcome === 'PASSED').length ||
      candidate.failedGateCount !== candidate.gateResults.filter((item) => item.outcome === 'FAILED').length ||
      candidate.notApplicableGateCount !== candidate.gateResults.filter((item) => item.outcome === 'NOT_APPLICABLE').length ||
      candidate.gateResultSetDigest !== expectedGateResultSetDigest ||
      !candidate.approvalRefs.every(isDigestBoundReference) ||
      new Set(candidate.approvalRefs).size !== candidate.approvalRefs.length ||
      (candidate.approvalRefs.length === 0
        ? candidate.approvalSetDigest !== null
        : !isDigest(candidate.approvalSetDigest)) ||
      candidate.failureReasons.length > SAST_PRODUCTION_GO_NO_GO_LIMITS.maximumFailureReasons ||
      new Set(candidate.failureReasons).size !== candidate.failureReasons.length ||
      !candidate.failureReasons.every((item) =>
        SAST_PRODUCTION_GO_NO_GO_FAILURE_REASONS.includes(item)
      ) ||
      !isNullableReference(candidate.entryAttestationId) ||
      !isNullableDigest(candidate.entryAttestationDigest) ||
      (candidate.entryAttestationId === null) !== (candidate.entryAttestationDigest === null) ||
      !isNullableReference(candidate.planId) ||
      !isNullableDigest(candidate.planDigest) ||
      (candidate.planId === null) !== (candidate.planDigest === null) ||
      !isNullableReference(candidate.providerId) ||
      !isNullableReference(candidate.providerAdapterRef) ||
      ![
        candidate.candidateScannerSetDigest,
        candidate.baselineScannerSetDigest,
        candidate.profileSetDigest,
        candidate.t051SnapshotDigest,
        candidate.t051PriorReleaseManifestDigest,
        candidate.t052SnapshotDigest,
        candidate.t054MeasurementsDigest,
        candidate.t055MeasurementsDigest
      ].every(isNullableDigest) ||
      !isNullableDigestBoundReference(candidate.rollbackTargetRef) ||
      !isNullableDigest(candidate.rollbackTargetDigest) ||
      (candidate.rollbackTargetRef === null) !== (candidate.rollbackTargetDigest === null) ||
      (candidate.rollbackTargetRef !== null &&
        !candidate.rollbackTargetRef.endsWith(`/${candidate.rollbackTargetDigest}`)) ||
      !isNullableReference(candidate.killSwitchEvidenceAttestationId) ||
      !isNullableDigest(candidate.killSwitchEvidenceAttestationDigest) ||
      (candidate.killSwitchEvidenceAttestationId === null) !==
        (candidate.killSwitchEvidenceAttestationDigest === null) ||
      !isDigestBoundReference(candidate.deploymentOperationsContractRef) ||
      !isDigest(candidate.deploymentOperationsContractDigest) ||
      !candidate.deploymentOperationsContractRef.endsWith(
        `/${candidate.deploymentOperationsContractDigest}`
      ) ||
      !isNullableDigestBoundReference(candidate.decisionActorRef) ||
      !isIsoInstant(candidate.decidedAt) ||
      candidate.deploymentOperationsEntryAuthorized !== (candidate.status === 'GO') ||
      candidate.findingAuthority !== false ||
      candidate.policyAuthority !== false ||
      candidate.publicationAuthority !== false ||
      candidate.scmMutationAuthority !== false ||
      candidate.aiAuthority !== false ||
      candidate.deploymentAuthority !== false ||
      candidate.kubernetesExecutionAuthority !== false ||
      candidate.productionMutationAuthority !== false ||
      candidate.productionReadinessAuthority !== false
    ) {
      return false;
    }
    const entryBindings = [
      candidate.providerId,
      candidate.providerAdapterRef,
      candidate.candidateScannerSetDigest,
      candidate.baselineScannerSetDigest,
      candidate.profileSetDigest,
      candidate.t051SnapshotDigest,
      candidate.t051PriorReleaseManifestDigest,
      candidate.t052SnapshotDigest,
      candidate.t054MeasurementsDigest,
      candidate.t055MeasurementsDigest
    ];
    if (
      candidate.entryAttestationId === null
        ? entryBindings.some((item) => item !== null)
        : entryBindings.some((item) => item === null)
    ) {
      return false;
    }
    const planBindings = [
      candidate.rollbackTargetRef,
      candidate.rollbackTargetDigest,
      candidate.killSwitchEvidenceAttestationId,
      candidate.killSwitchEvidenceAttestationDigest,
      candidate.decisionActorRef
    ];
    if (
      candidate.planId === null
        ? planBindings.some((item) => item !== null) || candidate.approvalRefs.length > 0
        : planBindings.some((item) => item === null)
    ) {
      return false;
    }
    if (!candidate.gateResults.every((item) => isGateResultValid(item, digestCanonical))) return false;
    if (
      candidate.status === 'GO' &&
      (!fullGateSet ||
        candidate.passedGateCount !== SAST_PRODUCTION_GO_NO_GO_GATE_IDS.length ||
        candidate.failedGateCount !== 0 ||
        candidate.notApplicableGateCount !== 0 ||
        candidate.approvalRefs.length !== SAST_END_TO_END_QUALIFICATION_APPROVAL_ROLES.length ||
        candidate.failureReasons.length !== 0 ||
        candidate.entryAttestationId === null ||
        candidate.planId === null ||
        candidate.providerId === null ||
        candidate.providerAdapterRef === null ||
        candidate.rollbackTargetRef === null ||
        candidate.killSwitchEvidenceAttestationId === null ||
        candidate.decisionActorRef === null)
    ) {
      return false;
    }
    if (
      candidate.status === 'PENDING_FINAL_EVIDENCE' &&
      (candidate.deploymentOperationsEntryAuthorized ||
        candidate.failedGateCount !== 0 ||
        candidate.notApplicableGateCount !== 0 ||
        candidate.failureReasons.length === 0)
    ) {
      return false;
    }
    if (
      candidate.status === 'BLOCKED_T055_QUALIFICATION' &&
      (candidate.gateResults.length !== 0 ||
        candidate.approvalRefs.length !== 0 ||
        !candidate.failureReasons.includes('T055_PREREQUISITE_MISSING'))
    ) {
      return false;
    }
    if (candidate.status === 'NO_GO' && candidate.failureReasons.length === 0) return false;
    const core = pickKeys(candidate, RECORD_CORE_KEYS);
    const expectedDigest = digestCanonical(stableJson(core));
    return (
      candidate.recordDigest === expectedDigest &&
      candidate.recordId === `sast-production-go-no-go-record://${stripDigest(expectedDigest)}`
    );
  } catch {
    return false;
  }
}

export function deriveSastProductionGoNoGoUpstreamObservations(
  t054Result: SastEndToEndQualificationResult,
  t055Result: SastSupplyChainRollbackQualificationResult
): ReadonlyMap<SastProductionGoNoGoGateId, number> | null {
  const t054 = t054Result.measurements;
  const t055 = t055Result.measurements;
  if (!t054 || !t055) return null;
  const maxP95Increase = Math.max(...t054.performanceBuckets.map((item) => item.p95LatencyIncrease));
  return new Map<SastProductionGoNoGoGateId, number>([
    ['T053_ISOLATED_INTEGRATION', t054Result.status === 'PASSED' && t054Result.t053ResultId ? 1 : 0],
    ['ARTIFACT_SIGNATURE_PROVENANCE', t055Result.status === 'PASSED' ? 1 : 0],
    ['SCANNER_PROFILE_COMPATIBILITY', t054Result.status === 'PASSED' ? 1 : 0],
    ['GOLDEN_CORPUS_EXACT', toBasisPoints(t054.goldenCorpusPassRate)],
    ['MUST_DETECT_RECALL', toBasisPoints(t054.mustDetectRecall)],
    ['CRITICAL_HIGH_PRECISION', toBasisPoints(t054.criticalHighPrecision)],
    ['PRIOR_MUST_DETECT_RECALL', toBasisPoints(t054.priorMustDetectRegressionRecall)],
    ['FALSE_POSITIVE_INCREASE', toBasisPoints(t054.falsePositiveIncrease)],
    ['SCANNER_FAILURE_RATE', toBasisPoints(t054.scannerFailureRate)],
    ['P95_LATENCY_REGRESSION', toBasisPoints(maxP95Increase)],
    ['FAST_LANE_ABSOLUTE_P95', t054.fastLaneP95Milliseconds],
    ['DEEP_LANE_ABSOLUTE_P95', t054.deepLaneP95Milliseconds],
    ['FINGERPRINT_CORRELATION', toBasisPoints(t054.fingerprintFixturePassRate)],
    ['EVIDENCE_PRIVACY', toBasisPoints(t054.evidencePrivacyPassRate)],
    ['CAPACITY_RESOURCE_LIMITS', toBasisPoints(t054.capacityPassRate)],
    ['ZERO_CROSS_TENANT_LEAK', t054.zeroToleranceCounts.crossTenantLeakCount],
    ['ZERO_SECRET_LEAK', t054.zeroToleranceCounts.secretLeakCount],
    ['ZERO_SANDBOX_ESCAPE', t054.zeroToleranceCounts.sandboxEscapeCount],
    ['ZERO_STALE_PUBLICATION', t054.zeroToleranceCounts.staleExternalPublicationCount],
    ['ZERO_UNAUTHORIZED_EGRESS', t054.zeroToleranceCounts.unauthorizedEgressCount],
    ['ZERO_MISSING_DESTRUCTION', t054.zeroToleranceCounts.missingDestructionEvidenceCount],
    ['ZERO_EVIDENCE_POLICY_VIOLATION', t054.zeroToleranceCounts.evidencePolicyViolationCount],
    ['ZERO_UNSIGNED_ARTIFACT_EXECUTION', t054.zeroToleranceCounts.unsignedArtifactExecutionCount],
    ['T055_ARTIFACT_DRILLS', t055.artifactSupplyChainDrillCount],
    ['T055_ALLOWLIST_DRILLS', t055.allowlistDrillCount],
    ['T055_DATABASE_DRILLS', t055.databaseDrillCount],
    ['T055_SCHEMA_DRILLS', t055.schemaDrillCount],
    ['T055_ROLLBACK_PHASES', t055.rollbackDrillCount],
    ['T055_PRE_EXECUTION_REJECTIONS', t055.preExecutionRejectionCount],
    ['T055_ARTIFACT_INVOCATIONS', t055.artifactInvocationCount],
    ['T055_CLEANUP_COMPLETION', t055.cleanupCompletedCount],
    ['T055_ZERO_NETWORK_EGRESS', t055.networkEgressCount],
    ['T055_ZERO_PRODUCTION_MUTATION', t055.productionMutationCount],
    ['T055_ZERO_FORBIDDEN_EFFECTS', t055.forbiddenSideEffectCount]
  ]);
}

function isUpstreamBundleValid(
  context: {
    manifest: SastProductionGoNoGoManifest;
    t054Manifest: SastEndToEndQualificationManifest;
    t055Manifest: SastSupplyChainRollbackQualificationManifest;
    upstream: SastProductionGoNoGoUpstreamBundle;
    verifySignature: SastEndToEndQualificationSignatureVerifier;
  },
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): boolean {
  const upstream = context.upstream;
  return (
    context.manifest.t055ManifestId === context.t055Manifest.manifestId &&
    context.manifest.t055ManifestDigest === context.t055Manifest.manifestDigest &&
    isSastEndToEndQualificationResultValid(upstream.t054Result, digestCanonical) &&
    upstream.t054Result.status === 'PASSED' &&
    upstream.t054Result.t055EntryAuthorized === true &&
    isSastEndToEndQualificationDependencySetValid(upstream.t054DependencySet, digestCanonical) &&
    isSastEndToEndQualificationArtifactVerificationSetValid(
      upstream.t054ArtifactVerificationSet,
      upstream.t054DependencySet,
      context.verifySignature,
      digestCanonical
    ) &&
    isSastSupplyChainRollbackQualificationEntryAttestationValid(
      upstream.t055EntryAttestation,
      context.t055Manifest,
      context.t054Manifest,
      upstream.t054Result,
      upstream.t054DependencySet,
      upstream.t054ArtifactVerificationSet,
      upstream.t054Plan,
      context.verifySignature,
      digestCanonical
    ) &&
    isSastSupplyChainRollbackQualificationPlanValid(
      upstream.t055Plan,
      context.t055Manifest,
      context.t054Manifest,
      upstream.t054Result,
      upstream.t054DependencySet,
      upstream.t054ArtifactVerificationSet,
      upstream.t054Plan,
      upstream.t055EntryAttestation,
      context.verifySignature,
      digestCanonical
    ) &&
    isSastSupplyChainRollbackQualificationResultValid(upstream.t055Result, digestCanonical) &&
    upstream.t055Result.status === 'PASSED' &&
    upstream.t055Result.t056EntryAuthorized === true &&
    upstream.t055Result.manifestId === context.t055Manifest.manifestId &&
    upstream.t055Result.manifestDigest === context.t055Manifest.manifestDigest &&
    upstream.t055Result.t054ResultId === upstream.t054Result.resultId &&
    upstream.t055Result.t054ResultDigest === upstream.t054Result.resultDigest &&
    upstream.t055Result.planId === upstream.t055Plan.planId &&
    upstream.t055Result.planDigest === upstream.t055Plan.planDigest
  );
}

function validateEvidenceSet(
  input: Readonly<SastProductionGoNoGoEvaluationInput> & {
    upstream: SastProductionGoNoGoUpstreamBundle;
    entryAttestation: SastProductionGoNoGoEntryAttestation;
  },
  digestCanonical: SastEndToEndQualificationCanonicalDigester
):
  | { status: 'INVALID'; reasons: SastProductionGoNoGoFailureReason[] }
  | {
      status: 'VALID';
      complete: boolean;
      gateResults: SastProductionGoNoGoGateResult[];
      stale: boolean;
      upstreamMismatch: boolean;
      notApplicable: boolean;
    } {
  if (!input.evidenceAttestations.every(isRecord)) {
    return { status: 'INVALID', reasons: ['EVIDENCE_INVALID'] };
  }
  const kinds = input.evidenceAttestations.map((item) => item.evidenceKind);
  const canonicalSubset = SAST_PRODUCTION_GO_NO_GO_EVIDENCE_KINDS.filter(
    (item) => kinds.includes(item)
  );
  if (
    input.evidenceAttestations.length > SAST_PRODUCTION_GO_NO_GO_EVIDENCE_KINDS.length ||
    new Set(kinds).size !== kinds.length ||
    !arraysEqual(kinds, canonicalSubset) ||
    !input.evidenceAttestations.every((item) =>
      isSastProductionGoNoGoEvidenceAttestationValid(
        item,
        input.manifest,
        input.entryAttestation,
        input.verifySignature,
        digestCanonical
      )
    )
  ) {
    return { status: 'INVALID', reasons: ['EVIDENCE_INVALID'] };
  }
  const complete = arraysEqual(kinds, SAST_PRODUCTION_GO_NO_GO_EVIDENCE_KINDS);
  const upstreamValues = deriveSastProductionGoNoGoUpstreamObservations(
    input.upstream.t054Result,
    input.upstream.t055Result
  );
  if (!upstreamValues) return { status: 'INVALID', reasons: ['UPSTREAM_BINDING_INVALID'] };
  const evaluatedAt = Date.parse(input.trustedEvaluatedAt);
  let stale = false;
  let upstreamMismatch = false;
  let notApplicable = false;
  const gateResults: SastProductionGoNoGoGateResult[] = [];
  for (const definition of input.manifest.gates) {
    const attestation = input.evidenceAttestations.find(
      (item) => item.evidenceKind === definition.evidenceKind
    );
    if (!attestation) continue;
    const observation = attestation.observations.find(
      (item) => item.gateId === definition.gateId
    );
    if (!observation) return { status: 'INVALID', reasons: ['EVIDENCE_INVALID'] };
    const observedAt = Date.parse(attestation.observedAt);
    const validUntil = Date.parse(attestation.validUntil);
    if (
      observedAt > evaluatedAt ||
      validUntil < evaluatedAt ||
      evaluatedAt - observedAt >
        SAST_PRODUCTION_GO_NO_GO_LIMITS.maximumEvidenceAgeSeconds * 1_000 ||
      attestation.signatures.some((item) => Date.parse(item.signedAt) > evaluatedAt)
    ) {
      stale = true;
    }
    if (observation.disposition === 'NOT_APPLICABLE') notApplicable = true;
    if (
      definition.evidenceKind === 'UPSTREAM_QUALIFICATION' &&
      observation.observedValue !== upstreamValues.get(definition.gateId)
    ) {
      upstreamMismatch = true;
    }
    const outcome = observation.disposition === 'NOT_APPLICABLE'
      ? 'NOT_APPLICABLE'
      : thresholdPasses(definition, observation.observedValue)
        ? 'PASSED'
        : 'FAILED';
    const core: SastProductionGoNoGoGateResultCore = {
      version: SAST_PRODUCTION_GO_NO_GO_GATE_RESULT_VERSION,
      gateId: definition.gateId,
      outcome,
      observedValue: observation.observedValue,
      thresholdOperator: definition.thresholdOperator,
      thresholdValue: definition.thresholdValue,
      unit: definition.unit,
      evidenceAttestationId: attestation.attestationId,
      evidenceAttestationDigest: attestation.attestationDigest,
      rationaleCode: outcome === 'PASSED'
        ? `${definition.rationaleCode}_SATISFIED`
        : outcome === 'FAILED'
          ? `${definition.rationaleCode}_BREACHED`
          : `${definition.rationaleCode}_NOT_APPLICABLE_PROHIBITED`
    };
    gateResults.push({ ...core, gateResultDigest: digestCanonical(stableJson(core)) });
  }
  return {
    status: 'VALID',
    complete,
    gateResults,
    stale,
    upstreamMismatch,
    notApplicable
  };
}

function validateApprovals(
  approvals: SastEndToEndQualificationSignature[],
  plan: SastProductionGoNoGoPlan,
  trustedEvaluatedAt: string,
  verifySignature: SastEndToEndQualificationSignatureVerifier
): 'VALID' | 'PENDING' | 'INVALID' {
  if (!approvals.every(isRecord)) return 'INVALID';
  const roles = approvals.map((item) => item.role);
  const canonicalSubset = SAST_END_TO_END_QUALIFICATION_APPROVAL_ROLES.filter(
    (item) => roles.includes(item)
  );
  if (
    approvals.length > SAST_END_TO_END_QUALIFICATION_APPROVAL_ROLES.length ||
    new Set(roles).size !== roles.length ||
    !arraysEqual(roles, canonicalSubset) ||
    new Set(approvals.map((item) => item.keyId)).size !== approvals.length
  ) {
    return 'INVALID';
  }
  const plannedAt = Date.parse(plan.decidedAt);
  const evaluatedAt = Date.parse(trustedEvaluatedAt);
  const maximumAge = SAST_PRODUCTION_GO_NO_GO_LIMITS.maximumApprovalAgeSeconds * 1_000;
  if (
    plannedAt > evaluatedAt ||
    evaluatedAt - plannedAt > maximumAge ||
    !approvals.every((item) => {
      const signedAt = Date.parse(item.signedAt);
      return (
        item.payloadDigest === plan.planDigest &&
        signedAt >= plannedAt &&
        signedAt < evaluatedAt &&
        evaluatedAt - signedAt <= maximumAge &&
        verifyQualificationSignature(item, verifySignature)
      );
    })
  ) {
    return 'INVALID';
  }
  return approvals.length === SAST_END_TO_END_QUALIFICATION_APPROVAL_ROLES.length
    ? 'VALID'
    : 'PENDING';
}

function buildRecord(
  input: Readonly<SastProductionGoNoGoEvaluationInput>,
  status: SastProductionGoNoGoStatus,
  gateResults: SastProductionGoNoGoGateResult[],
  approvals: SastEndToEndQualificationSignature[],
  failureReasons: SastProductionGoNoGoFailureReason[],
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): SastProductionGoNoGoRecord {
  const entry = input.entryAttestation;
  const plan = input.plan;
  const approvalRefs = approvals.map((item) => item.keyId);
  const core: SastProductionGoNoGoRecordCore = {
    version: SAST_PRODUCTION_GO_NO_GO_RECORD_VERSION,
    status,
    manifestId: input.manifest.manifestId,
    manifestDigest: input.manifest.manifestDigest,
    entryAttestationId: entry?.attestationId ?? null,
    entryAttestationDigest: entry?.attestationDigest ?? null,
    planId: plan?.planId ?? null,
    planDigest: plan?.planDigest ?? null,
    providerId: entry?.providerId ?? null,
    providerAdapterRef: entry?.providerAdapterRef ?? null,
    candidateScannerSetDigest: entry?.candidateScannerSetDigest ?? null,
    baselineScannerSetDigest: entry?.baselineScannerSetDigest ?? null,
    profileSetDigest: entry?.profileSetDigest ?? null,
    t051SnapshotDigest: entry?.t051SnapshotDigest ?? null,
    t051PriorReleaseManifestDigest: entry?.t051PriorReleaseManifestDigest ?? null,
    t052SnapshotDigest: entry?.t052SnapshotDigest ?? null,
    t054MeasurementsDigest: entry?.t054MeasurementsDigest ?? null,
    t055MeasurementsDigest: entry?.t055MeasurementsDigest ?? null,
    expectedGateCount: input.manifest.requiredGateCount,
    evaluatedGateCount: gateResults.length,
    passedGateCount: gateResults.filter((item) => item.outcome === 'PASSED').length,
    failedGateCount: gateResults.filter((item) => item.outcome === 'FAILED').length,
    notApplicableGateCount: gateResults.filter((item) => item.outcome === 'NOT_APPLICABLE').length,
    gateResults,
    gateResultSetDigest: gateResults.length === 0
      ? null
      : digestCanonical(stableJson(gateResults.map((item) => ({ gateId: item.gateId, gateResultDigest: item.gateResultDigest })))),
    approvalRefs,
    approvalSetDigest: approvals.length === 0
      ? null
      : digestCanonical(stableJson(approvals.map((item) => ({ role: item.role, keyId: item.keyId, payloadDigest: item.payloadDigest, signedAt: item.signedAt })))),
    failureReasons: uniqueOrdered(failureReasons).slice(0, SAST_PRODUCTION_GO_NO_GO_LIMITS.maximumFailureReasons),
    rollbackTargetRef: plan?.rollbackTargetRef ?? null,
    rollbackTargetDigest: plan?.rollbackTargetDigest ?? null,
    killSwitchEvidenceAttestationId: plan?.killSwitchEvidenceAttestationId ?? null,
    killSwitchEvidenceAttestationDigest: plan?.killSwitchEvidenceAttestationDigest ?? null,
    deploymentOperationsContractRef: input.manifest.deploymentOperationsContractRef,
    deploymentOperationsContractDigest: input.manifest.deploymentOperationsContractDigest,
    decisionActorRef: plan?.decisionActorRef ?? null,
    decidedAt: input.trustedEvaluatedAt,
    deploymentOperationsEntryAuthorized: status === 'GO',
    findingAuthority: false,
    policyAuthority: false,
    publicationAuthority: false,
    scmMutationAuthority: false,
    aiAuthority: false,
    deploymentAuthority: false,
    kubernetesExecutionAuthority: false,
    productionMutationAuthority: false,
    productionReadinessAuthority: false
  };
  const recordDigest = digestCanonical(stableJson(core));
  return {
    ...core,
    recordId: `sast-production-go-no-go-record://${stripDigest(recordDigest)}`,
    recordDigest
  };
}

function isEvidenceCoreValid(value: SastProductionGoNoGoEvidenceAttestationCore): boolean {
  return (
    hasExactKeys(value, EVIDENCE_CORE_KEYS) &&
    value.version === SAST_PRODUCTION_GO_NO_GO_EVIDENCE_ATTESTATION_VERSION &&
    SAST_PRODUCTION_GO_NO_GO_EVIDENCE_KINDS.includes(value.evidenceKind) &&
    isReference(value.providerId) &&
    isReference(value.providerAdapterRef) &&
    /^[a-f0-9]{40}$/u.test(value.repositoryCommitSha) &&
    [
      value.manifestDigest,
      value.entryAttestationDigest,
      value.candidateScannerSetDigest,
      value.baselineScannerSetDigest,
      value.profileSetDigest,
      value.t051SnapshotDigest,
      value.t051PriorReleaseManifestDigest,
      value.t052SnapshotDigest,
      value.t054MeasurementsDigest,
      value.t055MeasurementsDigest,
      value.evidenceDigest,
      value.observationSetDigest
    ].every(isDigest) &&
    isDigestBoundReference(value.evidenceRef) &&
    isIsoInstant(value.observedAt) &&
    isIsoInstant(value.validUntil) &&
    Date.parse(value.validUntil) > Date.parse(value.observedAt) &&
    value.observations.length > 0 &&
    value.observations.every((item) => isObservationValid(item)) &&
    value.customerContentObserved === false &&
    value.customerCodeExecuted === false &&
    value.packageInstallObserved === false &&
    value.repositoryBuildObserved === false &&
    value.dynamicTestObserved === false &&
    value.publicInternetEgressObserved === false &&
    value.productionMutationObserved === false &&
    value.kubernetesExecutionObserved === false
  );
}

function isObservationCoreValid(value: SastProductionGoNoGoObservationCore): boolean {
  return (
    hasExactKeys(value, OBSERVATION_CORE_KEYS) &&
    value.version === SAST_PRODUCTION_GO_NO_GO_OBSERVATION_VERSION &&
    SAST_PRODUCTION_GO_NO_GO_GATE_IDS.includes(value.gateId) &&
    SAST_PRODUCTION_GO_NO_GO_OBSERVATION_DISPOSITIONS.includes(value.disposition) &&
    (value.disposition === 'MEASURED'
      ? isSafeInteger(value.observedValue)
      : value.observedValue === null) &&
    SAST_PRODUCTION_GO_NO_GO_UNITS.includes(value.unit) &&
    isDigestBoundReference(value.evidenceRef) &&
    isDigest(value.evidenceDigest)
  );
}

function isObservationValid(value: unknown): value is SastProductionGoNoGoObservation {
  if (!hasExactKeys(value, [...OBSERVATION_CORE_KEYS, 'observationDigest'])) return false;
  const candidate = value as unknown as SastProductionGoNoGoObservation;
  const { observationDigest, ...core } = candidate;
  return isObservationCoreValid(core) && isDigest(observationDigest);
}

function isGateResultValid(
  value: unknown,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): value is SastProductionGoNoGoGateResult {
  if (!hasExactKeys(value, [...GATE_RESULT_CORE_KEYS, 'gateResultDigest'])) return false;
  const candidate = value as unknown as SastProductionGoNoGoGateResult;
  const definition = SAST_PRODUCTION_GO_NO_GO_GATE_CATALOG.find(
    (item) => item.gateId === candidate.gateId
  );
  if (!definition) return false;
  const expectedOutcome = candidate.observedValue === null
    ? 'NOT_APPLICABLE'
    : thresholdPasses(definition, candidate.observedValue)
      ? 'PASSED'
      : 'FAILED';
  const expectedRationale = expectedOutcome === 'PASSED'
    ? `${definition.rationaleCode}_SATISFIED`
    : expectedOutcome === 'FAILED'
      ? `${definition.rationaleCode}_BREACHED`
      : `${definition.rationaleCode}_NOT_APPLICABLE_PROHIBITED`;
  const core = pickKeys(candidate, GATE_RESULT_CORE_KEYS);
  return (
    candidate.version === SAST_PRODUCTION_GO_NO_GO_GATE_RESULT_VERSION &&
    candidate.outcome === expectedOutcome &&
    (isSafeInteger(candidate.observedValue) || candidate.observedValue === null) &&
    candidate.thresholdOperator === definition.thresholdOperator &&
    candidate.thresholdValue === definition.thresholdValue &&
    candidate.unit === definition.unit &&
    isReference(candidate.evidenceAttestationId) &&
    isDigest(candidate.evidenceAttestationDigest) &&
    candidate.rationaleCode === expectedRationale &&
    candidate.gateResultDigest === digestCanonical(stableJson(core))
  );
}

function pickEvidenceInput(candidate: SastProductionGoNoGoEvidenceAttestation) {
  return {
    manifestId: candidate.manifestId,
    manifestDigest: candidate.manifestDigest,
    entryAttestationId: candidate.entryAttestationId,
    entryAttestationDigest: candidate.entryAttestationDigest,
    evidenceKind: candidate.evidenceKind,
    providerId: candidate.providerId,
    providerAdapterRef: candidate.providerAdapterRef,
    repositoryCommitSha: candidate.repositoryCommitSha,
    candidateScannerSetDigest: candidate.candidateScannerSetDigest,
    baselineScannerSetDigest: candidate.baselineScannerSetDigest,
    profileSetDigest: candidate.profileSetDigest,
    t051SnapshotDigest: candidate.t051SnapshotDigest,
    t051PriorReleaseManifestDigest: candidate.t051PriorReleaseManifestDigest,
    t052SnapshotDigest: candidate.t052SnapshotDigest,
    t054MeasurementsDigest: candidate.t054MeasurementsDigest,
    t055MeasurementsDigest: candidate.t055MeasurementsDigest,
    evidenceRef: candidate.evidenceRef,
    evidenceDigest: candidate.evidenceDigest,
    observedAt: candidate.observedAt,
    validUntil: candidate.validUntil,
    externalEvidence: candidate.externalEvidence
  };
}

function pickObservationInput(candidate: SastProductionGoNoGoObservation) {
  return {
    gateId: candidate.gateId,
    disposition: candidate.disposition,
    observedValue: candidate.observedValue,
    unit: candidate.unit,
    evidenceRef: candidate.evidenceRef,
    evidenceDigest: candidate.evidenceDigest
  };
}

function deriveProfileSetDigest(
  manifest: SastEndToEndQualificationManifest,
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): string {
  return digestCanonical(stableJson(manifest.profiles));
}

function deriveRollbackTargetDigest(plan: SastSupplyChainRollbackQualificationPlan): string | null {
  const digests = plan.rollbackLedgerHeadAttestations.map((item) => item.baselineReleaseSetDigest);
  return digests.length > 0 && new Set(digests).size === 1 && isDigest(digests[0]) ? digests[0]! : null;
}

function thresholdPasses(
  definition: SastProductionGoNoGoGateDefinitionInput,
  observedValue: number | null
): boolean {
  if (!isSafeInteger(observedValue)) return false;
  if (definition.thresholdOperator === 'EXACT') return observedValue === definition.thresholdValue;
  if (definition.thresholdOperator === 'AT_LEAST') return observedValue >= definition.thresholdValue;
  return observedValue <= definition.thresholdValue;
}

function isSignatureSetValid(
  signatures: SastEndToEndQualificationSignature[],
  roles: readonly SastEndToEndQualificationSignatureRole[],
  payloadDigest: string,
  verifySignature: SastEndToEndQualificationSignatureVerifier
): boolean {
  return (
    signatures.length === roles.length &&
    arraysEqual(signatures.map((item) => item.role), roles) &&
    new Set(signatures.map((item) => item.keyId)).size === signatures.length &&
    signatures.every((item) =>
      item.payloadDigest === payloadDigest && verifyQualificationSignature(item, verifySignature)
    )
  );
}

function isSignatureFor(
  signature: SastEndToEndQualificationSignature,
  role: SastEndToEndQualificationSignatureRole,
  payloadDigest: string
): boolean {
  return isSastEndToEndQualificationSignatureValid(signature) && signature.role === role && signature.payloadDigest === payloadDigest;
}

function verifyQualificationSignature(
  signature: SastEndToEndQualificationSignature,
  verifySignature: SastEndToEndQualificationSignatureVerifier
): boolean {
  const payload = serializeSastEndToEndQualificationSignaturePayload(signature);
  return payload !== null && verifySignature(signature, payload);
}

function toBasisPoints(value: number): number {
  return Math.round(value * 10_000);
}

function isDigest(value: unknown): value is string {
  return typeof value === 'string' && /^sha256:[a-f0-9]{64}$/u.test(value);
}

function isNullableDigest(value: unknown): value is string | null {
  return value === null || isDigest(value);
}

function stripDigest(value: string): string {
  return value.slice('sha256:'.length);
}

function isReference(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && Buffer.byteLength(value, 'utf8') <= SAST_PRODUCTION_GO_NO_GO_LIMITS.maximumReferenceBytes;
}

function isDigestBoundReference(value: unknown): value is string {
  return isReference(value) && /\/sha256:[a-f0-9]{64}$/u.test(value);
}

function isNullableReference(value: unknown): value is string | null {
  return value === null || isReference(value);
}

function isNullableDigestBoundReference(value: unknown): value is string | null {
  return value === null || isDigestBoundReference(value);
}

function isIsoInstant(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) &&
    Number.isFinite(Date.parse(value)) &&
    new Date(value).toISOString() === value
  );
}

function isSemanticVersion(value: unknown): value is string {
  return typeof value === 'string' && /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u.test(value);
}

function isSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value);
}

function hasExactKeys(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  return isRecord(value) && arraysEqual(Object.keys(value).sort(compareText), [...keys].sort(compareText));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function pickKeys(value: object, keys: readonly string[]): Record<string, unknown> {
  const record = value as Record<string, unknown>;
  return Object.fromEntries(keys.map((key) => [key, record[key]]));
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value).sort(compareText).map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function arraysEqual<T>(left: readonly T[], right: readonly T[]): boolean {
  return left.length === right.length && left.every((item, index) => item === right[index]);
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function uniqueOrdered<T>(items: readonly T[]): T[] {
  return [...new Set(items)];
}
