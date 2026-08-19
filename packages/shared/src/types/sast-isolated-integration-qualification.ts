import { SAST_ARTIFACT_VALIDATION_LIMITS } from './sast-artifact-validation';
import {
  SAST_MULTI_CLASS_QUALIFICATION_EXPECTED_OUTCOMES,
  SAST_MULTI_CLASS_QUALIFICATION_REQUIRED_SCENARIOS,
  isSastMultiClassQualificationFixtureValid,
  isSastMultiClassQualificationSnapshotValid,
  type SastMultiClassQualificationCanonicalDigester,
  type SastMultiClassQualificationCorpusClass,
  type SastMultiClassQualificationExpectedOutcome,
  type SastMultiClassQualificationFixture,
  type SastMultiClassQualificationMaterializationKind,
  type SastMultiClassQualificationScenario,
  type SastMultiClassQualificationSnapshot
} from './sast-multi-class-qualification-corpus';
import {
  SAST_APPROVED_PROFILE_DIGESTS,
  SAST_PROFILE_IDS,
  SAST_SCAN_PROFILES,
  type SastProfileId,
  type SastScannerKind
} from './sast-runtime';

export const SAST_ISOLATED_QUALIFICATION_MANIFEST_VERSION =
  'sast-isolated-integration-qualification-manifest-v1' as const;
export const SAST_ISOLATED_QUALIFICATION_CELL_VERSION =
  'sast-isolated-integration-qualification-cell-v1' as const;
export const SAST_ISOLATED_QUALIFICATION_DEPENDENCY_SET_VERSION =
  'sast-isolated-integration-qualification-dependency-set-v1' as const;
export const SAST_ISOLATED_QUALIFICATION_EXECUTION_PLAN_VERSION =
  'sast-isolated-integration-qualification-plan-v1' as const;
export const SAST_ISOLATED_QUALIFICATION_RESULT_VERSION =
  'sast-isolated-integration-qualification-result-v1' as const;
export const SAST_ISOLATED_QUALIFICATION_SIGNATURE_VERSION =
  'sast-isolated-integration-qualification-signature-v1' as const;
export const SAST_ISOLATED_QUALIFICATION_RECEIPT_VERSION =
  'sast-isolated-integration-qualification-receipt-v1' as const;

export const SAST_ISOLATED_QUALIFICATION_PHASES = [
  'PROVISIONING',
  'MATERIALIZATION',
  'EXECUTION',
  'RESULT_INGRESS',
  'CLEANUP'
] as const;
export type SastIsolatedQualificationPhase =
  (typeof SAST_ISOLATED_QUALIFICATION_PHASES)[number];

export const SAST_ISOLATED_QUALIFICATION_CLEANUP_CONTROLS = [
  'CREDENTIAL_WIPE',
  'PROCESS_TREE_TERMINATED',
  'WRITABLE_VOLUME_DESTROYED',
  'RESULT_INGRESS_CLOSED',
  'MICROVM_TERMINATED',
  'FINAL_AUDIT_COMMITTED'
] as const;
export type SastIsolatedQualificationCleanupControl =
  (typeof SAST_ISOLATED_QUALIFICATION_CLEANUP_CONTROLS)[number];

export const SAST_ISOLATED_QUALIFICATION_ARTIFACT_KINDS = [
  'SCANNER_SET',
  'OPENGREP_IMAGE',
  'TRIVY_IMAGE',
  'SYFT_IMAGE',
  'OPENGREP_WRAPPER',
  'TRIVY_WRAPPER',
  'SYFT_WRAPPER',
  'OPENGREP_RULE_BUNDLE',
  'TRIVY_CHECKS_BUNDLE',
  'TRIVY_DATABASE',
  'RESULT_SCHEMA_BUNDLE',
  'NORMALIZER_BUNDLE',
  'MICROVM_KERNEL',
  'MICROVM_ROOTFS',
  'MATERIALIZER_IMAGE',
  'QUALIFICATION_RUNNER_IMAGE',
  'QUALIFICATION_HARNESS_IMAGE',
  'PROVIDER_POLICY',
  'TRUST_POLICY'
] as const;
export type SastIsolatedQualificationArtifactKind =
  (typeof SAST_ISOLATED_QUALIFICATION_ARTIFACT_KINDS)[number];

export const SAST_ISOLATED_QUALIFICATION_EXECUTION_TARGETS = [
  'ARTIFACT_VALIDATION',
  'REPOSITORY_PREFLIGHT',
  'SCANNER_RUNTIME'
] as const;
export type SastIsolatedQualificationExecutionTarget =
  (typeof SAST_ISOLATED_QUALIFICATION_EXECUTION_TARGETS)[number];

export const SAST_ISOLATED_QUALIFICATION_STATUSES = [
  'PENDING_PROVIDER_EXECUTION',
  'FAILED',
  'PASSED'
] as const;
export type SastIsolatedQualificationStatus =
  (typeof SAST_ISOLATED_QUALIFICATION_STATUSES)[number];

export const SAST_ISOLATED_QUALIFICATION_APPROVAL_ROLES = [
  'SECURITY_ENGINEERING',
  'SCAN_PLATFORM'
] as const;
export type SastIsolatedQualificationApprovalRole =
  (typeof SAST_ISOLATED_QUALIFICATION_APPROVAL_ROLES)[number];

export const SAST_ISOLATED_QUALIFICATION_RECEIPT_SIGNATURE_ROLES = [
  'MICROVM_PROVIDER',
  'QUALIFICATION_RUNTIME'
] as const;
export type SastIsolatedQualificationReceiptSignatureRole =
  (typeof SAST_ISOLATED_QUALIFICATION_RECEIPT_SIGNATURE_ROLES)[number];

export type SastIsolatedQualificationSignatureRole =
  | SastIsolatedQualificationApprovalRole
  | SastIsolatedQualificationReceiptSignatureRole;

export const SAST_ISOLATED_QUALIFICATION_FAILURE_REASONS = [
  'DEPENDENCY_SET_INVALID',
  'EXECUTION_PLAN_INVALID',
  'APPROVAL_SET_INVALID',
  'RECEIPT_INVALID',
  'RECEIPT_SIGNATURE_INVALID',
  'RECEIPT_DUPLICATE',
  'CELL_BINDING_INVALID',
  'ATTEMPT_REUSED',
  'SANDBOX_REUSED',
  'WORKLOAD_REUSED',
  'ATTESTATION_REUSED',
  'PROVIDER_MISMATCH',
  'OUTCOME_MISMATCH',
  'MATERIALIZATION_MISMATCH',
  'EGRESS_VIOLATION',
  'PROHIBITED_EFFECT',
  'CLEANUP_INCOMPLETE',
  'CLEANUP_SLO_EXCEEDED',
  'TIMESTAMP_INVALID',
  'EVIDENCE_STALE'
] as const;
export type SastIsolatedQualificationFailureReason =
  (typeof SAST_ISOLATED_QUALIFICATION_FAILURE_REASONS)[number];

export const SAST_ISOLATED_QUALIFICATION_LIMITS = Object.freeze({
  expectedCaseCount: 41,
  expectedSchemaParserCaseCount: 16,
  expectedMaliciousRepositoryCaseCount: 25,
  expectedProfileCount: 3,
  expectedCellCount: 123,
  cleanupSloSeconds: 60,
  maximumArtifacts: 32,
  maximumReferenceBytes: 2_048,
  maximumIdentifierBytes: 256,
  maximumMaterializedBytes: 2_147_483_649,
  maximumMaterializedEntries: 250_001,
  maximumMaterializedPathDepth: 65,
  maximumSimulatedDurationSeconds: 3_601,
  maximumFailureReasons: 32,
  maximumExecutionWindowSeconds: 86_400,
  maximumEvidenceAgeSeconds: 86_400,
  maximumIdentifierSetSize: 123
});

type Sha256Digest = `sha256:${string}`;
export type SastIsolatedQualificationCanonicalDigester =
  SastMultiClassQualificationCanonicalDigester;

type SastIsolatedQualificationSourceCase = Omit<
  SastMultiClassQualificationSnapshot['cases'][number],
  'corpusClass' | 'materializationKind'
> & {
  corpusClass: Extract<
    SastMultiClassQualificationCorpusClass,
    'SCHEMA_PARSER' | 'MALICIOUS_REPOSITORY'
  >;
  materializationKind: Extract<
    SastMultiClassQualificationMaterializationKind,
    'ARTIFACT_STREAM' | 'REPOSITORY_RECIPE'
  >;
};

export interface SastIsolatedQualificationExpectedMaterializationCore {
  bytes: number;
  entries: number;
  pathDepth: number;
  simulatedDurationSeconds: number;
  jsonDepth: number;
  maximumStringBytes: number;
}

export interface SastIsolatedQualificationExpectedMaterialization
  extends SastIsolatedQualificationExpectedMaterializationCore {
  projectionDigest: Sha256Digest;
}

export type SastIsolatedQualificationMaterializationSelectionSource =
  | 'FIXTURE_PROJECTION'
  | 'CASE_PROFILE_DECLARATION'
  | 'SHARED_VALIDATOR_LIMIT';

export interface SastIsolatedQualificationCellCore {
  version: typeof SAST_ISOLATED_QUALIFICATION_CELL_VERSION;
  ordinal: number;
  cellKey: string;
  sourceSnapshotDigest: Sha256Digest;
  caseId: string;
  caseDigest: Sha256Digest;
  caseKey: string;
  caseRevision: string;
  corpusClass: Extract<
    SastMultiClassQualificationCorpusClass,
    'SCHEMA_PARSER' | 'MALICIOUS_REPOSITORY'
  >;
  scenario: SastMultiClassQualificationScenario;
  fixturePath: string;
  fixtureId: string;
  fixtureDigest: Sha256Digest;
  fixtureBytes: number;
  materializationKind: Extract<
    SastMultiClassQualificationMaterializationKind,
    'ARTIFACT_STREAM' | 'REPOSITORY_RECIPE'
  >;
  materializationInputDigest: Sha256Digest;
  recipeActionDigest: Sha256Digest;
  materializationSelectionSource: SastIsolatedQualificationMaterializationSelectionSource;
  expectedMaterialization: SastIsolatedQualificationExpectedMaterialization;
  profileId: SastProfileId;
  profileDigest: Sha256Digest;
  requiredScanners: SastScannerKind[];
  isolationClass: 'HARDENED' | 'RESTRICTED';
  executionTarget: SastIsolatedQualificationExecutionTarget;
  expectedOutcome: SastMultiClassQualificationExpectedOutcome;
  freshMicroVmRequired: true;
  sandboxReuseAllowed: false;
  scenarioNameBranchingAllowed: false;
  platformOwnedFixtureRequired: true;
  repositoryCredentialMode: 'NOT_ISSUED_PLATFORM_FIXTURE';
  customerContentAccepted: false;
  customerCodeExecutionAllowed: false;
  packageInstallAllowed: false;
  repositoryBuildAllowed: false;
  dynamicTestAllowed: false;
  publicInternetEgressAllowed: false;
  findingAuthority: false;
  policyAuthority: false;
  publicationAuthority: false;
  productionReadinessAuthority: false;
}

export interface SastIsolatedQualificationCell
  extends SastIsolatedQualificationCellCore {
  cellId: string;
  cellDigest: Sha256Digest;
}

export interface SastIsolatedQualificationProfileBinding {
  profileId: SastProfileId;
  profileDigest: Sha256Digest;
}

export interface SastIsolatedQualificationManifestCore {
  version: typeof SAST_ISOLATED_QUALIFICATION_MANIFEST_VERSION;
  revision: string;
  publishedAt: string;
  ownerRef: string;
  sourceCorpusId: string;
  sourceSnapshotDigest: Sha256Digest;
  sourceCorpusRevision: string;
  provisioningContractRef: string;
  provisioningContractDigest: Sha256Digest;
  materializationPolicyRef: string;
  materializationPolicyDigest: Sha256Digest;
  profiles: SastIsolatedQualificationProfileBinding[];
  cells: SastIsolatedQualificationCell[];
  caseCount: 41;
  schemaParserCaseCount: 16;
  maliciousRepositoryCaseCount: 25;
  executionCellCount: 123;
  cellSetDigest: Sha256Digest;
  cleanupSloSeconds: 60;
  providerExecutionStatus: 'PENDING_PROVIDER_EXECUTION';
  oneFreshMicroVmPerCell: true;
  platformOwnedFixturesOnly: true;
  liveProviderEvidencePresent: false;
  customerContentAccepted: false;
  customerCodeExecutionAllowed: false;
  packageInstallAllowed: false;
  repositoryBuildAllowed: false;
  dynamicTestAllowed: false;
  productionReadinessAuthority: false;
  immutable: true;
}

export interface SastIsolatedQualificationManifest
  extends SastIsolatedQualificationManifestCore {
  manifestId: string;
  manifestDigest: Sha256Digest;
}

export interface SastIsolatedQualificationManifestInput {
  revision: string;
  publishedAt: string;
  ownerRef: string;
  sourceSnapshot: SastMultiClassQualificationSnapshot;
  sourceFixtures: readonly SastMultiClassQualificationFixture[];
  provisioningContractRef: string;
  provisioningContractDigest: Sha256Digest;
  materializationPolicyRef: string;
  materializationPolicyDigest: Sha256Digest;
}

export interface SastIsolatedQualificationArtifactBinding {
  kind: SastIsolatedQualificationArtifactKind;
  artifactRef: string;
  artifactDigest: Sha256Digest;
  signatureRef: string;
  provenanceRef: string;
}

export interface SastIsolatedQualificationDependencySetCore {
  version: typeof SAST_ISOLATED_QUALIFICATION_DEPENDENCY_SET_VERSION;
  revision: string;
  providerId: string;
  providerAdapterRef: string;
  validFrom: string;
  validUntil: string;
  artifacts: SastIsolatedQualificationArtifactBinding[];
  executionEnvironment: 'PRODUCTION_EQUIVALENT';
  liveProviderAdapterRequired: true;
  testOnly: false;
  platformManaged: true;
  customerContentAccepted: false;
  publicInternetEgressAllowed: false;
  immutable: true;
}

export interface SastIsolatedQualificationDependencySet
  extends SastIsolatedQualificationDependencySetCore {
  dependencySetId: string;
  dependencySetDigest: Sha256Digest;
}

export interface SastIsolatedQualificationDependencySetInput {
  revision: string;
  providerId: string;
  providerAdapterRef: string;
  validFrom: string;
  validUntil: string;
  artifacts: readonly SastIsolatedQualificationArtifactBinding[];
}

export interface SastIsolatedQualificationExecutionPlanCore {
  version: typeof SAST_ISOLATED_QUALIFICATION_EXECUTION_PLAN_VERSION;
  manifestId: string;
  manifestDigest: Sha256Digest;
  dependencySetId: string;
  dependencySetDigest: Sha256Digest;
  sourceSnapshotDigest: Sha256Digest;
  cellSetDigest: Sha256Digest;
  executionCellCount: 123;
  cleanupSloSeconds: 60;
  requiredApprovalRoles: SastIsolatedQualificationApprovalRole[];
  requiredReceiptSignatureRoles: SastIsolatedQualificationReceiptSignatureRole[];
  executionAuthority: 'DETACHED_DUAL_APPROVAL_REQUIRED';
  oneFreshMicroVmPerCell: true;
  sandboxReuseAllowed: false;
  platformOwnedFixturesOnly: true;
  customerContentAccepted: false;
  customerCodeExecutionAllowed: false;
  packageInstallAllowed: false;
  repositoryBuildAllowed: false;
  dynamicTestAllowed: false;
  publicInternetEgressAllowed: false;
  productionReadinessAuthority: false;
  immutable: true;
}

export interface SastIsolatedQualificationExecutionPlan
  extends SastIsolatedQualificationExecutionPlanCore {
  planId: string;
  planDigest: Sha256Digest;
}

export interface SastIsolatedQualificationSignature {
  version: typeof SAST_ISOLATED_QUALIFICATION_SIGNATURE_VERSION;
  role: SastIsolatedQualificationSignatureRole;
  keyId: string;
  payloadDigest: Sha256Digest;
  signedAt: string;
  algorithm: 'ED25519';
  valueBase64: string;
}

export interface SastIsolatedQualificationPhaseEgressObservation {
  phase: SastIsolatedQualificationPhase;
  publicInternetConnections: number;
  bytesSent: number;
  dnsQueries: number;
  destinations: string[];
}

export interface SastIsolatedQualificationProhibitedEffects {
  customerCodeExecutions: number;
  packageInstalls: number;
  repositoryBuilds: number;
  dynamicTests: number;
  publicInternetConnections: number;
  scmCredentialPersistences: number;
  hostMutations: number;
  unauthorizedResultWrites: number;
}

export interface SastIsolatedQualificationCleanupEvidence {
  control: SastIsolatedQualificationCleanupControl;
  status: 'VERIFIED' | 'FAILED';
  observedAt: string;
  evidenceRef: string;
  evidenceDigest: Sha256Digest;
}

export interface SastIsolatedQualificationReceiptCore {
  version: typeof SAST_ISOLATED_QUALIFICATION_RECEIPT_VERSION;
  planId: string;
  planDigest: Sha256Digest;
  manifestDigest: Sha256Digest;
  dependencySetDigest: Sha256Digest;
  providerId: string;
  cellId: string;
  cellDigest: Sha256Digest;
  caseId: string;
  caseDigest: Sha256Digest;
  fixtureId: string;
  fixtureDigest: Sha256Digest;
  profileId: SastProfileId;
  profileDigest: Sha256Digest;
  attemptId: string;
  sandboxId: string;
  workloadId: string;
  providerAttestationRef: string;
  providerAttestationDigest: Sha256Digest;
  runtimeAttestationRef: string;
  runtimeAttestationDigest: Sha256Digest;
  materializationInputDigest: Sha256Digest;
  recipeActionDigest: Sha256Digest;
  materializationProjectionDigest: Sha256Digest;
  materializationOutputDigest: Sha256Digest;
  materialized: SastIsolatedQualificationExpectedMaterializationCore;
  executionTarget: SastIsolatedQualificationExecutionTarget;
  isolationClass: 'HARDENED' | 'RESTRICTED';
  expectedOutcome: SastMultiClassQualificationExpectedOutcome;
  actualOutcome: SastMultiClassQualificationExpectedOutcome;
  startedAt: string;
  executionCompletedAt: string;
  cleanupStartedAt: string;
  cleanupCompletedAt: string;
  cleanupDurationSeconds: number;
  phaseEgress: SastIsolatedQualificationPhaseEgressObservation[];
  prohibitedEffects: SastIsolatedQualificationProhibitedEffects;
  cleanupEvidence: SastIsolatedQualificationCleanupEvidence[];
  freshMicroVmObserved: boolean;
  sandboxReuseObserved: boolean;
  platformOwnedFixtureObserved: boolean;
  repositoryCredentialIssued: boolean;
  customerContentObserved: boolean;
  findingAuthority: false;
  policyAuthority: false;
  publicationAuthority: false;
  productionReadinessAuthority: false;
  immutable: true;
}

export type SastIsolatedQualificationReceiptInput = Omit<
  SastIsolatedQualificationReceiptCore,
  'version'
>;

export interface SastIsolatedQualificationReceipt
  extends SastIsolatedQualificationReceiptCore {
  receiptId: string;
  receiptDigest: Sha256Digest;
}

export interface SastIsolatedQualificationSignedReceipt {
  receipt: SastIsolatedQualificationReceipt;
  signatures: readonly SastIsolatedQualificationSignature[];
}

export interface SastIsolatedQualificationResultCore {
  version: typeof SAST_ISOLATED_QUALIFICATION_RESULT_VERSION;
  manifestId: string;
  manifestDigest: Sha256Digest;
  dependencySetDigest: Sha256Digest | null;
  planDigest: Sha256Digest | null;
  status: SastIsolatedQualificationStatus;
  expectedCellCount: 123;
  receivedReceiptCount: number;
  validatedReceiptCount: number;
  missingCellCount: number;
  missingCellSetDigest: Sha256Digest;
  failureReasons: SastIsolatedQualificationFailureReason[];
  evaluatedAt: string;
  t053Complete: boolean;
  t054EntryAuthorized: boolean;
  findingAuthority: false;
  policyAuthority: false;
  publicationAuthority: false;
  productionReadinessAuthority: false;
  immutable: true;
}

export interface SastIsolatedQualificationResult
  extends SastIsolatedQualificationResultCore {
  resultId: string;
  resultDigest: Sha256Digest;
}

export type SastIsolatedQualificationSignatureVerifier = (
  signature: Readonly<SastIsolatedQualificationSignature>,
  canonicalPayload: string
) => boolean;

export interface SastIsolatedQualificationEvaluationInput {
  manifest: SastIsolatedQualificationManifest;
  dependencySet: SastIsolatedQualificationDependencySet | null;
  plan: SastIsolatedQualificationExecutionPlan | null;
  approvals: readonly SastIsolatedQualificationSignature[];
  signedReceipts: readonly SastIsolatedQualificationSignedReceipt[];
  evaluatedAt: string;
  verifySignature: SastIsolatedQualificationSignatureVerifier;
}

const MANIFEST_INPUT_KEYS = [
  'revision',
  'publishedAt',
  'ownerRef',
  'sourceSnapshot',
  'sourceFixtures',
  'provisioningContractRef',
  'provisioningContractDigest',
  'materializationPolicyRef',
  'materializationPolicyDigest'
] as const;
const EXPECTED_MATERIALIZATION_CORE_KEYS = [
  'bytes',
  'entries',
  'pathDepth',
  'simulatedDurationSeconds',
  'jsonDepth',
  'maximumStringBytes'
] as const;
const EXPECTED_MATERIALIZATION_KEYS = [
  ...EXPECTED_MATERIALIZATION_CORE_KEYS,
  'projectionDigest'
] as const;
const PROFILE_BINDING_KEYS = ['profileId', 'profileDigest'] as const;
const CELL_CORE_KEYS = [
  'version',
  'ordinal',
  'cellKey',
  'sourceSnapshotDigest',
  'caseId',
  'caseDigest',
  'caseKey',
  'caseRevision',
  'corpusClass',
  'scenario',
  'fixturePath',
  'fixtureId',
  'fixtureDigest',
  'fixtureBytes',
  'materializationKind',
  'materializationInputDigest',
  'recipeActionDigest',
  'materializationSelectionSource',
  'expectedMaterialization',
  'profileId',
  'profileDigest',
  'requiredScanners',
  'isolationClass',
  'executionTarget',
  'expectedOutcome',
  'freshMicroVmRequired',
  'sandboxReuseAllowed',
  'scenarioNameBranchingAllowed',
  'platformOwnedFixtureRequired',
  'repositoryCredentialMode',
  'customerContentAccepted',
  'customerCodeExecutionAllowed',
  'packageInstallAllowed',
  'repositoryBuildAllowed',
  'dynamicTestAllowed',
  'publicInternetEgressAllowed',
  'findingAuthority',
  'policyAuthority',
  'publicationAuthority',
  'productionReadinessAuthority'
] as const;
const CELL_KEYS = ['cellId', 'cellDigest', ...CELL_CORE_KEYS] as const;
const MANIFEST_CORE_KEYS = [
  'version',
  'revision',
  'publishedAt',
  'ownerRef',
  'sourceCorpusId',
  'sourceSnapshotDigest',
  'sourceCorpusRevision',
  'provisioningContractRef',
  'provisioningContractDigest',
  'materializationPolicyRef',
  'materializationPolicyDigest',
  'profiles',
  'cells',
  'caseCount',
  'schemaParserCaseCount',
  'maliciousRepositoryCaseCount',
  'executionCellCount',
  'cellSetDigest',
  'cleanupSloSeconds',
  'providerExecutionStatus',
  'oneFreshMicroVmPerCell',
  'platformOwnedFixturesOnly',
  'liveProviderEvidencePresent',
  'customerContentAccepted',
  'customerCodeExecutionAllowed',
  'packageInstallAllowed',
  'repositoryBuildAllowed',
  'dynamicTestAllowed',
  'productionReadinessAuthority',
  'immutable'
] as const;
const MANIFEST_KEYS = ['manifestId', 'manifestDigest', ...MANIFEST_CORE_KEYS] as const;
const ARTIFACT_KEYS = [
  'kind',
  'artifactRef',
  'artifactDigest',
  'signatureRef',
  'provenanceRef'
] as const;
const DEPENDENCY_SET_INPUT_KEYS = [
  'revision',
  'providerId',
  'providerAdapterRef',
  'validFrom',
  'validUntil',
  'artifacts'
] as const;
const DEPENDENCY_SET_CORE_KEYS = [
  'version',
  ...DEPENDENCY_SET_INPUT_KEYS,
  'executionEnvironment',
  'liveProviderAdapterRequired',
  'testOnly',
  'platformManaged',
  'customerContentAccepted',
  'publicInternetEgressAllowed',
  'immutable'
] as const;
const DEPENDENCY_SET_KEYS = [
  'dependencySetId',
  'dependencySetDigest',
  ...DEPENDENCY_SET_CORE_KEYS
] as const;
const PLAN_CORE_KEYS = [
  'version',
  'manifestId',
  'manifestDigest',
  'dependencySetId',
  'dependencySetDigest',
  'sourceSnapshotDigest',
  'cellSetDigest',
  'executionCellCount',
  'cleanupSloSeconds',
  'requiredApprovalRoles',
  'requiredReceiptSignatureRoles',
  'executionAuthority',
  'oneFreshMicroVmPerCell',
  'sandboxReuseAllowed',
  'platformOwnedFixturesOnly',
  'customerContentAccepted',
  'customerCodeExecutionAllowed',
  'packageInstallAllowed',
  'repositoryBuildAllowed',
  'dynamicTestAllowed',
  'publicInternetEgressAllowed',
  'productionReadinessAuthority',
  'immutable'
] as const;
const PLAN_KEYS = ['planId', 'planDigest', ...PLAN_CORE_KEYS] as const;
const SIGNATURE_KEYS = [
  'version',
  'role',
  'keyId',
  'payloadDigest',
  'signedAt',
  'algorithm',
  'valueBase64'
] as const;
const PHASE_EGRESS_KEYS = [
  'phase',
  'publicInternetConnections',
  'bytesSent',
  'dnsQueries',
  'destinations'
] as const;
const PROHIBITED_EFFECT_KEYS = [
  'customerCodeExecutions',
  'packageInstalls',
  'repositoryBuilds',
  'dynamicTests',
  'publicInternetConnections',
  'scmCredentialPersistences',
  'hostMutations',
  'unauthorizedResultWrites'
] as const;
const CLEANUP_EVIDENCE_KEYS = [
  'control',
  'status',
  'observedAt',
  'evidenceRef',
  'evidenceDigest'
] as const;
const RECEIPT_INPUT_KEYS = [
  'planId',
  'planDigest',
  'manifestDigest',
  'dependencySetDigest',
  'providerId',
  'cellId',
  'cellDigest',
  'caseId',
  'caseDigest',
  'fixtureId',
  'fixtureDigest',
  'profileId',
  'profileDigest',
  'attemptId',
  'sandboxId',
  'workloadId',
  'providerAttestationRef',
  'providerAttestationDigest',
  'runtimeAttestationRef',
  'runtimeAttestationDigest',
  'materializationInputDigest',
  'recipeActionDigest',
  'materializationProjectionDigest',
  'materializationOutputDigest',
  'materialized',
  'executionTarget',
  'isolationClass',
  'expectedOutcome',
  'actualOutcome',
  'startedAt',
  'executionCompletedAt',
  'cleanupStartedAt',
  'cleanupCompletedAt',
  'cleanupDurationSeconds',
  'phaseEgress',
  'prohibitedEffects',
  'cleanupEvidence',
  'freshMicroVmObserved',
  'sandboxReuseObserved',
  'platformOwnedFixtureObserved',
  'repositoryCredentialIssued',
  'customerContentObserved',
  'findingAuthority',
  'policyAuthority',
  'publicationAuthority',
  'productionReadinessAuthority',
  'immutable'
] as const;
const RECEIPT_CORE_KEYS = ['version', ...RECEIPT_INPUT_KEYS] as const;
const RECEIPT_KEYS = ['receiptId', 'receiptDigest', ...RECEIPT_CORE_KEYS] as const;
const SIGNED_RECEIPT_KEYS = ['receipt', 'signatures'] as const;
const RESULT_CORE_KEYS = [
  'version',
  'manifestId',
  'manifestDigest',
  'dependencySetDigest',
  'planDigest',
  'status',
  'expectedCellCount',
  'receivedReceiptCount',
  'validatedReceiptCount',
  'missingCellCount',
  'missingCellSetDigest',
  'failureReasons',
  'evaluatedAt',
  't053Complete',
  't054EntryAuthorized',
  'findingAuthority',
  'policyAuthority',
  'publicationAuthority',
  'productionReadinessAuthority',
  'immutable'
] as const;
const RESULT_KEYS = ['resultId', 'resultDigest', ...RESULT_CORE_KEYS] as const;
const EVALUATION_INPUT_KEYS = [
  'manifest',
  'dependencySet',
  'plan',
  'approvals',
  'signedReceipts',
  'evaluatedAt',
  'verifySignature'
] as const;

const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const SEMANTIC_VERSION_PATTERN =
  /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/u;
const OWNER_REF_PATTERN = /^team:\/\/[a-z0-9][a-z0-9._/-]{0,255}$/u;
const DIGEST_BOUND_REFERENCE_PATTERN =
  /^[a-z][a-z0-9+.-]*:\/\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+\/sha256:[a-f0-9]{64}$/u;
const PROVIDER_ID_PATTERN =
  /^microvm-provider:\/\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{1,512}$/u;
const CELL_ID_PATTERN = /^sast-isolated-qualification-cell:\/\/[a-f0-9]{64}$/u;
const MANIFEST_ID_PATTERN =
  /^sast-isolated-qualification-manifest:\/\/[a-f0-9]{64}$/u;
const DEPENDENCY_SET_ID_PATTERN =
  /^sast-isolated-qualification-dependency-set:\/\/[a-f0-9]{64}$/u;
const PLAN_ID_PATTERN = /^sast-isolated-qualification-plan:\/\/[a-f0-9]{64}$/u;
const RESULT_ID_PATTERN = /^sast-isolated-qualification-result:\/\/[a-f0-9]{64}$/u;
const RECEIPT_ID_PATTERN =
  /^sast-isolated-qualification-receipt:\/\/[a-f0-9]{64}$/u;
const CANONICAL_BASE64_PATTERN =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;
const CELL_KEY_PATTERN =
  /^t053\.(?:schema-parser|malicious-repository)\.[a-z0-9-]+\.(?:java-fast-v1|java-deep-v1|common-deep-v1)$/u;
const STABLE_JSON_INVALID_SENTINEL =
  '"__invalid_sast_isolated_qualification_shape__"';
const STABLE_JSON_MAXIMUM_DEPTH = 64;

export function buildSastIsolatedQualificationManifest(
  input: Readonly<SastIsolatedQualificationManifestInput>,
  digestCanonical: SastIsolatedQualificationCanonicalDigester
): SastIsolatedQualificationManifest | null {
  if (
    !hasExactKeys(input, MANIFEST_INPUT_KEYS) ||
    !isSemanticVersion(input.revision) ||
    !isIsoInstant(input.publishedAt) ||
    !isOwnerRef(input.ownerRef) ||
    !isDigestBoundReference(
      input.provisioningContractRef,
      input.provisioningContractDigest
    ) ||
    !isDigestBoundReference(
      input.materializationPolicyRef,
      input.materializationPolicyDigest
    ) ||
    !isSastMultiClassQualificationSnapshotValid(
      input.sourceSnapshot,
      digestCanonical
    ) ||
    !Array.isArray(input.sourceFixtures) ||
    input.sourceFixtures.length !== input.sourceSnapshot.fixtureCount ||
    input.sourceFixtures.some(
      (fixture) =>
        !isSastMultiClassQualificationFixtureValid(fixture, digestCanonical)
    )
  ) {
    return null;
  }

  const fixtures = new Map<string, SastMultiClassQualificationFixture>();
  for (const fixture of input.sourceFixtures) {
    if (fixtures.has(fixture.fixtureId)) return null;
    fixtures.set(fixture.fixtureId, fixture);
  }
  if (
    input.sourceSnapshot.cases.some((item) => {
      const fixture = fixtures.get(item.fixtureId);
      return (
        !fixture ||
        fixture.fixtureDigest !== item.fixtureDigest ||
        fixture.caseKey !== item.caseKey ||
        fixture.corpusClass !== item.corpusClass ||
        fixture.scenario !== item.scenario ||
        fixture.materializationKind !== item.materializationKind
      );
    })
  ) {
    return null;
  }

  const sourceCases = input.sourceSnapshot.cases
    .filter(
      (item): item is SastIsolatedQualificationSourceCase =>
        item.evidenceStage === 'T053_ISOLATED_INTEGRATION' &&
        (item.corpusClass === 'SCHEMA_PARSER' ||
          item.corpusClass === 'MALICIOUS_REPOSITORY') &&
        (item.materializationKind === 'ARTIFACT_STREAM' ||
          item.materializationKind === 'REPOSITORY_RECIPE')
    )
    .sort((left, right) => compareText(left.caseKey, right.caseKey));
  if (
    sourceCases.length !==
      SAST_ISOLATED_QUALIFICATION_LIMITS.expectedCaseCount ||
    sourceCases.filter((item) => item.corpusClass === 'SCHEMA_PARSER').length !==
      SAST_ISOLATED_QUALIFICATION_LIMITS.expectedSchemaParserCaseCount ||
    sourceCases.filter((item) => item.corpusClass === 'MALICIOUS_REPOSITORY')
      .length !==
      SAST_ISOLATED_QUALIFICATION_LIMITS.expectedMaliciousRepositoryCaseCount ||
    sourceCases.some(
      (item) =>
        (item.corpusClass !== 'SCHEMA_PARSER' &&
          item.corpusClass !== 'MALICIOUS_REPOSITORY') ||
        !arraysEqual(
          SAST_PROFILE_IDS.filter((profileId) => item.profiles.includes(profileId)),
          [...SAST_PROFILE_IDS]
        )
    )
  ) {
    return null;
  }

  const cells: SastIsolatedQualificationCell[] = [];
  for (const item of sourceCases) {
    const fixture = fixtures.get(item.fixtureId);
    if (!fixture) return null;
    for (const profileId of SAST_PROFILE_IDS) {
      const expected = expectedMaterialization(fixture, profileId, digestCanonical);
      if (!expected) return null;
      const core: SastIsolatedQualificationCellCore = {
        version: SAST_ISOLATED_QUALIFICATION_CELL_VERSION,
        ordinal: cells.length + 1,
        cellKey: `${item.caseKey.replace(/^t052\./u, 't053.')}.${slug(profileId)}`,
        sourceSnapshotDigest: input.sourceSnapshot.snapshotDigest,
        caseId: item.caseId,
        caseDigest: item.caseDigest,
        caseKey: item.caseKey,
        caseRevision: item.caseRevision,
        corpusClass: item.corpusClass,
        scenario: item.scenario,
        fixturePath: item.fixturePath,
        fixtureId: item.fixtureId,
        fixtureDigest: item.fixtureDigest,
        fixtureBytes: item.fixtureBytes,
        materializationKind: item.materializationKind,
        materializationInputDigest: digestCanonical(
          stableJson({
            fixtureId: fixture.fixtureId,
            fixtureDigest: fixture.fixtureDigest,
            profileId,
            profileDigest: SAST_APPROVED_PROFILE_DIGESTS[profileId],
            parameters: fixture.parameters,
            segments: fixture.segments,
            steps: fixture.steps,
            expectedMaterialization: expected.materialization
          })
        ),
        recipeActionDigest: digestCanonical(stableJson(fixture.steps)),
        materializationSelectionSource: expected.selectionSource,
        expectedMaterialization: expected.materialization,
        profileId,
        profileDigest: SAST_APPROVED_PROFILE_DIGESTS[profileId],
        requiredScanners: [...SAST_SCAN_PROFILES[profileId].requiredScanners],
        isolationClass:
          item.expectedOutcome === 'RESTRICTED_ESCALATION'
            ? 'RESTRICTED'
            : 'HARDENED',
        executionTarget: expectedExecutionTarget(item),
        expectedOutcome: item.expectedOutcome,
        freshMicroVmRequired: true,
        sandboxReuseAllowed: false,
        scenarioNameBranchingAllowed: false,
        platformOwnedFixtureRequired: true,
        repositoryCredentialMode: 'NOT_ISSUED_PLATFORM_FIXTURE',
        customerContentAccepted: false,
        customerCodeExecutionAllowed: false,
        packageInstallAllowed: false,
        repositoryBuildAllowed: false,
        dynamicTestAllowed: false,
        publicInternetEgressAllowed: false,
        findingAuthority: false,
        policyAuthority: false,
        publicationAuthority: false,
        productionReadinessAuthority: false
      };
      if (
        !isDigest(core.materializationInputDigest) ||
        !isDigest(core.recipeActionDigest) ||
        !isCellCoreValid(core, digestCanonical)
      ) {
        return null;
      }
      const cellDigest = digestCanonical(stableJson(core));
      if (!isDigest(cellDigest)) return null;
      cells.push({
        ...core,
        cellId: `sast-isolated-qualification-cell://${cellDigest.slice('sha256:'.length)}`,
        cellDigest
      });
    }
  }

  const cellSetDigest = digestCanonical(
    stableJson(
      cells.map((cell) => ({
        cellId: cell.cellId,
        cellDigest: cell.cellDigest
      }))
    )
  );
  if (!isDigest(cellSetDigest)) return null;
  const profiles = SAST_PROFILE_IDS.map((profileId) => ({
    profileId,
    profileDigest: SAST_APPROVED_PROFILE_DIGESTS[profileId]
  }));
  const core: SastIsolatedQualificationManifestCore = {
    version: SAST_ISOLATED_QUALIFICATION_MANIFEST_VERSION,
    revision: input.revision,
    publishedAt: input.publishedAt,
    ownerRef: input.ownerRef,
    sourceCorpusId: input.sourceSnapshot.corpusId,
    sourceSnapshotDigest: input.sourceSnapshot.snapshotDigest,
    sourceCorpusRevision: input.sourceSnapshot.revision,
    provisioningContractRef: input.provisioningContractRef,
    provisioningContractDigest: input.provisioningContractDigest,
    materializationPolicyRef: input.materializationPolicyRef,
    materializationPolicyDigest: input.materializationPolicyDigest,
    profiles,
    cells,
    caseCount: 41,
    schemaParserCaseCount: 16,
    maliciousRepositoryCaseCount: 25,
    executionCellCount: 123,
    cellSetDigest,
    cleanupSloSeconds: 60,
    providerExecutionStatus: 'PENDING_PROVIDER_EXECUTION',
    oneFreshMicroVmPerCell: true,
    platformOwnedFixturesOnly: true,
    liveProviderEvidencePresent: false,
    customerContentAccepted: false,
    customerCodeExecutionAllowed: false,
    packageInstallAllowed: false,
    repositoryBuildAllowed: false,
    dynamicTestAllowed: false,
    productionReadinessAuthority: false,
    immutable: true
  };
  if (!isManifestCoreValid(core, digestCanonical)) return null;
  const manifestDigest = digestCanonical(stableJson(core));
  if (!isDigest(manifestDigest)) return null;
  return {
    ...core,
    manifestId: `sast-isolated-qualification-manifest://${manifestDigest.slice('sha256:'.length)}`,
    manifestDigest
  };
}

export function isSastIsolatedQualificationManifestValid(
  value: unknown,
  digestCanonical: SastIsolatedQualificationCanonicalDigester
): value is SastIsolatedQualificationManifest {
  try {
    if (!hasExactKeys(value, MANIFEST_KEYS)) return false;
    const candidate = value as SastIsolatedQualificationManifest;
    if (
      typeof candidate.manifestId !== 'string' ||
      !MANIFEST_ID_PATTERN.test(candidate.manifestId) ||
      !isDigest(candidate.manifestDigest)
    ) {
      return false;
    }
    const core = manifestCore(candidate);
    if (!isManifestCoreValid(core, digestCanonical)) return false;
    const expectedDigest = digestCanonical(stableJson(core));
    return (
      expectedDigest === candidate.manifestDigest &&
      candidate.manifestId ===
        `sast-isolated-qualification-manifest://${expectedDigest.slice('sha256:'.length)}`
    );
  } catch {
    return false;
  }
}

export function buildSastIsolatedQualificationDependencySet(
  input: Readonly<SastIsolatedQualificationDependencySetInput>,
  digestCanonical: SastIsolatedQualificationCanonicalDigester
): SastIsolatedQualificationDependencySet | null {
  if (
    !hasExactKeys(input, DEPENDENCY_SET_INPUT_KEYS) ||
    !isSemanticVersion(input.revision) ||
    typeof input.providerId !== 'string' ||
    !PROVIDER_ID_PATTERN.test(input.providerId) ||
    !isDigestBoundReference(input.providerAdapterRef) ||
    !isIsoInstant(input.validFrom) ||
    !isIsoInstant(input.validUntil) ||
    Date.parse(input.validUntil) <= Date.parse(input.validFrom) ||
    secondsBetween(input.validFrom, input.validUntil) >
      SAST_ISOLATED_QUALIFICATION_LIMITS.maximumExecutionWindowSeconds ||
    !Array.isArray(input.artifacts) ||
    input.artifacts.length !== SAST_ISOLATED_QUALIFICATION_ARTIFACT_KINDS.length ||
    input.artifacts.length > SAST_ISOLATED_QUALIFICATION_LIMITS.maximumArtifacts ||
    input.artifacts.some((item) => !isArtifactBindingValid(item))
  ) {
    return null;
  }
  const byKind = new Map(
    input.artifacts.map((item) => [item.kind, cloneArtifact(item)])
  );
  if (byKind.size !== SAST_ISOLATED_QUALIFICATION_ARTIFACT_KINDS.length) {
    return null;
  }
  const artifacts = SAST_ISOLATED_QUALIFICATION_ARTIFACT_KINDS.map((kind) =>
    byKind.get(kind)
  );
  if (artifacts.some((item) => !item)) return null;
  const core: SastIsolatedQualificationDependencySetCore = {
    version: SAST_ISOLATED_QUALIFICATION_DEPENDENCY_SET_VERSION,
    revision: input.revision,
    providerId: input.providerId,
    providerAdapterRef: input.providerAdapterRef,
    validFrom: input.validFrom,
    validUntil: input.validUntil,
    artifacts: artifacts as SastIsolatedQualificationArtifactBinding[],
    executionEnvironment: 'PRODUCTION_EQUIVALENT',
    liveProviderAdapterRequired: true,
    testOnly: false,
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
      `sast-isolated-qualification-dependency-set://${dependencySetDigest.slice('sha256:'.length)}`,
    dependencySetDigest
  };
}

export function isSastIsolatedQualificationDependencySetValid(
  value: unknown,
  digestCanonical: SastIsolatedQualificationCanonicalDigester
): value is SastIsolatedQualificationDependencySet {
  try {
    if (!hasExactKeys(value, DEPENDENCY_SET_KEYS)) return false;
    const candidate = value as SastIsolatedQualificationDependencySet;
    if (
      typeof candidate.dependencySetId !== 'string' ||
      !DEPENDENCY_SET_ID_PATTERN.test(candidate.dependencySetId) ||
      !isDigest(candidate.dependencySetDigest)
    ) {
      return false;
    }
    const rebuilt = buildSastIsolatedQualificationDependencySet(
      dependencySetInput(candidate),
      digestCanonical
    );
    return rebuilt !== null && stableJson(rebuilt) === stableJson(candidate);
  } catch {
    return false;
  }
}

export function buildSastIsolatedQualificationExecutionPlan(
  input: Readonly<{
    manifest: SastIsolatedQualificationManifest;
    dependencySet: SastIsolatedQualificationDependencySet;
  }>,
  digestCanonical: SastIsolatedQualificationCanonicalDigester
): SastIsolatedQualificationExecutionPlan | null {
  if (
    !hasExactKeys(input, ['manifest', 'dependencySet']) ||
    !isSastIsolatedQualificationManifestValid(input.manifest, digestCanonical) ||
    !isSastIsolatedQualificationDependencySetValid(
      input.dependencySet,
      digestCanonical
    )
  ) {
    return null;
  }
  const provisioning = artifact(
    input.dependencySet,
    'PROVIDER_POLICY'
  );
  const materializer = artifact(
    input.dependencySet,
    'MATERIALIZER_IMAGE'
  );
  if (!provisioning || !materializer) return null;
  const core: SastIsolatedQualificationExecutionPlanCore = {
    version: SAST_ISOLATED_QUALIFICATION_EXECUTION_PLAN_VERSION,
    manifestId: input.manifest.manifestId,
    manifestDigest: input.manifest.manifestDigest,
    dependencySetId: input.dependencySet.dependencySetId,
    dependencySetDigest: input.dependencySet.dependencySetDigest,
    sourceSnapshotDigest: input.manifest.sourceSnapshotDigest,
    cellSetDigest: input.manifest.cellSetDigest,
    executionCellCount: 123,
    cleanupSloSeconds: 60,
    requiredApprovalRoles: [...SAST_ISOLATED_QUALIFICATION_APPROVAL_ROLES],
    requiredReceiptSignatureRoles: [
      ...SAST_ISOLATED_QUALIFICATION_RECEIPT_SIGNATURE_ROLES
    ],
    executionAuthority: 'DETACHED_DUAL_APPROVAL_REQUIRED',
    oneFreshMicroVmPerCell: true,
    sandboxReuseAllowed: false,
    platformOwnedFixturesOnly: true,
    customerContentAccepted: false,
    customerCodeExecutionAllowed: false,
    packageInstallAllowed: false,
    repositoryBuildAllowed: false,
    dynamicTestAllowed: false,
    publicInternetEgressAllowed: false,
    productionReadinessAuthority: false,
    immutable: true
  };
  const planDigest = digestCanonical(stableJson(core));
  if (!isDigest(planDigest)) return null;
  return {
    ...core,
    planId: `sast-isolated-qualification-plan://${planDigest.slice('sha256:'.length)}`,
    planDigest
  };
}

export function isSastIsolatedQualificationExecutionPlanValid(
  value: unknown,
  manifest: SastIsolatedQualificationManifest,
  dependencySet: SastIsolatedQualificationDependencySet,
  digestCanonical: SastIsolatedQualificationCanonicalDigester
): value is SastIsolatedQualificationExecutionPlan {
  try {
    if (!hasExactKeys(value, PLAN_KEYS)) return false;
    const candidate = value as SastIsolatedQualificationExecutionPlan;
    if (
      typeof candidate.planId !== 'string' ||
      !PLAN_ID_PATTERN.test(candidate.planId) ||
      !isDigest(candidate.planDigest)
    ) {
      return false;
    }
    const rebuilt = buildSastIsolatedQualificationExecutionPlan(
      { manifest, dependencySet },
      digestCanonical
    );
    return rebuilt !== null && stableJson(rebuilt) === stableJson(candidate);
  } catch {
    return false;
  }
}

export function buildSastIsolatedQualificationReceipt(
  input: Readonly<SastIsolatedQualificationReceiptInput>,
  digestCanonical: SastIsolatedQualificationCanonicalDigester
): SastIsolatedQualificationReceipt | null {
  if (!hasExactKeys(input, RECEIPT_INPUT_KEYS)) return null;
  const core: SastIsolatedQualificationReceiptCore = {
    version: SAST_ISOLATED_QUALIFICATION_RECEIPT_VERSION,
    ...input,
    materialized: { ...input.materialized },
    phaseEgress: input.phaseEgress.map((item) => ({
      ...item,
      destinations: [...item.destinations]
    })),
    prohibitedEffects: { ...input.prohibitedEffects },
    cleanupEvidence: input.cleanupEvidence.map((item) => ({ ...item }))
  };
  if (!isReceiptCoreValid(core)) return null;
  const receiptDigest = digestCanonical(stableJson(core));
  if (!isDigest(receiptDigest)) return null;
  return {
    ...core,
    receiptId:
      `sast-isolated-qualification-receipt://${receiptDigest.slice('sha256:'.length)}`,
    receiptDigest
  };
}

export function isSastIsolatedQualificationReceiptValid(
  value: unknown,
  digestCanonical: SastIsolatedQualificationCanonicalDigester
): value is SastIsolatedQualificationReceipt {
  try {
    if (!hasExactKeys(value, RECEIPT_KEYS)) return false;
    const candidate = value as SastIsolatedQualificationReceipt;
    if (
      typeof candidate.receiptId !== 'string' ||
      !RECEIPT_ID_PATTERN.test(candidate.receiptId) ||
      !isDigest(candidate.receiptDigest)
    ) {
      return false;
    }
    const core = receiptCore(candidate);
    if (!isReceiptCoreValid(core)) return false;
    const expectedDigest = digestCanonical(stableJson(core));
    return (
      expectedDigest === candidate.receiptDigest &&
      candidate.receiptId ===
        `sast-isolated-qualification-receipt://${expectedDigest.slice('sha256:'.length)}`
    );
  } catch {
    return false;
  }
}

export function serializeSastIsolatedQualificationSignaturePayload(
  signature: Readonly<SastIsolatedQualificationSignature>
): string | null {
  if (!isSastIsolatedQualificationSignatureValid(signature)) return null;
  return `${SAST_ISOLATED_QUALIFICATION_SIGNATURE_VERSION}\n${stableJson({
    role: signature.role,
    keyId: signature.keyId,
    payloadDigest: signature.payloadDigest,
    signedAt: signature.signedAt,
    algorithm: signature.algorithm
  })}`;
}

export function isSastIsolatedQualificationSignatureValid(
  value: unknown
): value is SastIsolatedQualificationSignature {
  if (!hasExactKeys(value, SIGNATURE_KEYS)) return false;
  const candidate = value as SastIsolatedQualificationSignature;
  return (
    candidate.version === SAST_ISOLATED_QUALIFICATION_SIGNATURE_VERSION &&
    [
      ...SAST_ISOLATED_QUALIFICATION_APPROVAL_ROLES,
      ...SAST_ISOLATED_QUALIFICATION_RECEIPT_SIGNATURE_ROLES
    ].includes(candidate.role) &&
    typeof candidate.keyId === 'string' &&
    candidate.keyId.startsWith('qualification-key://') &&
    isDigestBoundReference(candidate.keyId) &&
    isDigest(candidate.payloadDigest) &&
    isIsoInstant(candidate.signedAt) &&
    candidate.algorithm === 'ED25519' &&
    isCanonicalEd25519Signature(candidate.valueBase64)
  );
}

export function evaluateSastIsolatedQualificationEvidence(
  input: Readonly<SastIsolatedQualificationEvaluationInput>,
  digestCanonical: SastIsolatedQualificationCanonicalDigester
): SastIsolatedQualificationResult | null {
  try {
    if (
      !hasExactKeys(input, EVALUATION_INPUT_KEYS) ||
      !isSastIsolatedQualificationManifestValid(input.manifest, digestCanonical) ||
      !Array.isArray(input.approvals) ||
      !Array.isArray(input.signedReceipts) ||
      !isIsoInstant(input.evaluatedAt) ||
      typeof input.verifySignature !== 'function'
    ) {
      return null;
    }

    let status: SastIsolatedQualificationStatus = 'PENDING_PROVIDER_EXECUTION';
    const failureReasons: SastIsolatedQualificationFailureReason[] = [];
    let dependencySetDigest: Sha256Digest | null = null;
    let planDigest: Sha256Digest | null = null;
    const validatedCellIds: string[] = [];
    const seenReceiptIds = new Set<string>();
    const seenReceiptDigests = new Set<string>();
    const seenCellIds = new Set<string>();
    const seenAttemptIds = new Set<string>();
    const seenSandboxIds = new Set<string>();
    const seenWorkloadIds = new Set<string>();
    const seenAttestations = new Set<string>();

    if (input.dependencySet === null || input.plan === null) {
      if (input.dependencySet !== null) failureReasons.push('EXECUTION_PLAN_INVALID');
      if (input.plan !== null) failureReasons.push('DEPENDENCY_SET_INVALID');
      if (input.approvals.length > 0) failureReasons.push('APPROVAL_SET_INVALID');
      if (input.signedReceipts.length > 0) failureReasons.push('RECEIPT_INVALID');
    } else {
      dependencySetDigest = input.dependencySet.dependencySetDigest;
      planDigest = input.plan.planDigest;
      const dependencyValid = isSastIsolatedQualificationDependencySetValid(
        input.dependencySet,
        digestCanonical
      );
      const planValid =
        dependencyValid &&
        isSastIsolatedQualificationExecutionPlanValid(
          input.plan,
          input.manifest,
          input.dependencySet,
          digestCanonical
        );
      if (!dependencyValid) failureReasons.push('DEPENDENCY_SET_INVALID');
      if (!planValid) failureReasons.push('EXECUTION_PLAN_INVALID');

      const evaluatedAtMs = Date.parse(input.evaluatedAt);
      const validFromMs = Date.parse(input.dependencySet.validFrom);
      const validUntilMs = Date.parse(input.dependencySet.validUntil);
      if (evaluatedAtMs < validFromMs) failureReasons.push('TIMESTAMP_INVALID');
      if (evaluatedAtMs > validUntilMs) failureReasons.push('EVIDENCE_STALE');

      const approvalRequired =
        input.approvals.length > 0 || input.signedReceipts.length > 0;
      const approvalsValid =
        approvalRequired &&
        isSignatureSetValid(
          input.approvals,
          SAST_ISOLATED_QUALIFICATION_APPROVAL_ROLES,
          input.plan.planDigest,
          input.dependencySet.validFrom,
          input.evaluatedAt,
          input.verifySignature
        );
      if (approvalRequired && !approvalsValid) {
        failureReasons.push('APPROVAL_SET_INVALID');
      }

      if (
        input.signedReceipts.length >
        SAST_ISOLATED_QUALIFICATION_LIMITS.maximumIdentifierSetSize
      ) {
        failureReasons.push('RECEIPT_DUPLICATE');
      }

      for (const signedReceipt of input.signedReceipts.slice(
        0,
        SAST_ISOLATED_QUALIFICATION_LIMITS.maximumIdentifierSetSize
      )) {
        const failureCountBeforeReceipt = failureReasons.length;
        if (!hasExactKeys(signedReceipt, SIGNED_RECEIPT_KEYS)) {
          failureReasons.push('RECEIPT_INVALID');
          continue;
        }
        const receipt = signedReceipt.receipt;
        if (!isSastIsolatedQualificationReceiptValid(receipt, digestCanonical)) {
          failureReasons.push('RECEIPT_INVALID');
          continue;
        }
        const cell = input.manifest.cells.find((item) => item.cellId === receipt.cellId);
        if (!cell || !isReceiptBoundToCell(receipt, cell, input.plan, input.dependencySet)) {
          failureReasons.push('CELL_BINDING_INVALID');
        }
        if (receipt.providerId !== input.dependencySet.providerId) {
          failureReasons.push('PROVIDER_MISMATCH');
        }
        if (
          !isSignatureSetValid(
            signedReceipt.signatures,
            SAST_ISOLATED_QUALIFICATION_RECEIPT_SIGNATURE_ROLES,
            receipt.receiptDigest,
            receipt.cleanupCompletedAt,
            input.evaluatedAt,
            input.verifySignature
          )
        ) {
          failureReasons.push('RECEIPT_SIGNATURE_INVALID');
        }

        if (
          seenReceiptIds.has(receipt.receiptId) ||
          seenReceiptDigests.has(receipt.receiptDigest) ||
          seenCellIds.has(receipt.cellId)
        ) {
          failureReasons.push('RECEIPT_DUPLICATE');
        }
        if (seenAttemptIds.has(receipt.attemptId)) failureReasons.push('ATTEMPT_REUSED');
        if (seenSandboxIds.has(receipt.sandboxId)) failureReasons.push('SANDBOX_REUSED');
        if (seenWorkloadIds.has(receipt.workloadId)) failureReasons.push('WORKLOAD_REUSED');
        if (
          seenAttestations.has(receipt.providerAttestationRef) ||
          seenAttestations.has(receipt.runtimeAttestationRef)
        ) {
          failureReasons.push('ATTESTATION_REUSED');
        }
        seenReceiptIds.add(receipt.receiptId);
        seenReceiptDigests.add(receipt.receiptDigest);
        seenCellIds.add(receipt.cellId);
        seenAttemptIds.add(receipt.attemptId);
        seenSandboxIds.add(receipt.sandboxId);
        seenWorkloadIds.add(receipt.workloadId);
        seenAttestations.add(receipt.providerAttestationRef);
        seenAttestations.add(receipt.runtimeAttestationRef);

        const receiptFailures = receiptFailureReasons(
          receipt,
          cell ?? null,
          input.dependencySet,
          input.evaluatedAt
        );
        failureReasons.push(...receiptFailures);
        if (
          dependencyValid &&
          planValid &&
          approvalsValid &&
          cell &&
          receiptFailures.length === 0 &&
          failureReasons.length === failureCountBeforeReceipt
        ) {
          validatedCellIds.push(cell.cellId);
        }
      }
    }

    const validatedReceiptCount = validatedCellIds.length;
    const receivedReceiptCount = input.signedReceipts.length;
    const missingCellCount = Math.max(
      0,
      input.manifest.executionCellCount - validatedReceiptCount
    );
    const canonicalFailures = canonicalFailureReasons(failureReasons);
    if (canonicalFailures.length > 0) {
      status = 'FAILED';
    } else if (
      receivedReceiptCount === input.manifest.executionCellCount &&
      validatedReceiptCount === input.manifest.executionCellCount
    ) {
      status = 'PASSED';
    }
    const missingCellSetDigest = digestCanonical(
      stableJson(
        input.manifest.cells
          .filter((cell) => !validatedCellIds.includes(cell.cellId))
          .map((cell) => cell.cellId)
      )
    );
    if (!isDigest(missingCellSetDigest)) return null;
    return buildResult(
      {
        version: SAST_ISOLATED_QUALIFICATION_RESULT_VERSION,
        manifestId: input.manifest.manifestId,
        manifestDigest: input.manifest.manifestDigest,
        dependencySetDigest,
        planDigest,
        status,
        expectedCellCount: 123,
        receivedReceiptCount,
        validatedReceiptCount,
        missingCellCount,
        missingCellSetDigest,
        failureReasons: canonicalFailures,
        evaluatedAt: input.evaluatedAt,
        t053Complete: status === 'PASSED',
        t054EntryAuthorized: status === 'PASSED',
        findingAuthority: false,
        policyAuthority: false,
        publicationAuthority: false,
        productionReadinessAuthority: false,
        immutable: true
      },
      digestCanonical
    );
  } catch {
    return null;
  }
}

function buildResult(
  core: SastIsolatedQualificationResultCore,
  digestCanonical: SastIsolatedQualificationCanonicalDigester
): SastIsolatedQualificationResult | null {
  if (!isResultCoreValid(core)) return null;
  const resultDigest = digestCanonical(stableJson(core));
  if (!isDigest(resultDigest)) return null;
  return {
    ...core,
    resultId: `sast-isolated-qualification-result://${resultDigest.slice('sha256:'.length)}`,
    resultDigest
  };
}

export function isSastIsolatedQualificationResultValid(
  value: unknown,
  digestCanonical: SastIsolatedQualificationCanonicalDigester
): value is SastIsolatedQualificationResult {
  try {
    if (!hasExactKeys(value, RESULT_KEYS)) return false;
    const candidate = value as SastIsolatedQualificationResult;
    if (
      typeof candidate.resultId !== 'string' ||
      !RESULT_ID_PATTERN.test(candidate.resultId) ||
      !isDigest(candidate.resultDigest)
    ) {
      return false;
    }
    const core = resultCore(candidate);
    if (!isResultCoreValid(core)) return false;
    const expectedDigest = digestCanonical(stableJson(core));
    return (
      expectedDigest === candidate.resultDigest &&
      candidate.resultId ===
        `sast-isolated-qualification-result://${expectedDigest.slice('sha256:'.length)}`
    );
  } catch {
    return false;
  }
}

function isResultCoreValid(value: SastIsolatedQualificationResultCore): boolean {
  if (
    !hasExactKeys(value, RESULT_CORE_KEYS) ||
    value.version !== SAST_ISOLATED_QUALIFICATION_RESULT_VERSION ||
    typeof value.manifestId !== 'string' ||
    !MANIFEST_ID_PATTERN.test(value.manifestId) ||
    !isDigest(value.manifestDigest) ||
    !(
      (value.dependencySetDigest === null && value.planDigest === null) ||
      (isDigest(value.dependencySetDigest) && isDigest(value.planDigest))
    ) ||
    !SAST_ISOLATED_QUALIFICATION_STATUSES.includes(value.status) ||
    value.expectedCellCount !== 123 ||
    !isBoundedInteger(value.receivedReceiptCount, 0, Number.MAX_SAFE_INTEGER) ||
    !isBoundedInteger(value.validatedReceiptCount, 0, 123) ||
    !isBoundedInteger(value.missingCellCount, 0, 123) ||
    value.missingCellCount !== 123 - value.validatedReceiptCount ||
    !isDigest(value.missingCellSetDigest) ||
    !Array.isArray(value.failureReasons) ||
    value.failureReasons.length >
      SAST_ISOLATED_QUALIFICATION_LIMITS.maximumFailureReasons ||
    value.failureReasons.some(
      (reason) => !SAST_ISOLATED_QUALIFICATION_FAILURE_REASONS.includes(reason)
    ) ||
    !arraysEqual(value.failureReasons, canonicalFailureReasons(value.failureReasons)) ||
    !isIsoInstant(value.evaluatedAt) ||
    value.findingAuthority !== false ||
    value.policyAuthority !== false ||
    value.publicationAuthority !== false ||
    value.productionReadinessAuthority !== false ||
    value.immutable !== true
  ) {
    return false;
  }
  if (value.status === 'PASSED') {
    return (
      value.receivedReceiptCount === 123 &&
      value.validatedReceiptCount === 123 &&
      value.missingCellCount === 0 &&
      value.failureReasons.length === 0 &&
      value.t053Complete === true &&
      value.t054EntryAuthorized === true
    );
  }
  if (value.status === 'PENDING_PROVIDER_EXECUTION') {
    return (
      value.failureReasons.length === 0 &&
      value.validatedReceiptCount < 123 &&
      value.t053Complete === false &&
      value.t054EntryAuthorized === false
    );
  }
  return (
    value.failureReasons.length > 0 &&
    value.t053Complete === false &&
    value.t054EntryAuthorized === false
  );
}

function expectedMaterialization(
  fixture: SastMultiClassQualificationFixture,
  profileId: SastProfileId,
  digestCanonical: SastIsolatedQualificationCanonicalDigester
): {
  selectionSource: SastIsolatedQualificationMaterializationSelectionSource;
  materialization: SastIsolatedQualificationExpectedMaterialization;
} | null {
  const parameters = parameterMap(fixture);
  if (!parameters) return null;
  const core: SastIsolatedQualificationExpectedMaterializationCore = {
    bytes: fixture.materializedBytes,
    entries: fixture.materializedEntries,
    pathDepth: fixture.materializedPathDepth,
    simulatedDurationSeconds: fixture.simulatedDurationSeconds,
    jsonDepth: 0,
    maximumStringBytes: 0
  };
  let selectionSource: SastIsolatedQualificationMaterializationSelectionSource =
    'FIXTURE_PROJECTION';

  if (parameters.get('PROFILE_LIMIT_MODE') === 'SELECTED_PROFILE_LIMIT_PLUS_ONE') {
    if (
      parameters.get('PROFILE_SELECTION_SOURCE') !== 'CASE_PROFILE' ||
      parameters.get('MATERIALIZED_PROJECTION_MODE') !==
        'MAXIMUM_APPLICABLE_PROFILE_BOUND'
    ) {
      return null;
    }
    const metric = parameters.get('BOUNDARY_METRIC');
    const selected = parameters.get(`${profileId}_LIMIT_PLUS_ONE`);
    if (
      typeof metric !== 'string' ||
      !isResourceLimitMetric(metric) ||
      typeof selected !== 'number' ||
      !Number.isSafeInteger(selected) ||
      selected !== SAST_SCAN_PROFILES[profileId].limits[metric] + 1
    ) {
      return null;
    }
    selectionSource = 'CASE_PROFILE_DECLARATION';
    if (isByteMetric(metric)) core.bytes = selected;
    else if (isEntryMetric(metric)) core.entries = selected;
    else if (metric === 'maxPathDepth') core.pathDepth = selected;
    else if (metric === 'wallClockTimeoutSeconds') {
      core.simulatedDurationSeconds = selected;
    } else {
      return null;
    }

    const segmentOrdinal = parameters.get('PROFILE_BOUND_SEGMENT_ORDINAL');
    if (segmentOrdinal !== undefined) {
      const fixed = parameters.get('PROFILE_BOUND_FIXED_CONTRIBUTION');
      const unit = parameters.get('PROFILE_BOUND_UNIT_CONTRIBUTION');
      const materializationMetric = parameters.get(
        'PROFILE_BOUND_MATERIALIZATION_METRIC'
      );
      if (
        !Number.isSafeInteger(segmentOrdinal) ||
        typeof fixed !== 'number' ||
        !Number.isSafeInteger(fixed) ||
        typeof unit !== 'number' ||
        !Number.isSafeInteger(unit) ||
        unit <= 0 ||
        parameters.get('PROFILE_BOUND_REPEAT_FORMULA') !==
          'SELECTED_LIMIT_PLUS_ONE_MINUS_FIXED_CONTRIBUTION'
      ) {
        return null;
      }
      const segment = fixture.segments.find(
        (candidate) => candidate.ordinal === segmentOrdinal
      );
      const selectedRepeat = (selected - fixed) / unit;
      if (!segment || !Number.isSafeInteger(selectedRepeat) || selectedRepeat < 1) {
        return null;
      }
      if (materializationMetric === 'MATERIALIZED_BYTES') {
        core.bytes = fixture.segments.reduce(
          (total, candidate) =>
            total +
            decodedBase64Bytes(candidate.valueBase64) *
              (candidate.ordinal === segmentOrdinal
                ? selectedRepeat
                : candidate.repeat),
          0
        );
      } else if (materializationMetric !== 'MATERIALIZED_ENTRIES') {
        return null;
      }
    }
  } else if (
    parameters.get('BOUNDARY_SOURCE') === 'SAST_ARTIFACT_VALIDATION_LIMITS'
  ) {
    const metric = parameters.get('BOUNDARY_METRIC');
    const limit = parameters.get('BOUNDARY_LIMIT');
    const limitPlusOne = parameters.get('BOUNDARY_LIMIT_PLUS_ONE');
    if (
      typeof metric !== 'string' ||
      typeof limit !== 'number' ||
      typeof limitPlusOne !== 'number' ||
      limitPlusOne !== limit + 1
    ) {
      return null;
    }
    if (metric === 'maximumJsonDepth') {
      if (limit !== SAST_ARTIFACT_VALIDATION_LIMITS.maximumJsonDepth) return null;
      core.jsonDepth = limitPlusOne;
    } else if (metric === 'maximumStringBytes') {
      if (limit !== SAST_ARTIFACT_VALIDATION_LIMITS.maximumStringBytes) return null;
      core.maximumStringBytes = limitPlusOne;
    } else {
      return null;
    }
    selectionSource = 'SHARED_VALIDATOR_LIMIT';
  }

  if (!isExpectedMaterializationCoreValid(core)) return null;
  const projectionDigest = digestCanonical(stableJson(core));
  if (!isDigest(projectionDigest)) return null;
  return {
    selectionSource,
    materialization: { ...core, projectionDigest }
  };
}

function isManifestCoreValid(
  value: SastIsolatedQualificationManifestCore,
  digestCanonical: SastIsolatedQualificationCanonicalDigester
): boolean {
  if (
    !hasExactKeys(value, MANIFEST_CORE_KEYS) ||
    value.version !== SAST_ISOLATED_QUALIFICATION_MANIFEST_VERSION ||
    !isSemanticVersion(value.revision) ||
    !isIsoInstant(value.publishedAt) ||
    !isOwnerRef(value.ownerRef) ||
    typeof value.sourceCorpusId !== 'string' ||
    !/^sast-multi-class-qualification-corpus:\/\/[a-f0-9]{64}$/u.test(
      value.sourceCorpusId
    ) ||
    !isDigest(value.sourceSnapshotDigest) ||
    !isSemanticVersion(value.sourceCorpusRevision) ||
    !isDigestBoundReference(
      value.provisioningContractRef,
      value.provisioningContractDigest
    ) ||
    !isDigestBoundReference(
      value.materializationPolicyRef,
      value.materializationPolicyDigest
    ) ||
    !Array.isArray(value.profiles) ||
    !Array.isArray(value.cells) ||
    value.caseCount !== 41 ||
    value.schemaParserCaseCount !== 16 ||
    value.maliciousRepositoryCaseCount !== 25 ||
    value.executionCellCount !== 123 ||
    value.cells.length !== 123 ||
    value.cleanupSloSeconds !== 60 ||
    value.providerExecutionStatus !== 'PENDING_PROVIDER_EXECUTION' ||
    value.oneFreshMicroVmPerCell !== true ||
    value.platformOwnedFixturesOnly !== true ||
    value.liveProviderEvidencePresent !== false ||
    value.customerContentAccepted !== false ||
    value.customerCodeExecutionAllowed !== false ||
    value.packageInstallAllowed !== false ||
    value.repositoryBuildAllowed !== false ||
    value.dynamicTestAllowed !== false ||
    value.productionReadinessAuthority !== false ||
    value.immutable !== true
  ) {
    return false;
  }
  if (
    !arraysEqual(
      value.profiles.map((item) => item.profileId),
      [...SAST_PROFILE_IDS]
    ) ||
    value.profiles.some(
      (item) =>
        !hasExactKeys(item, PROFILE_BINDING_KEYS) ||
        !SAST_PROFILE_IDS.includes(item.profileId) ||
        item.profileDigest !== SAST_APPROVED_PROFILE_DIGESTS[item.profileId]
    ) ||
    value.cells.some((cell) => !isCellValid(cell, digestCanonical)) ||
    !arraysEqual(
      value.cells.map((cell) => cell.ordinal),
      Array.from({ length: 123 }, (_, index) => index + 1)
    ) ||
    !isCanonicalCellOrder(value.cells) ||
    !unique(value.cells.map((cell) => cell.cellKey)) ||
    !unique(value.cells.map((cell) => cell.cellId)) ||
    !unique(value.cells.map((cell) => cell.cellDigest)) ||
    value.cells.some(
      (cell) => cell.sourceSnapshotDigest !== value.sourceSnapshotDigest
    )
  ) {
    return false;
  }
  const caseIds = [...new Set(value.cells.map((cell) => cell.caseId))];
  if (
    caseIds.length !== 41 ||
    caseIds.some((caseId) => {
      const cells = value.cells.filter((cell) => cell.caseId === caseId);
      return (
        cells.length !== 3 ||
        !arraysEqual(
          cells.map((cell) => cell.profileId),
          [...SAST_PROFILE_IDS]
        )
      );
    })
  ) {
    return false;
  }
  const expectedCellSetDigest = digestCanonical(
    stableJson(
      value.cells.map((cell) => ({
        cellId: cell.cellId,
        cellDigest: cell.cellDigest
      }))
    )
  );
  return isDigest(value.cellSetDigest) && value.cellSetDigest === expectedCellSetDigest;
}

function isCellValid(
  value: unknown,
  digestCanonical: SastIsolatedQualificationCanonicalDigester
): value is SastIsolatedQualificationCell {
  if (!hasExactKeys(value, CELL_KEYS)) return false;
  const candidate = value as SastIsolatedQualificationCell;
  if (
    typeof candidate.cellId !== 'string' ||
    !CELL_ID_PATTERN.test(candidate.cellId) ||
    !isDigest(candidate.cellDigest)
  ) {
    return false;
  }
  const core = cellCore(candidate);
  if (!isCellCoreValid(core, digestCanonical)) return false;
  const expectedDigest = digestCanonical(stableJson(core));
  return (
    candidate.cellDigest === expectedDigest &&
    candidate.cellId ===
      `sast-isolated-qualification-cell://${expectedDigest.slice('sha256:'.length)}`
  );
}

function isCellCoreValid(
  value: SastIsolatedQualificationCellCore,
  digestCanonical: SastIsolatedQualificationCanonicalDigester
): boolean {
  if (
    !hasExactKeys(value, CELL_CORE_KEYS) ||
    value.version !== SAST_ISOLATED_QUALIFICATION_CELL_VERSION ||
    !Number.isSafeInteger(value.ordinal) ||
    value.ordinal < 1 ||
    value.ordinal > 123 ||
    typeof value.cellKey !== 'string' ||
    !CELL_KEY_PATTERN.test(value.cellKey) ||
    !isDigest(value.sourceSnapshotDigest) ||
    typeof value.caseId !== 'string' ||
    !/^sast-multi-class-qualification-case:\/\/[a-f0-9]{64}$/u.test(value.caseId) ||
    !isDigest(value.caseDigest) ||
    typeof value.caseKey !== 'string' ||
    !/^t052\.(?:schema-parser|malicious-repository)\.[a-z0-9-]+$/u.test(
      value.caseKey
    ) ||
    !isSemanticVersion(value.caseRevision) ||
    (value.corpusClass !== 'SCHEMA_PARSER' &&
      value.corpusClass !== 'MALICIOUS_REPOSITORY') ||
    typeof value.fixturePath !== 'string' ||
    !/^fixtures\/(?:schema-parser|malicious-repository)\/[a-z0-9-]+\.fixture\.json$/u.test(
      value.fixturePath
    ) ||
    typeof value.fixtureId !== 'string' ||
    !/^sast-multi-class-qualification-fixture:\/\/[a-f0-9]{64}$/u.test(
      value.fixtureId
    ) ||
    !isDigest(value.fixtureDigest) ||
    !Number.isSafeInteger(value.fixtureBytes) ||
    value.fixtureBytes < 1 ||
    (value.materializationKind !== 'ARTIFACT_STREAM' &&
      value.materializationKind !== 'REPOSITORY_RECIPE') ||
    !isDigest(value.materializationInputDigest) ||
    !isDigest(value.recipeActionDigest) ||
    ![
      'FIXTURE_PROJECTION',
      'CASE_PROFILE_DECLARATION',
      'SHARED_VALIDATOR_LIMIT'
    ].includes(value.materializationSelectionSource) ||
    !isExpectedMaterializationValid(
      value.expectedMaterialization,
      digestCanonical
    ) ||
    !SAST_PROFILE_IDS.includes(value.profileId) ||
    value.profileDigest !== SAST_APPROVED_PROFILE_DIGESTS[value.profileId] ||
    !Array.isArray(value.requiredScanners) ||
    !arraysEqual(
      value.requiredScanners,
      [...SAST_SCAN_PROFILES[value.profileId].requiredScanners]
    ) ||
    (value.isolationClass !== 'HARDENED' && value.isolationClass !== 'RESTRICTED') ||
    !SAST_ISOLATED_QUALIFICATION_EXECUTION_TARGETS.includes(
      value.executionTarget
    ) ||
    !SAST_MULTI_CLASS_QUALIFICATION_EXPECTED_OUTCOMES.includes(
      value.expectedOutcome
    ) ||
    !isScenarioForCorpusClass(value.corpusClass, value.scenario) ||
    value.executionTarget !== expectedExecutionTarget(value) ||
    value.isolationClass !==
      (value.expectedOutcome === 'RESTRICTED_ESCALATION'
        ? 'RESTRICTED'
        : 'HARDENED') ||
    value.freshMicroVmRequired !== true ||
    value.sandboxReuseAllowed !== false ||
    value.scenarioNameBranchingAllowed !== false ||
    value.platformOwnedFixtureRequired !== true ||
    value.repositoryCredentialMode !== 'NOT_ISSUED_PLATFORM_FIXTURE' ||
    value.customerContentAccepted !== false ||
    value.customerCodeExecutionAllowed !== false ||
    value.packageInstallAllowed !== false ||
    value.repositoryBuildAllowed !== false ||
    value.dynamicTestAllowed !== false ||
    value.publicInternetEgressAllowed !== false ||
    value.findingAuthority !== false ||
    value.policyAuthority !== false ||
    value.publicationAuthority !== false ||
    value.productionReadinessAuthority !== false
  ) {
    return false;
  }
  return value.cellKey === `${value.caseKey.replace(/^t052\./u, 't053.')}.${slug(value.profileId)}`;
}

function isExpectedMaterializationValid(
  value: unknown,
  digestCanonical: SastIsolatedQualificationCanonicalDigester
): value is SastIsolatedQualificationExpectedMaterialization {
  if (!hasExactKeys(value, EXPECTED_MATERIALIZATION_KEYS)) return false;
  const candidate = value as SastIsolatedQualificationExpectedMaterialization;
  if (!isDigest(candidate.projectionDigest)) return false;
  const core = expectedMaterializationCore(candidate);
  return (
    isExpectedMaterializationCoreValid(core) &&
    candidate.projectionDigest === digestCanonical(stableJson(core))
  );
}

function isExpectedMaterializationCoreValid(
  value: SastIsolatedQualificationExpectedMaterializationCore
): boolean {
  return (
    hasExactKeys(value, EXPECTED_MATERIALIZATION_CORE_KEYS) &&
    isBoundedInteger(
      value.bytes,
      0,
      SAST_ISOLATED_QUALIFICATION_LIMITS.maximumMaterializedBytes
    ) &&
    isBoundedInteger(
      value.entries,
      0,
      SAST_ISOLATED_QUALIFICATION_LIMITS.maximumMaterializedEntries
    ) &&
    isBoundedInteger(
      value.pathDepth,
      0,
      SAST_ISOLATED_QUALIFICATION_LIMITS.maximumMaterializedPathDepth
    ) &&
    isBoundedInteger(
      value.simulatedDurationSeconds,
      0,
      SAST_ISOLATED_QUALIFICATION_LIMITS.maximumSimulatedDurationSeconds
    ) &&
    isBoundedInteger(
      value.jsonDepth,
      0,
      SAST_ARTIFACT_VALIDATION_LIMITS.maximumJsonDepth + 1
    ) &&
    isBoundedInteger(
      value.maximumStringBytes,
      0,
      SAST_ARTIFACT_VALIDATION_LIMITS.maximumStringBytes + 1
    )
  );
}

function isReceiptCoreValid(value: SastIsolatedQualificationReceiptCore): boolean {
  if (
    !hasExactKeys(value, RECEIPT_CORE_KEYS) ||
    value.version !== SAST_ISOLATED_QUALIFICATION_RECEIPT_VERSION ||
    typeof value.planId !== 'string' ||
    !PLAN_ID_PATTERN.test(value.planId) ||
    !isDigest(value.planDigest) ||
    !isDigest(value.manifestDigest) ||
    !isDigest(value.dependencySetDigest) ||
    typeof value.providerId !== 'string' ||
    !PROVIDER_ID_PATTERN.test(value.providerId) ||
    typeof value.cellId !== 'string' ||
    !CELL_ID_PATTERN.test(value.cellId) ||
    !isDigest(value.cellDigest) ||
    typeof value.caseId !== 'string' ||
    !/^sast-multi-class-qualification-case:\/\/[a-f0-9]{64}$/u.test(value.caseId) ||
    !isDigest(value.caseDigest) ||
    typeof value.fixtureId !== 'string' ||
    !/^sast-multi-class-qualification-fixture:\/\/[a-f0-9]{64}$/u.test(
      value.fixtureId
    ) ||
    !isDigest(value.fixtureDigest) ||
    !SAST_PROFILE_IDS.includes(value.profileId) ||
    value.profileDigest !== SAST_APPROVED_PROFILE_DIGESTS[value.profileId] ||
    !isQualificationIdentity(value.attemptId, 'qualification-attempt://') ||
    !isQualificationIdentity(value.sandboxId, 'qualification-sandbox://') ||
    !isQualificationIdentity(value.workloadId, 'qualification-workload://') ||
    !isQualificationAttestation(
      value.providerAttestationRef,
      'provider-attestation://',
      value.providerAttestationDigest
    ) ||
    !isQualificationAttestation(
      value.runtimeAttestationRef,
      'runtime-attestation://',
      value.runtimeAttestationDigest
    ) ||
    !isDigest(value.materializationInputDigest) ||
    !isDigest(value.recipeActionDigest) ||
    !isDigest(value.materializationProjectionDigest) ||
    !isDigest(value.materializationOutputDigest) ||
    !isExpectedMaterializationCoreValid(value.materialized) ||
    !SAST_ISOLATED_QUALIFICATION_EXECUTION_TARGETS.includes(value.executionTarget) ||
    (value.isolationClass !== 'HARDENED' && value.isolationClass !== 'RESTRICTED') ||
    !SAST_MULTI_CLASS_QUALIFICATION_EXPECTED_OUTCOMES.includes(
      value.expectedOutcome
    ) ||
    !SAST_MULTI_CLASS_QUALIFICATION_EXPECTED_OUTCOMES.includes(value.actualOutcome) ||
    !isIsoInstant(value.startedAt) ||
    !isIsoInstant(value.executionCompletedAt) ||
    !isIsoInstant(value.cleanupStartedAt) ||
    !isIsoInstant(value.cleanupCompletedAt) ||
    Date.parse(value.executionCompletedAt) < Date.parse(value.startedAt) ||
    Date.parse(value.cleanupStartedAt) < Date.parse(value.executionCompletedAt) ||
    Date.parse(value.cleanupCompletedAt) < Date.parse(value.cleanupStartedAt) ||
    !isBoundedInteger(
      value.cleanupDurationSeconds,
      0,
      SAST_ISOLATED_QUALIFICATION_LIMITS.maximumSimulatedDurationSeconds
    ) ||
    value.cleanupDurationSeconds !==
      secondsBetween(value.cleanupStartedAt, value.cleanupCompletedAt) ||
    !isPhaseEgressSetValid(value.phaseEgress) ||
    !isProhibitedEffectsValid(value.prohibitedEffects) ||
    !isCleanupEvidenceSetValid(
      value.cleanupEvidence,
      value.cleanupStartedAt,
      value.cleanupCompletedAt
    ) ||
    typeof value.freshMicroVmObserved !== 'boolean' ||
    typeof value.sandboxReuseObserved !== 'boolean' ||
    typeof value.platformOwnedFixtureObserved !== 'boolean' ||
    typeof value.repositoryCredentialIssued !== 'boolean' ||
    typeof value.customerContentObserved !== 'boolean' ||
    value.findingAuthority !== false ||
    value.policyAuthority !== false ||
    value.publicationAuthority !== false ||
    value.productionReadinessAuthority !== false ||
    value.immutable !== true
  ) {
    return false;
  }
  return true;
}

function isPhaseEgressSetValid(value: unknown): value is SastIsolatedQualificationPhaseEgressObservation[] {
  if (!Array.isArray(value) || value.length > SAST_ISOLATED_QUALIFICATION_PHASES.length) {
    return false;
  }
  let previousIndex = -1;
  for (const item of value) {
    if (!hasExactKeys(item, PHASE_EGRESS_KEYS)) return false;
    const candidate = item as SastIsolatedQualificationPhaseEgressObservation;
    const phaseIndex = SAST_ISOLATED_QUALIFICATION_PHASES.indexOf(candidate.phase);
    if (
      phaseIndex <= previousIndex ||
      !isBoundedInteger(candidate.publicInternetConnections, 0, 1_000_000) ||
      !isBoundedInteger(candidate.bytesSent, 0, 1_000_000_000) ||
      !isBoundedInteger(candidate.dnsQueries, 0, 1_000_000) ||
      !Array.isArray(candidate.destinations) ||
      candidate.destinations.length > 32 ||
      !unique(candidate.destinations) ||
      candidate.destinations.some(
        (destination) =>
          typeof destination !== 'string' ||
          !destination.startsWith('network-destination://') ||
          !isDigestBoundReference(destination)
      )
    ) {
      return false;
    }
    previousIndex = phaseIndex;
  }
  return true;
}

function isProhibitedEffectsValid(
  value: unknown
): value is SastIsolatedQualificationProhibitedEffects {
  if (!hasExactKeys(value, PROHIBITED_EFFECT_KEYS)) return false;
  const candidate = value as SastIsolatedQualificationProhibitedEffects;
  return PROHIBITED_EFFECT_KEYS.every((key) =>
    isBoundedInteger(candidate[key], 0, 1_000_000)
  );
}

function isCleanupEvidenceSetValid(
  value: unknown,
  cleanupStartedAt: string,
  cleanupCompletedAt: string
): value is SastIsolatedQualificationCleanupEvidence[] {
  if (
    !Array.isArray(value) ||
    value.length > SAST_ISOLATED_QUALIFICATION_CLEANUP_CONTROLS.length
  ) {
    return false;
  }
  let previousIndex = -1;
  for (const item of value) {
    if (!hasExactKeys(item, CLEANUP_EVIDENCE_KEYS)) return false;
    const candidate = item as SastIsolatedQualificationCleanupEvidence;
    const controlIndex = SAST_ISOLATED_QUALIFICATION_CLEANUP_CONTROLS.indexOf(
      candidate.control
    );
    if (
      controlIndex <= previousIndex ||
      (candidate.status !== 'VERIFIED' && candidate.status !== 'FAILED') ||
      !isIsoInstant(candidate.observedAt) ||
      Date.parse(candidate.observedAt) < Date.parse(cleanupStartedAt) ||
      Date.parse(candidate.observedAt) > Date.parse(cleanupCompletedAt) ||
      !isDigestBoundReference(candidate.evidenceRef, candidate.evidenceDigest)
    ) {
      return false;
    }
    previousIndex = controlIndex;
  }
  return true;
}

function isReceiptBoundToCell(
  receipt: SastIsolatedQualificationReceipt,
  cell: SastIsolatedQualificationCell,
  plan: SastIsolatedQualificationExecutionPlan,
  dependencySet: SastIsolatedQualificationDependencySet
): boolean {
  return (
    receipt.planId === plan.planId &&
    receipt.planDigest === plan.planDigest &&
    receipt.manifestDigest === plan.manifestDigest &&
    receipt.dependencySetDigest === dependencySet.dependencySetDigest &&
    receipt.cellId === cell.cellId &&
    receipt.cellDigest === cell.cellDigest &&
    receipt.caseId === cell.caseId &&
    receipt.caseDigest === cell.caseDigest &&
    receipt.fixtureId === cell.fixtureId &&
    receipt.fixtureDigest === cell.fixtureDigest &&
    receipt.profileId === cell.profileId &&
    receipt.profileDigest === cell.profileDigest &&
    receipt.materializationInputDigest === cell.materializationInputDigest &&
    receipt.recipeActionDigest === cell.recipeActionDigest &&
    receipt.materializationProjectionDigest ===
      cell.expectedMaterialization.projectionDigest &&
    stableJson(receipt.materialized) ===
      stableJson(expectedMaterializationCore(cell.expectedMaterialization)) &&
    receipt.executionTarget === cell.executionTarget &&
    receipt.isolationClass === cell.isolationClass &&
    receipt.expectedOutcome === cell.expectedOutcome
  );
}

function receiptFailureReasons(
  receipt: SastIsolatedQualificationReceipt,
  cell: SastIsolatedQualificationCell | null,
  dependencySet: SastIsolatedQualificationDependencySet,
  evaluatedAt: string
): SastIsolatedQualificationFailureReason[] {
  const reasons: SastIsolatedQualificationFailureReason[] = [];
  if (
    Date.parse(receipt.startedAt) < Date.parse(dependencySet.validFrom) ||
    Date.parse(receipt.cleanupCompletedAt) > Date.parse(dependencySet.validUntil) ||
    Date.parse(receipt.cleanupCompletedAt) > Date.parse(evaluatedAt)
  ) {
    reasons.push('TIMESTAMP_INVALID');
  }
  if (
    secondsBetween(receipt.cleanupCompletedAt, evaluatedAt) >
    SAST_ISOLATED_QUALIFICATION_LIMITS.maximumEvidenceAgeSeconds
  ) {
    reasons.push('EVIDENCE_STALE');
  }
  if (!cell || receipt.actualOutcome !== cell.expectedOutcome) {
    reasons.push('OUTCOME_MISMATCH');
  }
  if (
    !cell ||
    receipt.materializationInputDigest !== cell.materializationInputDigest ||
    receipt.recipeActionDigest !== cell.recipeActionDigest ||
    receipt.materializationProjectionDigest !==
      cell.expectedMaterialization.projectionDigest ||
    stableJson(receipt.materialized) !==
      stableJson(expectedMaterializationCore(cell.expectedMaterialization))
  ) {
    reasons.push('MATERIALIZATION_MISMATCH');
  }
  if (
    !arraysEqual(
      receipt.phaseEgress.map((item) => item.phase),
      [...SAST_ISOLATED_QUALIFICATION_PHASES]
    ) ||
    receipt.phaseEgress.some(
      (item) =>
        item.publicInternetConnections !== 0 ||
        item.bytesSent !== 0 ||
        item.dnsQueries !== 0 ||
        item.destinations.length !== 0
    )
  ) {
    reasons.push('EGRESS_VIOLATION');
  }
  if (
    PROHIBITED_EFFECT_KEYS.some((key) => receipt.prohibitedEffects[key] !== 0) ||
    receipt.repositoryCredentialIssued ||
    receipt.customerContentObserved
  ) {
    reasons.push('PROHIBITED_EFFECT');
  }
  if (!receipt.freshMicroVmObserved || receipt.sandboxReuseObserved) {
    reasons.push('SANDBOX_REUSED');
  }
  if (!receipt.platformOwnedFixtureObserved) reasons.push('CELL_BINDING_INVALID');
  if (
    !arraysEqual(
      receipt.cleanupEvidence.map((item) => item.control),
      [...SAST_ISOLATED_QUALIFICATION_CLEANUP_CONTROLS]
    ) ||
    receipt.cleanupEvidence.some((item) => item.status !== 'VERIFIED')
  ) {
    reasons.push('CLEANUP_INCOMPLETE');
  }
  if (
    receipt.cleanupDurationSeconds >
    SAST_ISOLATED_QUALIFICATION_LIMITS.cleanupSloSeconds
  ) {
    reasons.push('CLEANUP_SLO_EXCEEDED');
  }
  return canonicalFailureReasons(reasons);
}

function isSignatureSetValid(
  signatures: readonly SastIsolatedQualificationSignature[],
  requiredRoles: readonly SastIsolatedQualificationSignatureRole[],
  payloadDigest: Sha256Digest,
  earliestSignedAt: string,
  latestSignedAt: string,
  verifySignature: SastIsolatedQualificationSignatureVerifier
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
      !isSastIsolatedQualificationSignatureValid(signature) ||
      signature.payloadDigest !== payloadDigest ||
      Date.parse(signature.signedAt) < Date.parse(earliestSignedAt) ||
      Date.parse(signature.signedAt) > Date.parse(latestSignedAt)
    ) {
      return false;
    }
    const payload = serializeSastIsolatedQualificationSignaturePayload(signature);
    if (!payload) return false;
    try {
      return verifySignature(signature, payload) === true;
    } catch {
      return false;
    }
  });
}

function isArtifactBindingValid(
  value: unknown
): value is SastIsolatedQualificationArtifactBinding {
  if (!hasExactKeys(value, ARTIFACT_KEYS)) return false;
  const candidate = value as SastIsolatedQualificationArtifactBinding;
  return (
    SAST_ISOLATED_QUALIFICATION_ARTIFACT_KINDS.includes(candidate.kind) &&
    isDigestBoundReference(candidate.artifactRef, candidate.artifactDigest) &&
    isDigestBoundReference(candidate.signatureRef) &&
    isDigestBoundReference(candidate.provenanceRef)
  );
}

function parameterMap(
  fixture: SastMultiClassQualificationFixture
): Map<string, string | number | boolean> | null {
  const output = new Map<string, string | number | boolean>();
  for (const parameter of fixture.parameters) {
    const values = [
      parameter.stringValue,
      parameter.integerValue,
      parameter.booleanValue
    ].filter((value) => value !== null);
    if (values.length !== 1 || output.has(parameter.name)) return null;
    output.set(parameter.name, values[0] as string | number | boolean);
  }
  return output;
}

type ResourceLimitMetric = keyof (typeof SAST_SCAN_PROFILES)['JAVA_FAST_V1']['limits'];

function isResourceLimitMetric(value: string): value is ResourceLimitMetric {
  return Object.prototype.hasOwnProperty.call(
    SAST_SCAN_PROFILES.JAVA_FAST_V1.limits,
    value
  );
}

function isByteMetric(metric: ResourceLimitMetric): boolean {
  return [
    'maxArtifactBytes',
    'maxRepositoryBytes',
    'maxSelectedBytes',
    'maxSingleFileBytes',
    'maxStdoutStderrBytes'
  ].includes(metric);
}

function isEntryMetric(metric: ResourceLimitMetric): boolean {
  return ['maxArtifactRecords', 'maxFileCount', 'maxFindings'].includes(metric);
}

function expectedExecutionTarget(input: {
  corpusClass: 'SCHEMA_PARSER' | 'MALICIOUS_REPOSITORY';
  expectedOutcome: SastMultiClassQualificationExpectedOutcome;
}): SastIsolatedQualificationExecutionTarget {
  if (input.corpusClass === 'SCHEMA_PARSER') return 'ARTIFACT_VALIDATION';
  return input.expectedOutcome === 'REJECT' ||
    input.expectedOutcome === 'RESTRICTED_ESCALATION'
    ? 'REPOSITORY_PREFLIGHT'
    : 'SCANNER_RUNTIME';
}

function isScenarioForCorpusClass(
  corpusClass: 'SCHEMA_PARSER' | 'MALICIOUS_REPOSITORY',
  scenario: SastMultiClassQualificationScenario
): boolean {
  return (
    SAST_MULTI_CLASS_QUALIFICATION_REQUIRED_SCENARIOS[corpusClass] as readonly string[]
  ).includes(scenario);
}

function manifestCore(
  value: SastIsolatedQualificationManifest
): SastIsolatedQualificationManifestCore {
  return Object.fromEntries(
    MANIFEST_CORE_KEYS.map((key) => [key, value[key]])
  ) as unknown as SastIsolatedQualificationManifestCore;
}

function cellCore(
  value: SastIsolatedQualificationCell
): SastIsolatedQualificationCellCore {
  return Object.fromEntries(
    CELL_CORE_KEYS.map((key) => [key, value[key]])
  ) as unknown as SastIsolatedQualificationCellCore;
}

function expectedMaterializationCore(
  value: SastIsolatedQualificationExpectedMaterialization
): SastIsolatedQualificationExpectedMaterializationCore {
  return Object.fromEntries(
    EXPECTED_MATERIALIZATION_CORE_KEYS.map((key) => [key, value[key]])
  ) as unknown as SastIsolatedQualificationExpectedMaterializationCore;
}

function receiptCore(
  value: SastIsolatedQualificationReceipt
): SastIsolatedQualificationReceiptCore {
  return Object.fromEntries(
    RECEIPT_CORE_KEYS.map((key) => [key, value[key]])
  ) as unknown as SastIsolatedQualificationReceiptCore;
}

function resultCore(
  value: SastIsolatedQualificationResult
): SastIsolatedQualificationResultCore {
  return Object.fromEntries(
    RESULT_CORE_KEYS.map((key) => [key, value[key]])
  ) as unknown as SastIsolatedQualificationResultCore;
}

function dependencySetInput(
  value: SastIsolatedQualificationDependencySet
): SastIsolatedQualificationDependencySetInput {
  return {
    revision: value.revision,
    providerId: value.providerId,
    providerAdapterRef: value.providerAdapterRef,
    validFrom: value.validFrom,
    validUntil: value.validUntil,
    artifacts: value.artifacts
  };
}

function cloneArtifact(
  value: SastIsolatedQualificationArtifactBinding
): SastIsolatedQualificationArtifactBinding {
  return { ...value };
}

function artifact(
  value: SastIsolatedQualificationDependencySet,
  kind: SastIsolatedQualificationArtifactKind
): SastIsolatedQualificationArtifactBinding | null {
  return value.artifacts.find((item) => item.kind === kind) ?? null;
}

function canonicalFailureReasons(
  values: readonly SastIsolatedQualificationFailureReason[]
): SastIsolatedQualificationFailureReason[] {
  const order = new Map(
    SAST_ISOLATED_QUALIFICATION_FAILURE_REASONS.map((value, index) => [
      value,
      index
    ])
  );
  return [...new Set(values)].sort(
    (left, right) => (order.get(left) ?? 0) - (order.get(right) ?? 0)
  );
}

function isDigestBoundReference(value: unknown, digest?: unknown): boolean {
  return (
    isBoundedText(value, SAST_ISOLATED_QUALIFICATION_LIMITS.maximumReferenceBytes) &&
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

function isQualificationAttestation(
  value: unknown,
  prefix: string,
  digest: unknown
): value is string {
  return (
    typeof value === 'string' &&
    value.startsWith(prefix) &&
    isDigestBoundReference(value, digest)
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

function secondsBetween(start: string, end: string): number {
  return (Date.parse(end) - Date.parse(start)) / 1000;
}

function isOwnerRef(value: unknown): value is string {
  return typeof value === 'string' && OWNER_REF_PATTERN.test(value);
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

function isBoundedInteger(value: unknown, minimum: number, maximum: number): boolean {
  return (
    typeof value === 'number' &&
    Number.isSafeInteger(value) &&
    value >= minimum &&
    value <= maximum
  );
}

function hasExactKeys(value: unknown, keys: readonly string[]): boolean {
  if (!isPlainObject(value)) return false;
  const actual = Object.keys(value).sort(compareText);
  const expected = [...keys].sort(compareText);
  return arraysEqual(actual, expected);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
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
    return Number.isFinite(value) ? JSON.stringify(value) : STABLE_JSON_INVALID_SENTINEL;
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
          `${JSON.stringify(key)}:${stableJsonValue(value[key], ancestors, depth + 1)}`
      )
      .join(',')}}`;
  } else {
    output = STABLE_JSON_INVALID_SENTINEL;
  }
  ancestors.delete(value);
  return output;
}

function decodedBase64Bytes(value: string): number {
  if (value.length === 0) return 0;
  const padding = value.endsWith('==') ? 2 : value.endsWith('=') ? 1 : 0;
  return (value.length / 4) * 3 - padding;
}

function arraysEqual<T>(left: readonly T[], right: readonly T[]): boolean {
  return left.length === right.length && left.every((item, index) => item === right[index]);
}

function unique(values: readonly string[]): boolean {
  return new Set(values).size === values.length;
}

function isCanonicalCellOrder(
  cells: readonly SastIsolatedQualificationCell[]
): boolean {
  return cells.every((cell, index) => {
    const expectedProfile = SAST_PROFILE_IDS[index % SAST_PROFILE_IDS.length];
    if (cell.profileId !== expectedProfile) return false;
    if (index === 0) return true;
    const previous = cells[index - 1];
    if (!previous) return false;
    return index % SAST_PROFILE_IDS.length === 0
      ? compareText(previous.caseKey, cell.caseKey) < 0
      : previous.caseKey === cell.caseKey;
  });
}

function slug(value: string): string {
  return value.toLowerCase().replaceAll('_', '-');
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
