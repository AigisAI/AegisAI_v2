import {
  isSastEndToEndQualificationSignatureValid,
  serializeSastEndToEndQualificationSignaturePayload,
  type SastEndToEndQualificationCanonicalDigester,
  type SastEndToEndQualificationSignature,
  type SastEndToEndQualificationSignatureVerifier
} from './sast-end-to-end-qualification';
import {
  SAST_PRODUCTION_GO_NO_GO_GATE_IDS,
  isSastProductionGoNoGoRecordValid,
  type SastProductionGoNoGoRecord
} from './sast-production-go-no-go';

export const PRODUCTION_DEPLOYMENT_OPERATIONS_FEATURE_ID =
  '005-production-deployment-operations';

export const PRODUCTION_DEPLOYMENT_OPERATIONS_CONTRACT_DIGEST =
  'sha256:f54339d493ac13a11dbc27742c088f13f6fe8f024307c350fb9ee9ea6f770c68';

export const PRODUCTION_DEPLOYMENT_OPERATIONS_CONTRACT_REF =
  `repository-file://specs/005-production-deployment-operations/contracts/deployment-operations.md/${PRODUCTION_DEPLOYMENT_OPERATIONS_CONTRACT_DIGEST}`;

export const DEPLOYMENT_SAST_QUALIFICATION_ENTRY_ATTESTATION_VERSION =
  'deployment-sast-qualification-entry-attestation-v1';

export const DEPLOYMENT_SAST_QUALIFICATION_BINDING_VERSION =
  'deployment-sast-qualification-binding-v1';

export const DEPLOYMENT_SAST_QUALIFICATION_LIMITS = Object.freeze({
  maximumRecordToAttestationSeconds: 60 * 60,
  maximumAttestationValiditySeconds: 60 * 60,
  maximumOperatorApprovalValiditySeconds: 24 * 60 * 60,
  maximumExecutionWindowSeconds: 8 * 60 * 60,
  maximumMicroVmTtlSeconds: 2 * 60 * 60,
  maximumNetworkBoundaryReferences: 64,
  maximumReferenceBytes: 2_048
});

export const DEPLOYMENT_ENVIRONMENTS = ['PRODUCTION'] as const;
export type DeploymentEnvironment = (typeof DEPLOYMENT_ENVIRONMENTS)[number];

export const PRODUCTION_PLANE_FORBIDDEN_NAMESPACES = [
  'default',
  'kube-system',
  'kube-public',
  'kube-node-lease'
] as const;

export const DEPLOYMENT_CREDENTIAL_SCOPES = [
  'CLUSTER_ADMIN',
  'MICROVM_PLATFORM_ADMIN',
  'SECRET_MANAGER_ADMIN'
] as const;
export type DeploymentCredentialScope = (typeof DEPLOYMENT_CREDENTIAL_SCOPES)[number];

export const DEPLOYMENT_CREDENTIAL_ALLOWED_USES = ['EXPLICIT_DEPLOYMENT_OPERATION'] as const;
export type DeploymentCredentialAllowedUse =
  (typeof DEPLOYMENT_CREDENTIAL_ALLOWED_USES)[number];

export const DEPLOYMENT_OPERATION_ACTORS = [
  'DEPLOYMENT_OPERATOR',
  'CONTROL_PLANE',
  'DATA_SECURITY_PLANE'
] as const;
export type DeploymentOperationActor = (typeof DEPLOYMENT_OPERATION_ACTORS)[number];

export const DEPLOYMENT_OPERATION_EVENT_TYPES = ['DEPLOYMENT_PREFLIGHT_VERIFIED'] as const;
export type DeploymentOperationEventType =
  (typeof DEPLOYMENT_OPERATION_EVENT_TYPES)[number];

export const MICROVM_ISOLATION_CLASSES = ['HARDENED', 'RESTRICTED'] as const;
export type MicroVmIsolationClass = (typeof MICROVM_ISOLATION_CLASSES)[number];

export const SCANNER_SANDBOX_FORBIDDEN_CAPABILITIES = [
  'PACKAGE_INSTALL',
  'CUSTOMER_REPOSITORY_BUILD',
  'DYNAMIC_TEST_EXECUTION',
  'DIRECT_SOURCE_UPLOAD',
  'AUTO_FIX_PULL_REQUEST'
] as const;
export type ScannerSandboxForbiddenCapability =
  (typeof SCANNER_SANDBOX_FORBIDDEN_CAPABILITIES)[number];

export const AI_PLANE_FORBIDDEN_DIRECT_INPUTS = [
  'SCM_CREDENTIAL',
  'FULL_REPOSITORY',
  'SOURCE_ARCHIVE',
  'RAW_SCANNER_PAYLOAD'
] as const;
export type AiPlaneForbiddenDirectInput =
  (typeof AI_PLANE_FORBIDDEN_DIRECT_INPUTS)[number];

export const DEPLOYMENT_PREFLIGHT_REQUIRED_APPROVALS = [
  'PRODUCTION_CHANGE_APPROVAL',
  'SECURITY_BOUNDARY_APPROVAL',
  'CREDENTIAL_HANDOFF_APPROVAL'
] as const;
export type DeploymentPreflightRequiredApproval =
  (typeof DEPLOYMENT_PREFLIGHT_REQUIRED_APPROVALS)[number];

export const DEPLOYMENT_CREDENTIAL_HANDOFF_MODES = [
  'EXTERNAL_SECRET_MANAGER_REFERENCE',
  'EPHEMERAL_OIDC_FEDERATION'
] as const;
export type DeploymentCredentialHandoffMode =
  (typeof DEPLOYMENT_CREDENTIAL_HANDOFF_MODES)[number];

export interface ProductionClusterProvisioning {
  environment: 'PRODUCTION';
  provider: string;
  region: string;
  clusterName: string;
  controlPlaneNamespace: string;
  scanPlaneNamespace: string;
  aiPlaneNamespace: string;
  dataSecurityNamespace: string;
  networkBoundaryRefs: string[];
  auditSinkRef: string;
}

export interface DeploymentCredentialBoundary {
  credentialProvider: string;
  credentialScope: DeploymentCredentialScope;
  allowedUse: 'EXPLICIT_DEPLOYMENT_OPERATION';
  localDevelopmentDefault: false;
  repositoryPersisted: false;
  rotationRequired: true;
  auditRequired: true;
}

export interface DeploymentOperationAuditSignal {
  environment: 'PRODUCTION';
  provider: string;
  operationId: string;
  actor: DeploymentOperationActor;
  targetType: 'SAST_QUALIFICATION_BINDING';
  targetId: string;
  eventType: DeploymentOperationEventType;
  occurredAt: string;
}

export interface MicroVmPlatformRollout {
  provider: string;
  providerAdapterRef: string;
  region: string;
  platformName: string;
  isolationClass: MicroVmIsolationClass;
  scannerSandboxProfileRef: string;
  tokenBrokerRef: string;
  evidenceStorageRef: string;
  egressPolicyRef: string;
  ttlSeconds: number;
  forbiddenScannerCapabilities: ScannerSandboxForbiddenCapability[];
}

export interface AiPlaneRepositoryAccessBoundary {
  advisoryOnly: true;
  receivesReducedEvidenceOnly: true;
  requestedDirectInputs: string[];
}

export interface DeploymentSastQualificationEntryAttestationCore {
  version: typeof DEPLOYMENT_SAST_QUALIFICATION_ENTRY_ATTESTATION_VERSION;
  goNoGoRecordId: string;
  goNoGoRecordDigest: string;
  goNoGoManifestId: string;
  goNoGoManifestDigest: string;
  goNoGoPlanId: string;
  goNoGoPlanDigest: string;
  repositoryCommitSha: string;
  providerId: string;
  providerAdapterRef: string;
  rollbackTargetRef: string;
  rollbackTargetDigest: string;
  killSwitchEvidenceAttestationId: string;
  killSwitchEvidenceAttestationDigest: string;
  deploymentOperationsContractRef: string;
  deploymentOperationsContractDigest: string;
  expectedGateCount: number;
  passedGateCount: number;
  recordDecidedAt: string;
  attestedAt: string;
  expiresAt: string;
  deploymentOperationsEntryAuthorized: true;
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

export interface DeploymentSastQualificationEntryAttestationDraft
  extends DeploymentSastQualificationEntryAttestationCore {
  attestationId: string;
  attestationDigest: string;
}

export interface DeploymentSastQualificationEntryAttestation
  extends DeploymentSastQualificationEntryAttestationDraft {
  signature: SastEndToEndQualificationSignature;
}

export interface DeploymentSastQualificationBindingCore {
  version: typeof DEPLOYMENT_SAST_QUALIFICATION_BINDING_VERSION;
  goNoGoRecordId: string;
  goNoGoRecordDigest: string;
  entryAttestationId: string;
  entryAttestationDigest: string;
  goNoGoManifestId: string;
  goNoGoManifestDigest: string;
  goNoGoPlanId: string;
  goNoGoPlanDigest: string;
  repositoryCommitSha: string;
  providerId: string;
  providerAdapterRef: string;
  rollbackTargetRef: string;
  rollbackTargetDigest: string;
  killSwitchEvidenceAttestationId: string;
  killSwitchEvidenceAttestationDigest: string;
  deploymentOperationsContractRef: string;
  deploymentOperationsContractDigest: string;
  authorizedAt: string;
  expiresAt: string;
  deploymentOperationsEntryAuthorized: true;
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

export interface DeploymentSastQualificationBinding
  extends DeploymentSastQualificationBindingCore {
  bindingId: string;
  bindingDigest: string;
}

export interface DeploymentSastQualificationEvidence {
  record: SastProductionGoNoGoRecord;
  entryAttestation: DeploymentSastQualificationEntryAttestation;
}

export interface DeploymentSastQualificationVerificationContext {
  trustedEvaluatedAt: string;
  verifySignature: SastEndToEndQualificationSignatureVerifier;
  digestCanonical: SastEndToEndQualificationCanonicalDigester;
}

export interface DeploymentOperatorApprovalReference {
  approval: DeploymentPreflightRequiredApproval;
  approvalRef: string;
  subjectDigest: string;
  approvedAt: string;
  validUntil: string;
}

export interface DeploymentOperationPreflight {
  clusterProvisioning: ProductionClusterProvisioning;
  microVmRollout: MicroVmPlatformRollout;
  credentialBoundaries: DeploymentCredentialBoundary[];
  sastQualification: DeploymentSastQualificationBinding;
  auditSignal: DeploymentOperationAuditSignal;
  operatorApprovals: DeploymentOperatorApprovalReference[];
  kmsKeyRef: string;
  secretManagerRef: string;
  objectStorageRef: string;
  dnsZoneRef: string;
}

export interface DeploymentExecutionWindow {
  startsAt: string;
  endsAt: string;
}

export interface DeploymentOperationHandoffManifest {
  preflight: DeploymentOperationPreflight;
  credentialHandoffMode: DeploymentCredentialHandoffMode;
  executionWindow: DeploymentExecutionWindow;
  rollbackPlanRef: string;
  incidentChannelRef: string;
  dryRunEvidenceRef: string;
  changeTicketRef: string;
}

const ENTRY_ATTESTATION_CORE_KEYS = [
  'version', 'goNoGoRecordId', 'goNoGoRecordDigest', 'goNoGoManifestId',
  'goNoGoManifestDigest', 'goNoGoPlanId', 'goNoGoPlanDigest',
  'repositoryCommitSha', 'providerId', 'providerAdapterRef', 'rollbackTargetRef',
  'rollbackTargetDigest', 'killSwitchEvidenceAttestationId',
  'killSwitchEvidenceAttestationDigest', 'deploymentOperationsContractRef',
  'deploymentOperationsContractDigest', 'expectedGateCount', 'passedGateCount',
  'recordDecidedAt', 'attestedAt', 'expiresAt',
  'deploymentOperationsEntryAuthorized', 'findingAuthority', 'policyAuthority',
  'publicationAuthority', 'scmMutationAuthority', 'aiAuthority',
  'deploymentAuthority', 'kubernetesExecutionAuthority',
  'productionMutationAuthority', 'productionReadinessAuthority'
] as const;

const QUALIFICATION_BINDING_CORE_KEYS = [
  'version', 'goNoGoRecordId', 'goNoGoRecordDigest', 'entryAttestationId',
  'entryAttestationDigest', 'goNoGoManifestId', 'goNoGoManifestDigest',
  'goNoGoPlanId', 'goNoGoPlanDigest', 'repositoryCommitSha', 'providerId',
  'providerAdapterRef', 'rollbackTargetRef', 'rollbackTargetDigest',
  'killSwitchEvidenceAttestationId', 'killSwitchEvidenceAttestationDigest',
  'deploymentOperationsContractRef', 'deploymentOperationsContractDigest',
  'authorizedAt', 'expiresAt', 'deploymentOperationsEntryAuthorized',
  'findingAuthority', 'policyAuthority', 'publicationAuthority',
  'scmMutationAuthority', 'aiAuthority', 'deploymentAuthority',
  'kubernetesExecutionAuthority', 'productionMutationAuthority',
  'productionReadinessAuthority'
] as const;

const CLUSTER_PROVISIONING_KEYS = [
  'environment', 'provider', 'region', 'clusterName', 'controlPlaneNamespace',
  'scanPlaneNamespace', 'aiPlaneNamespace', 'dataSecurityNamespace',
  'networkBoundaryRefs', 'auditSinkRef'
] as const;

const CREDENTIAL_BOUNDARY_KEYS = [
  'credentialProvider', 'credentialScope', 'allowedUse',
  'localDevelopmentDefault', 'repositoryPersisted', 'rotationRequired',
  'auditRequired'
] as const;

const MICROVM_ROLLOUT_KEYS = [
  'provider', 'providerAdapterRef', 'region', 'platformName', 'isolationClass',
  'scannerSandboxProfileRef', 'tokenBrokerRef', 'evidenceStorageRef',
  'egressPolicyRef', 'ttlSeconds', 'forbiddenScannerCapabilities'
] as const;

const AUDIT_SIGNAL_KEYS = [
  'environment', 'provider', 'operationId', 'actor', 'targetType', 'targetId',
  'eventType', 'occurredAt'
] as const;

const OPERATOR_APPROVAL_KEYS = [
  'approval', 'approvalRef', 'subjectDigest', 'approvedAt', 'validUntil'
] as const;

const PREFLIGHT_KEYS = [
  'clusterProvisioning', 'microVmRollout', 'credentialBoundaries',
  'sastQualification', 'auditSignal', 'operatorApprovals', 'kmsKeyRef',
  'secretManagerRef', 'objectStorageRef', 'dnsZoneRef'
] as const;

const HANDOFF_KEYS = [
  'preflight', 'credentialHandoffMode', 'executionWindow', 'rollbackPlanRef',
  'incidentChannelRef', 'dryRunEvidenceRef', 'changeTicketRef'
] as const;

export function buildDeploymentSastQualificationEntryAttestationDraft(
  input: {
    record: SastProductionGoNoGoRecord;
    attestedAt: string;
    expiresAt: string;
  },
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): DeploymentSastQualificationEntryAttestationDraft | null {
  try {
    const record = input.record;
    if (
      !isSastProductionGoNoGoRecordValid(record, digestCanonical) ||
      record.status !== 'GO' ||
      record.deploymentOperationsEntryAuthorized !== true ||
      record.planId === null || record.planDigest === null ||
      record.providerId === null || record.providerAdapterRef === null ||
      record.repositoryCommitSha === null || record.rollbackTargetRef === null ||
      record.rollbackTargetDigest === null ||
      record.killSwitchEvidenceAttestationId === null ||
      record.killSwitchEvidenceAttestationDigest === null ||
      record.expectedGateCount !== SAST_PRODUCTION_GO_NO_GO_GATE_IDS.length ||
      record.passedGateCount !== SAST_PRODUCTION_GO_NO_GO_GATE_IDS.length ||
      record.failedGateCount !== 0 || record.notApplicableGateCount !== 0 ||
      record.deploymentOperationsContractRef !==
        PRODUCTION_DEPLOYMENT_OPERATIONS_CONTRACT_REF ||
      record.deploymentOperationsContractDigest !==
        PRODUCTION_DEPLOYMENT_OPERATIONS_CONTRACT_DIGEST ||
      !isCanonicalInstant(input.attestedAt) ||
      !isCanonicalInstant(input.expiresAt)
    ) {
      return null;
    }
    const recordDecidedAt = Date.parse(record.decidedAt);
    const attestedAt = Date.parse(input.attestedAt);
    const expiresAt = Date.parse(input.expiresAt);
    if (
      attestedAt < recordDecidedAt ||
      attestedAt - recordDecidedAt >
        DEPLOYMENT_SAST_QUALIFICATION_LIMITS.maximumRecordToAttestationSeconds * 1_000 ||
      expiresAt <= attestedAt ||
      expiresAt - attestedAt >
        DEPLOYMENT_SAST_QUALIFICATION_LIMITS.maximumAttestationValiditySeconds * 1_000
    ) {
      return null;
    }
    const core: DeploymentSastQualificationEntryAttestationCore = {
      version: DEPLOYMENT_SAST_QUALIFICATION_ENTRY_ATTESTATION_VERSION,
      goNoGoRecordId: record.recordId,
      goNoGoRecordDigest: record.recordDigest,
      goNoGoManifestId: record.manifestId,
      goNoGoManifestDigest: record.manifestDigest,
      goNoGoPlanId: record.planId,
      goNoGoPlanDigest: record.planDigest,
      repositoryCommitSha: record.repositoryCommitSha,
      providerId: record.providerId,
      providerAdapterRef: record.providerAdapterRef,
      rollbackTargetRef: record.rollbackTargetRef,
      rollbackTargetDigest: record.rollbackTargetDigest,
      killSwitchEvidenceAttestationId: record.killSwitchEvidenceAttestationId,
      killSwitchEvidenceAttestationDigest: record.killSwitchEvidenceAttestationDigest,
      deploymentOperationsContractRef: record.deploymentOperationsContractRef,
      deploymentOperationsContractDigest: record.deploymentOperationsContractDigest,
      expectedGateCount: record.expectedGateCount,
      passedGateCount: record.passedGateCount,
      recordDecidedAt: record.decidedAt,
      attestedAt: input.attestedAt,
      expiresAt: input.expiresAt,
      deploymentOperationsEntryAuthorized: true,
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
    const attestationDigest = digestCanonical(stableJson(core));
    return {
      ...core,
      attestationId:
        `deployment-sast-qualification-entry-attestation://${stripDigest(attestationDigest)}`,
      attestationDigest
    };
  } catch {
    return null;
  }
}

export function buildDeploymentSastQualificationEntryAttestation(
  input: {
    record: SastProductionGoNoGoRecord;
    attestedAt: string;
    expiresAt: string;
    signature: SastEndToEndQualificationSignature;
  },
  digestCanonical: SastEndToEndQualificationCanonicalDigester
): DeploymentSastQualificationEntryAttestation | null {
  const draft = buildDeploymentSastQualificationEntryAttestationDraft(
    input,
    digestCanonical
  );
  if (
    draft === null ||
    !isQualificationAuthoritySignatureFor(
      input.signature,
      draft.attestationDigest,
      input.attestedAt
    )
  ) {
    return null;
  }
  return { ...draft, signature: input.signature };
}

export function isDeploymentSastQualificationEntryAttestationValid(
  value: unknown,
  record: SastProductionGoNoGoRecord,
  context: DeploymentSastQualificationVerificationContext
): value is DeploymentSastQualificationEntryAttestation {
  try {
    if (
      !hasExactKeys(value, [
        ...ENTRY_ATTESTATION_CORE_KEYS,
        'attestationId', 'attestationDigest', 'signature'
      ]) ||
      !isCanonicalInstant(context.trustedEvaluatedAt)
    ) {
      return false;
    }
    const candidate = value as unknown as DeploymentSastQualificationEntryAttestation;
    const rebuilt = buildDeploymentSastQualificationEntryAttestation(
      {
        record,
        attestedAt: candidate.attestedAt,
        expiresAt: candidate.expiresAt,
        signature: candidate.signature
      },
      context.digestCanonical
    );
    const trustedEvaluatedAt = Date.parse(context.trustedEvaluatedAt);
    return (
      rebuilt !== null && stableJson(rebuilt) === stableJson(candidate) &&
      trustedEvaluatedAt >= Date.parse(candidate.attestedAt) &&
      trustedEvaluatedAt < Date.parse(candidate.expiresAt) &&
      verifyQualificationSignature(candidate.signature, context.verifySignature)
    );
  } catch {
    return false;
  }
}

export function buildDeploymentSastQualificationBinding(
  evidence: DeploymentSastQualificationEvidence,
  context: DeploymentSastQualificationVerificationContext
): DeploymentSastQualificationBinding | null {
  try {
    if (!isDeploymentSastQualificationEntryAttestationValid(
      evidence.entryAttestation, evidence.record, context
    )) return null;
    const record = evidence.record;
    const attestation = evidence.entryAttestation;
    if (
      record.planId === null || record.planDigest === null ||
      record.repositoryCommitSha === null || record.providerId === null ||
      record.providerAdapterRef === null || record.rollbackTargetRef === null ||
      record.rollbackTargetDigest === null ||
      record.killSwitchEvidenceAttestationId === null ||
      record.killSwitchEvidenceAttestationDigest === null
    ) return null;
    const core: DeploymentSastQualificationBindingCore = {
      version: DEPLOYMENT_SAST_QUALIFICATION_BINDING_VERSION,
      goNoGoRecordId: record.recordId,
      goNoGoRecordDigest: record.recordDigest,
      entryAttestationId: attestation.attestationId,
      entryAttestationDigest: attestation.attestationDigest,
      goNoGoManifestId: record.manifestId,
      goNoGoManifestDigest: record.manifestDigest,
      goNoGoPlanId: record.planId,
      goNoGoPlanDigest: record.planDigest,
      repositoryCommitSha: record.repositoryCommitSha,
      providerId: record.providerId,
      providerAdapterRef: record.providerAdapterRef,
      rollbackTargetRef: record.rollbackTargetRef,
      rollbackTargetDigest: record.rollbackTargetDigest,
      killSwitchEvidenceAttestationId: record.killSwitchEvidenceAttestationId,
      killSwitchEvidenceAttestationDigest: record.killSwitchEvidenceAttestationDigest,
      deploymentOperationsContractRef: record.deploymentOperationsContractRef,
      deploymentOperationsContractDigest: record.deploymentOperationsContractDigest,
      authorizedAt: attestation.attestedAt,
      expiresAt: attestation.expiresAt,
      deploymentOperationsEntryAuthorized: true,
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
    const bindingDigest = context.digestCanonical(stableJson(core));
    return {
      ...core,
      bindingId: `deployment-sast-qualification-binding://${stripDigest(bindingDigest)}`,
      bindingDigest
    };
  } catch {
    return null;
  }
}

export function isDeploymentSastQualificationBindingValid(
  value: unknown,
  evidence: DeploymentSastQualificationEvidence,
  context: DeploymentSastQualificationVerificationContext
): value is DeploymentSastQualificationBinding {
  try {
    if (!hasExactKeys(value, [
      ...QUALIFICATION_BINDING_CORE_KEYS, 'bindingId', 'bindingDigest'
    ])) return false;
    const candidate = value as unknown as DeploymentSastQualificationBinding;
    const rebuilt = buildDeploymentSastQualificationBinding(evidence, context);
    return rebuilt !== null && stableJson(rebuilt) === stableJson(candidate);
  } catch {
    return false;
  }
}

export function isProductionClusterProvisioningBoundaryValid(
  input: unknown
): input is ProductionClusterProvisioning {
  if (!hasExactKeys(input, CLUSTER_PROVISIONING_KEYS)) return false;
  const candidate = input as unknown as ProductionClusterProvisioning;
  if (!Array.isArray(candidate.networkBoundaryRefs)) return false;
  const namespaces = [
    candidate.controlPlaneNamespace, candidate.scanPlaneNamespace,
    candidate.aiPlaneNamespace, candidate.dataSecurityNamespace
  ];
  return (
    candidate.environment === 'PRODUCTION' &&
    isProviderIdentity(candidate.provider) &&
    isSafeName(candidate.region) && isSafeName(candidate.clusterName) &&
    namespaces.every(isDnsLabel) && new Set(namespaces).size === namespaces.length &&
    namespaces.every((namespace) =>
      !PRODUCTION_PLANE_FORBIDDEN_NAMESPACES.some((reserved) => reserved === namespace)
    ) &&
    candidate.networkBoundaryRefs.length >= namespaces.length &&
    candidate.networkBoundaryRefs.length <=
      DEPLOYMENT_SAST_QUALIFICATION_LIMITS.maximumNetworkBoundaryReferences &&
    candidate.networkBoundaryRefs.every(isDigestBoundReference) &&
    new Set(candidate.networkBoundaryRefs).size === candidate.networkBoundaryRefs.length &&
    isDigestBoundReference(candidate.auditSinkRef)
  );
}

export function isDeploymentCredentialBoundaryCompliant(
  input: unknown
): input is DeploymentCredentialBoundary {
  if (!hasExactKeys(input, CREDENTIAL_BOUNDARY_KEYS)) return false;
  const candidate = input as unknown as DeploymentCredentialBoundary;
  return (
    isDigestBoundReference(candidate.credentialProvider) &&
    DEPLOYMENT_CREDENTIAL_SCOPES.includes(candidate.credentialScope) &&
    candidate.allowedUse === 'EXPLICIT_DEPLOYMENT_OPERATION' &&
    candidate.localDevelopmentDefault === false && candidate.repositoryPersisted === false &&
    candidate.rotationRequired === true && candidate.auditRequired === true
  );
}

export function isMicroVmPlatformRolloutBoundaryValid(
  input: unknown
): input is MicroVmPlatformRollout {
  if (!hasExactKeys(input, MICROVM_ROLLOUT_KEYS)) return false;
  const candidate = input as unknown as MicroVmPlatformRollout;
  if (!Array.isArray(candidate.forbiddenScannerCapabilities)) return false;
  const requiredRefs = [
    candidate.providerAdapterRef, candidate.scannerSandboxProfileRef,
    candidate.tokenBrokerRef,
    candidate.evidenceStorageRef, candidate.egressPolicyRef
  ];
  return (
    isProviderIdentity(candidate.provider) && requiredRefs.every(isDigestBoundReference) &&
    isSafeName(candidate.region) && isSafeName(candidate.platformName) &&
    MICROVM_ISOLATION_CLASSES.includes(candidate.isolationClass) &&
    Number.isSafeInteger(candidate.ttlSeconds) && candidate.ttlSeconds > 0 &&
    candidate.ttlSeconds <=
      DEPLOYMENT_SAST_QUALIFICATION_LIMITS.maximumMicroVmTtlSeconds &&
    arraysEqual(candidate.forbiddenScannerCapabilities, SCANNER_SANDBOX_FORBIDDEN_CAPABILITIES)
  );
}

export function doesAiPlaneInputRespectRepositoryGuardrails(
  input: unknown
): input is AiPlaneRepositoryAccessBoundary {
  if (!hasExactKeys(input, [
    'advisoryOnly', 'receivesReducedEvidenceOnly', 'requestedDirectInputs'
  ])) return false;
  const candidate = input as unknown as AiPlaneRepositoryAccessBoundary;
  return (
    candidate.advisoryOnly === true && candidate.receivesReducedEvidenceOnly === true &&
    Array.isArray(candidate.requestedDirectInputs) &&
    candidate.requestedDirectInputs.every((requestedInput) =>
      typeof requestedInput === 'string' &&
      !AI_PLANE_FORBIDDEN_DIRECT_INPUTS.some((forbiddenInput) =>
        forbiddenInput === requestedInput
      )
    )
  );
}

export function isDeploymentOperationPreflightReady(
  input: unknown,
  evidence: DeploymentSastQualificationEvidence,
  context: DeploymentSastQualificationVerificationContext
): input is DeploymentOperationPreflight {
  try {
    if (!hasExactKeys(input, PREFLIGHT_KEYS)) return false;
    const candidate = input as unknown as DeploymentOperationPreflight;
    if (
      !Array.isArray(candidate.credentialBoundaries) ||
      !Array.isArray(candidate.operatorApprovals) ||
      !isDeploymentSastQualificationBindingValid(
        candidate.sastQualification, evidence, context
      )
    ) return false;
    const credentialScopes = candidate.credentialBoundaries.map((item) => item.credentialScope);
    const approvalKinds = candidate.operatorApprovals.map((item) => item.approval);
    const requiredRefs = [
      candidate.kmsKeyRef, candidate.secretManagerRef,
      candidate.objectStorageRef, candidate.dnsZoneRef
    ];
    return (
      isProductionClusterProvisioningBoundaryValid(candidate.clusterProvisioning) &&
      isMicroVmPlatformRolloutBoundaryValid(candidate.microVmRollout) &&
      arraysEqual(credentialScopes, DEPLOYMENT_CREDENTIAL_SCOPES) &&
      candidate.credentialBoundaries.every(isDeploymentCredentialBoundaryCompliant) &&
      arraysEqual(approvalKinds, DEPLOYMENT_PREFLIGHT_REQUIRED_APPROVALS) &&
      candidate.operatorApprovals.every((approval) =>
        isDeploymentOperatorApprovalValid(
          approval, candidate.sastQualification, context.trustedEvaluatedAt
        )
      ) &&
      isDeploymentOperationAuditSignalValid(
        candidate.auditSignal, candidate.sastQualification, context.trustedEvaluatedAt
      ) &&
      candidate.clusterProvisioning.provider === candidate.sastQualification.providerId &&
      candidate.microVmRollout.provider === candidate.sastQualification.providerId &&
      candidate.microVmRollout.providerAdapterRef ===
        candidate.sastQualification.providerAdapterRef &&
      candidate.auditSignal.provider === candidate.sastQualification.providerId &&
      candidate.clusterProvisioning.region === candidate.microVmRollout.region &&
      requiredRefs.every(isDigestBoundReference)
    );
  } catch {
    return false;
  }
}

export function isDeploymentOperationHandoffManifestReady(
  input: unknown,
  evidence: DeploymentSastQualificationEvidence,
  context: DeploymentSastQualificationVerificationContext
): input is DeploymentOperationHandoffManifest {
  try {
    if (!hasExactKeys(input, HANDOFF_KEYS)) return false;
    const candidate = input as unknown as DeploymentOperationHandoffManifest;
    if (
      !hasExactKeys(candidate.executionWindow, ['startsAt', 'endsAt']) ||
      !isDeploymentOperationPreflightReady(candidate.preflight, evidence, context) ||
      !DEPLOYMENT_CREDENTIAL_HANDOFF_MODES.includes(candidate.credentialHandoffMode) ||
      !isCanonicalInstant(candidate.executionWindow.startsAt) ||
      !isCanonicalInstant(candidate.executionWindow.endsAt)
    ) return false;
    const startsAt = Date.parse(candidate.executionWindow.startsAt);
    const endsAt = Date.parse(candidate.executionWindow.endsAt);
    const trustedEvaluatedAt = Date.parse(context.trustedEvaluatedAt);
    const qualificationExpiresAt = Date.parse(candidate.preflight.sastQualification.expiresAt);
    return (
      startsAt >= trustedEvaluatedAt && startsAt < qualificationExpiresAt &&
      endsAt > startsAt &&
      endsAt - startsAt <=
        DEPLOYMENT_SAST_QUALIFICATION_LIMITS.maximumExecutionWindowSeconds * 1_000 &&
      candidate.rollbackPlanRef === candidate.preflight.sastQualification.rollbackTargetRef &&
      [candidate.rollbackPlanRef, candidate.incidentChannelRef,
        candidate.dryRunEvidenceRef, candidate.changeTicketRef]
        .every(isDigestBoundReference)
    );
  } catch {
    return false;
  }
}

function isDeploymentOperatorApprovalValid(
  value: unknown,
  binding: DeploymentSastQualificationBinding,
  trustedEvaluatedAt: string
): value is DeploymentOperatorApprovalReference {
  if (!hasExactKeys(value, OPERATOR_APPROVAL_KEYS)) return false;
  const candidate = value as unknown as DeploymentOperatorApprovalReference;
  if (
    !DEPLOYMENT_PREFLIGHT_REQUIRED_APPROVALS.includes(candidate.approval) ||
    !isDigestBoundReference(candidate.approvalRef) ||
    candidate.subjectDigest !== binding.bindingDigest ||
    !isCanonicalInstant(candidate.approvedAt) ||
    !isCanonicalInstant(candidate.validUntil) ||
    !isCanonicalInstant(trustedEvaluatedAt)
  ) return false;
  const approvedAt = Date.parse(candidate.approvedAt);
  const validUntil = Date.parse(candidate.validUntil);
  const trusted = Date.parse(trustedEvaluatedAt);
  return (
    approvedAt >= Date.parse(binding.authorizedAt) && approvedAt <= trusted &&
    validUntil > trusted &&
    validUntil - approvedAt <=
      DEPLOYMENT_SAST_QUALIFICATION_LIMITS.maximumOperatorApprovalValiditySeconds * 1_000
  );
}

function isDeploymentOperationAuditSignalValid(
  value: unknown,
  binding: DeploymentSastQualificationBinding,
  trustedEvaluatedAt: string
): value is DeploymentOperationAuditSignal {
  if (!hasExactKeys(value, AUDIT_SIGNAL_KEYS)) return false;
  const candidate = value as unknown as DeploymentOperationAuditSignal;
  return (
    candidate.environment === 'PRODUCTION' && candidate.provider === binding.providerId &&
    isDigestBoundReference(candidate.operationId) &&
    DEPLOYMENT_OPERATION_ACTORS.includes(candidate.actor) &&
    candidate.targetType === 'SAST_QUALIFICATION_BINDING' &&
    candidate.targetId === binding.bindingId &&
    DEPLOYMENT_OPERATION_EVENT_TYPES.includes(candidate.eventType) &&
    candidate.occurredAt === trustedEvaluatedAt
  );
}

function isQualificationAuthoritySignatureFor(
  signature: unknown,
  payloadDigest: string,
  signedAt: string
): signature is SastEndToEndQualificationSignature {
  return (
    isSastEndToEndQualificationSignatureValid(signature) &&
    signature.role === 'QUALIFICATION_AUTHORITY' &&
    signature.payloadDigest === payloadDigest && signature.signedAt === signedAt
  );
}

function verifyQualificationSignature(
  signature: SastEndToEndQualificationSignature,
  verifySignature: SastEndToEndQualificationSignatureVerifier
): boolean {
  try {
    const payload = serializeSastEndToEndQualificationSignaturePayload(signature);
    return payload !== null && verifySignature(signature, payload);
  } catch {
    return false;
  }
}

function hasExactKeys(
  value: unknown,
  keys: readonly string[]
): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort(compareText);
  const expected = [...keys].sort(compareText);
  return arraysEqual(actual, expected);
}

function isDigestBoundReference(value: unknown): value is string {
  if (
    typeof value !== 'string' || value.length === 0 ||
    new TextEncoder().encode(value).byteLength >
      DEPLOYMENT_SAST_QUALIFICATION_LIMITS.maximumReferenceBytes
  ) return false;
  return /^[a-z][a-z0-9+.-]*:\/\/[A-Za-z0-9][A-Za-z0-9._~:/-]*\/sha256:[a-f0-9]{64}$/u
    .test(value) && hasSafeUriSegments(value);
}

function isProviderIdentity(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 &&
    new TextEncoder().encode(value).byteLength <=
      DEPLOYMENT_SAST_QUALIFICATION_LIMITS.maximumReferenceBytes &&
    /^[a-z][a-z0-9+.-]*:\/\/[A-Za-z0-9][A-Za-z0-9._~:/-]*$/u.test(value) &&
    hasSafeUriSegments(value);
}

function hasSafeUriSegments(value: string): boolean {
  const remainder = value.slice(value.indexOf('://') + 3);
  return remainder.split('/').every((segment) =>
    segment.length > 0 && segment !== '.' && segment !== '..'
  );
}

function isCanonicalInstant(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function isDnsLabel(value: unknown): value is string {
  return typeof value === 'string' &&
    /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(value);
}

function isSafeName(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 255 &&
    /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,253}[A-Za-z0-9])?$/u.test(value);
}

function stripDigest(value: string): string {
  return value.slice('sha256:'.length);
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort(compareText).map((key) =>
      `${JSON.stringify(key)}:${stableJson((value as Record<string, unknown>)[key])}`
    ).join(',')}}`;
  }
  return JSON.stringify(value);
}

function arraysEqual<T>(left: readonly T[], right: readonly T[]): boolean {
  return left.length === right.length && left.every((item, index) => item === right[index]);
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
