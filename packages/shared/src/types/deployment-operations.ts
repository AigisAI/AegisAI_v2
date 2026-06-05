export const PRODUCTION_DEPLOYMENT_OPERATIONS_FEATURE_ID = '005-production-deployment-operations';

export const DEPLOYMENT_ENVIRONMENTS = ['PRODUCTION'] as const;
export type DeploymentEnvironment = (typeof DEPLOYMENT_ENVIRONMENTS)[number];

export const DEPLOYMENT_CREDENTIAL_SCOPES = [
  'CLUSTER_ADMIN',
  'MICROVM_PLATFORM_ADMIN',
  'SECRET_MANAGER_ADMIN'
] as const;
export type DeploymentCredentialScope = (typeof DEPLOYMENT_CREDENTIAL_SCOPES)[number];

export const DEPLOYMENT_CREDENTIAL_ALLOWED_USES = ['EXPLICIT_DEPLOYMENT_OPERATION'] as const;
export type DeploymentCredentialAllowedUse = (typeof DEPLOYMENT_CREDENTIAL_ALLOWED_USES)[number];

export const DEPLOYMENT_OPERATION_ACTORS = [
  'DEPLOYMENT_OPERATOR',
  'CONTROL_PLANE',
  'DATA_SECURITY_PLANE'
] as const;
export type DeploymentOperationActor = (typeof DEPLOYMENT_OPERATION_ACTORS)[number];

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
export type AiPlaneForbiddenDirectInput = (typeof AI_PLANE_FORBIDDEN_DIRECT_INPUTS)[number];

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
  targetType: string;
  targetId: string;
  eventType: string;
  metadata?: Record<string, unknown>;
  occurredAt: string;
}

export interface MicroVmPlatformRollout {
  provider: string;
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

export interface DeploymentOperationPreflight {
  clusterProvisioning: ProductionClusterProvisioning;
  microVmRollout: MicroVmPlatformRollout;
  credentialBoundary: DeploymentCredentialBoundary;
  auditSignal: DeploymentOperationAuditSignal;
  operatorApprovalRefs: DeploymentPreflightRequiredApproval[];
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

export function isProductionClusterProvisioningBoundaryValid(
  input: ProductionClusterProvisioning
): boolean {
  const namespaces = [
    input.controlPlaneNamespace,
    input.scanPlaneNamespace,
    input.aiPlaneNamespace,
    input.dataSecurityNamespace
  ];

  return (
    input.environment === 'PRODUCTION' &&
    namespaces.every((namespace) => namespace.length > 0) &&
    new Set(namespaces).size === namespaces.length &&
    input.networkBoundaryRefs.length > 0 &&
    input.auditSinkRef.length > 0
  );
}

export function isDeploymentCredentialBoundaryCompliant(
  input: DeploymentCredentialBoundary
): boolean {
  return (
    input.allowedUse === 'EXPLICIT_DEPLOYMENT_OPERATION' &&
    input.localDevelopmentDefault === false &&
    input.repositoryPersisted === false &&
    input.rotationRequired === true &&
    input.auditRequired === true
  );
}

export function isMicroVmPlatformRolloutBoundaryValid(input: MicroVmPlatformRollout): boolean {
  const requiredRefs = [
    input.scannerSandboxProfileRef,
    input.tokenBrokerRef,
    input.evidenceStorageRef,
    input.egressPolicyRef
  ];

  const includesForbiddenCapability = SCANNER_SANDBOX_FORBIDDEN_CAPABILITIES.every((capability) =>
    input.forbiddenScannerCapabilities.includes(capability)
  );

  return (
    MICROVM_ISOLATION_CLASSES.includes(input.isolationClass) &&
    requiredRefs.every((ref) => ref.length > 0) &&
    input.ttlSeconds > 0 &&
    includesForbiddenCapability
  );
}

export function doesAiPlaneInputRespectRepositoryGuardrails(
  input: AiPlaneRepositoryAccessBoundary
): boolean {
  return (
    input.advisoryOnly === true &&
    input.receivesReducedEvidenceOnly === true &&
    input.requestedDirectInputs.every(
      (requestedInput) =>
        !AI_PLANE_FORBIDDEN_DIRECT_INPUTS.some(
          (forbiddenInput) => forbiddenInput === requestedInput
        )
    )
  );
}

export function isDeploymentOperationPreflightReady(
  input: DeploymentOperationPreflight
): boolean {
  const requiredRefs = [
    input.kmsKeyRef,
    input.secretManagerRef,
    input.objectStorageRef,
    input.dnsZoneRef
  ];

  const hasRequiredApprovals = DEPLOYMENT_PREFLIGHT_REQUIRED_APPROVALS.every((approval) =>
    input.operatorApprovalRefs.includes(approval)
  );

  return (
    isProductionClusterProvisioningBoundaryValid(input.clusterProvisioning) &&
    isMicroVmPlatformRolloutBoundaryValid(input.microVmRollout) &&
    isDeploymentCredentialBoundaryCompliant(input.credentialBoundary) &&
    input.credentialBoundary.allowedUse === 'EXPLICIT_DEPLOYMENT_OPERATION' &&
    input.auditSignal.environment === 'PRODUCTION' &&
    requiredRefs.every((ref) => ref.length > 0) &&
    hasRequiredApprovals
  );
}

export function isDeploymentOperationHandoffManifestReady(
  input: DeploymentOperationHandoffManifest
): boolean {
  const requiredRefs = [
    input.rollbackPlanRef,
    input.incidentChannelRef,
    input.dryRunEvidenceRef,
    input.changeTicketRef
  ];

  return (
    isDeploymentOperationPreflightReady(input.preflight) &&
    DEPLOYMENT_CREDENTIAL_HANDOFF_MODES.includes(input.credentialHandoffMode) &&
    input.executionWindow.startsAt.length > 0 &&
    input.executionWindow.endsAt.length > 0 &&
    requiredRefs.every((ref) => ref.length > 0)
  );
}
