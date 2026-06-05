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
