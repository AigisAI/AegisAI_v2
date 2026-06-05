import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import test from 'node:test';

const contractFile = new URL('../src/types/deployment-operations.ts', import.meta.url);

const readContract = () => readFileSync(contractFile, 'utf8');

test('production deployment operations shared contracts define cluster provisioning boundaries', () => {
  assert.equal(existsSync(contractFile), true);

  const contract = readContract();

  for (const exportName of [
    'PRODUCTION_DEPLOYMENT_OPERATIONS_FEATURE_ID',
    'ProductionClusterProvisioning',
    'DeploymentCredentialBoundary',
    'DeploymentOperationAuditSignal',
    'isProductionClusterProvisioningBoundaryValid',
    'isDeploymentCredentialBoundaryCompliant'
  ]) {
    assert.match(contract, new RegExp(`export (interface|const|type|function) ${exportName}\\b`));
  }

  for (const requiredField of [
    'controlPlaneNamespace',
    'scanPlaneNamespace',
    'aiPlaneNamespace',
    'dataSecurityNamespace',
    'networkBoundaryRefs',
    'auditSinkRef'
  ]) {
    assert.match(contract, new RegExp(`\\b${requiredField}\\b`));
  }

  assert.match(contract, /environment:\s*'PRODUCTION'/);
});

test('deployment credential contracts cannot become local defaults or repository-persisted secrets', () => {
  assert.equal(existsSync(contractFile), true);

  const contract = readContract();

  assert.match(contract, /allowedUse:\s*'EXPLICIT_DEPLOYMENT_OPERATION'/);
  assert.match(contract, /localDevelopmentDefault:\s*false/);
  assert.match(contract, /repositoryPersisted:\s*false/);
  assert.match(contract, /rotationRequired:\s*true/);
  assert.match(contract, /auditRequired:\s*true/);

  for (const forbiddenField of [
    'credentialValue',
    'providerSecretValue',
    'accessKey',
    'secretAccessKey',
    'privateKey',
    'kubeconfig',
    'token'
  ]) {
    assert.doesNotMatch(contract, new RegExp(`\\b${forbiddenField}\\b`, 'i'));
  }
});

test('microVM rollout contracts preserve scanner sandbox isolation boundaries', () => {
  assert.equal(existsSync(contractFile), true);

  const contract = readContract();

  for (const exportName of [
    'MICROVM_ISOLATION_CLASSES',
    'SCANNER_SANDBOX_FORBIDDEN_CAPABILITIES',
    'MicroVmPlatformRollout',
    'isMicroVmPlatformRolloutBoundaryValid'
  ]) {
    assert.match(contract, new RegExp(`export (interface|const|type|function) ${exportName}\\b`));
  }

  for (const requiredField of [
    'scannerSandboxProfileRef',
    'tokenBrokerRef',
    'evidenceStorageRef',
    'egressPolicyRef',
    'ttlSeconds'
  ]) {
    assert.match(contract, new RegExp(`\\b${requiredField}\\b`));
  }

  assert.match(contract, /isolationClass:\s*MicroVmIsolationClass/);
  assert.match(contract, /'HARDENED'/);
  assert.match(contract, /'RESTRICTED'/);

  for (const forbiddenCapability of [
    'PACKAGE_INSTALL',
    'CUSTOMER_REPOSITORY_BUILD',
    'DYNAMIC_TEST_EXECUTION',
    'DIRECT_SOURCE_UPLOAD',
    'AUTO_FIX_PULL_REQUEST'
  ]) {
    assert.match(contract, new RegExp(`'${forbiddenCapability}'`));
  }
});

test('microVM rollout contracts keep AI plane away from repository and raw scanner inputs', () => {
  assert.equal(existsSync(contractFile), true);

  const contract = readContract();

  for (const exportName of [
    'AI_PLANE_FORBIDDEN_DIRECT_INPUTS',
    'AiPlaneRepositoryAccessBoundary',
    'doesAiPlaneInputRespectRepositoryGuardrails'
  ]) {
    assert.match(contract, new RegExp(`export (interface|const|type|function) ${exportName}\\b`));
  }

  for (const forbiddenInput of [
    'SCM_CREDENTIAL',
    'FULL_REPOSITORY',
    'SOURCE_ARCHIVE',
    'RAW_SCANNER_PAYLOAD'
  ]) {
    assert.match(contract, new RegExp(`'${forbiddenInput}'`));
  }

  assert.match(contract, /advisoryOnly:\s*true/);
  assert.match(contract, /receivesReducedEvidenceOnly:\s*true/);
});

test('deployment operation preflight contracts require explicit production execution inputs', () => {
  assert.equal(existsSync(contractFile), true);

  const contract = readContract();

  for (const exportName of [
    'DEPLOYMENT_PREFLIGHT_REQUIRED_APPROVALS',
    'DeploymentOperationPreflight',
    'isDeploymentOperationPreflightReady'
  ]) {
    assert.match(contract, new RegExp(`export (interface|const|type|function) ${exportName}\\b`));
  }

  for (const requiredField of [
    'clusterProvisioning',
    'microVmRollout',
    'credentialBoundary',
    'auditSignal',
    'operatorApprovalRefs',
    'kmsKeyRef',
    'secretManagerRef',
    'objectStorageRef',
    'dnsZoneRef'
  ]) {
    assert.match(contract, new RegExp(`\\b${requiredField}\\b`));
  }

  for (const requiredApproval of [
    'PRODUCTION_CHANGE_APPROVAL',
    'SECURITY_BOUNDARY_APPROVAL',
    'CREDENTIAL_HANDOFF_APPROVAL'
  ]) {
    assert.match(contract, new RegExp(`'${requiredApproval}'`));
  }
});

test('deployment operation preflight contracts reject persisted secrets and forbidden payload inputs', () => {
  assert.equal(existsSync(contractFile), true);

  const contract = readContract();

  for (const forbiddenField of [
    'credentialValue',
    'providerSecretValue',
    'accessKey',
    'secretAccessKey',
    'privateKey',
    'kubeconfig',
    'scmToken',
    'fullRepository',
    'sourceArchive',
    'rawScannerPayload'
  ]) {
    assert.doesNotMatch(contract, new RegExp(`\\b${forbiddenField}\\b`, 'i'));
  }

  assert.match(contract, /isDeploymentCredentialBoundaryCompliant/);
  assert.match(contract, /isProductionClusterProvisioningBoundaryValid/);
  assert.match(contract, /isMicroVmPlatformRolloutBoundaryValid/);
  assert.match(contract, /allowedUse\s*===\s*'EXPLICIT_DEPLOYMENT_OPERATION'/);
});

test('deployment handoff manifests connect preflight evidence to live operation controls', () => {
  assert.equal(existsSync(contractFile), true);

  const contract = readContract();

  for (const exportName of [
    'DEPLOYMENT_CREDENTIAL_HANDOFF_MODES',
    'DeploymentOperationHandoffManifest',
    'isDeploymentOperationHandoffManifestReady'
  ]) {
    assert.match(contract, new RegExp(`export (interface|const|type|function) ${exportName}\\b`));
  }

  for (const requiredField of [
    'preflight',
    'credentialHandoffMode',
    'executionWindow',
    'startsAt',
    'endsAt',
    'rollbackPlanRef',
    'incidentChannelRef',
    'dryRunEvidenceRef',
    'changeTicketRef'
  ]) {
    assert.match(contract, new RegExp(`\\b${requiredField}\\b`));
  }

  for (const handoffMode of [
    'EXTERNAL_SECRET_MANAGER_REFERENCE',
    'EPHEMERAL_OIDC_FEDERATION'
  ]) {
    assert.match(contract, new RegExp(`'${handoffMode}'`));
  }
});

test('deployment handoff manifests remain reference-only and cannot carry secrets or repositories', () => {
  assert.equal(existsSync(contractFile), true);

  const contract = readContract();

  for (const forbiddenField of [
    'credentialValue',
    'providerSecretValue',
    'accessKey',
    'secretAccessKey',
    'privateKey',
    'kubeconfig',
    'scmToken',
    'fullRepository',
    'sourceArchive',
    'rawScannerPayload'
  ]) {
    assert.doesNotMatch(contract, new RegExp(`\\b${forbiddenField}\\b`, 'i'));
  }

  assert.match(contract, /isDeploymentOperationPreflightReady/);
  assert.match(contract, /DEPLOYMENT_CREDENTIAL_HANDOFF_MODES\.includes/);
});
