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
