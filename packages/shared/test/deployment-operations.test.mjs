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
