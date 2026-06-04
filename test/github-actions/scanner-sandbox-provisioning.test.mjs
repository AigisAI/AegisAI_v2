import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import test from 'node:test';

const contractFile = new URL('../../deploy/scanner-sandbox/provisioning-contract.json', import.meta.url);
const forbiddenSecretFields = ['tokenValue', 'secretValue', 'accessToken', 'refreshToken', 'privateKey'];

const readContract = () => JSON.parse(readFileSync(contractFile, 'utf8'));

test('microVM scanner sandbox provisioning contract defines stronger-than-pod scan isolation', () => {
  assert.equal(existsSync(contractFile), true, `Expected scanner sandbox contract at ${contractFile.pathname}`);

  const contract = readContract();

  assert.equal(contract.kind, 'ScannerSandboxProvisioning');
  assert.equal(contract.sandboxProvider, 'MICROVM');
  assert.deepEqual(contract.supportedIsolationClasses, ['HARDENED', 'RESTRICTED']);
  assert.equal(contract.defaultIsolationClass, 'HARDENED');
  assert.equal(contract.ttlSeconds, 900);
  assert.equal(contract.networkEgressPolicy, 'SCM_AND_SCANNER_UPDATES_ONLY');
  assert.equal(contract.repositoryAccess.principal, 'REPO_READ');
  assert.equal(contract.repositoryAccess.tokenScope, 'tenant-repository-scan');
  assert.equal(contract.repositoryAccess.shortLived, true);
  assert.equal(contract.repositoryAccess.persistTokenValue, false);
  assert.equal(contract.evidenceHandoff.targetPlane, 'DATA_SECURITY_PLANE');
  assert.equal(contract.evidenceHandoff.output, 'redacted-evidence-pack-metadata');
});

test('microVM scanner sandbox forbids package install, builds, dynamic tests, direct upload, and AI repository access', () => {
  const contract = readContract();

  assert.deepEqual(contract.allowedOperations, [
    'SCAN_SCOPED_REPOSITORY_FETCH',
    'STATIC_SCANNER_RUN',
    'NORMALIZED_FINDING_OUTPUT',
    'REDACTED_EVIDENCE_PACK_BUILD'
  ]);
  assert.deepEqual(contract.forbiddenOperations, [
    'PACKAGE_INSTALL',
    'CUSTOMER_REPOSITORY_BUILD',
    'DYNAMIC_TESTING',
    'DIRECT_SOURCE_UPLOAD',
    'AI_FULL_REPOSITORY_ACCESS',
    'AUTO_FIX_PR_OR_MR'
  ]);

  for (const forbiddenOperation of contract.forbiddenOperations) {
    assert.equal(
      contract.allowedOperations.includes(forbiddenOperation),
      false,
      `Forbidden operation ${forbiddenOperation} must not be allowed`
    );
  }

  assert.equal(contract.aiPlaneAccess.fullRepository, false);
  assert.equal(contract.aiPlaneAccess.sourceArchive, false);
  assert.equal(contract.aiPlaneAccess.scmCredentials, false);
  assert.equal(contract.aiPlaneAccess.rawScannerPayload, false);
  assert.equal(contract.aiPlaneAccess.reducedEvidenceOnly, true);
  for (const forbiddenField of forbiddenSecretFields) {
    assert.equal(forbiddenField in contract.repositoryAccess, false);
  }
});
