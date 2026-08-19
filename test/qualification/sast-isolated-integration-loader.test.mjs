import assert from 'node:assert/strict';
import { cp, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import {
  SastIsolatedIntegrationLoadError,
  loadAndValidateIsolatedIntegrationPackage
} from '../../tools/sast-qualification/isolated-integration-loader.mjs';
import {
  createIsolatedIntegrationAssets,
  initializeIsolatedIntegrationAssets
} from '../../tools/sast-qualification/isolated-integration-assets.mjs';

const repositoryRoot = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const canonicalRoot = join(repositoryRoot, 'qualification', 't053-v1');

test('T053 loader accepts the exact immutable provider handoff only', async () => {
  const result = await loadAndValidateIsolatedIntegrationPackage();
  assert.equal(result.executionCellCount, 123);
  assert.equal(result.manifest.cells.length, 123);
  assert.equal(Object.isFrozen(result.manifest), true);
  assert.equal(Object.isFrozen(result.manifest.cells), true);
  assert.equal(Object.isFrozen(result.manifest.cells[0]), true);
  assert.equal(result.providerExecutionStatus, 'PENDING_PROVIDER_EXECUTION');
  assert.equal(result.productionReadinessAuthority, false);
  assert.match(result.manifestDigest, /^sha256:[a-f0-9]{64}$/u);
});

test('T053 generator is deterministic and bootstrap refuses overwrite', async () => {
  const first = createIsolatedIntegrationAssets();
  const second = createIsolatedIntegrationAssets();
  assert.equal(first.manifestText, second.manifestText);
  assert.equal(first.materializationPolicyText, second.materializationPolicyText);
  assert.equal(first.readmeText, second.readmeText);
  await assert.rejects(
    initializeIsolatedIntegrationAssets(),
    /refusing to overwrite existing T053 qualification root/u
  );
});

test('T053 materialization policy is closed and grants no local execution authority', () => {
  const policy = createIsolatedIntegrationAssets().materializationPolicy;
  assert.deepEqual(policy.allowedActions, [
    'EMIT_ARTIFACT_BYTES',
    'DECLARE_TREE_ENTRY',
    'DECLARE_SYMLINK',
    'DECLARE_SPECIAL_ENTRY',
    'DECLARE_SCANNER_OUTPUT',
    'ASSERT_NO_EGRESS',
    'ASSERT_NO_EXECUTION',
    'ASSERT_NO_SECRET_LEAK',
    'ASSERT_NO_AUTHORITY'
  ]);
  for (const field of [
    'generalCommandInterpreterAllowed',
    'argvAllowed',
    'environmentAllowed',
    'scriptAllowed',
    'urlInputAllowed',
    'customerContentAccepted',
    'scmCredentialIssued',
    'packageInstallAllowed',
    'repositoryBuildAllowed',
    'dynamicTestAllowed',
    'hostMaterializationAllowed',
    'publicInternetEgressAllowed',
    'sandboxReuseAllowed',
    'localExecutionAllowed',
    'productionReadinessAuthority'
  ]) {
    assert.equal(policy[field], false, field);
  }
  assert.equal(policy.guestMicroVmMaterializationRequired, true);
  assert.equal(policy.oneFreshMicroVmPerCell, true);
});

test('T053 loader rejects manifest, policy, and README byte drift', async (t) => {
  for (const [name, currentText, changedText] of [
    [
      'isolated-integration.manifest.json',
      '"executionCellCount": 123',
      '"executionCellCount": 122'
    ],
    [
      'materialization-policy.json',
      '"localExecutionAllowed": false',
      '"localExecutionAllowed": true'
    ],
    ['README.md', '123 execution cells', '122 execution cells']
  ]) {
    const root = await copyPackage(t);
    const path = join(root, name);
    const text = await readFile(path, 'utf8');
    const changed = text.replace(currentText, changedText);
    assert.notEqual(changed, text);
    await writeFile(path, changed, 'utf8');
    await assertLoadError(root, 'ASSET_DRIFT');
  }
});

test('T053 loader rejects missing, extra, noncanonical, and linked entries', async (t) => {
  const missingRoot = await copyPackage(t);
  await rm(join(missingRoot, 'README.md'));
  await assertLoadError(missingRoot, 'ROOT_ENTRIES_INVALID');

  const extraRoot = await copyPackage(t);
  await writeFile(join(extraRoot, 'extra.json'), '{}\n', 'utf8');
  await assertLoadError(extraRoot, 'ROOT_ENTRIES_INVALID');

  const crlfRoot = await copyPackage(t);
  const policyPath = join(crlfRoot, 'materialization-policy.json');
  const policy = await readFile(policyPath, 'utf8');
  await writeFile(policyPath, policy.replace('\n', '\r\n'), 'utf8');
  await assertLoadError(crlfRoot, 'ASSET_INVALID');

  const linkRoot = await copyPackage(t);
  const manifestPath = join(linkRoot, 'isolated-integration.manifest.json');
  await rm(manifestPath);
  try {
    await symlink(join(linkRoot, 'README.md'), manifestPath, 'file');
  } catch (error) {
    if (error?.code === 'EPERM' || error?.code === 'EACCES') {
      t.diagnostic(`symlink creation is unavailable: ${error.code}`);
      return;
    }
    throw error;
  }
  await assertLoadError(linkRoot, 'ROOT_ENTRIES_INVALID');
});

async function copyPackage(t) {
  const temporaryRoot = await mkdtemp(join(tmpdir(), 'aegis-t053-package-'));
  const root = join(temporaryRoot, 'qualification');
  await cp(canonicalRoot, root, { recursive: true });
  t.after(() => rm(temporaryRoot, { recursive: true, force: true }));
  return root;
}

async function assertLoadError(root, reason) {
  await assert.rejects(
    loadAndValidateIsolatedIntegrationPackage(root),
    (error) =>
      error instanceof SastIsolatedIntegrationLoadError && error.reason === reason
  );
}
