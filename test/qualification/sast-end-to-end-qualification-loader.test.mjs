import assert from 'node:assert/strict';
import { cp, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import {
  SastEndToEndQualificationLoadError,
  loadAndValidateEndToEndQualificationPackage
} from '../../tools/sast-qualification/end-to-end-qualification-loader.mjs';
import {
  createEndToEndQualificationAssets,
  initializeEndToEndQualificationAssets
} from '../../tools/sast-qualification/end-to-end-qualification-assets.mjs';

const repositoryRoot = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const canonicalRoot = join(repositoryRoot, 'qualification', 't054-v1');
const EXPECTED_MANIFEST_DIGEST =
  'sha256:1ff4e71b5a04c6098c5851f6b8146db70961e4246ae0329814533f2550b68741';

test('T054 loader accepts only the exact immutable 3,462-cell package', async () => {
  const result = await loadAndValidateEndToEndQualificationPackage();
  assert.equal(result.executionCellCount, 3462);
  assert.equal(result.manifest.cells.length, 3462);
  assert.equal(Object.isFrozen(result.manifest), true);
  assert.equal(Object.isFrozen(result.manifest.cells), true);
  assert.equal(Object.isFrozen(result.manifest.cells[0]), true);
  assert.equal(result.qualificationStatus, 'BLOCKED_T053_QUALIFICATION');
  assert.equal(result.t055EntryAuthorized, false);
  assert.equal(result.productionReadinessAuthority, false);
  assert.equal(result.manifestDigest, EXPECTED_MANIFEST_DIGEST);
});

test('T054 generator is deterministic and bootstrap refuses overwrite', async () => {
  const first = createEndToEndQualificationAssets();
  const second = createEndToEndQualificationAssets();
  assert.equal(first.manifestText, second.manifestText);
  assert.equal(first.measurementPolicyText, second.measurementPolicyText);
  assert.equal(first.readmeText, second.readmeText);
  await assert.rejects(
    initializeEndToEndQualificationAssets(),
    /refusing to overwrite existing T054 qualification root/u
  );
});

test('T054 policy denies local execution and every production authority', () => {
  const policy = createEndToEndQualificationAssets().measurementPolicy;
  assert.equal(policy.execution.aggregateMetricsAcceptedFromCaller, false);
  assert.equal(policy.prohibited.localExecutionAllowed, false);
  for (const value of Object.values(policy.prohibited)) assert.equal(value, false);
  for (const value of Object.values(policy.authority)) assert.equal(value, false);
  assert.equal(policy.denominators.totalExecutionCells, 3462);
  assert.equal(policy.denominators.performanceRunsPerArmBucket, 30);
});

test('T054 loader rejects manifest, policy, README, and root-entry drift', async (t) => {
  for (const [name, currentText, changedText] of [
    [
      'end-to-end-qualification.manifest.json',
      '"executionCellCount": 3462',
      '"executionCellCount": 3461'
    ],
    [
      'measurement-policy.json',
      '"localExecutionAllowed": false',
      '"localExecutionAllowed": true'
    ],
    ['README.md', '3,462', '3,461']
  ]) {
    const root = await copyPackage(t);
    const path = join(root, name);
    const text = await readFile(path, 'utf8');
    const changed = text.replace(currentText, changedText);
    assert.notEqual(changed, text);
    await writeFile(path, changed, 'utf8');
    await assertLoadError(root, 'ASSET_DRIFT');
  }

  const missingRoot = await copyPackage(t);
  await rm(join(missingRoot, 'README.md'));
  await assertLoadError(missingRoot, 'ROOT_ENTRIES_INVALID');

  const extraRoot = await copyPackage(t);
  await writeFile(join(extraRoot, 'extra.json'), '{}\n', 'utf8');
  await assertLoadError(extraRoot, 'ROOT_ENTRIES_INVALID');
});

test('T054 loader rejects CRLF and linked package entries', async (t) => {
  const crlfRoot = await copyPackage(t);
  const policyPath = join(crlfRoot, 'measurement-policy.json');
  const policy = await readFile(policyPath, 'utf8');
  await writeFile(policyPath, policy.replace('\n', '\r\n'), 'utf8');
  await assertLoadError(crlfRoot, 'ASSET_INVALID');

  const linkRoot = await copyPackage(t);
  const manifestPath = join(linkRoot, 'end-to-end-qualification.manifest.json');
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
  const temporaryRoot = await mkdtemp(join(tmpdir(), 'aegis-t054-package-'));
  const root = join(temporaryRoot, 'qualification');
  await cp(canonicalRoot, root, { recursive: true });
  t.after(() => rm(temporaryRoot, { recursive: true, force: true }));
  const committedManifest = JSON.parse(
    await readFile(join(root, 'end-to-end-qualification.manifest.json'), 'utf8')
  );
  assert.equal(committedManifest.manifestDigest, EXPECTED_MANIFEST_DIGEST);
  return root;
}

async function assertLoadError(root, reason) {
  await assert.rejects(
    loadAndValidateEndToEndQualificationPackage(root),
    (error) =>
      error instanceof SastEndToEndQualificationLoadError && error.reason === reason
  );
}
