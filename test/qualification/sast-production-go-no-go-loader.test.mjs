import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { cp, link, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import {
  createProductionGoNoGoAssets,
  initializeProductionGoNoGoAssets
} from '../../tools/sast-qualification/production-go-no-go-assets.mjs';
import {
  SastProductionGoNoGoLoadError,
  loadAndValidateProductionGoNoGoPackage
} from '../../tools/sast-qualification/production-go-no-go-loader.mjs';

const repositoryRoot = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const canonicalRoot = join(repositoryRoot, 'qualification', 't056-v1');
const EXPECTED_MANIFEST_DIGEST =
  'sha256:d14e1ebaa1cc624b735ea9f22bab096f750cff4cad34faff908d1408f4d9a71d';

test('T056 loader accepts only the exact immutable 54-gate package', async () => {
  const result = await loadAndValidateProductionGoNoGoPackage();
  assert.equal(result.gateCount, 54);
  assert.equal(result.manifest.gates.length, 54);
  assert.equal(Object.isFrozen(result.manifest), true);
  assert.equal(Object.isFrozen(result.manifest.gates), true);
  assert.equal(Object.isFrozen(result.manifest.gates[0]), true);
  assert.equal(result.qualificationStatus, 'BLOCKED_T055_QUALIFICATION');
  assert.equal(result.deploymentOperationsEntryAuthorized, false);
  assert.equal(result.deploymentAuthority, false);
  assert.equal(result.kubernetesExecutionAuthority, false);
  assert.equal(result.productionReadinessAuthority, false);
  assert.equal(result.manifestDigest, EXPECTED_MANIFEST_DIGEST);
});

test('T056 generator is deterministic and bootstrap refuses overwrite', async () => {
  const first = createProductionGoNoGoAssets();
  const second = createProductionGoNoGoAssets();
  assert.equal(first.manifestText, second.manifestText);
  assert.equal(first.policyText, second.policyText);
  assert.equal(first.readmeText, second.readmeText);
  assert.equal(existsSync(canonicalRoot), true);
  await assert.rejects(
    initializeProductionGoNoGoAssets(),
    /refusing to overwrite existing T056 qualification root/u
  );
});

test('T056 loader rejects oversized and hard-linked package entries', async (t) => {
  const oversizedRoot = await copyPackage(t);
  await writeFile(
    join(oversizedRoot, 'go-no-go-policy.json'),
    'x'.repeat(256 * 1024 + 1),
    'utf8'
  );
  await assertLoadError(oversizedRoot, 'ASSET_INVALID');

  const hardLinkRoot = await copyPackage(t);
  const manifestPath = join(hardLinkRoot, 'production-go-no-go.manifest.json');
  await rm(manifestPath);
  try {
    await link(join(hardLinkRoot, 'README.md'), manifestPath);
  } catch (error) {
    if (error?.code === 'EPERM' || error?.code === 'EACCES') {
      t.diagnostic(`hard-link creation is unavailable: ${error.code}`);
      return;
    }
    throw error;
  }
  await assertLoadError(hardLinkRoot, 'ASSET_INVALID');
});

test('T056 policy makes every gate mandatory and grants no production authority', () => {
  const policy = createProductionGoNoGoAssets().policy;
  assert.equal(policy.prerequisite.requiredStatus, 'PASSED');
  assert.equal(policy.prerequisite.requiredEntryAuthorization, 't056EntryAuthorized');
  assert.equal(
    policy.prerequisite.independentlyConfiguredTrustPolicyDigestRequired,
    true
  );
  assert.equal(policy.evidence.aggregateDecisionAcceptedFromCaller, false);
  assert.equal(policy.evidence.callerSelectedEvaluationTimeAllowed, false);
  assert.equal(policy.evidence.notApplicableAllowedForV1, false);
  assert.equal(policy.evidence.missingCategoryOutcome, 'PENDING_FINAL_EVIDENCE');
  assert.equal(policy.evidence.malformedStaleOrBreachedOutcome, 'NO_GO');
  assert.equal(policy.gateCatalog.length, 54);
  assert.ok(policy.gateCatalog.every((gate) => gate.notApplicableAllowed === false));
  assert.equal(policy.handoff.goAuthorizesOnly, 'DEPLOYMENT_OPERATIONS_ENTRY');
  assert.equal(policy.handoff.passingDoesNotExecuteKubernetes, true);
  assert.equal(policy.handoff.passingDoesNotEstablishProductionReadiness, true);
  for (const value of Object.values(policy.prohibited)) assert.equal(value, false);
  for (const [name, value] of Object.entries(policy.authority)) {
    if (name === 'goAuthorizationOnly') {
      assert.equal(value, '005_DEPLOYMENT_OPERATIONS_ENTRY');
    } else {
      assert.equal(value, false);
    }
  }
});

test('T056 loader rejects manifest, policy, README, and root-entry drift', async (t) => {
  for (const [name, currentText, changedText] of [
    [
      'production-go-no-go.manifest.json',
      '"requiredGateCount": 54',
      '"requiredGateCount": 53'
    ],
    [
      'go-no-go-policy.json',
      '"kubernetesExecutionAllowed": false',
      '"kubernetesExecutionAllowed": true'
    ],
    ['README.md', '54\nrelease-blocking gates', '53\nrelease-blocking gates']
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

test('T056 loader rejects CRLF and linked package entries', async (t) => {
  const crlfRoot = await copyPackage(t);
  const policyPath = join(crlfRoot, 'go-no-go-policy.json');
  const policy = await readFile(policyPath, 'utf8');
  await writeFile(policyPath, policy.replace('\n', '\r\n'), 'utf8');
  await assertLoadError(crlfRoot, 'ASSET_INVALID');

  const linkRoot = await copyPackage(t);
  const manifestPath = join(linkRoot, 'production-go-no-go.manifest.json');
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
  const temporaryRoot = await mkdtemp(join(tmpdir(), 'aegis-t056-package-'));
  const root = join(temporaryRoot, 'qualification');
  await cp(canonicalRoot, root, { recursive: true });
  t.after(() => rm(temporaryRoot, { recursive: true, force: true }));
  const committedManifest = JSON.parse(
    await readFile(join(root, 'production-go-no-go.manifest.json'), 'utf8')
  );
  assert.equal(committedManifest.manifestDigest, EXPECTED_MANIFEST_DIGEST);
  return root;
}

async function assertLoadError(root, reason) {
  await assert.rejects(
    loadAndValidateProductionGoNoGoPackage(root),
    (error) =>
      error instanceof SastProductionGoNoGoLoadError && error.reason === reason
  );
}
