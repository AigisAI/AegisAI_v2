import assert from 'node:assert/strict';
import { cp, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import {
  createSupplyChainRollbackQualificationAssets,
  initializeSupplyChainRollbackQualificationAssets
} from '../../tools/sast-qualification/supply-chain-rollback-qualification-assets.mjs';
import {
  SastSupplyChainRollbackQualificationLoadError,
  loadAndValidateSupplyChainRollbackQualificationPackage
} from '../../tools/sast-qualification/supply-chain-rollback-qualification-loader.mjs';

const repositoryRoot = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const canonicalRoot = join(repositoryRoot, 'qualification', 't055-v1');
const EXPECTED_MANIFEST_DIGEST =
  'sha256:662f8c25f9e9a4c236fb170339c7cf8eb13fd73433a0843b6caf00e9d006286e';

test('T055 loader accepts only the exact immutable 169-cell package', async () => {
  const result = await loadAndValidateSupplyChainRollbackQualificationPackage();
  assert.equal(result.executionCellCount, 169);
  assert.equal(result.manifest.cells.length, 169);
  assert.equal(Object.isFrozen(result.manifest), true);
  assert.equal(Object.isFrozen(result.manifest.cells), true);
  assert.equal(Object.isFrozen(result.manifest.cells[0]), true);
  assert.equal(result.qualificationStatus, 'BLOCKED_T054_QUALIFICATION');
  assert.equal(result.t056EntryAuthorized, false);
  assert.equal(result.deploymentAuthority, false);
  assert.equal(result.productionReadinessAuthority, false);
  assert.equal(result.manifestDigest, EXPECTED_MANIFEST_DIGEST);
});

test('T055 generator is deterministic and bootstrap refuses overwrite', async () => {
  const first = createSupplyChainRollbackQualificationAssets();
  const second = createSupplyChainRollbackQualificationAssets();
  assert.equal(first.manifestText, second.manifestText);
  assert.equal(first.drillPolicyText, second.drillPolicyText);
  assert.equal(first.readmeText, second.readmeText);
  await assert.rejects(
    initializeSupplyChainRollbackQualificationAssets(),
    /refusing to overwrite existing T055 qualification root/u
  );
});

test('T055 policy denies local execution and all production authority', () => {
  const policy = createSupplyChainRollbackQualificationAssets().drillPolicy;
  assert.equal(policy.prerequisite.exactT054ResultRequired, true);
  assert.equal(policy.prerequisite.exactT054DependencySetRequired, true);
  assert.equal(
    policy.prerequisite.exactT054ArtifactVerificationSetRequired,
    true
  );
  assert.equal(policy.prerequisite.exactT054PlanRequired, true);
  assert.equal(policy.prerequisite.sameProviderAndAdapterRequired, true);
  assert.equal(
    policy.prerequisite.independentlyConfiguredTrustPolicyDigestRequired,
    true
  );
  assert.equal(policy.execution.readOnlyArtifactMountRequired, true);
  assert.equal(policy.execution.exactSignatureEnvelopeDigestRequired, true);
  assert.equal(policy.execution.exactProvenanceEnvelopeDigestRequired, true);
  assert.equal(policy.execution.aggregateMetricsAcceptedFromCaller, false);
  assert.equal(policy.rollback.appendOnlyActivationLedgerRequired, true);
  for (const value of Object.values(policy.prohibited)) assert.equal(value, false);
  assert.equal(policy.authority.findingAuthority, false);
  assert.equal(policy.authority.policyAuthority, false);
  assert.equal(policy.authority.publicationAuthority, false);
  assert.equal(policy.authority.deploymentAuthority, false);
  assert.equal(policy.authority.kubernetesAuthority, false);
  assert.equal(policy.authority.productionReadinessAuthority, false);
  assert.equal(policy.authority.nextStageAuthorizationOnly, 'T056_ENTRY');
  assert.equal(policy.denominators.totalExecutionCells, 169);
  assert.equal(policy.denominators.preExecutionRejections, 115);
  assert.equal(policy.denominators.artifactInvocations, 39);
});

test('T055 loader rejects manifest, policy, README, and root-entry drift', async (t) => {
  for (const [name, currentText, changedText] of [
    [
      'supply-chain-rollback-qualification.manifest.json',
      '"executionCellCount": 169',
      '"executionCellCount": 168'
    ],
    [
      'drill-policy.json',
      '"localExecutionAllowed": false',
      '"localExecutionAllowed": true'
    ],
    ['README.md', '169 production-equivalent', '168 production-equivalent']
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

test('T055 loader rejects CRLF and linked package entries', async (t) => {
  const crlfRoot = await copyPackage(t);
  const policyPath = join(crlfRoot, 'drill-policy.json');
  const policy = await readFile(policyPath, 'utf8');
  await writeFile(policyPath, policy.replace('\n', '\r\n'), 'utf8');
  await assertLoadError(crlfRoot, 'ASSET_INVALID');

  const linkRoot = await copyPackage(t);
  const manifestPath = join(
    linkRoot,
    'supply-chain-rollback-qualification.manifest.json'
  );
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
  const temporaryRoot = await mkdtemp(join(tmpdir(), 'aegis-t055-package-'));
  const root = join(temporaryRoot, 'qualification');
  await cp(canonicalRoot, root, { recursive: true });
  t.after(() => rm(temporaryRoot, { recursive: true, force: true }));
  const committedManifest = JSON.parse(
    await readFile(
      join(root, 'supply-chain-rollback-qualification.manifest.json'),
      'utf8'
    )
  );
  assert.equal(committedManifest.manifestDigest, EXPECTED_MANIFEST_DIGEST);
  return root;
}

async function assertLoadError(root, reason) {
  await assert.rejects(
    loadAndValidateSupplyChainRollbackQualificationPackage(root),
    (error) =>
      error instanceof SastSupplyChainRollbackQualificationLoadError &&
      error.reason === reason
  );
}
