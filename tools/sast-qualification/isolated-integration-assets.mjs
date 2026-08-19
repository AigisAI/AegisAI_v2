import { createHash } from 'node:crypto';
import { constants, readFileSync } from 'node:fs';
import { lstat, mkdir, open, readdir, realpath } from 'node:fs/promises';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  buildSastIsolatedQualificationManifest
} from '../../packages/shared/dist/index.js';
import { createMultiClassCorpusAssets } from './multi-class-corpus-assets.mjs';

const MODULE_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(MODULE_DIRECTORY, '../..');
export const ISOLATED_INTEGRATION_ROOT = resolve(
  REPOSITORY_ROOT,
  'qualification/t053-v1'
);
export const ISOLATED_INTEGRATION_MANIFEST_PATH = join(
  ISOLATED_INTEGRATION_ROOT,
  'isolated-integration.manifest.json'
);
export const ISOLATED_INTEGRATION_POLICY_PATH = join(
  ISOLATED_INTEGRATION_ROOT,
  'materialization-policy.json'
);
const PROVISIONING_CONTRACT_PATH = resolve(
  REPOSITORY_ROOT,
  'deploy/scanner-sandbox/provisioning-contract.json'
);
const REVISION = '1.0.0';
const PUBLISHED_AT = '2026-08-20T00:00:00.000Z';
const OWNER_REF = 'team://security-engineering/sast-qualification';
const EXPECTED_ROOT_ENTRIES = [
  'README.md',
  'isolated-integration.manifest.json',
  'materialization-policy.json'
];

const MATERIALIZATION_POLICY = Object.freeze({
  version: 'sast-isolated-integration-materialization-policy-v1',
  revision: REVISION,
  ownerRef: OWNER_REF,
  sourceCorpusRevision: '1.0.2',
  evidenceStage: 'T053_ISOLATED_INTEGRATION',
  allowedCorpusClasses: ['SCHEMA_PARSER', 'MALICIOUS_REPOSITORY'],
  allowedMaterializationKinds: ['ARTIFACT_STREAM', 'REPOSITORY_RECIPE'],
  allowedActions: [
    'EMIT_ARTIFACT_BYTES',
    'DECLARE_TREE_ENTRY',
    'DECLARE_SYMLINK',
    'DECLARE_SPECIAL_ENTRY',
    'DECLARE_SCANNER_OUTPUT',
    'ASSERT_NO_EGRESS',
    'ASSERT_NO_EXECUTION',
    'ASSERT_NO_SECRET_LEAK',
    'ASSERT_NO_AUTHORITY'
  ],
  selectionSource: 'BOUND_FIXTURE_AND_CASE_PROFILE_ONLY',
  scenarioNameBranchingAllowed: false,
  generalCommandInterpreterAllowed: false,
  argvAllowed: false,
  environmentAllowed: false,
  scriptAllowed: false,
  urlInputAllowed: false,
  customerContentAccepted: false,
  scmCredentialIssued: false,
  packageInstallAllowed: false,
  repositoryBuildAllowed: false,
  dynamicTestAllowed: false,
  hostMaterializationAllowed: false,
  guestMicroVmMaterializationRequired: true,
  productionEquivalentProviderRequired: true,
  oneFreshMicroVmPerCell: true,
  sandboxReuseAllowed: false,
  publicInternetEgressAllowed: false,
  cleanupSloSeconds: 60,
  providerAndRuntimeSignaturesRequired: true,
  localExecutionAllowed: false,
  productionReadinessAuthority: false,
  immutable: true
});

export function createIsolatedIntegrationAssets() {
  const sourceAssets = createMultiClassCorpusAssets();
  const sourceFixtures = [...sourceAssets.fixtures.values()].map((text) =>
    JSON.parse(text)
  );
  const materializationPolicyText = `${JSON.stringify(
    MATERIALIZATION_POLICY,
    null,
    2
  )}\n`;
  const materializationPolicyDigest = digest(materializationPolicyText);
  const provisioningContractText = readFileSync(PROVISIONING_CONTRACT_PATH, 'utf8');
  const provisioningContractDigest = digest(provisioningContractText);
  const manifest = buildSastIsolatedQualificationManifest(
    {
      revision: REVISION,
      publishedAt: PUBLISHED_AT,
      ownerRef: OWNER_REF,
      sourceSnapshot: sourceAssets.snapshot,
      sourceFixtures,
      provisioningContractRef:
        `repository-file://deploy/scanner-sandbox/provisioning-contract.json/${provisioningContractDigest}`,
      provisioningContractDigest,
      materializationPolicyRef:
        `repository-file://qualification/t053-v1/materialization-policy.json/${materializationPolicyDigest}`,
      materializationPolicyDigest
    },
    digest
  );
  if (!manifest) throw new Error('failed to construct T053 isolated integration manifest');
  const manifestText = `${JSON.stringify(manifest, null, 2)}\n`;
  const readmeText = `# T053 Isolated Integration Qualification v1

This package is the immutable provider handoff for the 41 T052 schema/parser and
malicious-repository cases expanded across all three signed profiles (123 execution cells).

- \`isolated-integration.manifest.json\` binds the exact source case, fixture, profile,
  materialization projection, provisioning contract, and cleanup requirements for every cell.
- \`materialization-policy.json\` is a closed declarative action allowlist. It has no shell,
  command, argv, environment, script, URL, package-install, build, dynamic-test, customer-content,
  host-materialization, or public-internet authority.
- Every cell requires a new production-equivalent microVM. Hostile objects may be materialized
  only inside that guest. Provider and qualification-runtime signatures, zero prohibited effects,
  phase-bound zero egress, and complete destruction evidence within 60 seconds are mandatory.
- Repository validation never launches a scanner or microVM and cannot produce a passing T053
  verdict. Until a live dependency set, dual plan approvals, and 123 valid dual-signed receipts
  exist, the only valid aggregate state is \`PENDING_PROVIDER_EXECUTION\`.
- A T053 pass grants entry to T054 only. It never grants finding, policy, publication, rollout,
  Kubernetes, or production-readiness authority.

Manifest: \`${manifest.manifestDigest}\`
Source snapshot: \`${manifest.sourceSnapshotDigest}\`

Do not hand-edit generated assets. Change the reviewed generator, increment the immutable
revision, regenerate, and run \`corepack pnpm qualification:validate\`.
`;
  return Object.freeze({
    manifest,
    manifestText,
    materializationPolicy: MATERIALIZATION_POLICY,
    materializationPolicyText,
    readmeText
  });
}

export async function initializeIsolatedIntegrationAssets() {
  const parent = dirname(ISOLATED_INTEGRATION_ROOT);
  const parentInspection = await inspectPlainDirectory(parent);
  if (await optionalLstat(ISOLATED_INTEGRATION_ROOT)) {
    throw new Error('refusing to overwrite existing T053 qualification root');
  }
  await mkdir(ISOLATED_INTEGRATION_ROOT, { recursive: false });
  const root = await inspectPlainDirectory(
    ISOLATED_INTEGRATION_ROOT,
    parentInspection.canonical
  );
  const assets = createIsolatedIntegrationAssets();
  await createExclusiveFile(join(ISOLATED_INTEGRATION_ROOT, 'README.md'), assets.readmeText);
  await createExclusiveFile(ISOLATED_INTEGRATION_MANIFEST_PATH, assets.manifestText);
  await createExclusiveFile(
    ISOLATED_INTEGRATION_POLICY_PATH,
    assets.materializationPolicyText
  );
  await assertDirectoryStable(
    ISOLATED_INTEGRATION_ROOT,
    root,
    'T053 qualification root changed during initialization'
  );
  await assertDirectoryStable(
    parent,
    parentInspection,
    'T053 qualification parent changed during initialization'
  );
  return assets;
}

export async function writeIsolatedIntegrationAssets() {
  const root = await inspectPlainDirectory(ISOLATED_INTEGRATION_ROOT);
  await assertExactRootEntries(root);
  const assets = createIsolatedIntegrationAssets();
  await writeStableRegularFile(
    join(ISOLATED_INTEGRATION_ROOT, 'README.md'),
    assets.readmeText,
    root.canonical
  );
  await writeStableRegularFile(
    ISOLATED_INTEGRATION_MANIFEST_PATH,
    assets.manifestText,
    root.canonical
  );
  await writeStableRegularFile(
    ISOLATED_INTEGRATION_POLICY_PATH,
    assets.materializationPolicyText,
    root.canonical
  );
  await assertDirectoryStable(
    ISOLATED_INTEGRATION_ROOT,
    root,
    'T053 qualification root changed during generation'
  );
  return assets;
}

async function assertExactRootEntries(root) {
  const entries = await readdir(ISOLATED_INTEGRATION_ROOT, { withFileTypes: true });
  entries.sort((left, right) => compareText(left.name, right.name));
  if (!arraysEqual(entries.map((entry) => entry.name), EXPECTED_ROOT_ENTRIES)) {
    throw new Error('T053 qualification root entries differ from the reviewed set');
  }
  for (const entry of entries) {
    const stat = await lstat(join(ISOLATED_INTEGRATION_ROOT, entry.name), {
      bigint: true
    });
    if (entry.isSymbolicLink() || stat.isSymbolicLink() || !stat.isFile()) {
      throw new Error(`T053 qualification root entry is unsafe: ${entry.name}`);
    }
  }
  await assertDirectoryStable(
    ISOLATED_INTEGRATION_ROOT,
    root,
    'T053 qualification root changed during inspection'
  );
}

async function createExclusiveFile(path, text) {
  let handle;
  try {
    handle = await open(
      path,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | noFollowFlag(),
      0o600
    );
    await handle.writeFile(text, 'utf8');
    await handle.sync();
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function writeStableRegularFile(path, text, canonicalRoot) {
  const parentPath = dirname(path);
  const parent = await inspectPlainDirectory(parentPath, canonicalRoot);
  const before = await lstat(path, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n) {
    throw new Error(`T053 write target is unsafe: ${path}`);
  }
  const canonicalBefore = await realpath(path);
  ensureWithin(canonicalRoot, canonicalBefore, path);
  let handle;
  try {
    handle = await open(path, constants.O_WRONLY | noFollowFlag());
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || opened.isSymbolicLink() || opened.nlink !== 1n) {
      throw new Error(`T053 opened write target is unsafe: ${path}`);
    }
    await handle.truncate(0);
    await handle.writeFile(text, 'utf8');
    await handle.sync();
    const openedAfter = await handle.stat({ bigint: true });
    const after = await lstat(path, { bigint: true });
    const canonicalAfter = await realpath(path);
    ensureWithin(canonicalRoot, canonicalAfter, path);
    if (
      !sameNodeIdentity(opened, openedAfter) ||
      !sameNodeIdentity(before, after) ||
      canonicalAfter !== canonicalBefore
    ) {
      throw new Error(`T053 write target changed during write: ${path}`);
    }
  } finally {
    await handle?.close().catch(() => undefined);
  }
  await assertDirectoryStable(
    parentPath,
    parent,
    `T053 write directory changed during write: ${parentPath}`
  );
}

async function inspectPlainDirectory(path, canonicalRoot) {
  const stat = await lstat(path, { bigint: true });
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`T053 qualification directory is unsafe: ${path}`);
  }
  const canonical = await realpath(path);
  if (canonicalRoot) ensureWithin(canonicalRoot, canonical, path, true);
  return { stat, canonical };
}

async function assertDirectoryStable(path, expected, reason) {
  const current = await inspectPlainDirectory(path);
  if (
    current.canonical !== expected.canonical ||
    !sameNodeIdentity(current.stat, expected.stat)
  ) {
    throw new Error(reason);
  }
}

async function optionalLstat(path) {
  try {
    return await lstat(path, { bigint: true });
  } catch (error) {
    if (error && typeof error === 'object' && error.code === 'ENOENT') return null;
    throw error;
  }
}

function ensureWithin(root, candidate, label, allowRoot = false) {
  const relation = relative(root, candidate);
  if (
    (!allowRoot && relation === '') ||
    relation.startsWith('..') ||
    relation.includes(':')
  ) {
    throw new Error(`T053 qualification path escapes root: ${label}`);
  }
}

function sameNodeIdentity(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.nlink === right.nlink
  );
}

function noFollowFlag() {
  return typeof constants.O_NOFOLLOW === 'number' ? constants.O_NOFOLLOW : 0;
}

function digest(value) {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}

function arraysEqual(left, right) {
  return left.length === right.length && left.every((item, index) => item === right[index]);
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const assets = process.argv.includes('--initialize')
    ? await initializeIsolatedIntegrationAssets()
    : await writeIsolatedIntegrationAssets();
  process.stdout.write(
    `${process.argv.includes('--initialize') ? 'initialized' : 'generated'} ${assets.manifest.executionCellCount} T053 execution cells (${assets.manifest.manifestDigest})\n`
  );
}
