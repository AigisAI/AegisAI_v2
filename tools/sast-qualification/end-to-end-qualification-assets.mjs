import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, readdir, realpath, rm } from 'node:fs/promises';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  buildSastEndToEndQualificationManifest
} from '../../packages/shared/dist/index.js';
import {
  createGoldenCorpusAssets,
  createInitialPriorReleaseManifest
} from './golden-corpus-assets.mjs';
import { createIsolatedIntegrationAssets } from './isolated-integration-assets.mjs';
import { createMultiClassCorpusAssets } from './multi-class-corpus-assets.mjs';

const MODULE_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(MODULE_DIRECTORY, '../..');
export const END_TO_END_QUALIFICATION_ROOT = resolve(
  REPOSITORY_ROOT,
  'qualification/t054-v1'
);
export const END_TO_END_QUALIFICATION_MANIFEST_PATH = join(
  END_TO_END_QUALIFICATION_ROOT,
  'end-to-end-qualification.manifest.json'
);
export const END_TO_END_QUALIFICATION_POLICY_PATH = join(
  END_TO_END_QUALIFICATION_ROOT,
  'measurement-policy.json'
);

const REVISION = '1.0.0';
const PUBLISHED_AT = '2026-08-20T00:00:00.000Z';
const OWNER_REF = 'team://security-engineering/sast-qualification';
const EXPECTED_ROOT_ENTRIES = [
  'README.md',
  'end-to-end-qualification.manifest.json',
  'measurement-policy.json'
];

const MEASUREMENT_POLICY = Object.freeze({
  version: 'sast-end-to-end-qualification-measurement-policy-v1',
  revision: REVISION,
  ownerRef: OWNER_REF,
  prerequisite: {
    stage: 'T053_ISOLATED_INTEGRATION',
    requiredStatus: 'PASSED',
    requiredEntryAuthorization: 't054EntryAuthorized',
    cryptographicEntryAttestationRequired: true
  },
  execution: {
    evidenceStage: 'T054_END_TO_END_AND_PERFORMANCE',
    productionEquivalentProviderRequired: true,
    liveProviderAdapterRequired: true,
    oneFreshMicroVmPerAttempt: true,
    maximumAttemptsPerCell: 2,
    infrastructureRetryLimit: 1,
    retriesIncludedInReliabilityDenominator: true,
    cleanupSloSeconds: 60,
    queueToCleanupMeasurementRequired: true,
    candidateAndBaselineArtifactBindingRequired: true,
    aggregateMetricsAcceptedFromCaller: false,
    trustedClockRequired: true,
    detachedDualApprovalRequired: true,
    receiptSignatureRoles: [
      'MICROVM_PROVIDER',
      'QUALIFICATION_RUNTIME',
      'TELEMETRY_AUTHORITY'
    ]
  },
  denominators: {
    goldenCandidateCaseProfileCells: 1880,
    goldenNegativeBaselineCaseProfileCells: 940,
    fingerprintAndEvidencePrivacyCaseProfileCells: 102,
    performanceProfileSizeBuckets: 9,
    performanceRunsPerArmBucket: 30,
    performanceCandidateAndBaselineCells: 540,
    totalExecutionCells: 3462
  },
  thresholds: {
    goldenCorpusExactPassRate: 1,
    mustDetectRecallMinimum: 0.95,
    criticalHighPrecisionMinimum: 0.9,
    priorMustDetectRecall: 1,
    falsePositiveIncreaseMaximum: 0.02,
    scannerFailureRateMaximum: 0.02,
    candidateP95LatencyIncreaseMaximum: 0.2,
    fastLaneP95MillisecondsMaximum: 600000,
    deepLaneP95MillisecondsMaximum: 2700000,
    fingerprintFixturePassRate: 1,
    evidencePrivacyPassRate: 1,
    capacityPassRate: 1,
    allZeroToleranceCounts: 0
  },
  prohibited: {
    customerContentAccepted: false,
    customerCodeExecutionAllowed: false,
    packageInstallAllowed: false,
    repositoryBuildAllowed: false,
    dynamicTestAllowed: false,
    publicInternetEgressAllowed: false,
    externalPublicationAllowed: false,
    localExecutionAllowed: false
  },
  authority: {
    findingAuthority: false,
    policyAuthority: false,
    publicationAuthority: false,
    deploymentAuthority: false,
    productionReadinessAuthority: false
  },
  immutable: true
});

export function createEndToEndQualificationAssets() {
  const priorReleaseManifest = createInitialPriorReleaseManifest();
  const golden = createGoldenCorpusAssets(priorReleaseManifest);
  const multiClass = createMultiClassCorpusAssets();
  const isolated = createIsolatedIntegrationAssets();
  const measurementPolicyText = `${JSON.stringify(MEASUREMENT_POLICY, null, 2)}\n`;
  const measurementPolicyDigest = digest(measurementPolicyText);
  const manifest = buildSastEndToEndQualificationManifest(
    {
      revision: REVISION,
      publishedAt: PUBLISHED_AT,
      ownerRef: OWNER_REF,
      goldenSnapshot: golden.snapshot,
      priorReleaseManifest,
      multiClassSnapshot: multiClass.snapshot,
      t053Manifest: isolated.manifest,
      measurementPolicyRef:
        `repository-file://qualification/t054-v1/measurement-policy.json/${measurementPolicyDigest}`,
      measurementPolicyDigest
    },
    digest
  );
  if (!manifest) {
    throw new Error('failed to construct T054 end-to-end qualification manifest');
  }
  const manifestText = `${JSON.stringify(manifest, null, 2)}\n`;
  const readmeText = `# T054 End-to-End Qualification v1

This immutable handoff expands the reviewed T051/T052 inputs into exactly 3,462
production-equivalent execution cells: 1,880 candidate golden cells, 940 baseline negative
cells, 102 candidate fingerprint/privacy end-to-end cells, and 540 candidate/baseline
performance cells (nine profile-size buckets, 30 post-warm-up runs per arm).

- T054 cannot issue an execution plan until a valid T053 \`PASSED\` result and a separately
  signed \`t054EntryAuthorized\` attestation are verified offline.
- Every receipt binds the exact manifest, dependency set, candidate and baseline scanner sets,
  hardware class, plan, cell, profile, provider, attempt chain, all queue-to-cleanup phases,
  resource observations, and cleanup evidence.
- Detached Security Engineering and Scan Platform approvals must strictly predate execution.
  Provider, qualification-runtime, and telemetry signatures are required for every receipt.
- One infrastructure retry is allowed, but the failed first attempt remains in the scanner
  reliability denominator. Attempt, sandbox, workload, attestation, receipt, and cell identities
  cannot be reused anywhere in the evidence set.
- The verifier recomputes every denominator, percentile, precision/recall/false-positive,
  reliability, capacity, resource, and zero-tolerance aggregate from signed receipts. Caller
  aggregates are never accepted.
- Repository validation launches no scanner or microVM and cannot fabricate a T054 pass. Without
  real T053 evidence it remains \`BLOCKED_T053_QUALIFICATION\`; with only a partial valid T054 run
  it remains \`PENDING_PROVIDER_EXECUTION\`.
- A T054 pass authorizes entry to T055 only. It grants no finding, policy, publication,
  deployment, Kubernetes, or production-readiness authority.

Manifest: \`${manifest.manifestDigest}\`
T053 manifest: \`${manifest.t053ManifestDigest}\`
T051 snapshot: \`${manifest.t051SnapshotDigest}\`
T052 snapshot: \`${manifest.t052SnapshotDigest}\`

Do not hand-edit generated assets. Change the reviewed generator, increment the immutable
revision, regenerate, and run \`corepack pnpm qualification:validate\`.
`;
  return Object.freeze({
    manifest,
    manifestText,
    measurementPolicy: MEASUREMENT_POLICY,
    measurementPolicyText,
    readmeText
  });
}

export async function initializeEndToEndQualificationAssets() {
  const parentPath = dirname(END_TO_END_QUALIFICATION_ROOT);
  const parent = await inspectDirectory(parentPath);
  if (await optionalLstat(END_TO_END_QUALIFICATION_ROOT)) {
    throw new Error('refusing to overwrite existing T054 qualification root');
  }
  await mkdir(END_TO_END_QUALIFICATION_ROOT, { recursive: false });
  const root = await inspectDirectory(
    END_TO_END_QUALIFICATION_ROOT,
    parent.canonical
  );
  const assets = createEndToEndQualificationAssets();
  await createExclusiveFile(join(root.canonical, 'README.md'), assets.readmeText);
  await createExclusiveFile(
    join(root.canonical, 'end-to-end-qualification.manifest.json'),
    assets.manifestText
  );
  await createExclusiveFile(
    join(root.canonical, 'measurement-policy.json'),
    assets.measurementPolicyText
  );
  await assertDirectoryStable(END_TO_END_QUALIFICATION_ROOT, root);
  await assertDirectoryStable(parentPath, parent);
  return assets;
}

export async function writeEndToEndQualificationAssets() {
  const root = await inspectDirectory(END_TO_END_QUALIFICATION_ROOT);
  await assertExactRoot(root.canonical);
  const assets = createEndToEndQualificationAssets();
  await writeStableRegularFile(
    join(root.canonical, 'README.md'),
    assets.readmeText,
    root.canonical
  );
  await writeStableRegularFile(
    join(root.canonical, 'end-to-end-qualification.manifest.json'),
    assets.manifestText,
    root.canonical
  );
  await writeStableRegularFile(
    join(root.canonical, 'measurement-policy.json'),
    assets.measurementPolicyText,
    root.canonical
  );
  await assertDirectoryStable(END_TO_END_QUALIFICATION_ROOT, root);
  return assets;
}

async function assertExactRoot(canonicalRoot) {
  const entries = await readdir(canonicalRoot, { withFileTypes: true });
  entries.sort((left, right) => compareText(left.name, right.name));
  if (!arraysEqual(entries.map((entry) => entry.name), EXPECTED_ROOT_ENTRIES)) {
    throw new Error('T054 qualification root entries differ from the reviewed set');
  }
  for (const entry of entries) {
    const stat = await lstat(join(canonicalRoot, entry.name), { bigint: true });
    if (
      entry.isSymbolicLink() ||
      stat.isSymbolicLink() ||
      !stat.isFile() ||
      stat.nlink !== 1n
    ) {
      throw new Error(`T054 qualification root entry is unsafe: ${entry.name}`);
    }
  }
  const root = await inspectDirectory(END_TO_END_QUALIFICATION_ROOT);
  if (root.canonical !== canonicalRoot) {
    throw new Error('T054 qualification root changed during inspection');
  }
}

async function createExclusiveFile(path, text) {
  let handle;
  let created = false;
  let failure;
  try {
    handle = await open(
      path,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | noFollowFlag(),
      0o600
    );
    created = true;
    await handle.writeFile(text, 'utf8');
    await handle.sync();
  } catch (error) {
    failure = error;
  } finally {
    await handle?.close().catch(() => undefined);
  }
  if (failure) {
    if (created) await rm(path, { force: true }).catch(() => undefined);
    throw failure;
  }
}

async function writeStableRegularFile(path, text, canonicalRoot) {
  const parentPath = dirname(path);
  const parent = await inspectDirectory(parentPath, canonicalRoot);
  const before = await lstat(path, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n) {
    throw new Error(`T054 write target is unsafe: ${path}`);
  }
  const canonicalBefore = await realpath(path);
  ensureWithin(canonicalRoot, canonicalBefore, path);
  let handle;
  try {
    handle = await open(path, constants.O_WRONLY | noFollowFlag());
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || opened.isSymbolicLink() || opened.nlink !== 1n) {
      throw new Error(`T054 opened write target is unsafe: ${path}`);
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
      throw new Error(`T054 write target changed during write: ${path}`);
    }
  } finally {
    await handle?.close().catch(() => undefined);
  }
  await assertDirectoryStable(parentPath, parent);
}

async function inspectDirectory(path, canonicalParent) {
  const stat = await lstat(path, { bigint: true });
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`T054 qualification directory is unsafe: ${path}`);
  }
  const canonical = await realpath(path);
  if (canonicalParent) ensureWithin(canonicalParent, canonical, path, true);
  return { canonical, stat };
}

async function assertDirectoryStable(path, expected) {
  const current = await inspectDirectory(path);
  if (
    current.canonical !== expected.canonical ||
    current.stat.dev !== expected.stat.dev ||
    current.stat.ino !== expected.stat.ino
  ) {
    throw new Error(`T054 qualification directory changed during write: ${path}`);
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

function ensureWithin(root, candidate, label, allowRoot = false) {
  const relation = relative(root, candidate);
  if (
    (!allowRoot && relation === '') ||
    relation.startsWith('..') ||
    relation.includes(':')
  ) {
    throw new Error(`T054 qualification path escapes root: ${label}`);
  }
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
    ? await initializeEndToEndQualificationAssets()
    : await writeEndToEndQualificationAssets();
  process.stdout.write(
    `${process.argv.includes('--initialize') ? 'initialized' : 'generated'} ${assets.manifest.executionCellCount} T054 execution cells (${assets.manifest.manifestDigest})\n`
  );
}
