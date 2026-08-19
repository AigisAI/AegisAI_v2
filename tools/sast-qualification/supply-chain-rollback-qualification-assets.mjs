import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, readdir, realpath, rm } from 'node:fs/promises';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  buildSastSupplyChainRollbackQualificationManifest
} from '../../packages/shared/dist/index.js';
import { createEndToEndQualificationAssets } from './end-to-end-qualification-assets.mjs';

const MODULE_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(MODULE_DIRECTORY, '../..');
export const SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_ROOT = resolve(
  REPOSITORY_ROOT,
  'qualification/t055-v1'
);
export const SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_MANIFEST_PATH = join(
  SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_ROOT,
  'supply-chain-rollback-qualification.manifest.json'
);
export const SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_POLICY_PATH = join(
  SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_ROOT,
  'drill-policy.json'
);

const REVISION = '1.0.0';
const PUBLISHED_AT = '2026-08-20T00:00:00.000Z';
const OWNER_REF =
  `team://security-engineering/sast-supply-chain/${digest('t055-owner')}`;
const EXPECTED_ROOT_ENTRIES = [
  'README.md',
  'drill-policy.json',
  'supply-chain-rollback-qualification.manifest.json'
];

const DRILL_POLICY = Object.freeze({
  version: 'sast-supply-chain-rollback-drill-policy-v1',
  revision: REVISION,
  ownerRef: OWNER_REF,
  prerequisite: {
    stage: 'T054_END_TO_END_AND_PERFORMANCE',
    requiredStatus: 'PASSED',
    requiredEntryAuthorization: 't055EntryAuthorized',
    exactT054ManifestRequired: true,
    exactT054ResultRequired: true,
    exactT054DependencySetRequired: true,
    exactT054ArtifactVerificationSetRequired: true,
    exactT054PlanRequired: true,
    sameProviderAndAdapterRequired: true,
    qualificationAuthorityEntryAttestationRequired: true,
    independentlyConfiguredTrustPolicyDigestRequired: true,
    authenticatedRollbackLedgerHeadAttestationsRequired: true
  },
  execution: {
    evidenceStage: 'T055_SUPPLY_CHAIN_DATABASE_SCHEMA_ROLLBACK',
    productionEquivalentProviderRequired: true,
    oneFreshIsolatedEnvironmentPerDrill: true,
    readOnlyArtifactMountRequired: true,
    mountedArtifactRehashRequired: true,
    exactSignatureEnvelopeDigestRequired: true,
    exactProvenanceEnvelopeDigestRequired: true,
    internalVulnerabilityDatabaseMirrorRequired: true,
    externalDatabaseEnrichmentRejectedBeforeEgress: true,
    canonicalResultSchemaRequired: true,
    detachedDualApprovalRequired: true,
    trustedClockRequired: true,
    cleanupSloSeconds: 60,
    aggregateMetricsAcceptedFromCaller: false,
    receiptSignatureRoles: [
      'SUPPLY_CHAIN_AUTHORITY',
      'MICROVM_PROVIDER',
      'QUALIFICATION_RUNTIME'
    ],
    rollbackLedgerHeadSignatureRoles: [
      'QUALIFICATION_AUTHORITY',
      'SUPPLY_CHAIN_AUTHORITY'
    ]
  },
  denominators: {
    artifactCount: 36,
    artifactDrillsPerArtifact: 4,
    artifactSupplyChainDrills: 144,
    unlistedComponentDrills: 1,
    vulnerabilityDatabaseDrills: 6,
    resultSchemaDrills: 3,
    rollbackProfiles: 3,
    rollbackDrillsPerProfile: 5,
    rollbackDrills: 15,
    preExecutionRejections: 115,
    artifactInvocations: 39,
    totalExecutionCells: 169
  },
  rollback: {
    orderedPhases: [
      'ROLLBACK_CANDIDATE_SUSPEND',
      'ROLLBACK_QUEUE_ADMISSION_FENCE',
      'ROLLBACK_IN_FLIGHT_ABORT_AND_CLEANUP',
      'ROLLBACK_DERIVE_AND_REVERIFY_LAST_KNOWN_GOOD',
      'ROLLBACK_ACTIVATE_BASELINE_APPEND_ONLY'
    ],
    exactCandidateAndBaselineReleaseSetDigestsRequired: true,
    candidateInvocationsAfterFenceMaximum: 0,
    inFlightAbortEvidenceRequired: true,
    lastKnownGoodReverificationRequired: true,
    appendOnlyActivationLedgerRequired: true,
    authenticatedPriorLedgerHeadRequired: true,
    exactLedgerSequenceIncrementRequired: true
  },
  prohibited: {
    customerContentAccepted: false,
    customerCodeExecutionAllowed: false,
    packageInstallAllowed: false,
    repositoryBuildAllowed: false,
    dynamicTestAllowed: false,
    publicInternetEgressAllowed: false,
    productionMutationAllowed: false,
    localExecutionAllowed: false
  },
  authority: {
    findingAuthority: false,
    policyAuthority: false,
    publicationAuthority: false,
    deploymentAuthority: false,
    kubernetesAuthority: false,
    productionReadinessAuthority: false,
    nextStageAuthorizationOnly: 'T056_ENTRY'
  },
  immutable: true
});

export function createSupplyChainRollbackQualificationAssets() {
  const t054 = createEndToEndQualificationAssets();
  const drillPolicyText = `${JSON.stringify(DRILL_POLICY, null, 2)}\n`;
  const drillPolicyDigest = digest(drillPolicyText);
  const manifest = buildSastSupplyChainRollbackQualificationManifest(
    {
      revision: REVISION,
      publishedAt: PUBLISHED_AT,
      ownerRef: OWNER_REF,
      drillPolicyRef:
        `repository-file://qualification/t055-v1/drill-policy.json/${drillPolicyDigest}`,
      drillPolicyDigest,
      t054Manifest: t054.manifest
    },
    digest
  );
  if (!manifest) {
    throw new Error('failed to construct T055 supply-chain rollback manifest');
  }
  const manifestText = `${JSON.stringify(manifest, null, 2)}\n`;
  const readmeText = `# T055 Supply-Chain and Rollback Qualification v1

This immutable handoff defines exactly 169 production-equivalent drills before final go/no-go:
144 artifact mount/digest/signature/provenance drills over all 36 T054 artifacts, one unlisted
component rejection, six internal vulnerability-database drills, three result-schema drills, and
15 ordered rollback drills across the three scanner profiles.

- T055 cannot issue a plan until the exact T054 manifest, PASSED result, dependency set, complete
  per-artifact verification set, and execution plan are rebound by a Qualification Authority
  Ed25519 entry attestation. Provider qualification cannot be transferred.
- The trust bundle is independently pinned by \`SAST_T055_TRUST_POLICY_DIGEST\`. Every T054
  artifact signature and provenance envelope is reloaded and verified before T055 evidence is
  accepted.
- Positive artifact drills require a read-only mount, exact mount rehash, exact signature and
  provenance envelope digests, successful verification, and allowlist admission. Each negative
  drill isolates digest, signature, provenance, allowlist, stale DB, network, or schema rejection
  before artifact invocation or external egress.
- Rollback evidence is ordered per profile: suspend candidate, fence queue admission, abort and
  clean in-flight work, derive and reverify the exact last-known-good release set, then activate
  that baseline through a digest-chained append-only audit entry. Before plan approval, each
  profile's durable prior ledger head and sequence are authenticated by independent Qualification
  Authority and Supply Chain Authority signatures; the activation must be its exact next entry.
- Detached Security Engineering and Scan Platform approvals must strictly predate the earliest
  submitted receipt or attempt.
  Supply Chain Authority, MicroVM Provider, and Qualification Runtime signatures are required on
  every receipt. Attempt, sandbox, workload, attestation, audit, receipt, and cell identities are
  globally single-use.
- Repository validation executes no scanner, customer code, package installation, repository
  build, dynamic test, provider workload, network request, Kubernetes action, or production
  mutation. Without external T054 and drill evidence it remains
  \`BLOCKED_T054_QUALIFICATION\`.
- A complete pass authorizes entry to T056 only. It grants no finding, policy, publication,
  deployment, Kubernetes, or production-readiness authority.

Manifest: \`${manifest.manifestDigest}\`
T054 manifest: \`${manifest.t054ManifestDigest}\`
Drill policy: \`${manifest.drillPolicyDigest}\`

Do not hand-edit generated assets. Change the reviewed generator, increment the immutable
revision, regenerate, and run \`corepack pnpm qualification:validate\`.
`;
  return Object.freeze({
    manifest,
    manifestText,
    drillPolicy: DRILL_POLICY,
    drillPolicyText,
    readmeText
  });
}

export async function initializeSupplyChainRollbackQualificationAssets() {
  const parentPath = dirname(SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_ROOT);
  const parent = await inspectDirectory(parentPath);
  if (await optionalLstat(SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_ROOT)) {
    throw new Error('refusing to overwrite existing T055 qualification root');
  }
  await mkdir(SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_ROOT, { recursive: false });
  const root = await inspectDirectory(
    SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_ROOT,
    parent.canonical
  );
  const assets = createSupplyChainRollbackQualificationAssets();
  await createExclusiveFile(join(root.canonical, 'README.md'), assets.readmeText);
  await createExclusiveFile(
    join(root.canonical, 'drill-policy.json'),
    assets.drillPolicyText
  );
  await createExclusiveFile(
    join(root.canonical, 'supply-chain-rollback-qualification.manifest.json'),
    assets.manifestText
  );
  await assertDirectoryStable(SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_ROOT, root);
  await assertDirectoryStable(parentPath, parent);
  return assets;
}

export async function writeSupplyChainRollbackQualificationAssets() {
  const root = await inspectDirectory(SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_ROOT);
  await assertExactRoot(root.canonical);
  const assets = createSupplyChainRollbackQualificationAssets();
  await writeStableRegularFile(
    join(root.canonical, 'README.md'),
    assets.readmeText,
    root.canonical
  );
  await writeStableRegularFile(
    join(root.canonical, 'drill-policy.json'),
    assets.drillPolicyText,
    root.canonical
  );
  await writeStableRegularFile(
    join(root.canonical, 'supply-chain-rollback-qualification.manifest.json'),
    assets.manifestText,
    root.canonical
  );
  await assertDirectoryStable(SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_ROOT, root);
  return assets;
}

async function assertExactRoot(canonicalRoot) {
  const entries = await readdir(canonicalRoot, { withFileTypes: true });
  entries.sort((left, right) => compareText(left.name, right.name));
  if (!arraysEqual(entries.map((entry) => entry.name), EXPECTED_ROOT_ENTRIES)) {
    throw new Error('T055 qualification root entries differ from the reviewed set');
  }
  for (const entry of entries) {
    const stat = await lstat(join(canonicalRoot, entry.name), { bigint: true });
    if (
      entry.isSymbolicLink() ||
      stat.isSymbolicLink() ||
      !stat.isFile() ||
      stat.nlink !== 1n
    ) {
      throw new Error(`T055 qualification root entry is unsafe: ${entry.name}`);
    }
  }
  const root = await inspectDirectory(SUPPLY_CHAIN_ROLLBACK_QUALIFICATION_ROOT);
  if (root.canonical !== canonicalRoot) {
    throw new Error('T055 qualification root changed during inspection');
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
    throw new Error(`T055 write target is unsafe: ${path}`);
  }
  const canonicalBefore = await realpath(path);
  ensureWithin(canonicalRoot, canonicalBefore, path);
  let handle;
  try {
    handle = await open(path, constants.O_WRONLY | noFollowFlag());
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || opened.isSymbolicLink() || opened.nlink !== 1n) {
      throw new Error(`T055 opened write target is unsafe: ${path}`);
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
      throw new Error(`T055 write target changed during write: ${path}`);
    }
  } finally {
    await handle?.close().catch(() => undefined);
  }
  await assertDirectoryStable(parentPath, parent);
}

async function inspectDirectory(path, canonicalParent) {
  const stat = await lstat(path, { bigint: true });
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`T055 qualification directory is unsafe: ${path}`);
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
    throw new Error(`T055 qualification directory changed during write: ${path}`);
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
    throw new Error(`T055 qualification path escapes root: ${label}`);
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
    ? await initializeSupplyChainRollbackQualificationAssets()
    : await writeSupplyChainRollbackQualificationAssets();
  process.stdout.write(
    `${process.argv.includes('--initialize') ? 'initialized' : 'generated'} ${assets.manifest.executionCellCount} T055 execution cells (${assets.manifest.manifestDigest})\n`
  );
}
