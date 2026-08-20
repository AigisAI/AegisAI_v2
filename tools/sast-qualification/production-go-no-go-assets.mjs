import { createHash } from 'node:crypto';
import { constants, readFileSync } from 'node:fs';
import { lstat, mkdir, open, readdir, realpath, rm } from 'node:fs/promises';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  SAST_PRODUCTION_GO_NO_GO_EVIDENCE_KINDS,
  SAST_PRODUCTION_GO_NO_GO_GATE_CATALOG,
  buildSastProductionGoNoGoManifest
} from '../../packages/shared/dist/index.js';
import { createEndToEndQualificationAssets } from './end-to-end-qualification-assets.mjs';
import { createSupplyChainRollbackQualificationAssets } from './supply-chain-rollback-qualification-assets.mjs';

const MODULE_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(MODULE_DIRECTORY, '../..');
const DEPLOYMENT_OPERATIONS_CONTRACT_PATH = resolve(
  REPOSITORY_ROOT,
  'specs/005-production-deployment-operations/contracts/deployment-operations.md'
);
export const PRODUCTION_GO_NO_GO_ROOT = resolve(
  REPOSITORY_ROOT,
  'qualification/t056-v1'
);
export const PRODUCTION_GO_NO_GO_MANIFEST_PATH = join(
  PRODUCTION_GO_NO_GO_ROOT,
  'production-go-no-go.manifest.json'
);
export const PRODUCTION_GO_NO_GO_POLICY_PATH = join(
  PRODUCTION_GO_NO_GO_ROOT,
  'go-no-go-policy.json'
);

const REVISION = '1.0.1';
const PUBLISHED_AT = '2026-08-20T02:00:00.000Z';
const OWNER_REF = `team://security-engineering/sast-production-readiness/${digest('t056-owner')}`;
const EXPECTED_ROOT_ENTRIES = [
  'README.md',
  'go-no-go-policy.json',
  'production-go-no-go.manifest.json'
];

export function createProductionGoNoGoAssets() {
  const t054 = createEndToEndQualificationAssets();
  const t055 = createSupplyChainRollbackQualificationAssets();
  const deploymentOperationsContractText = readCanonicalRepositoryText(
    DEPLOYMENT_OPERATIONS_CONTRACT_PATH,
    '005 deployment-operations contract'
  );
  const deploymentOperationsContractDigest = digest(deploymentOperationsContractText);
  const deploymentOperationsContractRef =
    `repository-file://specs/005-production-deployment-operations/contracts/deployment-operations.md/${deploymentOperationsContractDigest}`;
  const policy = Object.freeze({
    version: 'sast-production-go-no-go-policy-v1',
    revision: REVISION,
    ownerRef: OWNER_REF,
    prerequisite: {
      stage: 'T055_SUPPLY_CHAIN_DATABASE_SCHEMA_ROLLBACK',
      requiredStatus: 'PASSED',
      requiredEntryAuthorization: 't056EntryAuthorized',
      exactT054ManifestResultDependencyVerificationPlanRequired: true,
      exactT055ManifestEntryPlanResultRequired: true,
      sameProviderAndAdapterRequired: true,
      qualificationAuthorityEntryAttestationRequired: true,
      independentlyConfiguredTrustPolicyDigestRequired: true
    },
    evidence: {
      requiredKinds: [...SAST_PRODUCTION_GO_NO_GO_EVIDENCE_KINDS],
      exactCanonicalGateCatalogRequired: true,
      aggregateDecisionAcceptedFromCaller: false,
      callerSelectedEvaluationTimeAllowed: false,
      missingCategoryOutcome: 'PENDING_FINAL_EVIDENCE',
      malformedStaleOrBreachedOutcome: 'NO_GO',
      notApplicableAllowedForV1: false,
      maximumEvidenceAgeSeconds: 86_400,
      finalApprovalRoles: ['SECURITY_ENGINEERING', 'SCAN_PLATFORM'],
      finalApprovalMaximumAgeSeconds: 3_600
    },
    gateCatalog: SAST_PRODUCTION_GO_NO_GO_GATE_CATALOG.map((item) => ({
      ...item,
      requiredSignatureRoles: [...item.requiredSignatureRoles],
      notApplicableAllowed: false
    })),
    handoff: {
      deploymentOperationsContractRef,
      deploymentOperationsContractDigest,
      goAuthorizesOnly: 'DEPLOYMENT_OPERATIONS_ENTRY',
      passingDoesNotExecuteKubernetes: true,
      passingDoesNotEstablishProductionReadiness: true
    },
    prohibited: {
      customerContentAccepted: false,
      customerCodeExecutionAllowed: false,
      packageInstallAllowed: false,
      repositoryBuildAllowed: false,
      dynamicTestAllowed: false,
      publicInternetEgressAllowed: false,
      localProviderEvidenceAllowed: false,
      productionMutationAllowed: false,
      kubernetesExecutionAllowed: false
    },
    authority: {
      findingAuthority: false,
      policyAuthority: false,
      publicationAuthority: false,
      scmMutationAuthority: false,
      aiAuthority: false,
      deploymentAuthority: false,
      kubernetesExecutionAuthority: false,
      productionMutationAuthority: false,
      productionReadinessAuthority: false,
      goAuthorizationOnly: '005_DEPLOYMENT_OPERATIONS_ENTRY'
    },
    immutable: true
  });
  const policyText = `${JSON.stringify(policy, null, 2)}\n`;
  const policyDigest = digest(policyText);
  const manifest = buildSastProductionGoNoGoManifest(
    {
      revision: REVISION,
      publishedAt: PUBLISHED_AT,
      ownerRef: OWNER_REF,
      gatePolicyRef:
        `repository-file://qualification/t056-v1/go-no-go-policy.json/${policyDigest}`,
      gatePolicyDigest: policyDigest,
      t055Manifest: t055.manifest,
      t054Manifest: t054.manifest,
      deploymentOperationsContractRef,
      deploymentOperationsContractDigest
    },
    digest
  );
  if (!manifest) throw new Error('failed to construct T056 production go/no-go manifest');
  const manifestText = `${JSON.stringify(manifest, null, 2)}\n`;
  const readmeText = `# T056 Immutable Production Go/No-Go Evidence v1

This repository-owned package closes the final SAST decision boundary before the separate 005
deployment-operations flow. It defines one canonical catalog of ${manifest.requiredGateCount}
release-blocking gates and accepts no caller-supplied overall decision.

- Plan creation requires the exact passing T054/T055 chain, the same provider and adapter, and a
  Qualification Authority Ed25519 entry attestation. The trust bundle is independently pinned by
  \`SAST_T056_TRUST_POLICY_DIGEST\`.
- Exactly six evidence attestations cover upstream qualification, repository validation, canary
  telemetry replay, kill-switch propagation, rollback readiness, and the reference-only 005
  deployment boundary. Each attestation binds the candidate/baseline scanner sets, profiles,
  T051/T052 corpus revisions, one repository commit shared by all six categories, T054/T055
  measurements, digest-paired evidence references, and required signer roles.
- The verifier recomputes every upstream observation from the signed T054/T055 results. It does not
  accept a caller aggregate, caller verdict, omitted denominator, or retry-erased measurement.
- Missing whole evidence categories or final approvals remain \`PENDING_FINAL_EVIDENCE\`.
  Malformed, unsigned, stale, drifted, threshold-breaching, or \`NOT_APPLICABLE\` evidence is
  \`NO_GO\`. Every v1 gate is mandatory.
- Security Engineering and Scan Platform independently sign the exact decision plan. The immutable
  record retains the shared repository commit, every per-gate outcome, rationale, evidence binding,
  rollback target, kill-switch evidence, decision actor, and decision time.
- \`GO\` sets only \`deploymentOperationsEntryAuthorized=true\`. Finding, policy, publication,
  SCM, AI, deployment execution, Kubernetes execution, production mutation, and production-
  readiness authority remain false.
- Repository validation creates no external qualification, provider, canary, Kubernetes, or
  production evidence. Without a real T055 pass it remains \`BLOCKED_T055_QUALIFICATION\`.

Manifest: \`${manifest.manifestDigest}\`
T055 manifest: \`${manifest.t055ManifestDigest}\`
Gate policy: \`${manifest.gatePolicyDigest}\`
005 contract: \`${manifest.deploymentOperationsContractDigest}\`

Do not hand-edit generated assets. Change the reviewed generator, increment the immutable
revision, regenerate, and run \`corepack pnpm qualification:validate\`.
`;
  return Object.freeze({
    manifest,
    manifestText,
    policy,
    policyText,
    readmeText,
    t054Manifest: t054.manifest,
    t055Manifest: t055.manifest,
    deploymentOperationsContractDigest
  });
}

export async function initializeProductionGoNoGoAssets() {
  const parentPath = dirname(PRODUCTION_GO_NO_GO_ROOT);
  const parent = await inspectDirectory(parentPath);
  if (await optionalLstat(PRODUCTION_GO_NO_GO_ROOT)) {
    throw new Error('refusing to overwrite existing T056 qualification root');
  }
  await mkdir(PRODUCTION_GO_NO_GO_ROOT, { recursive: false });
  const root = await inspectDirectory(PRODUCTION_GO_NO_GO_ROOT, parent.canonical);
  const assets = createProductionGoNoGoAssets();
  await createExclusiveFile(join(root.canonical, 'README.md'), assets.readmeText);
  await createExclusiveFile(join(root.canonical, 'go-no-go-policy.json'), assets.policyText);
  await createExclusiveFile(
    join(root.canonical, 'production-go-no-go.manifest.json'),
    assets.manifestText
  );
  await assertDirectoryStable(PRODUCTION_GO_NO_GO_ROOT, root);
  await assertDirectoryStable(parentPath, parent);
  return assets;
}

export async function writeProductionGoNoGoAssets() {
  const root = await inspectDirectory(PRODUCTION_GO_NO_GO_ROOT);
  await assertExactRoot(root.canonical);
  const assets = createProductionGoNoGoAssets();
  await writeStableRegularFile(join(root.canonical, 'README.md'), assets.readmeText, root.canonical);
  await writeStableRegularFile(join(root.canonical, 'go-no-go-policy.json'), assets.policyText, root.canonical);
  await writeStableRegularFile(
    join(root.canonical, 'production-go-no-go.manifest.json'),
    assets.manifestText,
    root.canonical
  );
  await assertDirectoryStable(PRODUCTION_GO_NO_GO_ROOT, root);
  return assets;
}

async function assertExactRoot(canonicalRoot) {
  const entries = await readdir(canonicalRoot, { withFileTypes: true });
  entries.sort((left, right) => compareText(left.name, right.name));
  if (!arraysEqual(entries.map((entry) => entry.name), EXPECTED_ROOT_ENTRIES)) {
    throw new Error('T056 qualification root entries differ from the reviewed set');
  }
  for (const entry of entries) {
    const stat = await lstat(join(canonicalRoot, entry.name), { bigint: true });
    if (entry.isSymbolicLink() || stat.isSymbolicLink() || !stat.isFile() || stat.nlink !== 1n) {
      throw new Error(`T056 qualification root entry is unsafe: ${entry.name}`);
    }
  }
  const root = await inspectDirectory(PRODUCTION_GO_NO_GO_ROOT);
  if (root.canonical !== canonicalRoot) {
    throw new Error('T056 qualification root changed during inspection');
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
    throw new Error(`T056 write target is unsafe: ${path}`);
  }
  const canonicalBefore = await realpath(path);
  ensureWithin(canonicalRoot, canonicalBefore, path);
  let handle;
  try {
    handle = await open(path, constants.O_WRONLY | noFollowFlag());
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || opened.isSymbolicLink() || opened.nlink !== 1n) {
      throw new Error(`T056 opened write target is unsafe: ${path}`);
    }
    await handle.truncate(0);
    await handle.writeFile(text, 'utf8');
    await handle.sync();
    const openedAfter = await handle.stat({ bigint: true });
    const after = await lstat(path, { bigint: true });
    const canonicalAfter = await realpath(path);
    ensureWithin(canonicalRoot, canonicalAfter, path);
    if (!sameNodeIdentity(opened, openedAfter) || !sameNodeIdentity(before, after) || canonicalAfter !== canonicalBefore) {
      throw new Error(`T056 write target changed during write: ${path}`);
    }
  } finally {
    await handle?.close().catch(() => undefined);
  }
  await assertDirectoryStable(parentPath, parent);
}

async function inspectDirectory(path, canonicalParent) {
  const stat = await lstat(path, { bigint: true });
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`T056 qualification directory is unsafe: ${path}`);
  }
  const canonical = await realpath(path);
  if (canonicalParent) ensureWithin(canonicalParent, canonical, path, true);
  return { canonical, stat };
}

async function assertDirectoryStable(path, expected) {
  const current = await inspectDirectory(path);
  if (current.canonical !== expected.canonical || current.stat.dev !== expected.stat.dev || current.stat.ino !== expected.stat.ino) {
    throw new Error(`T056 qualification directory changed during write: ${path}`);
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

function readCanonicalRepositoryText(path, label) {
  const buffer = readFileSync(path);
  const decoded = new TextDecoder('utf-8', { fatal: true }).decode(buffer);
  const text = decoded.replace(/\r\n/gu, '\n').normalize('NFC');
  if (text.includes('\u0000') || text.includes('\r') || !text.endsWith('\n')) {
    throw new Error(`${label} is not canonical UTF-8/NFC/LF text`);
  }
  return text;
}

function sameNodeIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.mode === right.mode && left.nlink === right.nlink;
}

function noFollowFlag() {
  return typeof constants.O_NOFOLLOW === 'number' ? constants.O_NOFOLLOW : 0;
}

function ensureWithin(root, candidate, label, allowRoot = false) {
  const relation = relative(root, candidate);
  if ((!allowRoot && relation === '') || relation.startsWith('..') || relation.includes(':')) {
    throw new Error(`T056 qualification path escapes root: ${label}`);
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
    ? await initializeProductionGoNoGoAssets()
    : await writeProductionGoNoGoAssets();
  process.stdout.write(
    `${process.argv.includes('--initialize') ? 'initialized' : 'generated'} ${assets.manifest.requiredGateCount} T056 gates (${assets.manifest.manifestDigest})\n`
  );
}
